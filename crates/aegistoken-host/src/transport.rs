//! libusb transport for the AegisToken Management HID interface.
//!
//! Device discovery uses the USB VID/PID and the interface's string descriptor
//! (`HID Management`), so it works for both the composite device and the
//! per-interface devices that the Windows HID backend exposes.
//!
//! No WinUSB/Zadig driver is installed: on Windows libusb uses its HID backend
//! against the inbox HID driver, on Linux it detaches the kernel HID driver, and
//! on macOS access needs no driver work.

use core::fmt;
use std::time::Duration;

use aegis_core::configuration::{DEFAULT_PRODUCT_ID, DEFAULT_VENDOR_ID};
use aegis_core::management::REPORT_SIZE;
use rusb::{ConfigDescriptor, Context, DeviceHandle, Direction, TransferType, UsbContext};

use crate::framing::{self, FramingError, Response};

/// USB interface class code for HID.
const HID_CLASS: u8 = 0x03;

/// Interface string descriptor used to locate the Management HID interface.
const MANAGEMENT_INTERFACE_NAME: &str = "HID Management";

/// Connection options resolved from the command line.
#[derive(Debug, Clone)]
pub struct Options {
    /// Expected USB vendor id.
    pub vid: u16,
    /// Expected USB product id.
    pub pid: u16,
    /// Explicit interface number, bypassing string-based discovery.
    pub interface: Option<u8>,
    /// Per-transfer timeout.
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            vid: DEFAULT_VENDOR_ID,
            pid: DEFAULT_PRODUCT_ID,
            interface: None,
            timeout: Duration::from_millis(2000),
        }
    }
}

/// Transport failure.
#[derive(Debug)]
pub enum Error {
    /// libusb reported an error.
    Usb(rusb::Error),
    /// No USB device matched the requested VID/PID.
    NoDevice {
        /// Requested vendor id.
        vid: u16,
        /// Requested product id.
        pid: u16,
    },
    /// A matching device was found but no Management HID interface was located.
    NoManagementInterface,
    /// The transfer timed out.
    Timeout,
    /// The device returned a malformed report.
    Framing(FramingError),
    /// An interrupt write was short.
    ShortWrite {
        /// Expected number of bytes.
        expected: usize,
        /// Bytes actually written.
        written: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usb(error) => write!(f, "USB error: {error}"),
            Error::NoDevice { vid, pid } => {
                write!(f, "no AegisToken device with VID {vid:04x}:{pid:04x} found")
            }
            Error::NoManagementInterface => {
                f.write_str("Management HID interface not found; try --interface <N>")
            }
            Error::Timeout => f.write_str("timed out waiting for the device"),
            Error::Framing(error) => write!(f, "{error}"),
            Error::ShortWrite { expected, written } => {
                write!(f, "short interrupt write: {written}/{expected} bytes")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<rusb::Error> for Error {
    fn from(error: rusb::Error) -> Self {
        match error {
            rusb::Error::Timeout => Error::Timeout,
            other => Error::Usb(other),
        }
    }
}

impl From<FramingError> for Error {
    fn from(error: FramingError) -> Self {
        Error::Framing(error)
    }
}

/// Interrupt endpoints of the selected interface.
#[derive(Debug, Clone, Copy)]
struct Endpoints {
    interface: u8,
    endpoint_in: u8,
    endpoint_out: u8,
}

/// An open Management HID interface.
pub struct ManagementDevice {
    handle: DeviceHandle<Context>,
    interface: u8,
    endpoint_in: u8,
    endpoint_out: u8,
    timeout: Duration,
}

impl ManagementDevice {
    /// Open the Management HID interface of the first matching device.
    pub fn open(options: &Options) -> Result<Self, Error> {
        let context = Context::new()?;
        let devices = context.devices()?;
        let mut matched_device = false;

        for device in devices.iter() {
            let Ok(descriptor) = device.device_descriptor() else {
                continue;
            };
            if descriptor.vendor_id() != options.vid || descriptor.product_id() != options.pid {
                continue;
            }
            matched_device = true;

            let Ok(config) = device.active_config_descriptor() else {
                continue;
            };
            let handle = device.open()?;
            let Some(endpoints) = select_interface(&handle, &config, options.interface) else {
                continue;
            };

            // Linux binds `usbhid` to HID interfaces; detach it so we can claim
            // the interface. Unsupported platforms return `NotSupported`.
            let _ = handle.set_auto_detach_kernel_driver(true);
            handle.claim_interface(endpoints.interface)?;

            return Ok(Self {
                handle,
                interface: endpoints.interface,
                endpoint_in: endpoints.endpoint_in,
                endpoint_out: endpoints.endpoint_out,
                timeout: options.timeout,
            });
        }

        if matched_device {
            Err(Error::NoManagementInterface)
        } else {
            Err(Error::NoDevice {
                vid: options.vid,
                pid: options.pid,
            })
        }
    }

    /// Interface number in use.
    #[must_use]
    pub const fn interface(&self) -> u8 {
        self.interface
    }

    /// Send one command and collect the reassembled response.
    pub fn request(&mut self, command: u8, payload: &[u8]) -> Result<Response, Error> {
        for report in framing::encode(command, payload) {
            let written = self
                .handle
                .write_interrupt(self.endpoint_out, &report, self.timeout)?;
            if written != report.len() {
                return Err(Error::ShortWrite {
                    expected: report.len(),
                    written,
                });
            }
        }

        let mut assembler = framing::ResponseAssembler::new();
        loop {
            let mut buffer = [0u8; REPORT_SIZE];
            let read = self
                .handle
                .read_interrupt(self.endpoint_in, &mut buffer, self.timeout)?;
            if read == 0 {
                continue;
            }
            if let Some(response) = assembler.accept(&buffer)? {
                return Ok(response);
            }
        }
    }
}

/// Pick the Management HID interface and its interrupt endpoints.
///
/// When `requested` is set, the interface is chosen by number; otherwise the
/// interface whose string descriptor names the Management function is used.
fn select_interface(
    handle: &DeviceHandle<Context>,
    config: &ConfigDescriptor,
    requested: Option<u8>,
) -> Option<Endpoints> {
    for interface in config.interfaces() {
        for setting in interface.descriptors() {
            if setting.class_code() != HID_CLASS {
                continue;
            }
            if let Some(wanted) = requested {
                if setting.interface_number() != wanted {
                    continue;
                }
            } else if !is_management(handle, setting.description_string_index()) {
                continue;
            }
            if let Some(endpoints) = endpoints_of(&setting) {
                return Some(endpoints);
            }
        }
    }
    None
}

/// Whether the interface's description string names the Management function.
fn is_management(handle: &DeviceHandle<Context>, string_index: Option<u8>) -> bool {
    let Some(index) = string_index else {
        return false;
    };
    match handle.read_string_descriptor_ascii(index) {
        Ok(name) => name.contains(MANAGEMENT_INTERFACE_NAME),
        Err(_) => false,
    }
}

/// Collect the interrupt IN/OUT endpoints of an interface setting.
fn endpoints_of(setting: &rusb::InterfaceDescriptor<'_>) -> Option<Endpoints> {
    let mut endpoint_in = None;
    let mut endpoint_out = None;
    for endpoint in setting.endpoint_descriptors() {
        if endpoint.transfer_type() != TransferType::Interrupt {
            continue;
        }
        match endpoint.direction() {
            Direction::In => endpoint_in = Some(endpoint.address()),
            Direction::Out => endpoint_out = Some(endpoint.address()),
        }
    }
    Some(Endpoints {
        interface: setting.interface_number(),
        endpoint_in: endpoint_in?,
        endpoint_out: endpoint_out?,
    })
}

/// List matching USB devices and their HID interfaces (no device opened).
pub fn describe(options: &Options) -> Result<Vec<String>, Error> {
    let context = Context::new()?;
    let devices = context.devices()?;
    let mut lines = Vec::new();

    for device in devices.iter() {
        let Ok(descriptor) = device.device_descriptor() else {
            continue;
        };
        if descriptor.vendor_id() != options.vid || descriptor.product_id() != options.pid {
            continue;
        }
        let bus = device.bus_number();
        let address = device.address();
        lines.push(format!(
            "bus {bus:03} address {address:03} VID {vid:04x}:{pid:04x}",
            vid = descriptor.vendor_id(),
            pid = descriptor.product_id(),
        ));

        let Ok(config) = device.active_config_descriptor() else {
            continue;
        };
        for interface in config.interfaces() {
            for setting in interface.descriptors() {
                if setting.class_code() != HID_CLASS {
                    continue;
                }
                lines.push(format!(
                    "  interface {} (HID, {} endpoints)",
                    setting.interface_number(),
                    setting.num_endpoints(),
                ));
            }
        }
    }
    Ok(lines)
}
