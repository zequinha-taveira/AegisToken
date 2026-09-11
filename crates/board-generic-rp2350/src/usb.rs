//! USB device composition (PRD §7.1, §12, §27).
//!
//! AegisToken presents itself to the host as a single composite USB device
//! exposing three independent HID functions:
//!
//! ```text
//! USB Device
//! ├── HID Keyboard    usage page 0x01    → boot-protocol keyboard (8-byte reports)
//! ├── FIDO HID        usage page 0xF1D0  → CTAPHID transport (64-byte reports)
//! │   ├── CTAP1 / U2F      (aegis-core::u2f, CTAPHID MSG)
//! │   └── CTAP2 / FIDO2    (aegis-core::ctap2, CTAPHID CBOR)
//! └── Management HID  usage page 0xFF00  → vendor management transport
//!     ├── Device Info       (ManagementCommand::GetDeviceInfo)
//!     ├── Capabilities      (ManagementCommand::GetCapabilities)
//!     ├── Configuration     (Get/Set/Validate/Commit)
//!     ├── Commissioning     (GetLifecycle, CommissionDevice)
//!     └── Diagnostics       (GetStatus, GetDiagnostics)
//! ```
//!
//! The FIDO and Management functions use the HID class defined in [`crate::hid`],
//! which lets the host tell the two apart by interface name. The keyboard uses
//! `embassy-usb`'s stock HID class so it can advertise the boot subclass and
//! keyboard boot protocol.
//!
//! **Security note:** the keyboard interface is a keystroke-injection surface.
//! It is registered unconditionally here; a build that must not be able to type
//! should drop the `keyboard` function from [`Usb::new`]. The application-level
//! protocols are owned by `aegis-core`; this module only provides the transport.
//!
//! The USB product string is `AegisToken FIDO2 USB Authenticator`.

use aegis_core::PRODUCT_USB_STRING;
use aegis_core::configuration::{DEFAULT_PRODUCT_ID, DEFAULT_VENDOR_ID};
use embassy_rp::Peri;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver as RpUsbDriver, InterruptHandler};
use embassy_usb::class::hid::{
    Config as KeyboardHidConfig, HidBootProtocol as KeyboardBoot, HidSubclass as KeyboardSubclass,
    HidWriter as KeyboardHidWriter, State as KeyboardHidState,
};
use embassy_usb::{Builder, Config as UsbConfig, UsbDevice};
use static_cell::StaticCell;

use crate::hid::{HidReader, HidReaderWriter, HidWriter, State as HidState};

/// Interface name for the FIDO HID function.
const FIDO_INTERFACE_NAME: &str = "HID FIDO Authenticator";

/// Interface name for the Management HID function.
const MANAGEMENT_INTERFACE_NAME: &str = "HID Management";

/// USB manufacturer string.
const MANUFACTURER: &str = "AegisToken";

/// USB serial-number string.
///
/// Fixed for now; a unique value can later be derived from the RP2350 chip/OTP
/// identifier.
const SERIAL_NUMBER: &str = "AEGIS-0001";

/// Maximum power draw advertised by the device, in milliamps.
const MAX_POWER_MA: u16 = 100;

/// Endpoint packet size and report size, in bytes.
const REPORT_SIZE: u8 = 64;

/// Keyboard boot report size, in bytes (modifier, reserved, 6 keycodes).
const KEYBOARD_REPORT_SIZE: u8 = 8;

/// Poll interval for the keyboard interrupt IN endpoint, in milliseconds.
const KEYBOARD_POLL_MS: u8 = 10;

/// Poll interval for the FIDO interrupt endpoints, in milliseconds.
const FIDO_POLL_MS: u8 = 1;

/// Poll interval for the Management interrupt endpoints, in milliseconds.
const MANAGEMENT_POLL_MS: u8 = 10;

/// CTAPHID HID report descriptor (FIDO Alliance usage page `0xF1D0`).
///
/// Input Report Data (`0x20`) and Output Report Data (`0x21`), 64 bytes each.
pub static FIDO_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

/// Management HID report descriptor (vendor-defined usage page `0xFF00`).
///
/// Input Report Data (`0x02`) and Output Report Data (`0x03`), 64 bytes each.
pub static MANAGEMENT_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0x00, 0xFF, // Usage Page (Vendor Defined 0xFF00)
    0x09, 0x01, // Usage (0x01)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x02, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x03, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

/// Boot-protocol keyboard HID report descriptor (Generic Desktop, Usage `0x06`).
///
/// Input report (8 bytes): 1 modifier byte, 1 reserved byte, 6 keycodes.
/// Output report (1 byte): 5 LED bits plus 3 padding bits.
///
/// Advertising this interface makes the device enumerable as a keyboard; see
/// the module documentation for the implications.
pub static KEYBOARD_REPORT_DESCRIPTOR: [u8; 63] = [
    0x05, 0x01, // Usage Page (Generic Desktop)
    0x09, 0x06, // Usage (Keyboard)
    0xA1, 0x01, // Collection (Application)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0xE0, //   Usage Minimum (224, Left Control)
    0x29, 0xE7, //   Usage Maximum (231, Right GUI)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x01, //   Logical Maximum (1)
    0x75, 0x01, //   Report Size (1)
    0x95, 0x08, //   Report Count (8)
    0x81, 0x02, //   Input (Data, Variable, Absolute) -> modifier byte
    0x95, 0x01, //   Report Count (1)
    0x75, 0x08, //   Report Size (8)
    0x81, 0x01, //   Input (Constant) -> reserved byte
    0x95, 0x06, //   Report Count (6)
    0x75, 0x08, //   Report Size (8)
    0x15, 0x00, //   Logical Minimum (0)
    0x25, 0x65, //   Logical Maximum (101)
    0x05, 0x07, //   Usage Page (Keyboard/Keypad)
    0x19, 0x00, //   Usage Minimum (0)
    0x29, 0x65, //   Usage Maximum (101)
    0x81, 0x00, //   Input (Data, Array, Absolute) -> 6 keycodes
    0x05, 0x08, //   Usage Page (LEDs)
    0x19, 0x01, //   Usage Minimum (1, Num Lock)
    0x29, 0x05, //   Usage Maximum (5, Kana)
    0x95, 0x05, //   Report Count (5)
    0x75, 0x01, //   Report Size (1)
    0x91, 0x02, //   Output (Data, Variable, Absolute) -> LED bits
    0x95, 0x01, //   Report Count (1)
    0x75, 0x03, //   Report Size (3)
    0x91, 0x01, //   Output (Constant) -> padding
    0xC0, // End Collection
];

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

// embassy-usb always needs a configuration descriptor buffer and the BOS/MS OS
// buffers, even when no BOS features are advertised.
static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESCRIPTOR: StaticCell<[u8; 128]> = StaticCell::new();
static MSOS_DESCRIPTOR: StaticCell<[u8; 128]> = StaticCell::new();
// Must fit the longest string descriptor in UTF-16 (2 + 2 * chars); the product
// string is 33 chars, so keep comfortable headroom.
static CONTROL_BUF: StaticCell<[u8; 256]> = StaticCell::new();
static KEYBOARD_STATE: StaticCell<KeyboardHidState<'static>> = StaticCell::new();
static FIDO_STATE: StaticCell<HidState<'static>> = StaticCell::new();
static MANAGEMENT_STATE: StaticCell<HidState<'static>> = StaticCell::new();

/// Concrete embassy-rp USB driver for the RP2350 USB peripheral.
pub type RpUsb = RpUsbDriver<'static, USB>;

/// Keyboard HID writer (interrupt IN only).
///
/// Keycodes are 8-byte boot reports; the interface is registered with the boot
/// keyboard subclass/protocol so the host can use it before its HID driver
/// loads.
pub type KeyboardWriter = KeyboardHidWriter<'static, RpUsb, 8>;

/// FIDO HID reader/writer pair.
pub type FidoHid = HidReaderWriter<'static, RpUsb, 64, 64>;
/// FIDO HID reader.
pub type FidoReader = HidReader<'static, RpUsb, 64>;
/// FIDO HID writer.
pub type FidoWriter = HidWriter<'static, RpUsb, 64>;

/// Management HID reader/writer pair.
pub type ManagementHid = HidReaderWriter<'static, RpUsb, 64, 64>;
/// Management HID reader.
pub type ManagementReader = HidReader<'static, RpUsb, 64>;
/// Management HID writer.
pub type ManagementWriter = HidWriter<'static, RpUsb, 64>;

/// The composed USB device and its three HID functions.
pub struct Usb {
    /// The USB device, which must be `run()`.
    pub device: UsbDevice<'static, RpUsb>,
    /// Boot-protocol keyboard transport (input reports only).
    pub keyboard: KeyboardWriter,
    /// FIDO HID transport (CTAP1/U2F and CTAP2/FIDO2).
    pub fido: FidoHid,
    /// Management HID transport (device info, configuration, diagnostics, ...).
    pub management: ManagementHid,
}

impl Usb {
    /// Build the USB device from the USB peripheral.
    pub fn new(usb: Peri<'static, USB>) -> Self {
        let driver = RpUsbDriver::new(usb, Irqs);

        let mut config = UsbConfig::new(DEFAULT_VENDOR_ID, DEFAULT_PRODUCT_ID);
        config.manufacturer = Some(MANUFACTURER);
        config.product = Some(PRODUCT_USB_STRING);
        config.serial_number = Some(SERIAL_NUMBER);
        config.max_power = MAX_POWER_MA;
        config.max_packet_size_0 = 64;
        // Report an independently powered device that can request remote wakeup
        // (configuration descriptor `bmAttributes` bits 6 and 5).
        config.self_powered = true;
        config.supports_remote_wakeup = true;
        config.composite_with_iads = false;
        config.device_class = 0;
        config.device_sub_class = 0;
        config.device_protocol = 0;

        let mut builder = Builder::new(
            driver,
            config,
            CONFIG_DESCRIPTOR.init([0; 256]),
            BOS_DESCRIPTOR.init([0; 128]),
            MSOS_DESCRIPTOR.init([0; 128]),
            CONTROL_BUF.init([0; 256]),
        );

        let keyboard = KeyboardHidWriter::new(
            &mut builder,
            KEYBOARD_STATE.init(KeyboardHidState::new()),
            KeyboardHidConfig {
                report_descriptor: &KEYBOARD_REPORT_DESCRIPTOR,
                request_handler: None,
                poll_ms: KEYBOARD_POLL_MS,
                max_packet_size: u16::from(KEYBOARD_REPORT_SIZE),
                hid_subclass: KeyboardSubclass::Boot,
                hid_boot_protocol: KeyboardBoot::Keyboard,
            },
        );

        let fido = HidReaderWriter::new(
            &mut builder,
            FIDO_STATE.init(HidState::new()),
            &FIDO_REPORT_DESCRIPTOR,
            FIDO_INTERFACE_NAME,
            FIDO_POLL_MS,
            REPORT_SIZE as u16,
        );

        let management = HidReaderWriter::new(
            &mut builder,
            MANAGEMENT_STATE.init(HidState::new()),
            &MANAGEMENT_REPORT_DESCRIPTOR,
            MANAGEMENT_INTERFACE_NAME,
            MANAGEMENT_POLL_MS,
            REPORT_SIZE as u16,
        );

        Self {
            device: builder.build(),
            keyboard,
            fido,
            management,
        }
    }
}
