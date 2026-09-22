//! USB device composition (PRD §7.1, §12, §27).
//!
//! AegisToken presents itself to the host as a single composite USB device
//! exposing three independent HID functions plus a CCID smart-card interface:
//!
//! ```text
//! USB Device
//! ├── HID Keyboard    usage page 0x01    → boot-protocol keyboard (8-byte reports)
//! ├── FIDO HID        usage page 0xF1D0  → CTAPHID transport (64-byte reports)
//! │   ├── CTAP1 / U2F      (aegis-core::u2f, CTAPHID MSG)
//! │   └── CTAP2 / FIDO2    (aegis-core::ctap2, CTAPHID CBOR)
//! ├── Management HID  usage page 0xFF00  → vendor management transport
//! │   ├── Device Info       (ManagementCommand::GetDeviceInfo)
//! │   ├── Capabilities      (ManagementCommand::GetCapabilities)
//! │   ├── Configuration     (Get/Set/Validate/Commit)
//! │   ├── Commissioning     (GetLifecycle, CommissionDevice)
//! │   └── Diagnostics       (GetStatus, GetDiagnostics)
//! └── CCID             class 0x0B        → ISO 7816 applets (PIV, OpenPGP, OATH)
//!     ├── APDU framing and AID routing   (aegis-applets)
//!     └── PIN/retry framework            (aegis-applets)
//! ```
//!
//! The FIDO and Management functions use the HID class defined in [`crate::hid`],
//! which lets the host tell the two apart by interface name. The keyboard uses
//! `embassy-usb`'s stock HID class so it can advertise the boot subclass and
//! keyboard boot protocol, and the CCID function uses the class in
//! [`crate::ccid`].
//!
//! **Security note:** the keyboard interface is a keystroke-injection surface.
//! It is registered unconditionally here; a build that must not be able to type
//! should drop the `keyboard` function from [`Usb::new`]. The application-level
//! protocols are owned by `aegis-core`; this module only provides the transport.
//!
//! The USB manufacturer, product, vendor and product identifiers come from the
//! board profile, and the serial number from the RP2350's unique chip
//! identifier.

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

use crate::capabilities::BoardProfile;
use crate::ccid::{CcidClass, State as CcidState};
use crate::hid::{HidReader, HidReaderWriter, HidWriter, State as HidState};
use aegis_core::identity::BoardIdentity;

/// Interface name for the FIDO HID function.
const FIDO_INTERFACE_NAME: &str = "HID FIDO Authenticator";

/// Interface name for the Management HID function.
const MANAGEMENT_INTERFACE_NAME: &str = "HID Management";

/// Scratch buffer for the runtime-derived USB serial number (16 hex digits).
static SERIAL_NUMBER_BUF: StaticCell<[u8; aegis_core::identity::CHIP_ID_HEX_LEN]> =
    StaticCell::new();

/// USB serial number derived from the RP2350's unique chip identifier.
///
/// Binding the identity to the MCU instead of the carrier board keeps a device
/// distinguishable when the board is swapped or sourced from a different
/// vendor. When OTP is not readable the same fallback as
/// [`aegis_core::identity::McuIdentity`] is formatted, so the serial number and
/// the reported MCU identity never disagree.
fn serial_number() -> &'static str {
    let chip_id = crate::otp::read_unique_id().unwrap_or(aegis_core::identity::FALLBACK_UNIQUE_ID);
    let bytes = SERIAL_NUMBER_BUF.init(aegis_core::identity::chip_id_hex(chip_id));
    core::str::from_utf8(bytes).expect("chip identifier hex is ASCII")
}

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
static CCID_STATE: StaticCell<CcidState> = StaticCell::new();

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

/// CCID smart-card transport (ISO 7816 applets).
pub type Ccid = CcidClass<'static, RpUsb>;

/// The composed USB device and its functions.
pub struct Usb {
    /// The USB device, which must be `run()`.
    pub device: UsbDevice<'static, RpUsb>,
    /// Boot-protocol keyboard transport (input reports only).
    pub keyboard: KeyboardWriter,
    /// FIDO HID transport (CTAP1/U2F and CTAP2/FIDO2).
    pub fido: FidoHid,
    /// Management HID transport (device info, configuration, diagnostics, ...).
    pub management: ManagementHid,
    /// CCID transport (PIV, OpenPGP and OATH applets).
    pub ccid: Ccid,
}

/// Scratch buffer for the runtime-derived USB product string.
static PRODUCT_STRING_BUF: StaticCell<[u8; 64]> = StaticCell::new();

/// Intern a product string slice into static storage for embassy-usb.
pub fn intern_product_string(s: &str) -> &'static str {
    let mut buf = [0u8; 64];
    let len = s.len().min(64);
    buf[..len].copy_from_slice(&s.as_bytes()[..len]);
    let bytes = PRODUCT_STRING_BUF.init(buf);
    core::str::from_utf8(&bytes[..len]).unwrap_or("AegisToken")
}

impl Usb {
    /// Build the USB device from the USB peripheral and board profile.
    pub fn new(usb: Peri<'static, USB>, profile: &BoardProfile) -> Self {
        Self::with_identity(usb, profile.identity())
    }

    /// Build the USB device using an explicit BoardIdentity (e.g. provisioned post-flash).
    pub fn with_identity(usb: Peri<'static, USB>, identity: BoardIdentity) -> Self {
        let driver = RpUsbDriver::new(usb, Irqs);

        let mut config = UsbConfig::new(identity.vendor_id, identity.product_id);
        config.manufacturer = Some(identity.manufacturer);
        config.product = Some(identity.product);
        config.serial_number = Some(serial_number());
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

        let ccid = CcidClass::new(&mut builder, CCID_STATE.init(CcidState::new()));

        Self {
            device: builder.build(),
            keyboard,
            fido,
            management,
            ccid,
        }
    }
}
