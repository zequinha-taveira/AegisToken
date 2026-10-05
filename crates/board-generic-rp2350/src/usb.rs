//! USB device composition (PRD §7.1, §12, §27).
//!
//! AegisToken presents itself to the host as a single composite USB device
//! exposing two independent HID functions plus a CCID smart-card interface.
//! The opt-in 1050:0407 laboratory identity adds a third, *experimental* OTP
//! HID interface (not compatible with Yubico OTP commands):
//!
//! ```text
//! USB Device
//! ├── FIDO HID        usage page 0xF1D0  → CTAPHID transport (64-byte reports)
//! │   ├── CTAP1 / U2F      (aegis-core::u2f, CTAPHID MSG)
//! │   └── CTAP2 / FIDO2    (aegis-core::ctap2, CTAPHID CBOR)
//! ├── Management HID  usage page 0xFF00  → vendor management transport
//! │   ├── Device Info       (ManagementCommand::GetDeviceInfo)
//! │   ├── Capabilities      (ManagementCommand::GetCapabilities)
//! │   ├── Configuration     (Get/Set/Validate/Commit)
//! │   ├── Commissioning     (GetLifecycle, CommissionDevice)
//! │   └── Diagnostics       (GetStatus, GetDiagnostics)
//! ├── OTP Lab HID     usage page 0xFF51  → bounded read-only INFO/PING
//! │   └── 1050:0407 lab identity ONLY; not commercial Yubico OTP
//! └── CCID             class 0x0B        → ISO 7816 applets (PIV, OpenPGP, OATH)
//!     ├── APDU framing and AID routing   (aegis-applets)
//!     └── PIN/retry framework            (aegis-applets)
//! ```
//!
//! Each HID function has its own interface and endpoints via [`crate::hid`]. No
//! boot keyboard or commercial YubiKey OTP protocol is advertised. The CCID
//! function uses [`crate::ccid`].
//!
//! The USB manufacturer, product, vendor and product identifiers come from the
//! board profile, and the serial number from the RP2350's unique chip
//! identifier.

use embassy_rp::Peri;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver as RpUsbDriver, InterruptHandler};
use embassy_usb::{Builder, Config as UsbConfig, UsbDevice};
use static_cell::StaticCell;

use crate::capabilities::{BoardProfile, YUBICO_VENDOR_ID, YUBIKEY5_LAB_PRODUCT_ID};
use crate::ccid::{CcidClass, State as CcidState};
use crate::hid::{HidReader, HidReaderWriter, HidWriter, State as HidState};
use aegis_core::identity::BoardIdentity;

/// Interface name for the FIDO HID function.
const FIDO_INTERFACE_NAME: &str = "HID FIDO Authenticator";

/// Interface name for the Management HID function.
const MANAGEMENT_INTERFACE_NAME: &str = "HID Management";

/// Interface name for the experimental lab-only OTP-labelled HID function.
const OTP_INTERFACE_NAME: &str = "HID OTP Lab (experimental)";

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

/// Poll interval for the FIDO interrupt endpoints, in milliseconds.
const FIDO_POLL_MS: u8 = 1;

/// Poll interval for the Management interrupt endpoints, in milliseconds.
const MANAGEMENT_POLL_MS: u8 = 10;

/// Poll interval for the lab OTP interrupt endpoints, in milliseconds.
const OTP_POLL_MS: u8 = 10;

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

/// Experimental OTP lab HID report descriptor (vendor-defined page `0xFF51`).
///
/// This deliberately does NOT use the Yubico OTP HID usage page/report format:
/// fixed 64-byte Input/Output reports, no report ID and no Feature reports.
pub static OTP_LAB_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0x51, 0xFF, // Usage Page (Vendor Defined 0xFF51)
    0x09, 0x01, // Usage (lab transport)
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

const _: () = assert!(REPORT_SIZE as usize == aegis_core::otp_lab::REPORT_SIZE);

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

// embassy-usb always needs a configuration descriptor buffer and the BOS/MS OS
// buffers, even when no BOS features are advertised.
static CONFIG_DESCRIPTOR: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESCRIPTOR: StaticCell<[u8; 128]> = StaticCell::new();
static MSOS_DESCRIPTOR: StaticCell<[u8; 128]> = StaticCell::new();
// Must fit the longest string descriptor in UTF-16 (2 + 2 * chars); the product
// string is at most 33 chars for the lab profile, so keep headroom.
static CONTROL_BUF: StaticCell<[u8; 256]> = StaticCell::new();
static FIDO_STATE: StaticCell<HidState<'static>> = StaticCell::new();
static MANAGEMENT_STATE: StaticCell<HidState<'static>> = StaticCell::new();
static OTP_STATE: StaticCell<HidState<'static>> = StaticCell::new();
static CCID_STATE: StaticCell<CcidState> = StaticCell::new();

/// Concrete embassy-rp USB driver for the RP2350 USB peripheral.
pub type RpUsb = RpUsbDriver<'static, USB>;

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

/// Experimental lab OTP HID reader/writer pair.
pub type OtpHid = HidReaderWriter<'static, RpUsb, 64, 64>;
/// Experimental lab OTP HID reader.
pub type OtpReader = HidReader<'static, RpUsb, 64>;
/// Experimental lab OTP HID writer.
pub type OtpWriter = HidWriter<'static, RpUsb, 64>;

/// CCID smart-card transport (ISO 7816 applets).
pub type Ccid = CcidClass<'static, RpUsb>;

/// The composed USB device and its functions.
pub struct Usb {
    /// The USB device, which must be `run()`.
    pub device: UsbDevice<'static, RpUsb>,
    /// FIDO HID transport (CTAP1/U2F and CTAP2/FIDO2).
    pub fido: FidoHid,
    /// Management HID transport (device info, configuration, diagnostics, ...).
    pub management: ManagementHid,
    /// Present only for the authorized lab USB identity; not Yubico OTP.
    pub otp: Option<OtpHid>,
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

        // Match the actual enumerated identity, including any provisioned USB
        // override: never expose a lab OTP descriptor for the generic VID/PID,
        // and never advertise 1050:0407 without the dedicated interface.
        let otp = (identity.vendor_id == YUBICO_VENDOR_ID
            && identity.product_id == YUBIKEY5_LAB_PRODUCT_ID)
            .then(|| {
                HidReaderWriter::new(
                    &mut builder,
                    OTP_STATE.init(HidState::new()),
                    &OTP_LAB_REPORT_DESCRIPTOR,
                    OTP_INTERFACE_NAME,
                    OTP_POLL_MS,
                    REPORT_SIZE as u16,
                )
            });

        let ccid = CcidClass::new(&mut builder, CCID_STATE.init(CcidState::new()));

        Self {
            device: builder.build(),
            fido,
            management,
            otp,
            ccid,
        }
    }
}
