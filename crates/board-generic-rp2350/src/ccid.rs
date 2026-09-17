//! USB CCID class (roadmap Phase 11).
//!
//! `embassy-usb` ships HID, CDC, MIDI and DFU classes but no smart-card
//! interface, so this module implements the subset of the CCID class the
//! device needs: one slot, T=0, two bulk endpoints (`OUT` for `PC_to_RDR_*`
//! messages, `IN` for `RDR_to_PC_*` responses) and the mandatory class control
//! requests.
//!
//! The class only moves bytes. Message interpretation and APDU dispatch live in
//! `aegis-applets`; the firmware task connects the two.

use core::mem::MaybeUninit;

use embassy_usb::Builder;
use embassy_usb::Handler;
use embassy_usb::control::{InResponse, OutResponse, Recipient, RequestType};
use embassy_usb::driver::{Driver, EndpointError, EndpointIn, EndpointOut};
use embassy_usb::types::InterfaceNumber;

/// USB interface class code for smart card / CCID.
pub const USB_CLASS_CCID: u8 = 0x0B;

/// CCID functional descriptor type (`bDescriptorType`).
const CCID_DESCRIPTOR_TYPE: u8 = 0x21;

/// Bulk endpoint packet size for full-speed operation.
pub const MAX_PACKET_SIZE: u16 = 64;

/// Default and only clock frequency, in kHz.
const CLOCK_KHZ: u32 = 4_000;

/// Default and only data rate, in bps.
const DATA_RATE_BPS: u32 = 115_200;

// Class-specific control requests (CCID rev 1.1, §6).
const REQ_ABORT: u8 = 0x01;
const REQ_GET_CLOCK_FREQUENCIES: u8 = 0x02;
const REQ_GET_DATA_RATES: u8 = 0x03;

/// CCID functional descriptor (CCID rev 1.1, §5.1), 54 bytes.
///
/// Advertises a single slot, T=0 only, automatic activation and voltage
/// selection, and short-APDU exchange level with a maximum message length of
/// 271 bytes (`aegis-applets` reassembly is larger; the host is told the
/// standard short-APDU bound until the applets accept extended APDUs).
///
/// `dwFeatures = 0x0406_0000`: bits 17 (automatic activation on `IccPowerOn`)
/// and 18 (automatic voltage selection) plus exchange level 1 (short APDU) in
/// bits 26-27.
static CCID_DESCRIPTOR: [u8; 54] = [
    0x36, 0x21, // bLength, bDescriptorType
    0x10, 0x01, // bcdCCID = 1.10
    0x00, // bMaxSlotIndex
    0x07, // bVoltageSupport = 5V | 3V | 1.8V
    0x01, 0x00, 0x00, 0x00, // dwProtocols = T=0
    0xA0, 0x0F, 0x00, 0x00, // dwDefaultClock = 4000 kHz
    0xA0, 0x0F, 0x00, 0x00, // dwMaximumClock = 4000 kHz
    0x00, // bNumClockSupported
    0x00, 0xC2, 0x01, 0x00, // dwDataRate = 115200 bps
    0x00, 0xC2, 0x01, 0x00, // dwMaxDataRate = 115200 bps
    0x00, // bNumDataRatesSupported
    0xFE, 0x00, 0x00, 0x00, // dwMaxIFSD = 254
    0x00, 0x00, 0x00, 0x00, // dwSynchProtocols
    0x00, 0x00, 0x00, 0x00, // dwMechanical
    0x00, 0x00, 0x06, 0x04, // dwFeatures
    0x0F, 0x01, 0x00, 0x00, // dwMaxCCIDMessageLength = 271
    0x00, // bClassGetResponse
    0x00, // bClassEnvelope
    0x00, 0x00, // wLcdLayout
    0x00, // bPINSupport
    0x01, // bMaxCCIDBusySlots
];

// The functional descriptor is defined by CCID rev 1.1 §5.1 as exactly 54 bytes.
const _: () = assert!(CCID_DESCRIPTOR.len() == 54);

/// CCID class shared state, owned by the USB builder for the device's lifetime.
pub struct State {
    control: MaybeUninit<Control>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    /// Create a new `State`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            control: MaybeUninit::uninit(),
        }
    }
}

/// Per-interface control state, registered as a USB control handler.
struct Control {
    interface: InterfaceNumber,
}

impl Handler for Control {
    fn control_out(
        &mut self,
        req: embassy_usb::control::Request,
        _data: &[u8],
    ) -> Option<OutResponse> {
        if (req.request_type, req.recipient, req.index)
            != (
                RequestType::Class,
                Recipient::Interface,
                self.interface.0 as u16,
            )
        {
            return None;
        }
        match req.request {
            // The bulk ABORT message is the primary path; the class request is
            // acknowledged for completeness.
            REQ_ABORT => Some(OutResponse::Accepted),
            _ => Some(OutResponse::Rejected),
        }
    }

    fn control_in<'a>(
        &'a mut self,
        req: embassy_usb::control::Request,
        buf: &'a mut [u8],
    ) -> Option<InResponse<'a>> {
        if (req.request_type, req.recipient, req.index)
            != (
                RequestType::Class,
                Recipient::Interface,
                self.interface.0 as u16,
            )
        {
            return None;
        }
        match req.request {
            REQ_GET_CLOCK_FREQUENCIES => frequency_table(buf, CLOCK_KHZ),
            REQ_GET_DATA_RATES => frequency_table(buf, DATA_RATE_BPS),
            _ => Some(InResponse::Rejected),
        }
    }
}

/// Encode the two-entry table CCID uses for clocks and data rates.
fn frequency_table<'a>(buf: &'a mut [u8], value: u32) -> Option<InResponse<'a>> {
    if buf.len() < 8 {
        return Some(InResponse::Rejected);
    }
    buf[..4].copy_from_slice(&value.to_le_bytes());
    buf[4..8].fill(0);
    Some(InResponse::Accepted(&buf[..8]))
}

/// CCID bulk endpoints.
pub struct CcidClass<'d, D: Driver<'d>> {
    read_ep: D::EndpointOut,
    write_ep: D::EndpointIn,
}

impl<'d, D: Driver<'d>> CcidClass<'d, D> {
    /// Register the CCID function on `builder`.
    pub fn new(builder: &mut Builder<'d, D>, state: &'d mut State) -> Self {
        let (interface, read_ep, write_ep) = {
            let mut function = builder.function(USB_CLASS_CCID, 0x00, 0x00);
            let mut interface_builder = function.interface();
            let interface = interface_builder.interface_number();
            let mut alt = interface_builder.alt_setting(USB_CLASS_CCID, 0x00, 0x00, None);

            // `descriptor` prefixes the descriptor with its length and type, so
            // the body excludes the first two bytes of the functional
            // descriptor.
            alt.descriptor(CCID_DESCRIPTOR_TYPE, &CCID_DESCRIPTOR[2..]);
            let read_ep = alt.endpoint_bulk_out(None, MAX_PACKET_SIZE);
            let write_ep = alt.endpoint_bulk_in(None, MAX_PACKET_SIZE);
            (interface, read_ep, write_ep)
        };

        let control = state.control.write(Control { interface });
        builder.handler(control);

        Self { read_ep, write_ep }
    }

    /// Read one bulk OUT packet.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
        self.read_ep.read(buf).await
    }

    /// Write a CCID response, splitting it into endpoint packets.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), EndpointError> {
        for chunk in data.chunks(usize::from(MAX_PACKET_SIZE)) {
            self.write_ep.write(chunk).await?;
        }
        Ok(())
    }
}
