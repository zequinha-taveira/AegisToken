//! Minimal USB HID class with per-interface string descriptors.
//!
//! `embassy-usb`'s stock HID class always advertises `iInterface = 0`, but
//! AegisToken exposes two distinct HID functions (FIDO and Management) that the
//! host must be able to tell apart by name. This module therefore implements
//! the subset of the HID class the device actually uses:
//!
//! * a HID descriptor plus a caller-supplied report descriptor,
//! * the mandatory class control requests, and
//! * one interrupt IN and one interrupt OUT endpoint for raw reports.
//!
//! Report IDs and the boot protocol are intentionally not supported: every
//! report is a fixed-size byte buffer, exactly as CTAPHID and the Management
//! protocol expect.

use core::mem::MaybeUninit;
use core::ops::Range;

use embassy_usb::control::{InResponse, OutResponse, Recipient, Request, RequestType};
use embassy_usb::driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointOut};
use embassy_usb::types::{InterfaceNumber, StringIndex};
use embassy_usb::{Builder, Handler};

/// USB interface class code for HID.
const USB_CLASS_HID: u8 = 0x03;

/// HID class descriptor type (`bDescriptorType`).
const HID_DESCRIPTOR_TYPE: u8 = 0x21;
/// HID report descriptor type.
const HID_REPORT_DESCRIPTOR_TYPE: u8 = 0x22;
/// HID class specification release, BCD little-endian (1.10).
const HID_SPEC_VERSION: [u8; 2] = [0x10, 0x01];
/// `bCountryCode`: no localized hardware.
const HID_COUNTRY_NONE: u8 = 0x00;
/// Number of class descriptors that follow the HID descriptor.
const HID_DESCRIPTOR_COUNT: u8 = 1;

// Class-specific control requests (HID 1.11, §7.2).
const HID_GET_REPORT: u8 = 0x01;
const HID_GET_IDLE: u8 = 0x02;
const HID_GET_PROTOCOL: u8 = 0x03;
const HID_SET_REPORT: u8 = 0x09;
const HID_SET_IDLE: u8 = 0x0a;
const HID_SET_PROTOCOL: u8 = 0x0b;

/// Error when reading a HID report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The given buffer was too small to hold the received report.
    BufferOverflow,
    /// The endpoint is disabled.
    Disabled,
    /// The report was only partially read; the range marks the bytes filled by
    /// the call that was dropped. A subsequent `read` resumes at the range end.
    Sync(Range<usize>),
}

impl From<EndpointError> for ReadError {
    fn from(value: EndpointError) -> Self {
        match value {
            EndpointError::BufferOverflow => ReadError::BufferOverflow,
            EndpointError::Disabled => ReadError::Disabled,
        }
    }
}

/// HID class shared state, owned by the USB builder for the device's lifetime.
pub struct State<'d> {
    control: MaybeUninit<Control<'d>>,
}

impl<'d> Default for State<'d> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'d> State<'d> {
    /// Create a new `State`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            control: MaybeUninit::uninit(),
        }
    }
}

/// Per-interface control state, registered as a USB control handler.
struct Control<'d> {
    interface: InterfaceNumber,
    interface_string: StringIndex,
    interface_name: &'d str,
    report_descriptor: &'d [u8],
    hid_descriptor: [u8; 9],
}

/// Build the 9-byte HID class descriptor for a report descriptor of the given
/// length. This is both advertised after the interface descriptor and returned
/// for `GET_DESCRIPTOR(HID)`.
fn hid_descriptor(report_descriptor_len: usize) -> [u8; 9] {
    [
        9, // bLength
        HID_DESCRIPTOR_TYPE,
        HID_SPEC_VERSION[0],
        HID_SPEC_VERSION[1],
        HID_COUNTRY_NONE,
        HID_DESCRIPTOR_COUNT,
        HID_REPORT_DESCRIPTOR_TYPE,
        (report_descriptor_len & 0xFF) as u8,
        ((report_descriptor_len >> 8) & 0xFF) as u8,
    ]
}

/// Descriptor type requested by a standard `GET_DESCRIPTOR` control transfer.
const fn requested_descriptor_type(value: u16) -> u8 {
    (value >> 8) as u8
}

/// Register a HID function on `builder` and return its interrupt endpoints.
fn build<'d, D: Driver<'d>>(
    builder: &mut Builder<'d, D>,
    state: &'d mut State<'d>,
    report_descriptor: &'d [u8],
    interface_name: &'d str,
    poll_ms: u8,
    max_packet_size: u16,
) -> (D::EndpointOut, D::EndpointIn) {
    let interface_string = builder.string();
    let hid_descriptor = hid_descriptor(report_descriptor.len());

    // Scope the function/interface/alternate builders so their mutable borrow of
    // `builder` ends before the control handler is registered below.
    let (interface, endpoint_out, endpoint_in) = {
        let mut function = builder.function(USB_CLASS_HID, 0, 0);
        let mut interface_builder = function.interface();
        let interface = interface_builder.interface_number();
        let mut alt = interface_builder.alt_setting(USB_CLASS_HID, 0, 0, Some(interface_string));

        // `descriptor` prefixes the descriptor with its length and type, so the
        // 7-byte body excludes the first two bytes of `hid_descriptor`.
        alt.descriptor(HID_DESCRIPTOR_TYPE, &hid_descriptor[2..]);
        let endpoint_in = alt.endpoint_interrupt_in(None, max_packet_size, poll_ms);
        let endpoint_out = alt.endpoint_interrupt_out(None, max_packet_size, poll_ms);
        (interface, endpoint_out, endpoint_in)
    };

    let control = state.control.write(Control {
        interface,
        interface_string,
        interface_name,
        report_descriptor,
        hid_descriptor,
    });
    builder.handler(control);

    (endpoint_out, endpoint_in)
}

/// HID reader/writer pair.
pub struct HidReaderWriter<'d, D: Driver<'d>, const READ_N: usize, const WRITE_N: usize> {
    reader: HidReader<'d, D, READ_N>,
    writer: HidWriter<'d, D, WRITE_N>,
}

impl<'d, D: Driver<'d>, const READ_N: usize, const WRITE_N: usize>
    HidReaderWriter<'d, D, READ_N, WRITE_N>
{
    /// Create a HID function with both IN and OUT interrupt endpoints.
    pub fn new(
        builder: &mut Builder<'d, D>,
        state: &'d mut State<'d>,
        report_descriptor: &'d [u8],
        interface_name: &'d str,
        poll_ms: u8,
        max_packet_size: u16,
    ) -> Self {
        let (endpoint_out, endpoint_in) = build(
            builder,
            state,
            report_descriptor,
            interface_name,
            poll_ms,
            max_packet_size,
        );
        Self {
            reader: HidReader {
                endpoint: endpoint_out,
                offset: 0,
            },
            writer: HidWriter {
                endpoint: endpoint_in,
            },
        }
    }

    /// Split into separate reader and writer.
    #[must_use]
    pub fn split(self) -> (HidReader<'d, D, READ_N>, HidWriter<'d, D, WRITE_N>) {
        (self.reader, self.writer)
    }
}

/// HID interrupt IN writer.
pub struct HidWriter<'d, D: Driver<'d>, const N: usize> {
    endpoint: D::EndpointIn,
}

impl<'d, D: Driver<'d>, const N: usize> HidWriter<'d, D, N> {
    /// Wait for the endpoint to be enabled.
    pub async fn ready(&mut self) {
        self.endpoint.wait_enabled().await;
    }

    /// Write one HID report to the interrupt IN endpoint.
    pub async fn write(&mut self, report: &[u8]) -> Result<(), EndpointError> {
        assert!(report.len() <= N);
        let max_packet_size = usize::from(self.endpoint.info().max_packet_size);
        // A short report whose length is a multiple of the packet size needs a
        // zero-length packet to terminate the transfer.
        let zlp_needed = report.len() < N && report.len() % max_packet_size == 0;
        for chunk in report.chunks(max_packet_size) {
            self.endpoint.write(chunk).await?;
        }
        if zlp_needed {
            self.endpoint.write(&[]).await?;
        }
        Ok(())
    }
}

/// HID interrupt OUT reader.
pub struct HidReader<'d, D: Driver<'d>, const N: usize> {
    endpoint: D::EndpointOut,
    /// Bytes already read for a report larger than one packet, so a dropped
    /// future resumes instead of losing synchronisation.
    offset: usize,
}

impl<'d, D: Driver<'d>, const N: usize> HidReader<'d, D, N> {
    /// Wait for the endpoint to be enabled.
    pub async fn ready(&mut self) {
        self.endpoint.wait_enabled().await;
    }

    /// Read one HID report from the interrupt OUT endpoint.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        assert!(N != 0);
        assert!(buf.len() >= N);

        let max_packet_size = usize::from(self.endpoint.info().max_packet_size);
        let starting_offset = self.offset;
        let mut total = starting_offset;

        loop {
            for chunk in buf[starting_offset..N].chunks_mut(max_packet_size) {
                match self.endpoint.read(chunk).await {
                    Ok(size) => {
                        total += size;
                        if size < max_packet_size || total == N {
                            self.offset = 0;
                            break;
                        }
                        self.offset = total;
                    }
                    Err(error) => {
                        self.offset = 0;
                        return Err(error.into());
                    }
                }
            }
            // Hosts may send a zero-length packet first; keep waiting until at
            // least one byte of the report has arrived.
            if total > 0 {
                break;
            }
        }

        if starting_offset > 0 {
            Err(ReadError::Sync(starting_offset..total))
        } else {
            Ok(total)
        }
    }
}

impl<'d> Handler for Control<'d> {
    fn get_string(&mut self, index: StringIndex, _lang_id: u16) -> Option<&str> {
        (index == self.interface_string).then_some(self.interface_name)
    }

    fn control_out(&mut self, req: Request, _data: &[u8]) -> Option<OutResponse> {
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
            // Accept the idle rate and the (always report) protocol; reports are
            // delivered on the interrupt OUT endpoint, not the control pipe.
            HID_SET_IDLE | HID_SET_PROTOCOL => Some(OutResponse::Accepted),
            HID_SET_REPORT | HID_GET_REPORT => Some(OutResponse::Rejected),
            _ => Some(OutResponse::Rejected),
        }
    }

    fn control_in<'a>(&'a mut self, req: Request, buf: &'a mut [u8]) -> Option<InResponse<'a>> {
        if req.index != self.interface.0 as u16 {
            return None;
        }
        match (req.request_type, req.recipient) {
            (RequestType::Standard, Recipient::Interface) => match req.request {
                Request::GET_DESCRIPTOR => match requested_descriptor_type(req.value) {
                    HID_REPORT_DESCRIPTOR_TYPE => {
                        Some(InResponse::Accepted(self.report_descriptor))
                    }
                    HID_DESCRIPTOR_TYPE => Some(InResponse::Accepted(&self.hid_descriptor)),
                    _ => Some(InResponse::Rejected),
                },
                _ => Some(InResponse::Rejected),
            },
            (RequestType::Class, Recipient::Interface) => match req.request {
                HID_GET_PROTOCOL => {
                    buf[0] = 1; // report protocol
                    Some(InResponse::Accepted(&buf[0..1]))
                }
                HID_GET_IDLE => {
                    buf[0] = 0;
                    Some(InResponse::Accepted(&buf[0..1]))
                }
                _ => Some(InResponse::Rejected),
            },
            _ => None,
        }
    }
}
