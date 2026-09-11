//! Management HID report framing for the host.
//!
//! The wire format is owned by [`aegis_core::management`]; this module adapts it
//! to heap-allocated host buffers and turns a stream of 64-byte reports into a
//! [`Response`]. Keeping the framing independent of libusb makes it unit
//! testable without a device attached.

use aegis_core::management::{self, Assembler, Message, PAYLOAD_PER_REPORT, REPORT_SIZE};

/// A reassembled Management HID response.
///
/// The transport body is one status byte followed by an optional CBOR payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Response operation code (command with `0x80` set).
    pub command: u8,
    /// Status byte (zero on success).
    pub status: u8,
    /// CBOR payload following the status byte.
    pub body: Vec<u8>,
}

/// Failure while building or parsing Management HID frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// The report violated the protocol (version, sequence or length).
    Protocol,
    /// A completed response carried no status byte.
    EmptyResponse,
}

impl core::fmt::Display for FramingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FramingError::Protocol => f.write_str("malformed Management HID report"),
            FramingError::EmptyResponse => f.write_str("empty Management HID response"),
        }
    }
}

impl core::error::Error for FramingError {}

/// Split a command payload into fixed 64-byte Management HID reports.
#[must_use]
pub fn encode(command: u8, payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    let mut reports = Vec::new();
    let first = payload.len().min(PAYLOAD_PER_REPORT);
    let init = management::init_report(command, payload.len() as u16, &payload[..first])
        .expect("first chunk fits one report");
    reports.push(init);

    let mut offset = first;
    let mut sequence = 0u16;
    while offset < payload.len() {
        let end = (offset + PAYLOAD_PER_REPORT).min(payload.len());
        let cont = management::cont_report(command, sequence, &payload[offset..end])
            .expect("continuation chunk fits one report");
        reports.push(cont);
        offset = end;
        sequence += 1;
    }
    reports
}

/// Incrementally reassembles response reports into a [`Response`].
#[derive(Default)]
pub struct ResponseAssembler {
    inner: Assembler,
}

impl ResponseAssembler {
    /// Create an empty assembler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: Assembler::new(),
        }
    }

    /// Feed one raw report, returning a response once a message completes.
    pub fn accept(&mut self, report: &[u8; REPORT_SIZE]) -> Result<Option<Response>, FramingError> {
        let frame = management::parse_report(report).map_err(|_| FramingError::Protocol)?;
        let message = self
            .inner
            .accept(frame)
            .map_err(|_| FramingError::Protocol)?;
        message.map(Response::from_message).transpose()
    }
}

impl Response {
    fn from_message(message: Message) -> Result<Self, FramingError> {
        let Some((&status, body)) = message.payload.split_first() else {
            return Err(FramingError::EmptyResponse);
        };
        Ok(Self {
            command: message.command,
            status,
            body: body.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(command: u8, payload: &[u8]) -> Response {
        let mut assembler = ResponseAssembler::new();
        for report in encode(command, payload) {
            if let Some(response) = assembler.accept(&report).unwrap() {
                return response;
            }
        }
        panic!("message did not complete");
    }

    #[test]
    fn single_report_round_trip_carries_status_and_body() {
        let response = complete(0x81, &[0x00, 0xA0]);
        assert_eq!(response.command, 0x81);
        assert_eq!(response.status, 0x00);
        assert_eq!(response.body, vec![0xA0]);
    }

    #[test]
    fn multi_report_payload_round_trips() {
        let body: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
        let response = complete(0x82, &body);
        assert_eq!(response.command, 0x82);
        assert_eq!(response.status, body[0]);
        assert_eq!(response.body, body[1..]);
    }

    #[test]
    fn response_without_status_is_rejected() {
        let report = management::init_report(0x81, 0, &[]).unwrap();
        let mut assembler = ResponseAssembler::new();
        assert_eq!(assembler.accept(&report), Err(FramingError::EmptyResponse));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut report = management::init_report(0x81, 1, &[0]).unwrap();
        report[0] = 0xEE;
        let mut assembler = ResponseAssembler::new();
        assert_eq!(assembler.accept(&report), Err(FramingError::Protocol));
    }

    #[test]
    fn continuation_before_init_is_rejected() {
        let report = management::cont_report(0x81, 0, &[0]).unwrap();
        let mut assembler = ResponseAssembler::new();
        assert_eq!(assembler.accept(&report), Err(FramingError::Protocol));
    }
}
