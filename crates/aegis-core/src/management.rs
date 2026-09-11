//! Management HID transport framing (PRD §12, §13).
//!
//! The Management HID interface is a separate USB HID function from FIDO HID.
//! It carries a simple framed protocol over fixed 64-byte reports: one
//! initialization report followed by zero or more continuation reports. Command
//! semantics are defined above this layer.

use crate::error::CoreError;

/// Size of a Management HID report, in bytes.
pub const REPORT_SIZE: usize = 64;

/// Header size of every report.
pub const HEADER_LEN: usize = 5;

/// Payload bytes per report.
pub const PAYLOAD_PER_REPORT: usize = REPORT_SIZE - HEADER_LEN;

/// Management protocol version.
pub const PROTOCOL_VERSION: u8 = 1;

/// Largest management message the reassembler accepts.
pub const MAX_MESSAGE_BYTES: usize = 2048;

/// Continuation flag in the header's flags byte.
const FLAG_CONTINUATION: u8 = 0x01;

/// A parsed Management HID report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// First report of a message.
    Init {
        /// Operation code.
        command: u8,
        /// Total message length across all reports.
        total_length: u16,
        /// Payload fragment.
        data: heapless::Vec<u8, PAYLOAD_PER_REPORT>,
    },
    /// Continuation report.
    Cont {
        /// Operation code (echoed from the init report).
        command: u8,
        /// Sequence number, starting at zero.
        sequence: u16,
        /// Payload fragment.
        data: heapless::Vec<u8, PAYLOAD_PER_REPORT>,
    },
}

/// Build an initialization report.
pub fn init_report(
    command: u8,
    total_length: u16,
    data: &[u8],
) -> Result<[u8; REPORT_SIZE], CoreError> {
    if data.len() > PAYLOAD_PER_REPORT {
        return Err(CoreError::ProtocolError);
    }
    let mut report = [0u8; REPORT_SIZE];
    report[0] = PROTOCOL_VERSION;
    report[1] = command;
    report[2..4].copy_from_slice(&total_length.to_le_bytes());
    report[4] = 0;
    report[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
    Ok(report)
}

/// Build a continuation report.
pub fn cont_report(
    command: u8,
    sequence: u16,
    data: &[u8],
) -> Result<[u8; REPORT_SIZE], CoreError> {
    if data.len() > PAYLOAD_PER_REPORT {
        return Err(CoreError::ProtocolError);
    }
    let mut report = [0u8; REPORT_SIZE];
    report[0] = PROTOCOL_VERSION;
    report[1] = command;
    report[2..4].copy_from_slice(&sequence.to_le_bytes());
    report[4] = FLAG_CONTINUATION;
    report[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
    Ok(report)
}

/// Parse a raw 64-byte report.
pub fn parse_report(report: &[u8; REPORT_SIZE]) -> Result<Frame, CoreError> {
    if report[0] != PROTOCOL_VERSION {
        return Err(CoreError::ProtocolError);
    }
    let command = report[1];
    let word = u16::from_le_bytes([report[2], report[3]]);
    let mut data = heapless::Vec::new();
    data.extend_from_slice(&report[HEADER_LEN..])
        .map_err(|_| CoreError::ProtocolError)?;

    if report[4] & FLAG_CONTINUATION != 0 {
        Ok(Frame::Cont {
            command,
            sequence: word,
            data,
        })
    } else {
        Ok(Frame::Init {
            command,
            total_length: word,
            data,
        })
    }
}

/// A fully reassembled management message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Operation code.
    pub command: u8,
    /// Complete payload.
    pub payload: heapless::Vec<u8, MAX_MESSAGE_BYTES>,
}

struct InProgress {
    command: u8,
    expected: usize,
    received: usize,
    next_sequence: u16,
    buffer: heapless::Vec<u8, MAX_MESSAGE_BYTES>,
}

/// Reassembles Management HID reports into complete messages.
#[derive(Default)]
pub struct Assembler {
    current: Option<InProgress>,
}

impl Assembler {
    /// Create an empty assembler.
    #[must_use]
    pub const fn new() -> Self {
        Self { current: None }
    }

    /// Drop any partially received message.
    pub fn reset(&mut self) {
        self.current = None;
    }

    /// Feed one report, returning a completed message when available.
    pub fn accept(&mut self, frame: Frame) -> Result<Option<Message>, CoreError> {
        match frame {
            Frame::Init {
                command,
                total_length,
                data,
            } => {
                self.current = None;
                let expected = usize::from(total_length);
                if expected > MAX_MESSAGE_BYTES {
                    return Err(CoreError::ProtocolError);
                }
                let mut buffer = heapless::Vec::new();
                let take = expected.min(data.len());
                buffer
                    .extend_from_slice(&data[..take])
                    .map_err(|_| CoreError::ProtocolError)?;

                if buffer.len() >= expected {
                    return Ok(Some(Message {
                        command,
                        payload: buffer,
                    }));
                }
                self.current = Some(InProgress {
                    command,
                    expected,
                    received: take,
                    next_sequence: 0,
                    buffer,
                });
                Ok(None)
            }
            Frame::Cont {
                command,
                sequence,
                data,
            } => {
                let Some(state) = self.current.as_mut() else {
                    return Err(CoreError::ProtocolError);
                };
                if state.command != command || sequence != state.next_sequence {
                    self.current = None;
                    return Err(CoreError::ProtocolError);
                }
                let remaining = state.expected - state.received;
                let take = remaining.min(data.len());
                state
                    .buffer
                    .extend_from_slice(&data[..take])
                    .map_err(|_| CoreError::ProtocolError)?;
                state.received += take;
                state.next_sequence = state.next_sequence.wrapping_add(1);

                if state.received >= state.expected {
                    let state = self.current.take().expect("in progress");
                    return Ok(Some(Message {
                        command: state.command,
                        payload: state.buffer,
                    }));
                }
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(report: [u8; REPORT_SIZE]) -> Frame {
        parse_report(&report).unwrap()
    }

    #[test]
    fn init_round_trip() {
        let Frame::Init {
            command,
            total_length,
            data,
        } = decode(init_report(0x10, 3, &[1, 2, 3]).unwrap())
        else {
            panic!("expected init");
        };
        assert_eq!(command, 0x10);
        assert_eq!(total_length, 3);
        assert_eq!(&data[..3], &[1, 2, 3]);
    }

    #[test]
    fn continuation_round_trip() {
        let Frame::Cont {
            command,
            sequence,
            data,
        } = decode(cont_report(0x10, 4, &[5, 6]).unwrap())
        else {
            panic!("expected continuation");
        };
        assert_eq!(command, 0x10);
        assert_eq!(sequence, 4);
        assert_eq!(&data[..2], &[5, 6]);
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut report = init_report(1, 0, &[]).unwrap();
        report[0] = 0xEE;
        assert_eq!(parse_report(&report), Err(CoreError::ProtocolError));
    }

    #[test]
    fn single_report_message_completes() {
        let mut asm = Assembler::new();
        let msg = asm
            .accept(decode(init_report(1, 3, &[7, 7, 7]).unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(msg.command, 1);
        assert_eq!(&msg.payload[..], &[7, 7, 7]);
    }

    #[test]
    fn multi_report_message_reassembles() {
        let mut asm = Assembler::new();
        let payload: heapless::Vec<u8, 200> = (0..200u16).map(|i| i as u8).collect();

        let first = &payload[..PAYLOAD_PER_REPORT];
        assert!(
            asm.accept(decode(init_report(0x20, 200, first).unwrap()))
                .unwrap()
                .is_none()
        );

        let mut offset = PAYLOAD_PER_REPORT;
        let mut seq = 0u16;
        loop {
            let end = (offset + PAYLOAD_PER_REPORT).min(payload.len());
            let result = asm
                .accept(decode(
                    cont_report(0x20, seq, &payload[offset..end]).unwrap(),
                ))
                .unwrap();
            offset = end;
            if let Some(msg) = result {
                assert_eq!(&msg.payload[..], &payload[..]);
                break;
            }
            seq += 1;
        }
    }

    #[test]
    fn wrong_sequence_is_rejected() {
        let mut asm = Assembler::new();
        asm.accept(decode(
            init_report(1, 200, &[0u8; PAYLOAD_PER_REPORT]).unwrap(),
        ))
        .unwrap();
        assert_eq!(
            asm.accept(decode(cont_report(1, 5, &[0u8; 10]).unwrap())),
            Err(CoreError::ProtocolError)
        );
    }

    #[test]
    fn continuation_without_init_is_rejected() {
        let mut asm = Assembler::new();
        assert_eq!(
            asm.accept(decode(cont_report(1, 0, &[0u8; 10]).unwrap())),
            Err(CoreError::ProtocolError)
        );
    }
}
