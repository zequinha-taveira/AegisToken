//! CTAPHID transport framing (PRD §12).
//!
//! USB HID reports are fixed at 64 bytes. CTAPHID splits larger messages into
//! one initialization packet plus zero or more continuation packets, each
//! carrying a 32-bit channel id. This module implements the wire format and a
//! host-testable reassembler; FIDO command handling lives above it.

use crate::error::CoreError;

/// Size of a CTAPHID HID report, in bytes.
pub const REPORT_SIZE: usize = 64;

/// CTAPHID protocol version advertised at INIT.
pub const PROTOCOL_VERSION: u8 = 2;

/// Broadcast channel used for the INIT request and its response.
pub const BROADCAST_CHANNEL: u32 = 0xFFFF_FFFF;

/// Payload bytes carried by an initialization packet (7-byte header).
pub const INIT_DATA_LEN: usize = 57;

/// Payload bytes carried by a continuation packet (5-byte header).
pub const CONT_DATA_LEN: usize = 59;

/// Largest CTAPHID message the reassembler accepts.
pub const MAX_MESSAGE_BYTES: usize = 2048;

/// High bit set in the initialization packet's command byte.
const INIT_FLAG: u8 = 0x80;

/// CTAPHID commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtapHidCommand {
    /// Echo an arbitrary payload.
    Ping,
    /// Encapsulated CTAP1/U2F message.
    Msg,
    /// Channel lock.
    Lock,
    /// Channel allocation.
    Init,
    /// Blink the device.
    Wink,
    /// Encapsulated CTAP2 message.
    Cbor,
    /// Cancel the pending operation.
    Cancel,
    /// Busy/keepalive notification.
    Keepalive,
    /// Error response.
    Error,
    /// Unknown command code, preserved for error reporting.
    Unknown(u8),
}

impl CtapHidCommand {
    /// Command code without the initialization flag.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            CtapHidCommand::Ping => 0x01,
            CtapHidCommand::Msg => 0x03,
            CtapHidCommand::Lock => 0x04,
            CtapHidCommand::Init => 0x06,
            CtapHidCommand::Wink => 0x08,
            CtapHidCommand::Cbor => 0x10,
            CtapHidCommand::Cancel => 0x11,
            CtapHidCommand::Keepalive => 0x3B,
            CtapHidCommand::Error => 0x3F,
            CtapHidCommand::Unknown(code) => code,
        }
    }

    /// Decode a command code (without the initialization flag).
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x01 => CtapHidCommand::Ping,
            0x03 => CtapHidCommand::Msg,
            0x04 => CtapHidCommand::Lock,
            0x06 => CtapHidCommand::Init,
            0x08 => CtapHidCommand::Wink,
            0x10 => CtapHidCommand::Cbor,
            0x11 => CtapHidCommand::Cancel,
            0x3B => CtapHidCommand::Keepalive,
            0x3F => CtapHidCommand::Error,
            other => CtapHidCommand::Unknown(other),
        }
    }
}

/// CTAPHID protocol error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidError {
    /// Invalid command.
    InvalidCmd = 0x01,
    /// Invalid parameter.
    InvalidPar = 0x02,
    /// Invalid message length.
    InvalidLen = 0x03,
    /// Invalid sequence number.
    InvalidSeq = 0x04,
    /// Message timed out.
    MsgTimeout = 0x05,
    /// Channel is busy.
    ChannelBusy = 0x06,
    /// Channel requires a lock.
    LockRequired = 0x0A,
    /// Invalid channel.
    InvalidChannel = 0x0B,
    /// Unspecified error.
    Other = 0x7F,
}

/// A parsed CTAPHID packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Initialization packet.
    Init {
        /// Channel id.
        channel: u32,
        /// Command.
        command: CtapHidCommand,
        /// Total message length across all packets.
        length: u16,
        /// Payload fragment.
        data: heapless::Vec<u8, INIT_DATA_LEN>,
    },
    /// Continuation packet.
    Cont {
        /// Channel id.
        channel: u32,
        /// Sequence number, `0..=127`.
        sequence: u8,
        /// Payload fragment.
        data: heapless::Vec<u8, CONT_DATA_LEN>,
    },
}

/// Build an initialization packet.
pub fn init_report(
    channel: u32,
    command: CtapHidCommand,
    length: u16,
    data: &[u8],
) -> Result<[u8; REPORT_SIZE], CoreError> {
    if data.len() > INIT_DATA_LEN {
        return Err(CoreError::ProtocolError);
    }
    let mut report = [0u8; REPORT_SIZE];
    report[0..4].copy_from_slice(&channel.to_be_bytes());
    report[4] = INIT_FLAG | (command.code() & 0x7F);
    report[5..7].copy_from_slice(&length.to_be_bytes());
    report[7..7 + data.len()].copy_from_slice(data);
    Ok(report)
}

/// Build a continuation packet.
pub fn cont_report(
    channel: u32,
    sequence: u8,
    data: &[u8],
) -> Result<[u8; REPORT_SIZE], CoreError> {
    if sequence > 127 || data.len() > CONT_DATA_LEN {
        return Err(CoreError::ProtocolError);
    }
    let mut report = [0u8; REPORT_SIZE];
    report[0..4].copy_from_slice(&channel.to_be_bytes());
    report[4] = sequence;
    report[5..5 + data.len()].copy_from_slice(data);
    Ok(report)
}

/// Build an error response packet.
pub fn error_report(channel: u32, code: CtapHidError) -> [u8; REPORT_SIZE] {
    let mut report = [0u8; REPORT_SIZE];
    report[0..4].copy_from_slice(&channel.to_be_bytes());
    report[4] = INIT_FLAG | (CtapHidCommand::Error.code() & 0x7F);
    report[5..7].copy_from_slice(&1u16.to_be_bytes());
    report[7] = code as u8;
    report
}

/// Parse a raw 64-byte report.
pub fn parse_report(report: &[u8; REPORT_SIZE]) -> Result<Packet, CoreError> {
    let channel = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
    let command_byte = report[4];

    if command_byte & INIT_FLAG != 0 {
        let command = CtapHidCommand::from_code(command_byte & 0x7F);
        let length = u16::from_be_bytes([report[5], report[6]]);
        let mut data = heapless::Vec::new();
        data.extend_from_slice(&report[7..])
            .map_err(|_| CoreError::ProtocolError)?;
        Ok(Packet::Init {
            channel,
            command,
            length,
            data,
        })
    } else {
        let sequence = command_byte & 0x7F;
        let mut data = heapless::Vec::new();
        data.extend_from_slice(&report[5..])
            .map_err(|_| CoreError::ProtocolError)?;
        Ok(Packet::Cont {
            channel,
            sequence,
            data,
        })
    }
}

/// A fully reassembled CTAPHID message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Channel the message arrived on.
    pub channel: u32,
    /// Command.
    pub command: CtapHidCommand,
    /// Complete payload.
    pub payload: heapless::Vec<u8, MAX_MESSAGE_BYTES>,
}

struct InProgress {
    channel: u32,
    command: CtapHidCommand,
    expected: usize,
    received: usize,
    next_sequence: u8,
    buffer: heapless::Vec<u8, MAX_MESSAGE_BYTES>,
}

/// Reassembles CTAPHID packets into complete messages.
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

    /// Feed one packet, returning a completed message when available.
    ///
    /// Invalid sequences, mismatched channels and oversized messages surface as
    /// [`CoreError::ProtocolError`] and abort the in-flight message.
    pub fn accept(&mut self, packet: Packet) -> Result<Option<Message>, CoreError> {
        match packet {
            Packet::Init {
                channel,
                command,
                length,
                data,
            } => {
                self.current = None;
                let expected = usize::from(length);
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
                        channel,
                        command,
                        payload: buffer,
                    }));
                }

                self.current = Some(InProgress {
                    channel,
                    command,
                    expected,
                    received: take,
                    next_sequence: 0,
                    buffer,
                });
                Ok(None)
            }
            Packet::Cont {
                channel,
                sequence,
                data,
            } => {
                let Some(state) = self.current.as_mut() else {
                    return Err(CoreError::ProtocolError);
                };
                if state.channel != channel || sequence != state.next_sequence {
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
                state.next_sequence = state.next_sequence.wrapping_add(1) & 0x7F;

                if state.received >= state.expected {
                    let state = self.current.take().expect("in progress");
                    return Ok(Some(Message {
                        channel: state.channel,
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

    fn decode(report: [u8; REPORT_SIZE]) -> Packet {
        parse_report(&report).unwrap()
    }

    #[test]
    fn init_round_trip() {
        let Packet::Init {
            channel,
            command,
            length,
            data,
        } = decode(init_report(0x1234_5678, CtapHidCommand::Ping, 3, &[1, 2, 3]).unwrap())
        else {
            panic!("expected init");
        };
        assert_eq!(channel, 0x1234_5678);
        assert_eq!(command, CtapHidCommand::Ping);
        assert_eq!(length, 3);
        assert_eq!(&data[..3], &[1, 2, 3]);
    }

    #[test]
    fn continuation_round_trip() {
        let Packet::Cont {
            channel,
            sequence,
            data,
        } = decode(cont_report(7, 5, &[9, 8, 7]).unwrap())
        else {
            panic!("expected continuation");
        };
        assert_eq!(channel, 7);
        assert_eq!(sequence, 5);
        assert_eq!(&data[..3], &[9, 8, 7]);
    }

    #[test]
    fn error_report_carries_code() {
        let report = error_report(0xABCD, CtapHidError::InvalidCmd);
        let Packet::Init {
            command,
            length,
            data,
            ..
        } = decode(report)
        else {
            panic!("expected init");
        };
        assert_eq!(command, CtapHidCommand::Error);
        assert_eq!(length, 1);
        assert_eq!(data[0], CtapHidError::InvalidCmd as u8);
    }

    #[test]
    fn single_packet_message_completes_immediately() {
        let mut asm = Assembler::new();
        let report = init_report(1, CtapHidCommand::Cbor, 3, &[0xAA, 0xBB, 0xCC]).unwrap();
        let msg = asm.accept(decode(report)).unwrap().unwrap();
        assert_eq!(msg.channel, 1);
        assert_eq!(msg.command, CtapHidCommand::Cbor);
        assert_eq!(&msg.payload[..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn zero_length_message_completes() {
        let mut asm = Assembler::new();
        let report = init_report(1, CtapHidCommand::Init, 0, &[]).unwrap();
        let msg = asm.accept(decode(report)).unwrap().unwrap();
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn multi_packet_message_reassembles() {
        let mut asm = Assembler::new();
        let payload: heapless::Vec<u8, 200> = (0..200u16).map(|i| i as u8).collect();

        let first = &payload[..INIT_DATA_LEN];
        assert!(
            asm.accept(decode(
                init_report(9, CtapHidCommand::Msg, 200, first).unwrap()
            ))
            .unwrap()
            .is_none()
        );

        let mut offset = INIT_DATA_LEN;
        let mut seq = 0u8;
        loop {
            let end = (offset + CONT_DATA_LEN).min(payload.len());
            let chunk = &payload[offset..end];
            let result = asm
                .accept(decode(cont_report(9, seq, chunk).unwrap()))
                .unwrap();
            offset = end;
            if let Some(msg) = result {
                assert_eq!(msg.payload.len(), 200);
                assert_eq!(&msg.payload[..], &payload[..]);
                break;
            }
            seq += 1;
        }
    }

    #[test]
    fn padding_beyond_length_is_ignored() {
        let mut asm = Assembler::new();
        // Declare 60 bytes: fits in init (57) plus 3 of the continuation.
        let first = [0x11; INIT_DATA_LEN];
        assert!(
            asm.accept(decode(
                init_report(2, CtapHidCommand::Cbor, 60, &first).unwrap()
            ))
            .unwrap()
            .is_none()
        );
        let cont = cont_report(2, 0, &[0x22; CONT_DATA_LEN]).unwrap();
        let msg = asm.accept(decode(cont)).unwrap().unwrap();
        assert_eq!(msg.payload.len(), 60);
        assert!(msg.payload[57..].iter().all(|b| *b == 0x22));
    }

    #[test]
    fn wrong_sequence_is_rejected() {
        let mut asm = Assembler::new();
        let first = [0u8; INIT_DATA_LEN];
        asm.accept(decode(
            init_report(1, CtapHidCommand::Msg, 200, &first).unwrap(),
        ))
        .unwrap();
        let bad = cont_report(1, 3, &[0u8; CONT_DATA_LEN]).unwrap();
        assert_eq!(asm.accept(decode(bad)), Err(CoreError::ProtocolError));
    }

    #[test]
    fn continuation_without_init_is_rejected() {
        let mut asm = Assembler::new();
        let cont = cont_report(1, 0, &[0u8; 10]).unwrap();
        assert_eq!(asm.accept(decode(cont)), Err(CoreError::ProtocolError));
    }

    #[test]
    fn oversized_message_is_rejected() {
        let mut asm = Assembler::new();
        let report = init_report(1, CtapHidCommand::Cbor, 0xFFFF, &[]).unwrap();
        assert_eq!(asm.accept(decode(report)), Err(CoreError::ProtocolError));
    }

    #[test]
    fn channel_mismatch_is_rejected() {
        let mut asm = Assembler::new();
        let first = [0u8; INIT_DATA_LEN];
        asm.accept(decode(
            init_report(1, CtapHidCommand::Msg, 200, &first).unwrap(),
        ))
        .unwrap();
        let bad = cont_report(2, 0, &[0u8; CONT_DATA_LEN]).unwrap();
        assert_eq!(asm.accept(decode(bad)), Err(CoreError::ProtocolError));
    }
}
