//! Experimental OTP-labelled HID transport for the authorized YubiKey 5 lab profile.
//!
//! This is NOT the Yubico OTP wire protocol. It has no slots, programmable
//! secrets, keyboard output, challenge-response, AES/Yubico OTP, or `ykman otp`
//! commands. Its only commands are read-only INFO and bounded PING. In particular
//! it never touches the RP2350 one-time-programmable memory or the YKOATH applet.
//!
//! One 64-byte interrupt OUT report produces at most one 64-byte interrupt IN
//! report (no report ID or fragmentation). Both directions have the same header:
//!
//! ```text
//! byte  0       magic = A5
//! byte  1       version = 01
//! byte  2       command (01 PING, 02 INFO)
//! byte  3       status (requests = 00; responses: 00 OK, 01 unknown command,
//!                            02 invalid command payload length)
//! bytes 4..8    opaque nonzero/non-broadcast channel, big-endian u32
//! byte  8       payload length (0..=54)
//! byte  9       reserved = 00
//! bytes 10..64  payload followed by zero padding
//! ```
//!
//! Malformed reports are silently discarded; well-formed unknown commands and
//! INFO with a payload receive a status response on the same channel. Channels
//! correlate requests and responses only: they are NOT authenticated sessions.

/// HID interrupt report length; descriptor and both endpoints use 64 bytes.
pub const REPORT_SIZE: usize = 64;
/// Number of data octets after the fixed 10-byte header.
pub const MAX_PAYLOAD: usize = REPORT_SIZE - 10;
/// Protocol magic (not the Yubico OTP framing).
pub const MAGIC: u8 = 0xA5;
/// Lab wire protocol version.
pub const VERSION: u8 = 1;
/// Safe, public identifier returned by INFO (never a device secret).
pub const INFO: &[u8] = b"AEGIS-OTP-LAB/1";

/// Command codes in the lab-only protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Return the same 0..=54 payload octets.
    Ping,
    /// Return the fixed lab protocol identifier; request payload must be empty.
    Info,
    /// Reject without performing any privileged operation.
    Unknown(u8),
}

impl Command {
    /// Decode a command byte; unknown values remain intact for error replies.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x01 => Self::Ping,
            0x02 => Self::Info,
            other => Self::Unknown(other),
        }
    }

    /// Byte sent on the wire.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ping => 0x01,
            Self::Info => 0x02,
            Self::Unknown(other) => other,
        }
    }
}

/// Reply status; a malformed *frame* is silently dropped, not acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Successful INFO or PING.
    Ok = 0,
    /// A valid frame requested a command this lab transport does not implement.
    UnknownCommand = 1,
    /// INFO must have no request data.
    InvalidLength = 2,
}

/// Invalid report, or response/request that cannot fit in one report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Exactly 64 report bytes are required.
    ReportSize,
    /// Incorrect magic or version.
    Header,
    /// Zero/broadcast is not a valid correlation channel.
    Channel,
    /// A request status or the reserved header byte is nonzero.
    Reserved,
    /// Payload is longer than 54 bytes.
    PayloadLength,
    /// Nonzero bytes follow the declared payload.
    Padding,
}

/// A validated host-to-device request; payload borrows the supplied report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// Client-provided correlation channel, not an authenticated session.
    pub channel: u32,
    /// Requested lab operation.
    pub command: Command,
    /// Exactly the declared payload (not the padding).
    pub payload: &'a [u8],
}

fn valid_channel(channel: u32) -> bool {
    channel != 0 && channel != u32::MAX
}

/// Parse and strictly validate a 64-byte host request before dispatching.
pub fn parse_request(report: &[u8]) -> Result<Request<'_>, FrameError> {
    if report.len() != REPORT_SIZE {
        return Err(FrameError::ReportSize);
    }
    if report[0] != MAGIC || report[1] != VERSION {
        return Err(FrameError::Header);
    }
    if report[3] != 0 || report[9] != 0 {
        return Err(FrameError::Reserved);
    }
    let channel = u32::from_be_bytes([report[4], report[5], report[6], report[7]]);
    if !valid_channel(channel) {
        return Err(FrameError::Channel);
    }
    let len = usize::from(report[8]);
    if len > MAX_PAYLOAD {
        return Err(FrameError::PayloadLength);
    }
    if report[10 + len..].iter().any(|&byte| byte != 0) {
        return Err(FrameError::Padding);
    }
    Ok(Request {
        channel,
        command: Command::from_code(report[2]),
        payload: &report[10..10 + len],
    })
}

fn encode(
    command: Command,
    channel: u32,
    status: Status,
    payload: &[u8],
) -> Result<[u8; REPORT_SIZE], FrameError> {
    if !valid_channel(channel) {
        return Err(FrameError::Channel);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::PayloadLength);
    }
    let mut report = [0u8; REPORT_SIZE];
    report[0] = MAGIC;
    report[1] = VERSION;
    report[2] = command.code();
    report[3] = status as u8;
    report[4..8].copy_from_slice(&channel.to_be_bytes());
    report[8] = payload.len() as u8;
    report[10..10 + payload.len()].copy_from_slice(payload);
    Ok(report)
}

/// Encode a host request (useful to host-side tools and round-trip tests).
pub fn encode_request(
    command: Command,
    channel: u32,
    payload: &[u8],
) -> Result<[u8; REPORT_SIZE], FrameError> {
    encode(command, channel, Status::Ok, payload)
}

/// Encode a device response. Errors never echo untrusted request payloads.
pub fn encode_response(
    command: Command,
    channel: u32,
    status: Status,
    payload: &[u8],
) -> Result<[u8; REPORT_SIZE], FrameError> {
    if status != Status::Ok && !payload.is_empty() {
        return Err(FrameError::PayloadLength);
    }
    encode(command, channel, status, payload)
}

/// Dispatch a single report with no persistent state, secrets, or side effects.
/// Invalid frames get no response, including partial USB packets.
#[must_use]
pub fn handle_report(report: &[u8]) -> Option<[u8; REPORT_SIZE]> {
    let request = parse_request(report).ok()?;
    let (status, payload) = match request.command {
        Command::Ping => (Status::Ok, request.payload),
        Command::Info if request.payload.is_empty() => (Status::Ok, INFO),
        Command::Info => (Status::InvalidLength, &[][..]),
        Command::Unknown(_) => (Status::UnknownCommand, &[][..]),
    };
    encode_response(request.command, request.channel, status, payload).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_round_trip_and_zero_padding() {
        let report = encode_request(Command::Ping, 0x0123_4567, b"hello").unwrap();
        let parsed = parse_request(&report).unwrap();
        assert_eq!(parsed.channel, 0x0123_4567);
        assert_eq!(parsed.command, Command::Ping);
        assert_eq!(parsed.payload, b"hello");
        assert!(report[15..].iter().all(|&byte| byte == 0));
        assert_eq!(handle_report(&report).unwrap(), report);
    }

    #[test]
    fn info_is_read_only_and_rejects_payload() {
        let report = encode_request(Command::Info, 1, &[]).unwrap();
        let answer = handle_report(&report).unwrap();
        assert_eq!(answer[3], Status::Ok as u8);
        assert_eq!(answer[8] as usize, INFO.len());
        assert_eq!(&answer[10..10 + INFO.len()], INFO);
        assert!(answer[10 + INFO.len()..].iter().all(|&byte| byte == 0));
        let invalid = encode_request(Command::Info, 1, b"x").unwrap();
        let answer = handle_report(&invalid).unwrap();
        assert_eq!(answer[3], Status::InvalidLength as u8);
        assert_eq!(answer[8], 0);
    }

    #[test]
    fn unknown_command_returns_only_an_error_on_same_channel() {
        let report = encode_request(Command::Unknown(0xF0), 42, b"secret").unwrap();
        let answer = handle_report(&report).unwrap();
        assert_eq!(answer[2], 0xF0);
        assert_eq!(answer[3], Status::UnknownCommand as u8);
        assert_eq!(&answer[4..8], &42u32.to_be_bytes());
        assert!(answer[8..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn max_payload_and_encoder_limits() {
        let payload = [0x7Bu8; MAX_PAYLOAD];
        let report = encode_request(Command::Ping, u32::MAX - 1, &payload).unwrap();
        assert_eq!(parse_request(&report).unwrap().payload, payload);
        assert_eq!(handle_report(&report).unwrap(), report);
        assert_eq!(
            encode_request(Command::Ping, 1, &[0; MAX_PAYLOAD + 1]),
            Err(FrameError::PayloadLength)
        );
        assert_eq!(
            encode_response(Command::Info, 1, Status::UnknownCommand, b"x"),
            Err(FrameError::PayloadLength)
        );
    }

    #[test]
    fn malformed_reports_are_silently_dropped() {
        let valid = encode_request(Command::Ping, 1, b"hi").unwrap();
        let cases: &[(usize, u8, FrameError)] = &[
            (0, 0, FrameError::Header),
            (1, 2, FrameError::Header),
            (3, 1, FrameError::Reserved),
            (8, 55, FrameError::PayloadLength),
            (9, 1, FrameError::Reserved),
            (12, 1, FrameError::Padding),
        ];
        for &(offset, value, error) in cases {
            let mut report = valid;
            report[offset] = value;
            assert_eq!(parse_request(&report), Err(error));
            assert_eq!(handle_report(&report), None);
        }
        for n in [0, 1, 63, 65] {
            assert_eq!(parse_request(&[0; 65][..n]), Err(FrameError::ReportSize));
            assert_eq!(handle_report(&[0; 65][..n]), None);
        }
    }

    #[test]
    fn invalid_channels_and_reply_status_are_rejected() {
        for channel in [0, u32::MAX] {
            assert_eq!(
                encode_request(Command::Ping, channel, &[]),
                Err(FrameError::Channel)
            );
            let mut report = encode_request(Command::Ping, 1, &[]).unwrap();
            report[4..8].copy_from_slice(&channel.to_be_bytes());
            assert_eq!(parse_request(&report), Err(FrameError::Channel));
            assert_eq!(handle_report(&report), None);
        }
        let answer = handle_report(&encode_request(Command::Info, 1, b"x").unwrap()).unwrap();
        assert_eq!(parse_request(&answer), Err(FrameError::Reserved));
    }
}
