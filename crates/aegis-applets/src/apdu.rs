//! ISO 7816-4 command and response APDUs, status words and chaining.
//!
//! A command APDU is parsed without copying: [`Apdu::data`] borrows the frame
//! received from the transport. Cases 1-4 are supported in both short and
//! extended encodings. Responses longer than the host's `Le` are split by
//! [`Chainer`] into `61xx` + `GET RESPONSE` exchanges.

use heapless::Vec;

/// Command APDU header length (`CLA INS P1 P2`).
pub const HEADER_LEN: usize = 4;

/// Status word length in bytes.
pub const SW_LEN: usize = 2;

/// Largest response a short APDU can carry (`Le` of `0x00` means 256).
pub const SHORT_RESPONSE_LIMIT: usize = 256;

/// Largest response an extended APDU can carry (`Le` of `0x0000` means 65536).
pub const EXTENDED_RESPONSE_LIMIT: usize = 65_536;

/// ISO 7816-4 status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sw(pub u16);

impl Sw {
    /// `9000`: command processed successfully.
    pub const OK: Self = Self(0x9000);
    /// `6700`: wrong length in `Lc` or `Le`.
    pub const WRONG_LENGTH: Self = Self(0x6700);
    /// `6A80`: incorrect data in the data field.
    pub const WRONG_DATA: Self = Self(0x6A80);
    /// `6A81`: function not supported.
    pub const FUNCTION_NOT_SUPPORTED: Self = Self(0x6A81);
    /// `6A82`: file or application not found.
    pub const FILE_NOT_FOUND: Self = Self(0x6A82);
    /// `6A84`: not enough memory space.
    pub const NOT_ENOUGH_MEMORY: Self = Self(0x6A84);
    /// `6A86`: incorrect `P1`/`P2`.
    pub const INCORRECT_PARAMETERS: Self = Self(0x6A86);
    /// `6A88`: referenced data or reference data not found.
    pub const REFERENCED_DATA_NOT_FOUND: Self = Self(0x6A88);
    /// `6984`: referenced object or authentication data is not valid.
    pub const OATH_OBJECT_NOT_FOUND: Self = Self(0x6984);
    /// `6982`: security status not satisfied.
    pub const SECURITY_STATUS_NOT_SATISFIED: Self = Self(0x6982);
    /// `6983`: authentication method blocked.
    pub const AUTHENTICATION_BLOCKED: Self = Self(0x6983);
    /// `6984`: authentication is not enabled or a response does not match.
    pub const AUTH_NOT_ENABLED: Self = Self(0x6984);
    /// `6984`: authentication response did not match.
    pub const AUTHENTICATION_FAILED: Self = Self(0x6984);
    /// `6985`: conditions of use not satisfied.
    pub const CONDITIONS_NOT_SATISFIED: Self = Self(0x6985);
    /// `6986`: command not allowed (no current file selected).
    pub const COMMAND_NOT_ALLOWED: Self = Self(0x6986);
    /// `6D00`: instruction not supported.
    pub const INS_NOT_SUPPORTED: Self = Self(0x6D00);
    /// `6E00`: class not supported.
    pub const CLA_NOT_SUPPORTED: Self = Self(0x6E00);
    /// `6F00`: no precise diagnosis.
    pub const NO_PRECISE_DIAGNOSIS: Self = Self(0x6F00);

    /// Internal marker: the command needs User Presence before it can proceed.
    ///
    /// This status is never encoded onto the wire; [`crate::card::Card`]
    /// converts it into [`crate::card::Outcome::PresenceRequired`] and the
    /// firmware resolves it with the presence source.
    pub const PRESENCE_REQUIRED: Self = Self(0x6FF0);

    /// Raw 16-bit status word.
    #[must_use]
    pub const fn code(self) -> u16 {
        self.0
    }

    /// Status word as the two bytes placed on the wire, `SW1` first.
    #[must_use]
    pub const fn bytes(self) -> [u8; SW_LEN] {
        [(self.0 >> 8) as u8, self.0 as u8]
    }

    /// Whether this is the success status `9000`.
    #[must_use]
    pub const fn is_success(self) -> bool {
        self.0 == Self::OK.0
    }

    /// `63Cx`: verification failed, `x` attempts remain.
    #[must_use]
    pub const fn retries_left(remaining: u8) -> Self {
        Self(0x63C0 | (remaining as u16 & 0x0F))
    }

    /// `61xx`: `xx` response bytes are available (or 256 when `xx` is zero).
    #[must_use]
    pub const fn bytes_remaining(remaining: u8) -> Self {
        Self(0x6100 | remaining as u16)
    }

    /// Whether this is a retry indicator (`63C0`..`63CF`).
    #[must_use]
    pub const fn is_retry_indicator(self) -> bool {
        (self.0 & 0xFFF0) == 0x63C0
    }

    /// Whether this status announces more response bytes (`61xx`).
    #[must_use]
    pub const fn is_bytes_remaining(self) -> bool {
        (self.0 & 0xFF00) == 0x6100
    }
}

/// A parsed command APDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Apdu<'a> {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter byte 1.
    pub p1: u8,
    /// Parameter byte 2.
    pub p2: u8,
    /// Command data field; empty for cases 1 and 2.
    pub data: &'a [u8],
    /// Expected response length in bytes, when the command carries an `Le`.
    ///
    /// An `Le` of zero is normalised: 256 for short APDUs, 65536 for extended.
    pub le: Option<u32>,
    /// Whether the APDU used the extended encoding.
    pub extended: bool,
}

impl<'a> Apdu<'a> {
    /// Parse a command APDU, validating its self-described length.
    ///
    /// Returns [`Sw::WRONG_LENGTH`] when the frame is malformed or its declared
    /// lengths do not exactly consume it.
    pub fn parse(frame: &'a [u8]) -> Result<Self, Sw> {
        if frame.len() < HEADER_LEN {
            return Err(Sw::WRONG_LENGTH);
        }
        let header = [frame[0], frame[1], frame[2], frame[3]];
        let body = &frame[HEADER_LEN..];

        // Case 1: no body at all.
        if body.is_empty() {
            return Ok(Self::new(header, &[], None, false));
        }

        // A leading zero in the Lc position selects the extended encoding, but
        // only when more bytes follow: a five-byte frame is a short case 2 with
        // `Le = 0` meaning 256.
        if body[0] == 0 && body.len() > 1 {
            if body.len() < 3 {
                // `00 xx` cannot encode either an extended Lc or Le pair.
                return Err(Sw::WRONG_LENGTH);
            }
            let first = u16::from_be_bytes([body[1], body[2]]);
            let rest = &body[3..];
            if rest.is_empty() {
                // Case 2E: `Le` only.
                return Ok(Self::new(header, &[], Some(normalise(first, 65536)), true));
            }
            let data_len = usize::from(first);
            if rest.len() == data_len {
                // Case 3E: data, no `Le`.
                return Ok(Self::new(header, rest, None, true));
            }
            if rest.len() == data_len + 2 {
                // Case 4E: data and `Le`.
                let le = u16::from_be_bytes([rest[data_len], rest[data_len + 1]]);
                return Ok(Self::new(
                    header,
                    &rest[..data_len],
                    Some(normalise(le, 65536)),
                    true,
                ));
            }
            return Err(Sw::WRONG_LENGTH);
        }

        let lc = usize::from(body[0]);
        let rest = &body[1..];
        if rest.is_empty() {
            // Case 2S: `Le` only, zero meaning 256.
            return Ok(Self::new(
                header,
                &[],
                Some(normalise(u16::from(body[0]), 256)),
                false,
            ));
        }
        if rest.len() == lc {
            // Case 3S: data, no `Le`.
            return Ok(Self::new(header, rest, None, false));
        }
        if rest.len() == lc + 1 {
            // Case 4S: data and `Le`.
            let le = u32::from(rest[lc]);
            return Ok(Self::new(
                header,
                &rest[..lc],
                Some(normalise(le as u16, 256)),
                false,
            ));
        }
        Err(Sw::WRONG_LENGTH)
    }

    const fn new(
        header: [u8; HEADER_LEN],
        data: &'a [u8],
        le: Option<u32>,
        extended: bool,
    ) -> Self {
        Self {
            cla: header[0],
            ins: header[1],
            p1: header[2],
            p2: header[3],
            data,
            le,
            extended,
        }
    }

    /// Number of response bytes the host is willing to accept.
    ///
    /// Commands without an `Le` (cases 1 and 3) report zero; callers that must
    /// send data anyway should treat zero as [`SHORT_RESPONSE_LIMIT`].
    #[must_use]
    pub const fn expected_len(&self) -> usize {
        match self.le {
            Some(le) => le as usize,
            None => 0,
        }
    }

    /// Whether the command carries a data field.
    #[must_use]
    pub fn has_data(&self) -> bool {
        !self.data.is_empty()
    }
}

/// Map a zero length field to its documented maximum.
const fn normalise(value: u16, zero_means: u32) -> u32 {
    if value == 0 { zero_means } else { value as u32 }
}

/// An APDU response: data plus a status word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response<'a> {
    /// Response data, empty when only a status is returned.
    pub data: &'a [u8],
    /// Final status word.
    pub sw: Sw,
}

impl<'a> Response<'a> {
    /// Build a response from data and a status word.
    #[must_use]
    pub const fn new(data: &'a [u8], sw: Sw) -> Self {
        Self { data, sw }
    }

    /// A successful response carrying `data`.
    #[must_use]
    pub const fn ok(data: &'a [u8]) -> Self {
        Self::new(data, Sw::OK)
    }

    /// A status-only response.
    #[must_use]
    pub const fn status(sw: Sw) -> Self {
        Self::new(&[], sw)
    }

    /// A response asking the firmware for User Presence.
    #[must_use]
    pub const fn presence_required() -> Self {
        Self::new(&[], Sw::PRESENCE_REQUIRED)
    }

    /// Encode `data || SW1 SW2` into `out`, returning the number of bytes.
    ///
    /// Returns `None` when `out` is too small.
    pub fn encode_into(&self, out: &mut [u8]) -> Option<usize> {
        let len = self.data.len() + SW_LEN;
        if out.len() < len {
            return None;
        }
        out[..self.data.len()].copy_from_slice(self.data);
        out[self.data.len()..len].copy_from_slice(&self.sw.bytes());
        Some(len)
    }
}

/// Splits responses larger than the requested length into `61xx` exchanges.
///
/// `N` is the largest response the card can buffer. [`Chainer::begin`] starts a
/// new response and returns its first chunk; [`Chainer::get_response`] serves
/// the chunks a host retrieves after a `61xx`.
#[derive(Debug)]
pub struct Chainer<const N: usize> {
    pending: Vec<u8, N>,
    delivered: usize,
}

impl<const N: usize> Default for Chainer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Chainer<N> {
    /// Create an empty chainer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pending: Vec::new(),
            delivered: 0,
        }
    }

    /// Discard any pending response bytes.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.delivered = 0;
    }

    /// Whether a chained response is still being served.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.delivered < self.pending.len()
    }

    /// Number of bytes still pending.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.pending.len() - self.delivered
    }

    /// Start a new response, returning the first chunk.
    ///
    /// When the data fits in `le` bytes it is returned whole with [`Sw::OK`].
    /// Otherwise exactly `le` bytes are returned with `61xx`, and the rest is
    /// held for [`Chainer::get_response`]. A response larger than `N` fails
    /// closed with [`Sw::NO_PRECISE_DIAGNOSIS`].
    pub fn begin(&mut self, data: &[u8], le: usize) -> Response<'_> {
        self.clear();
        if data.len() > N || self.pending.extend_from_slice(data).is_err() {
            self.clear();
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        self.deliver(le)
    }

    /// Serve the pending bytes of the last response.
    pub fn get_response(&mut self, le: usize) -> Response<'_> {
        if !self.is_pending() {
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        }
        self.deliver(le)
    }

    fn deliver(&mut self, le: usize) -> Response<'_> {
        let remaining = self.remaining();
        if remaining == 0 {
            return Response::ok(&[]);
        }
        let le = if le == 0 { SHORT_RESPONSE_LIMIT } else { le };
        let start = self.delivered;
        if remaining <= le {
            self.delivered = self.pending.len();
            return Response::ok(&self.pending[start..self.delivered]);
        }
        self.delivered += le;
        let remaining = self.remaining().min(255) as u8;
        Response::new(
            &self.pending[start..start + le],
            Sw::bytes_remaining(remaining),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_case_1() {
        let apdu = Apdu::parse(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        assert_eq!(apdu.cla, 0x00);
        assert_eq!(apdu.ins, 0xA4);
        assert_eq!(apdu.data, b"");
        assert_eq!(apdu.le, None);
        assert!(!apdu.extended);
    }

    #[test]
    fn parses_case_2_short() {
        let apdu = Apdu::parse(&[0x00, 0xCA, 0x00, 0x00, 0x20]).unwrap();
        assert_eq!(apdu.data, b"");
        assert_eq!(apdu.le, Some(0x20));
        assert_eq!(apdu.expected_len(), 0x20);
    }

    #[test]
    fn short_le_zero_means_256() {
        let apdu = Apdu::parse(&[0x00, 0xCA, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(apdu.le, Some(256));
        assert!(!apdu.extended);
    }

    #[test]
    fn parses_case_3_short() {
        let apdu = Apdu::parse(&[0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB]).unwrap();
        assert_eq!(apdu.data, &[0xAA, 0xBB]);
        assert_eq!(apdu.le, None);
    }

    #[test]
    fn parses_case_4_short() {
        let apdu = Apdu::parse(&[0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x10]).unwrap();
        assert_eq!(apdu.data, &[0xAA, 0xBB]);
        assert_eq!(apdu.le, Some(0x10));
    }

    #[test]
    fn parses_case_4_short_le_zero_means_256() {
        let apdu = Apdu::parse(&[0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB, 0x00]).unwrap();
        assert_eq!(apdu.le, Some(256));
    }

    #[test]
    fn parses_extended_case_2() {
        // `00 CA 01 00 00 01 00`: extended Le of 256.
        let apdu = Apdu::parse(&[0x00, 0xCA, 0x01, 0x00, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(apdu.data, b"");
        assert_eq!(apdu.le, Some(256));
        assert!(apdu.extended);
    }

    #[test]
    fn parses_extended_case_2_le_zero_means_65536() {
        let apdu = Apdu::parse(&[0x00, 0xCA, 0x01, 0x00, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(apdu.le, Some(65_536));
        assert!(apdu.extended);
    }

    #[test]
    fn parses_extended_case_3() {
        // `00 D0 01 00 00 00 04 DE AD BE EF`: extended Lc of 4, no Le.
        let apdu = Apdu::parse(&[
            0x00, 0xD0, 0x01, 0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
        ])
        .unwrap();
        assert_eq!(apdu.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(apdu.le, None);
        assert!(apdu.extended);
    }

    #[test]
    fn parses_extended_case_4() {
        let frame = [
            0x00, 0xD0, 0x01, 0x00, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0x00, 0x40,
        ];
        let apdu = Apdu::parse(&frame).unwrap();
        assert_eq!(apdu.data, &[0xDE, 0xAD]);
        assert_eq!(apdu.le, Some(0x40));
        assert!(apdu.extended);
    }

    #[test]
    fn rejects_truncated_frames() {
        assert_eq!(Apdu::parse(&[]), Err(Sw::WRONG_LENGTH));
        assert_eq!(Apdu::parse(&[0x00, 0xA4, 0x04]), Err(Sw::WRONG_LENGTH));
        assert_eq!(
            Apdu::parse(&[0x00, 0xA4, 0x04, 0x00, 0x05, 0x01]),
            Err(Sw::WRONG_LENGTH)
        );
        assert_eq!(
            Apdu::parse(&[0x00, 0xA4, 0x04, 0x00, 0x00, 0x01]),
            Err(Sw::WRONG_LENGTH)
        );
    }

    #[test]
    fn rejects_trailing_bytes() {
        assert_eq!(
            Apdu::parse(&[0x00, 0xA4, 0x04, 0x00, 0x01, 0xAA, 0xBB, 0xCC]),
            Err(Sw::WRONG_LENGTH)
        );
    }

    #[test]
    fn status_word_helpers() {
        assert!(Sw::OK.is_success());
        assert!(!Sw::INS_NOT_SUPPORTED.is_success());
        assert_eq!(Sw::retries_left(3).bytes(), [0x63, 0xC3]);
        assert!(Sw::retries_left(1).is_retry_indicator());
        assert!(!Sw::retries_left(1).is_success());
        assert_eq!(Sw::bytes_remaining(0x44).bytes(), [0x61, 0x44]);
        assert!(Sw::bytes_remaining(0).is_bytes_remaining());
        assert_eq!(Sw::WRONG_LENGTH.code(), 0x6700);
    }

    #[test]
    fn response_encodes_data_then_status() {
        let response = Response::ok(&[0x01, 0x02]);
        let mut out = [0u8; 8];
        let len = response.encode_into(&mut out).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&out[..len], &[0x01, 0x02, 0x90, 0x00]);

        let short = Response::status(Sw::FILE_NOT_FOUND);
        let mut out = [0u8; 2];
        assert_eq!(short.encode_into(&mut out), Some(2));
        assert_eq!(out, [0x6A, 0x82]);

        let mut tiny = [0u8; 1];
        assert_eq!(short.encode_into(&mut tiny), None);
    }

    #[test]
    fn chainer_sends_small_responses_whole() {
        let mut chainer = Chainer::<64>::new();
        let response = chainer.begin(&[1, 2, 3], 256);
        assert_eq!(response.data, &[1, 2, 3]);
        assert_eq!(response.sw, Sw::OK);
        assert!(!chainer.is_pending());
    }

    #[test]
    fn chainer_splits_large_responses() {
        let data = [0xAB; 300];
        let mut chainer = Chainer::<512>::new();
        let first = chainer.begin(&data, 256);
        assert_eq!(first.data.len(), 256);
        assert_eq!(first.sw, Sw::bytes_remaining(44));
        assert_eq!(chainer.remaining(), 44);

        let second = chainer.get_response(256);
        assert_eq!(second.data, &[0xAB; 44]);
        assert_eq!(second.sw, Sw::OK);
        assert!(!chainer.is_pending());
    }

    #[test]
    fn chainer_holds_back_when_le_is_not_enough_for_all_chunks() {
        let data = [0x11; 600];
        let mut chainer = Chainer::<1024>::new();
        let first = chainer.begin(&data, 256);
        assert_eq!(first.sw, Sw::bytes_remaining(255));

        let second = chainer.get_response(256);
        assert_eq!(second.data.len(), 256);
        assert_eq!(second.sw, Sw::bytes_remaining(88));

        let third = chainer.get_response(256);
        assert_eq!(third.data.len(), 88);
        assert_eq!(third.sw, Sw::OK);
    }

    #[test]
    fn chainer_rejects_oversized_responses_fail_closed() {
        let data = [0u8; 65];
        let mut chainer = Chainer::<64>::new();
        let response = chainer.begin(&data, 256);
        assert_eq!(response.sw, Sw::NO_PRECISE_DIAGNOSIS);
        assert_eq!(response.data, b"");
        assert!(!chainer.is_pending());
    }

    #[test]
    fn chainer_get_response_without_pending_is_conditions() {
        let mut chainer = Chainer::<64>::new();
        assert_eq!(chainer.get_response(256).sw, Sw::CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn chainer_begin_resets_pending_state() {
        let mut chainer = Chainer::<64>::new();
        let _ = chainer.begin(&[1; 40], 16);
        assert!(chainer.is_pending());
        let response = chainer.begin(&[2, 3], 256);
        assert_eq!(response.data, &[2, 3]);
        assert!(!chainer.is_pending());
    }
}
