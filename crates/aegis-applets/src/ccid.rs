//! USB CCID message framing (CCID rev 1.1) and bulk reassembly.
//!
//! AegisToken exposes its applets over USB CCID (class `0x0B`). Every CCID
//! message starts with a ten-byte header — `bMessageType`, a little-endian
//! `dwLength`, `bSlot`, `bSeq` and three message-specific bytes — optionally
//! followed by a payload. The host sends messages as one or more bulk OUT
//! packets; [`Assembler`] turns those packets back into complete frames.
//!
//! The card side implements a single slot, T=0 protocol, so `XfrBlock` payloads
//! are raw command APDUs and responses are `data || SW1 SW2`.

use heapless::Vec;

/// CCID message header length, in bytes.
pub const HEADER_LEN: usize = 10;

/// Largest CCID message the card buffers, header included.
///
/// The firmware advertises this same bound as `dwMaxCCIDMessageLength`.
pub const MAX_MESSAGE_BYTES: usize = 2100;

/// Largest payload a single CCID message may carry.
pub const MAX_PAYLOAD_BYTES: usize = MAX_MESSAGE_BYTES - HEADER_LEN;

/// `PC_to_RDR_SetParameters` message type.
pub const PC_TO_RDR_SET_PARAMETERS: u8 = 0x61;
/// `PC_to_RDR_IccPowerOn` message type.
pub const PC_TO_RDR_ICC_POWER_ON: u8 = 0x62;
/// `PC_to_RDR_IccPowerOff` message type.
pub const PC_TO_RDR_ICC_POWER_OFF: u8 = 0x63;
/// `PC_to_RDR_GetSlotStatus` message type.
pub const PC_TO_RDR_GET_SLOT_STATUS: u8 = 0x65;
/// `PC_to_RDR_Escape` message type.
pub const PC_TO_RDR_ESCAPE: u8 = 0x6B;
/// `PC_to_RDR_XfrBlock` message type.
pub const PC_TO_RDR_XFR_BLOCK: u8 = 0x6F;
/// `PC_to_RDR_Abort` message type.
pub const PC_TO_RDR_ABORT: u8 = 0x72;

/// `RDR_to_PC_DataBlock` message type.
pub const RDR_TO_PC_DATA_BLOCK: u8 = 0x80;
/// `RDR_to_PC_SlotStatus` message type.
pub const RDR_TO_PC_SLOT_STATUS: u8 = 0x81;
/// `RDR_to_PC_Parameters` message type.
pub const RDR_TO_PC_PARAMETERS: u8 = 0x82;
/// `RDR_to_PC_Escape` message type.
pub const RDR_TO_PC_ESCAPE: u8 = 0x83;

/// `bStatus`: command processed without error.
pub const STATUS_OK: u8 = 0x00;
/// `bStatus`: command failed.
pub const STATUS_FAILED: u8 = 0x01;
/// `bError`: no error.
pub const ERROR_NONE: u8 = 0x00;
/// `bError`: an error occurred.
pub const ERROR_OCCURRED: u8 = 0x01;

/// `bClockStatus` / ICC status: the card is active.
pub const ICC_STATUS_ACTIVE: u8 = 0x00;
/// ICC status: the card is present but inactive.
pub const ICC_STATUS_INACTIVE: u8 = 0x01;
/// ICC status: no card present.
pub const ICC_STATUS_NO_ICC: u8 = 0x02;
/// ICC status: communication error.
pub const ICC_STATUS_COMM_ERROR: u8 = 0x03;

/// `bProtocolNum`: T=0.
pub const PROTOCOL_T0: u8 = 0x00;
/// `bProtocolNum`: T=1.
pub const PROTOCOL_T1: u8 = 0x01;

/// Malformed or unsupported CCID traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcidError {
    /// The frame is shorter than a CCID header.
    ShortFrame,
    /// `dwLength` does not match the frame, or a field has the wrong length.
    BadLength,
    /// The message type is not implemented by this card.
    UnsupportedMessage,
    /// The message does not fit the reassembly buffer.
    Overflow,
}

/// Parsed CCID message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// `bMessageType`.
    pub message_type: u8,
    /// `dwLength`, the payload length.
    pub length: u32,
    /// `bSlot`; the card implements a single slot.
    pub slot: u8,
    /// `bSeq`, echoed in the response.
    pub sequence: u8,
    /// The three message-specific bytes.
    pub specific: [u8; 3],
}

impl Header {
    /// Parse a header, requiring the frame to match its declared length.
    pub fn parse(frame: &[u8]) -> Result<Self, CcidError> {
        if frame.len() < HEADER_LEN {
            return Err(CcidError::ShortFrame);
        }
        let length = u32::from_le_bytes([frame[1], frame[2], frame[3], frame[4]]);
        if usize::try_from(length).map_or(true, |length| length + HEADER_LEN != frame.len()) {
            return Err(CcidError::BadLength);
        }
        Ok(Self {
            message_type: frame[0],
            length,
            slot: frame[5],
            sequence: frame[6],
            specific: [frame[7], frame[8], frame[9]],
        })
    }
}

/// A command received from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request<'a> {
    /// `IccPowerOn`: activate the card; reply with the ATR.
    IccPowerOn {
        /// `bSlot`.
        slot: u8,
        /// `bSeq`.
        sequence: u8,
        /// `bPowerSelect`.
        power_select: u8,
    },
    /// `IccPowerOff`.
    IccPowerOff {
        /// `bSlot`.
        slot: u8,
        /// `bSeq`.
        sequence: u8,
    },
    /// `GetSlotStatus`.
    GetSlotStatus {
        /// `bSlot`.
        slot: u8,
        /// `bSeq`.
        sequence: u8,
    },
    /// `SetParameters`.
    SetParameters {
        /// `bSlot`.
        slot: u8,
        /// `bSeq`.
        sequence: u8,
        /// `bProtocolNum` requested by the host.
        protocol: u8,
        /// Protocol data structure.
        data: &'a [u8],
    },
    /// `XfrBlock`: an APDU exchange.
    XfrBlock {
        /// `bSlot`.
        slot: u8,
        /// `bSeq`.
        sequence: u8,
        /// `bBWI`, the block waiting time.
        bwi: u8,
        /// `wLevelParameter`.
        level_parameter: u16,
        /// The command APDU (T=0) or block (higher protocols).
        data: &'a [u8],
    },
    /// `Escape`: vendor-specific command.
    Escape {
        /// `bSlot`.
        slot: u8,
        /// `bSeq`.
        sequence: u8,
        /// Escape payload.
        data: &'a [u8],
    },
    /// `Abort`.
    Abort {
        /// `bSlot`.
        slot: u8,
        /// `bSeq`.
        sequence: u8,
    },
}

impl<'a> Request<'a> {
    /// Parse a complete frame into a command.
    pub fn parse(frame: &'a [u8]) -> Result<Self, CcidError> {
        let header = Header::parse(frame)?;
        let payload = &frame[HEADER_LEN..];
        match header.message_type {
            PC_TO_RDR_ICC_POWER_ON if payload.is_empty() => Ok(Self::IccPowerOn {
                slot: header.slot,
                sequence: header.sequence,
                power_select: header.specific[0],
            }),
            PC_TO_RDR_ICC_POWER_OFF if payload.is_empty() => Ok(Self::IccPowerOff {
                slot: header.slot,
                sequence: header.sequence,
            }),
            PC_TO_RDR_GET_SLOT_STATUS if payload.is_empty() => Ok(Self::GetSlotStatus {
                slot: header.slot,
                sequence: header.sequence,
            }),
            PC_TO_RDR_SET_PARAMETERS if !payload.is_empty() => Ok(Self::SetParameters {
                slot: header.slot,
                sequence: header.sequence,
                protocol: payload[0],
                data: &payload[1..],
            }),
            PC_TO_RDR_XFR_BLOCK => Ok(Self::XfrBlock {
                slot: header.slot,
                sequence: header.sequence,
                bwi: header.specific[0],
                level_parameter: u16::from_le_bytes([header.specific[1], header.specific[2]]),
                data: payload,
            }),
            PC_TO_RDR_ESCAPE => Ok(Self::Escape {
                slot: header.slot,
                sequence: header.sequence,
                data: payload,
            }),
            PC_TO_RDR_ABORT if payload.is_empty() => Ok(Self::Abort {
                slot: header.slot,
                sequence: header.sequence,
            }),
            _ => Err(CcidError::UnsupportedMessage),
        }
    }

    /// `bSeq` of the request, echoed in the response.
    #[must_use]
    pub const fn sequence(&self) -> u8 {
        match self {
            Self::IccPowerOn { sequence, .. }
            | Self::IccPowerOff { sequence, .. }
            | Self::GetSlotStatus { sequence, .. }
            | Self::SetParameters { sequence, .. }
            | Self::XfrBlock { sequence, .. }
            | Self::Escape { sequence, .. }
            | Self::Abort { sequence, .. } => *sequence,
        }
    }

    /// `bSlot` targeted by the request.
    #[must_use]
    pub const fn slot(&self) -> u8 {
        match self {
            Self::IccPowerOn { slot, .. }
            | Self::IccPowerOff { slot, .. }
            | Self::GetSlotStatus { slot, .. }
            | Self::SetParameters { slot, .. }
            | Self::XfrBlock { slot, .. }
            | Self::Escape { slot, .. }
            | Self::Abort { slot, .. } => *slot,
        }
    }
}

/// A response sent back to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response<'a> {
    /// `bMessageType`.
    pub message_type: u8,
    /// `bSeq` copied from the request.
    pub sequence: u8,
    /// `bStatus` (`bmCommandStatus`).
    pub status: u8,
    /// `bError` (`bmError`).
    pub error: u8,
    /// The three message-specific bytes: for data blocks `[status, error,
    /// chain]` is split across [`Response::status`], [`Response::error`] and
    /// `specific[2]`.
    pub specific: [u8; 3],
    /// Payload following the header.
    pub data: &'a [u8],
}

impl<'a> Response<'a> {
    /// A `RDR_to_PC_DataBlock` carrying `data`.
    #[must_use]
    pub const fn data_block(sequence: u8, data: &'a [u8]) -> Self {
        Self {
            message_type: RDR_TO_PC_DATA_BLOCK,
            sequence,
            status: STATUS_OK,
            error: ERROR_NONE,
            specific: [0; 3],
            data,
        }
    }

    /// A failed `RDR_to_PC_DataBlock` with no payload.
    #[must_use]
    pub const fn data_block_failed(sequence: u8) -> Self {
        Self {
            message_type: RDR_TO_PC_DATA_BLOCK,
            sequence,
            status: STATUS_FAILED,
            error: ERROR_OCCURRED,
            specific: [0; 3],
            data: &[],
        }
    }

    /// A `RDR_to_PC_SlotStatus` with the given ICC status.
    #[must_use]
    pub const fn slot_status(sequence: u8, icc_status: u8) -> Self {
        Self {
            message_type: RDR_TO_PC_SLOT_STATUS,
            sequence,
            status: STATUS_OK,
            error: ERROR_NONE,
            specific: [icc_status, 0, 0],
            data: &[],
        }
    }

    /// A failed `RDR_to_PC_SlotStatus`.
    #[must_use]
    pub const fn slot_status_failed(sequence: u8) -> Self {
        Self {
            message_type: RDR_TO_PC_SLOT_STATUS,
            sequence,
            status: STATUS_FAILED,
            error: ERROR_OCCURRED,
            specific: [ICC_STATUS_COMM_ERROR, 0, 0],
            data: &[],
        }
    }

    /// A `RDR_to_PC_Parameters` confirming `protocol`.
    #[must_use]
    pub const fn parameters(sequence: u8, protocol: u8, data: &'a [u8]) -> Self {
        Self {
            message_type: RDR_TO_PC_PARAMETERS,
            sequence,
            status: STATUS_OK,
            error: ERROR_NONE,
            specific: [protocol, 0, 0],
            data,
        }
    }

    /// A failed `RDR_to_PC_Parameters`.
    #[must_use]
    pub const fn parameters_failed(sequence: u8) -> Self {
        Self {
            message_type: RDR_TO_PC_PARAMETERS,
            sequence,
            status: STATUS_FAILED,
            error: ERROR_OCCURRED,
            specific: [0; 3],
            data: &[],
        }
    }

    /// A `RDR_to_PC_Escape` carrying `data`.
    #[must_use]
    pub const fn escape(sequence: u8, data: &'a [u8]) -> Self {
        Self {
            message_type: RDR_TO_PC_ESCAPE,
            sequence,
            status: STATUS_OK,
            error: ERROR_NONE,
            specific: [0; 3],
            data,
        }
    }

    /// Encode header plus payload into `out`.
    pub fn encode_into(&self, out: &mut [u8]) -> Result<usize, CcidError> {
        let total = HEADER_LEN + self.data.len();
        if out.len() < total {
            return Err(CcidError::Overflow);
        }
        write_header_into(out, self.message_type, self.data.len(), self.sequence);
        out[7] = self.status;
        out[8] = self.error;
        out[9] = self.specific[0];
        out[HEADER_LEN..total].copy_from_slice(self.data);
        Ok(total)
    }
}

/// Write a ten-byte CCID header into `out` for a payload of `data_len` bytes.
///
/// Used to build a `RDR_to_PC_DataBlock` whose payload was already written at
/// `out[HEADER_LEN..]`, avoiding a copy.
pub fn write_data_block_header(
    sequence: u8,
    data_len: usize,
    out: &mut [u8],
) -> Result<(), CcidError> {
    if out.len() < HEADER_LEN + data_len {
        return Err(CcidError::Overflow);
    }
    write_header_into(out, RDR_TO_PC_DATA_BLOCK, data_len, sequence);
    out[7] = STATUS_OK;
    out[8] = ERROR_NONE;
    out[9] = 0;
    Ok(())
}

fn write_header_into(out: &mut [u8], message_type: u8, data_len: usize, sequence: u8) {
    out[0] = message_type;
    out[1..5].copy_from_slice(&(data_len as u32).to_le_bytes());
    out[5] = 0;
    out[6] = sequence;
}

/// Reassembles bulk OUT packets into complete CCID frames.
#[derive(Debug)]
pub struct Assembler<const N: usize> {
    buffer: Vec<u8, N>,
}

impl<const N: usize> Default for Assembler<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Assembler<N> {
    /// Create an empty assembler.
    #[must_use]
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Drop every buffered byte.
    pub fn reset(&mut self) {
        self.buffer.clear();
    }

    /// Number of buffered bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the assembler holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Append a bulk packet.
    ///
    /// Fails with [`CcidError::Overflow`] when the packet would exceed the
    /// buffer; the caller should [`Assembler::reset`] and let the host retry.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), CcidError> {
        if self.buffer.len() + chunk.len() > N {
            return Err(CcidError::Overflow);
        }
        self.buffer
            .extend_from_slice(chunk)
            .map_err(|_| CcidError::Overflow)
    }

    /// Return the next complete frame without consuming it.
    ///
    /// `Ok(None)` means more packets are needed. A declared length larger than
    /// the buffer fails with [`CcidError::Overflow`].
    pub fn pending(&self) -> Result<Option<&[u8]>, CcidError> {
        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }
        let length = u32::from_le_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]);
        let Some(length) = usize::try_from(length).ok() else {
            return Err(CcidError::Overflow);
        };
        if length > N - HEADER_LEN {
            return Err(CcidError::Overflow);
        }
        let total = HEADER_LEN + length;
        if self.buffer.len() < total {
            return Ok(None);
        }
        Ok(Some(&self.buffer[..total]))
    }

    /// Remove the first `frame_len` bytes after a frame was handled.
    pub fn consume(&mut self, frame_len: usize) {
        if frame_len >= self.buffer.len() {
            self.buffer.clear();
            return;
        }
        self.buffer.copy_within(frame_len.., 0);
        let len = self.buffer.len() - frame_len;
        self.buffer.truncate(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(message_type: u8, sequence: u8, specific: [u8; 3], payload: &[u8]) -> Vec<u8, 64> {
        let mut out = Vec::new();
        out.push(message_type).unwrap();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        out.push(0).unwrap();
        out.push(sequence).unwrap();
        out.extend_from_slice(&specific).unwrap();
        out.extend_from_slice(payload).unwrap();
        out
    }

    #[test]
    fn header_round_trips() {
        let bytes = frame(PC_TO_RDR_XFR_BLOCK, 7, [0x0A, 0x00, 0x00], &[0x00, 0xA4]);
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.message_type, PC_TO_RDR_XFR_BLOCK);
        assert_eq!(header.length, 2);
        assert_eq!(header.slot, 0);
        assert_eq!(header.sequence, 7);
        assert_eq!(header.specific, [0x0A, 0x00, 0x00]);
    }

    #[test]
    fn header_rejects_short_and_mismatched_frames() {
        assert_eq!(Header::parse(&[0u8; 9]), Err(CcidError::ShortFrame));
        // Declared length does not consume the frame.
        let mut bytes = frame(PC_TO_RDR_XFR_BLOCK, 1, [0; 3], &[0x01, 0x02]);
        bytes[1] = 5;
        assert_eq!(Header::parse(&bytes), Err(CcidError::BadLength));
    }

    #[test]
    fn parses_power_and_status_requests() {
        let on = frame(PC_TO_RDR_ICC_POWER_ON, 1, [0x00, 0x00, 0x00], &[]);
        assert_eq!(
            Request::parse(&on),
            Ok(Request::IccPowerOn {
                slot: 0,
                sequence: 1,
                power_select: 0
            })
        );

        let off = frame(PC_TO_RDR_ICC_POWER_OFF, 2, [0; 3], &[]);
        assert_eq!(
            Request::parse(&off),
            Ok(Request::IccPowerOff {
                slot: 0,
                sequence: 2
            })
        );

        let status = frame(PC_TO_RDR_GET_SLOT_STATUS, 3, [0; 3], &[]);
        assert_eq!(
            Request::parse(&status),
            Ok(Request::GetSlotStatus {
                slot: 0,
                sequence: 3
            })
        );

        let abort = frame(PC_TO_RDR_ABORT, 4, [0; 3], &[]);
        assert_eq!(
            Request::parse(&abort),
            Ok(Request::Abort {
                slot: 0,
                sequence: 4
            })
        );
    }

    #[test]
    fn parses_xfr_block_with_bwi_and_level_parameter() {
        let bytes = frame(
            PC_TO_RDR_XFR_BLOCK,
            9,
            [0x0B, 0x01, 0x00],
            &[0x00, 0xB0, 0x00],
        );
        assert_eq!(
            Request::parse(&bytes),
            Ok(Request::XfrBlock {
                slot: 0,
                sequence: 9,
                bwi: 0x0B,
                level_parameter: 1,
                data: &[0x00, 0xB0, 0x00],
            })
        );
    }

    #[test]
    fn parses_set_parameters_and_escape() {
        let bytes = frame(
            PC_TO_RDR_SET_PARAMETERS,
            5,
            [0x01, 0x00, 0x00],
            &[0x00, 0x00],
        );
        assert_eq!(
            Request::parse(&bytes),
            Ok(Request::SetParameters {
                slot: 0,
                sequence: 5,
                protocol: 0,
                data: &[0x00],
            })
        );

        let escape = frame(PC_TO_RDR_ESCAPE, 6, [0; 3], &[0xDE]);
        assert_eq!(
            Request::parse(&escape),
            Ok(Request::Escape {
                slot: 0,
                sequence: 6,
                data: &[0xDE],
            })
        );
    }

    #[test]
    fn rejects_unknown_message_types() {
        let unknown = frame(0x99, 1, [0; 3], &[]);
        assert_eq!(Request::parse(&unknown), Err(CcidError::UnsupportedMessage));
    }

    #[test]
    fn rejects_fields_with_wrong_payload_length() {
        // PowerOn must not carry a payload.
        let wrong = frame(PC_TO_RDR_ICC_POWER_ON, 1, [0; 3], &[0x00]);
        assert_eq!(Request::parse(&wrong), Err(CcidError::UnsupportedMessage));
        // SetParameters requires at least the protocol byte.
        let wrong = frame(PC_TO_RDR_SET_PARAMETERS, 1, [0; 3], &[]);
        assert_eq!(Request::parse(&wrong), Err(CcidError::UnsupportedMessage));
    }

    #[test]
    fn response_encodes_header_and_payload() {
        let response = Response::data_block(7, &[0x6A, 0x82]);
        let mut out = [0u8; 32];
        let len = response.encode_into(&mut out).unwrap();
        assert_eq!(len, HEADER_LEN + 2);
        assert_eq!(out[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(&out[1..5], &2u32.to_le_bytes());
        assert_eq!(out[5], 0);
        assert_eq!(out[6], 7);
        assert_eq!(out[7], STATUS_OK);
        assert_eq!(out[8], ERROR_NONE);
        assert_eq!(out[9], 0);
        assert_eq!(&out[HEADER_LEN..len], &[0x6A, 0x82]);

        let mut tiny = [0u8; HEADER_LEN + 1];
        assert_eq!(response.encode_into(&mut tiny), Err(CcidError::Overflow));
    }

    #[test]
    fn slot_status_encodes_icc_state() {
        let response = Response::slot_status(3, ICC_STATUS_INACTIVE);
        let mut out = [0u8; 16];
        let len = response.encode_into(&mut out).unwrap();
        assert_eq!(len, HEADER_LEN);
        assert_eq!(out[0], RDR_TO_PC_SLOT_STATUS);
        assert_eq!(&out[1..5], &0u32.to_le_bytes());
        assert_eq!(out[9], ICC_STATUS_INACTIVE);
    }

    #[test]
    fn parameters_encode_protocol() {
        let response = Response::parameters(4, PROTOCOL_T0, &[]);
        let mut out = [0u8; 16];
        let len = response.encode_into(&mut out).unwrap();
        assert_eq!(len, HEADER_LEN);
        assert_eq!(out[0], RDR_TO_PC_PARAMETERS);
        assert_eq!(out[9], PROTOCOL_T0);
    }

    #[test]
    fn data_block_header_writes_length_in_place() {
        let mut out = [0u8; 32];
        out[HEADER_LEN..HEADER_LEN + 3].copy_from_slice(&[1, 2, 3]);
        write_data_block_header(8, 3, &mut out).unwrap();
        assert_eq!(out[0], RDR_TO_PC_DATA_BLOCK);
        assert_eq!(&out[1..5], &3u32.to_le_bytes());
        assert_eq!(out[6], 8);
        assert_eq!(out[9], 0);
    }

    #[test]
    fn assembler_rebuilds_messages_across_packets() {
        let bytes = frame(
            PC_TO_RDR_XFR_BLOCK,
            1,
            [0x0A, 0x00, 0x00],
            &[0x00, 0xA4, 0x04, 0x00, 0x02, 0xAA, 0xBB],
        );
        let mut assembler = Assembler::<64>::new();
        assert!(assembler.pending().unwrap().is_none());
        assembler.feed(&bytes[..5]).unwrap();
        assert!(assembler.pending().unwrap().is_none());
        assembler.feed(&bytes[5..12]).unwrap();
        assert!(assembler.pending().unwrap().is_none());
        assembler.feed(&bytes[12..]).unwrap();
        let pending = assembler.pending().unwrap().unwrap();
        assert_eq!(pending, &bytes[..]);
        assembler.consume(pending.len());
        assert!(assembler.is_empty());
    }

    #[test]
    fn assembler_handles_pipelined_messages() {
        let first = frame(PC_TO_RDR_GET_SLOT_STATUS, 1, [0; 3], &[]);
        let second = frame(PC_TO_RDR_ICC_POWER_ON, 2, [0; 3], &[]);
        let mut bytes = Vec::<u8, 64>::new();
        bytes.extend_from_slice(&first).unwrap();
        bytes.extend_from_slice(&second).unwrap();

        let mut assembler = Assembler::<64>::new();
        assembler.feed(&bytes).unwrap();
        let pending = assembler.pending().unwrap().unwrap();
        assert_eq!(pending, &first[..]);
        let len = pending.len();
        assembler.consume(len);
        let pending = assembler.pending().unwrap().unwrap();
        assert_eq!(pending, &second[..]);
        let len = pending.len();
        assembler.consume(len);
        assert!(assembler.pending().unwrap().is_none());
    }

    #[test]
    fn assembler_refuses_messages_larger_than_its_buffer() {
        let mut assembler = Assembler::<32>::new();
        let mut bytes = frame(PC_TO_RDR_XFR_BLOCK, 1, [0; 3], &[]);
        bytes[1..5].copy_from_slice(&64u32.to_le_bytes());
        assembler.feed(&bytes).unwrap();
        assert_eq!(assembler.pending(), Err(CcidError::Overflow));

        let mut roomy = Assembler::<64>::new();
        roomy.feed(&bytes).unwrap();
        assert_eq!(roomy.pending(), Err(CcidError::Overflow));
    }

    #[test]
    fn request_accessors_report_slot_and_sequence() {
        let bytes = frame(PC_TO_RDR_GET_SLOT_STATUS, 42, [0; 3], &[]);
        let request = Request::parse(&bytes).unwrap();
        assert_eq!(request.sequence(), 42);
        assert_eq!(request.slot(), 0);
    }
}
