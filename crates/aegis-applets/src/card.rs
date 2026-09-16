//! The card front end: a CCID reassembler driving an applet router.
//!
//! [`Card`] is the only type the firmware's CCID task needs. It consumes bulk
//! OUT packets with [`Card::feed`] and produces encoded CCID responses with
//! [`Card::poll`], implementing the power/slot state machine and forwarding
//! `XfrBlock` APDUs to the selected applet.

use crate::apdu::Sw;
use crate::ccid::{self, Assembler, CcidError, Request};
use crate::router::{Applet, DEFAULT_RESPONSE_BYTES, Router};
use aegis_core::authenticator::Rng;

/// Answer-to-Reset returned when the host powers the card on.
///
/// `3B 00` declares direct convention, no interface bytes and no historical
/// characters, which makes T=0 the only protocol — exactly what the card
/// implements (raw APDUs in `XfrBlock`, `data || SW1 SW2` in responses).
pub const ATR: &[u8] = &[0x3B, 0x00];

/// What a call to [`Card::poll`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// An encoded CCID response is ready in the output buffer.
    Response(usize),
    /// The command needs User Presence; resolve it with
    /// [`Card::complete_presence`].
    PresenceRequired,
}

/// CCID card session over a set of applets.
pub struct Card<
    'a,
    const RESPONSE: usize = DEFAULT_RESPONSE_BYTES,
    const MESSAGE: usize = { ccid::MAX_MESSAGE_BYTES },
> {
    assembler: Assembler<MESSAGE>,
    router: Router<'a, RESPONSE>,
    powered: bool,
    pending_sequence: Option<u8>,
}

impl<const RESPONSE: usize, const MESSAGE: usize> core::fmt::Debug for Card<'_, RESPONSE, MESSAGE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Card")
            .field("buffered_bytes", &self.assembler.len())
            .field("powered", &self.powered)
            .field("selected_aid", &self.router.selected_aid())
            .finish()
    }
}

/// A [`Card`] with the default response and message buffers.
pub type DefaultCard<'a> = Card<'a, DEFAULT_RESPONSE_BYTES, { ccid::MAX_MESSAGE_BYTES }>;

impl<'a, const RESPONSE: usize, const MESSAGE: usize> Card<'a, RESPONSE, MESSAGE> {
    /// Create a card over `applets`.
    #[must_use]
    pub fn new(applets: &'a mut [&'a mut dyn Applet]) -> Self {
        Self {
            assembler: Assembler::new(),
            router: Router::new(applets),
            powered: false,
            pending_sequence: None,
        }
    }

    /// Append a bulk OUT packet, reassembling CCID frames.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), CcidError> {
        self.assembler.feed(chunk)
    }

    /// Handle the next complete CCID message, if one is buffered.
    ///
    /// On success the encoded response is written to `out` and its length
    /// returned. `Ok(None)` means more packets are needed; an
    /// [`Outcome::PresenceRequired`] must be resolved with
    /// [`Card::complete_presence`] before the next message is processed.
    pub fn poll(
        &mut self,
        rng: &mut dyn Rng,
        out: &mut [u8],
    ) -> Result<Option<Outcome>, CcidError> {
        if self.pending_sequence.is_some() {
            return Ok(None);
        }
        let Self {
            assembler,
            router,
            powered,
            pending_sequence,
        } = self;
        let Some(frame) = assembler.pending()? else {
            return Ok(None);
        };
        let frame_len = frame.len();
        let result = handle_frame::<RESPONSE, MESSAGE>(frame, router, powered, rng, out);
        assembler.consume(frame_len);
        match result? {
            FrameOutcome::Encoded(len) => Ok(Some(Outcome::Response(len))),
            FrameOutcome::PresenceRequired(sequence) => {
                *pending_sequence = Some(sequence);
                Ok(Some(Outcome::PresenceRequired))
            }
        }
    }

    /// Resolve a pending [`Outcome::PresenceRequired`].
    ///
    /// The pending command is completed (or refused) and its response encoded
    /// into `out`. `rng` backs completions that need fresh entropy.
    pub fn complete_presence(
        &mut self,
        confirmed: bool,
        rng: &mut dyn Rng,
        out: &mut [u8],
    ) -> Result<Option<usize>, CcidError> {
        let Some(sequence) = self.pending_sequence.take() else {
            return Ok(None);
        };
        let response = if confirmed {
            self.router.confirm_presence(rng)
        } else {
            self.router.deny_presence()
        };
        encode_data_block(sequence, response, out).map(Some)
    }

    /// Drop buffered bytes, the selection and the power state.
    pub fn reset(&mut self) {
        self.assembler.reset();
        self.router.reset();
        self.powered = false;
        self.pending_sequence = None;
    }

    /// Whether the host has powered the card on.
    #[must_use]
    pub const fn is_powered(&self) -> bool {
        self.powered
    }

    /// AID of the selected applet, if any.
    #[must_use]
    pub fn selected_aid(&self) -> Option<&'static [u8]> {
        self.router.selected_aid()
    }
}

/// Result of handling one CCID frame.
enum FrameOutcome {
    /// A response was encoded; it occupies `usize` bytes of the output buffer.
    Encoded(usize),
    /// The command needs User Presence before it can complete.
    PresenceRequired(u8),
}

/// Handle one complete CCID frame, encoding the response into `out`.
fn handle_frame<const RESPONSE: usize, const MESSAGE: usize>(
    frame: &[u8],
    router: &mut Router<'_, RESPONSE>,
    powered: &mut bool,
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<FrameOutcome, CcidError> {
    let request = match Request::parse(frame) {
        Ok(request) => request,
        Err(_) => {
            let sequence = frame.get(6).copied().unwrap_or(0);
            let len = ccid::Response::slot_status_failed(sequence).encode_into(out)?;
            return Ok(FrameOutcome::Encoded(len));
        }
    };
    if request.slot() != 0 {
        let len = ccid::Response::slot_status_failed(request.sequence()).encode_into(out)?;
        return Ok(FrameOutcome::Encoded(len));
    }

    let encoded = match request {
        Request::IccPowerOn { sequence, .. } => {
            *powered = true;
            ccid::Response::data_block(sequence, ATR).encode_into(out)?
        }
        Request::IccPowerOff { sequence, .. } => {
            *powered = false;
            ccid::Response::slot_status(sequence, ccid::ICC_STATUS_INACTIVE).encode_into(out)?
        }
        Request::GetSlotStatus { sequence, .. } => {
            let status = if *powered {
                ccid::ICC_STATUS_ACTIVE
            } else {
                ccid::ICC_STATUS_INACTIVE
            };
            ccid::Response::slot_status(sequence, status).encode_into(out)?
        }
        Request::SetParameters {
            sequence, protocol, ..
        } => {
            if protocol == ccid::PROTOCOL_T0 {
                ccid::Response::parameters(sequence, ccid::PROTOCOL_T0, &[]).encode_into(out)?
            } else {
                ccid::Response::parameters_failed(sequence).encode_into(out)?
            }
        }
        Request::XfrBlock { sequence, data, .. } => {
            if !*powered {
                ccid::Response::data_block_failed(sequence).encode_into(out)?
            } else {
                let response = router.command(data, rng);
                if response.sw == Sw::PRESENCE_REQUIRED {
                    return Ok(FrameOutcome::PresenceRequired(sequence));
                }
                encode_data_block(sequence, response, out)?
            }
        }
        Request::Escape { sequence, .. } => {
            ccid::Response::data_block_failed(sequence).encode_into(out)?
        }
        Request::Abort { sequence, .. } => {
            let status = if *powered {
                ccid::ICC_STATUS_ACTIVE
            } else {
                ccid::ICC_STATUS_INACTIVE
            };
            ccid::Response::slot_status(sequence, status).encode_into(out)?
        }
    };
    Ok(FrameOutcome::Encoded(encoded))
}

/// Encode an APDU response as a `RDR_to_PC_DataBlock`.
fn encode_data_block(
    sequence: u8,
    response: crate::apdu::Response<'_>,
    out: &mut [u8],
) -> Result<usize, CcidError> {
    if out.len() < ccid::HEADER_LEN {
        return Err(CcidError::Overflow);
    }
    let Some(encoded) = response.encode_into(&mut out[ccid::HEADER_LEN..]) else {
        return Err(CcidError::Overflow);
    };
    ccid::write_data_block_header(sequence, encoded, out)?;
    Ok(ccid::HEADER_LEN + encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aid;
    use crate::placeholder::Placeholder;
    use heapless::Vec;

    /// Build a CCID frame with the given message type, sequence and payload.
    fn frame(message_type: u8, sequence: u8, payload: &[u8]) -> Vec<u8, 64> {
        let mut out = Vec::new();
        out.push(message_type).unwrap();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        out.extend_from_slice(&[0x00, sequence, 0x00, 0x00, 0x00])
            .unwrap();
        out.extend_from_slice(payload).unwrap();
        out
    }

    /// Build an XfrBlock frame carrying a command APDU.
    fn xfr(sequence: u8, apdu: &[u8]) -> Vec<u8, 64> {
        frame(ccid::PC_TO_RDR_XFR_BLOCK, sequence, apdu)
    }

    /// Deterministic RNG for command processing.
    struct TestRng;

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0x5A);
        }
    }

    struct Fixture {
        piv: Placeholder,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                piv: Placeholder::new(aid::PIV),
            }
        }
    }

    fn with_card<F>(fixture: &mut Fixture, f: F)
    where
        F: FnOnce(&mut Card<'_, 64, 64>),
    {
        let mut applets: [&mut dyn Applet; 1] = [&mut fixture.piv];
        let mut card = Card::<64, 64>::new(&mut applets);
        assert!(!card.is_powered());
        f(&mut card);
    }

    fn poll_one(card: &mut Card<'_, 64, 64>, bytes: &[u8]) -> Vec<u8, 128> {
        card.feed(bytes).unwrap();
        let mut out = [0u8; 128];
        let Some(Outcome::Response(len)) = card.poll(&mut TestRng, &mut out).unwrap() else {
            panic!("expected an encoded response");
        };
        let mut response = Vec::new();
        response.extend_from_slice(&out[..len]).unwrap();
        response
    }

    #[test]
    fn power_on_returns_the_atr() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            let response = poll_one(card, &frame(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]));
            assert!(card.is_powered());
            assert_eq!(response[0], ccid::RDR_TO_PC_DATA_BLOCK);
            assert_eq!(&response[1..5], &2u32.to_le_bytes());
            assert_eq!(&response[10..], ATR);
        });
    }

    #[test]
    fn slot_status_tracks_power_state() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            let response = poll_one(card, &frame(ccid::PC_TO_RDR_GET_SLOT_STATUS, 2, &[]));
            assert_eq!(response[0], ccid::RDR_TO_PC_SLOT_STATUS);
            assert_eq!(response[9], ccid::ICC_STATUS_INACTIVE);

            poll_one(card, &frame(ccid::PC_TO_RDR_ICC_POWER_ON, 3, &[]));
            let response = poll_one(card, &frame(ccid::PC_TO_RDR_GET_SLOT_STATUS, 4, &[]));
            assert_eq!(response[9], ccid::ICC_STATUS_ACTIVE);

            poll_one(card, &frame(ccid::PC_TO_RDR_ICC_POWER_OFF, 5, &[]));
            assert!(!card.is_powered());
        });
    }

    #[test]
    fn set_parameters_accepts_t0_only() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            let response = poll_one(
                card,
                &frame(ccid::PC_TO_RDR_SET_PARAMETERS, 1, &[ccid::PROTOCOL_T0]),
            );
            assert_eq!(response[0], ccid::RDR_TO_PC_PARAMETERS);
            assert_eq!(response[7], ccid::STATUS_OK);
            assert_eq!(response[9], ccid::PROTOCOL_T0);

            let response = poll_one(
                card,
                &frame(ccid::PC_TO_RDR_SET_PARAMETERS, 2, &[ccid::PROTOCOL_T1]),
            );
            assert_eq!(response[7], ccid::STATUS_FAILED);
        });
    }

    #[test]
    fn xfr_block_requires_power() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            let response = poll_one(card, &xfr(1, &[0x00, 0xA4, 0x04, 0x00]));
            assert_eq!(response[0], ccid::RDR_TO_PC_DATA_BLOCK);
            assert_eq!(response[7], ccid::STATUS_FAILED);
        });
    }

    #[test]
    fn selects_a_known_applet_over_ccid() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            poll_one(card, &frame(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]));

            let mut apdu = Vec::<u8, 32>::new();
            apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
            apdu.push(aid::PIV.len() as u8).unwrap();
            apdu.extend_from_slice(aid::PIV).unwrap();
            let response = poll_one(card, &xfr(2, &apdu));
            assert_eq!(response[0], ccid::RDR_TO_PC_DATA_BLOCK);
            assert_eq!(response[7], ccid::STATUS_OK);
            assert_eq!(&response[10..12], &[0x90, 0x00]);
            assert_eq!(card.selected_aid(), Some(aid::PIV));
        });
    }

    #[test]
    fn rejects_an_unknown_applet_over_ccid() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            poll_one(card, &frame(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]));
            let apdu = [0x00, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x00];
            let response = poll_one(card, &xfr(2, &apdu));
            assert_eq!(&response[10..12], &[0x6A, 0x82]);
            assert_eq!(card.selected_aid(), None);
        });
    }

    #[test]
    fn rejects_unsupported_instructions_over_ccid() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            poll_one(card, &frame(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]));
            let mut apdu = Vec::<u8, 32>::new();
            apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
            apdu.push(aid::PIV.len() as u8).unwrap();
            apdu.extend_from_slice(aid::PIV).unwrap();
            poll_one(card, &xfr(2, &apdu));

            let response = poll_one(card, &xfr(3, &[0x00, 0xCB, 0x3F, 0xFF]));
            assert_eq!(&response[10..12], &[0x6D, 0x00]);
        });
    }

    #[test]
    fn escape_is_refused() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            let response = poll_one(card, &frame(ccid::PC_TO_RDR_ESCAPE, 7, &[0x01]));
            assert_eq!(response[0], ccid::RDR_TO_PC_DATA_BLOCK);
            assert_eq!(response[7], ccid::STATUS_FAILED);
        });
    }

    #[test]
    fn abort_reports_slot_status() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            let response = poll_one(card, &frame(ccid::PC_TO_RDR_ABORT, 8, &[]));
            assert_eq!(response[0], ccid::RDR_TO_PC_SLOT_STATUS);
            assert_eq!(response[9], ccid::ICC_STATUS_INACTIVE);
        });
    }

    #[test]
    fn malformed_frames_are_answered_with_a_failure() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            // Unknown message type but valid header.
            let response = poll_one(card, &frame(0x99, 9, &[]));
            assert_eq!(response[0], ccid::RDR_TO_PC_SLOT_STATUS);
            assert_eq!(response[7], ccid::STATUS_FAILED);
            // Non-zero slot.
            let mut outside_slot = frame(ccid::PC_TO_RDR_GET_SLOT_STATUS, 10, &[]);
            outside_slot[5] = 3;
            let response = poll_one(card, &outside_slot);
            assert_eq!(response[7], ccid::STATUS_FAILED);
        });
    }

    #[test]
    fn pipelined_frames_are_processed_in_order() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            let mut bytes = Vec::<u8, 64>::new();
            bytes
                .extend_from_slice(&frame(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]))
                .unwrap();
            bytes
                .extend_from_slice(&frame(ccid::PC_TO_RDR_GET_SLOT_STATUS, 2, &[]))
                .unwrap();
            card.feed(&bytes).unwrap();

            let mut out = [0u8; 64];
            let first = card.poll(&mut TestRng, &mut out).unwrap().unwrap();
            assert_eq!(out[0], ccid::RDR_TO_PC_DATA_BLOCK);
            let _ = first;
            let second = card.poll(&mut TestRng, &mut out).unwrap().unwrap();
            assert_eq!(out[0], ccid::RDR_TO_PC_SLOT_STATUS);
            assert_eq!(out[6], 2);
            let _ = second;
            assert_eq!(card.poll(&mut TestRng, &mut out).unwrap(), None);
        });
    }

    #[test]
    fn reset_drops_power_selection_and_buffers() {
        let mut fixture = Fixture::new();
        with_card(&mut fixture, |card| {
            poll_one(card, &frame(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]));
            card.reset();
            assert!(!card.is_powered());
            assert_eq!(card.selected_aid(), None);
            assert!(card.poll(&mut TestRng, &mut [0u8; 64]).unwrap().is_none());
        });
    }

    use crate::apdu::{Apdu, Response};

    /// Applet that asks for User Presence for every command.
    struct PresenceApplet;

    impl Applet for PresenceApplet {
        fn aid(&self) -> &'static [u8] {
            crate::aid::OATH
        }

        fn process(&mut self, _apdu: &Apdu<'_>, _rng: &mut dyn Rng) -> Response<'_> {
            Response::presence_required()
        }

        fn confirm_presence(&mut self, _rng: &mut dyn Rng) -> Response<'_> {
            Response::ok(&[0xAA])
        }

        fn deny_presence(&mut self) -> Response<'_> {
            Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    fn select_oath(card: &mut Card<'_, 64, 64>) {
        let mut apdu = Vec::<u8, 32>::new();
        apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
        apdu.push(crate::aid::OATH.len() as u8).unwrap();
        apdu.extend_from_slice(crate::aid::OATH).unwrap();
        let response = poll_one(card, &xfr(2, &apdu));
        assert_eq!(&response[10..12], &[0x90, 0x00]);
    }

    #[test]
    fn presence_flow_round_trips() {
        let mut applet = PresenceApplet;
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut card = Card::<64, 64>::new(&mut applets);
        let mut out = [0u8; 128];

        card.feed(&frame(ccid::PC_TO_RDR_ICC_POWER_ON, 1, &[]))
            .unwrap();
        let _ = card.poll(&mut TestRng, &mut out).unwrap();
        select_oath(&mut card);

        card.feed(&xfr(3, &[0x00, 0xA6, 0x00, 0x00])).unwrap();
        assert_eq!(
            card.poll(&mut TestRng, &mut out).unwrap(),
            Some(Outcome::PresenceRequired)
        );
        // Further frames are held until the pending command is resolved.
        card.feed(&xfr(4, &[0x00, 0xA6, 0x00, 0x00])).unwrap();
        assert_eq!(card.poll(&mut TestRng, &mut out).unwrap(), None);

        let len = card
            .complete_presence(true, &mut TestRng, &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(out[0], ccid::RDR_TO_PC_DATA_BLOCK);
        assert_eq!(out[6], 3, "response echoes the pending sequence");
        assert_eq!(&out[10..len], &[0xAA, 0x90, 0x00]);

        assert_eq!(
            card.poll(&mut TestRng, &mut out).unwrap(),
            Some(Outcome::PresenceRequired)
        );
        let len = card
            .complete_presence(false, &mut TestRng, &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(&out[10..len], &[0x69, 0x82]);
        assert_eq!(
            card.complete_presence(true, &mut TestRng, &mut out)
                .unwrap(),
            None
        );
    }
}
