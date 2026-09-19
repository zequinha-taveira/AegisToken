//! AID-based applet selection and command dispatch.
//!
//! The router owns the ISO 7816 session: it parses command APDUs, resolves
//! `SELECT` by application identifier (prefix match), forwards everything else
//! to the selected applet and applies response chaining. Applets never see
//! transport details and never depend on each other.

use crate::apdu::{Apdu, Chainer, Response, Sw};
use aegis_core::authenticator::Rng;

/// Interindustry class byte accepted by the router.
pub const CLA_INTERINDUSTRY: u8 = 0x00;
/// `SELECT` instruction.
pub const INS_SELECT: u8 = 0xA4;
/// `GET RESPONSE` instruction.
pub const INS_GET_RESPONSE: u8 = 0xC0;
/// Yubico OATH `SEND REMAINING`, equivalent to `GET RESPONSE` for its
/// protocol-level response chaining.
pub const INS_SEND_REMAINING: u8 = 0xA5;

/// `SELECT` by DF name (`P1 = 0x04`).
pub const SELECT_BY_DF_NAME: u8 = 0x04;

/// Default response buffer size held by a [`Router`].
pub const DEFAULT_RESPONSE_BYTES: usize = 2048;

/// An application that can be selected by AID and process commands.
pub trait Applet {
    /// Application identifier this applet answers to.
    ///
    /// Matching is by prefix, so an applet may register the stable head of an
    /// AID whose tail varies per card (for example OpenPGP).
    fn aid(&self) -> &'static [u8];

    /// Called when the applet is selected; resets any session state.
    fn select(&mut self) -> Response<'_> {
        Response::ok(&[])
    }

    /// Process a command after selection.
    ///
    /// `rng` supplies entropy for commands that generate key material.
    fn process(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_>;

    /// Complete an operation that answered [`Sw::PRESENCE_REQUIRED`].
    ///
    /// `rng` supplies fresh entropy when completion itself is cryptographic
    /// (RSA blinding re-randomizes on every private operation, including
    /// the presence-deferred one).
    fn confirm_presence(&mut self, rng: &mut dyn Rng) -> Response<'_> {
        let _ = rng;
        Response::status(Sw::CONDITIONS_NOT_SATISFIED)
    }

    /// Abort an operation that answered [`Sw::PRESENCE_REQUIRED`].
    fn deny_presence(&mut self) -> Response<'_> {
        Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED)
    }
}

/// Routes commands to at most one selected applet.
pub struct Router<'a, const RESPONSE: usize = DEFAULT_RESPONSE_BYTES> {
    applets: &'a mut [&'a mut dyn Applet],
    selected: Option<usize>,
    chain: Chainer<RESPONSE>,
}

impl<const RESPONSE: usize> core::fmt::Debug for Router<'_, RESPONSE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Router")
            .field("applet_count", &self.applets.len())
            .field("selected", &self.selected)
            .field("pending_bytes", &self.chain.remaining())
            .finish()
    }
}

impl<'a, const RESPONSE: usize> Router<'a, RESPONSE> {
    /// Create a router over `applets`.
    #[must_use]
    pub fn new(applets: &'a mut [&'a mut dyn Applet]) -> Self {
        Self {
            applets,
            selected: None,
            chain: Chainer::new(),
        }
    }

    /// AID of the currently selected applet, if any.
    #[must_use]
    pub fn selected_aid(&self) -> Option<&'static [u8]> {
        self.selected.map(|index| self.applets[index].aid())
    }

    /// Whether an applet is currently selected.
    #[must_use]
    pub fn is_selected(&self) -> bool {
        self.selected.is_some()
    }

    /// Handle one command APDU and produce the response.
    pub fn command(&mut self, frame: &[u8], rng: &mut dyn Rng) -> Response<'_> {
        let apdu = match Apdu::parse(frame) {
            Ok(apdu) => apdu,
            Err(sw) => return Response::status(sw),
        };
        if apdu.cla != CLA_INTERINDUSTRY {
            return Response::status(Sw::CLA_NOT_SUPPORTED);
        }

        let Self {
            applets,
            selected,
            chain,
        } = self;

        if apdu.ins == INS_SELECT {
            if apdu.p1 != SELECT_BY_DF_NAME {
                return Response::status(Sw::INCORRECT_PARAMETERS);
            }
            chain.clear();
            let found = applets
                .iter()
                .position(|applet| apdu.data.starts_with(applet.aid()));
            match found {
                Some(index) => {
                    *selected = Some(index);
                    let applet: &mut dyn Applet = &mut *applets[index];
                    applet.select()
                }
                None => {
                    *selected = None;
                    Response::status(Sw::FILE_NOT_FOUND)
                }
            }
        } else if apdu.ins == INS_GET_RESPONSE
            || (apdu.ins == INS_SEND_REMAINING && chain.is_pending())
        {
            chain.get_response(apdu.expected_len())
        } else {
            let Some(index) = *selected else {
                return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
            };
            let applet: &mut dyn Applet = &mut *applets[index];
            let response = applet.process(&apdu, rng);
            if response.sw == Sw::PRESENCE_REQUIRED {
                return response;
            }
            if response.sw.is_success() {
                chain.begin(response.data, apdu.expected_len())
            } else {
                response
            }
        }
    }

    /// Complete an operation that answered [`Sw::PRESENCE_REQUIRED`].
    pub fn confirm_presence(&mut self, rng: &mut dyn Rng) -> Response<'_> {
        let Some(index) = self.selected else {
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        };
        let applet: &mut dyn Applet = &mut *self.applets[index];
        applet.confirm_presence(rng)
    }

    /// Abort an operation that answered [`Sw::PRESENCE_REQUIRED`].
    pub fn deny_presence(&mut self) -> Response<'_> {
        let Some(index) = self.selected else {
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        };
        let applet: &mut dyn Applet = &mut *self.applets[index];
        applet.deny_presence()
    }

    /// Drop the selection and any pending chained response.
    pub fn reset(&mut self) {
        self.selected = None;
        self.chain.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aid;
    use heapless::Vec;

    /// Deterministic RNG for commands that need entropy.
    struct TestRng;

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0x5A);
        }
    }

    /// Applet with scripted responses, for exercising the router.
    struct TestApplet {
        aid: &'static [u8],
        payload: Vec<u8, 1024>,
        selections: u32,
    }

    impl TestApplet {
        fn new(aid: &'static [u8]) -> Self {
            Self {
                aid,
                payload: Vec::new(),
                selections: 0,
            }
        }
    }

    impl Applet for TestApplet {
        fn aid(&self) -> &'static [u8] {
            self.aid
        }

        fn select(&mut self) -> Response<'_> {
            self.selections += 1;
            Response::ok(&[])
        }

        fn process(&mut self, apdu: &Apdu<'_>, _rng: &mut dyn Rng) -> Response<'_> {
            match apdu.ins {
                0x01 => Response::ok(&[0x01]),
                0x02 => Response::ok(&self.payload),
                _ => Response::status(Sw::INS_NOT_SUPPORTED),
            }
        }
    }

    fn command(ins: u8, p1: u8, data: &[u8], le: Option<u8>) -> Vec<u8, 64> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, ins, p1, 0x00]).unwrap();
        if !data.is_empty() {
            frame.push(data.len() as u8).unwrap();
            frame.extend_from_slice(data).unwrap();
        }
        if let Some(le) = le {
            frame.push(le).unwrap();
        }
        frame
    }

    #[test]
    fn selects_a_known_aid() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        let response = router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        assert_eq!(response.sw, Sw::OK);
        assert_eq!(router.selected_aid(), Some(aid::PIV));
        assert_eq!(applet.selections, 1);
    }

    #[test]
    fn rejects_an_unknown_aid() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        let response = router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, b"\xA0\x00", None),
            &mut TestRng,
        );
        assert_eq!(response.sw, Sw::FILE_NOT_FOUND);
        assert_eq!(router.selected_aid(), None);
    }

    #[test]
    fn selects_profile_specific_aids_by_prefix() {
        let mut applet = TestApplet::new(aid::OPENPGP);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        let full = [
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let response = router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, &full, None),
            &mut TestRng,
        );
        assert_eq!(response.sw, Sw::OK);
        assert_eq!(router.selected_aid(), Some(aid::OPENPGP));
    }

    #[test]
    fn rejects_select_with_incorrect_p1() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        let response = router.command(&command(INS_SELECT, 0x00, aid::PIV, None), &mut TestRng);
        assert_eq!(response.sw, Sw::INCORRECT_PARAMETERS);
        assert_eq!(router.selected_aid(), None);
    }

    #[test]
    fn requires_a_selection_before_commands() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        let response = router.command(&command(0x01, 0x00, &[], None), &mut TestRng);
        assert_eq!(response.sw, Sw::CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn dispatches_to_the_selected_applet() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let response = router.command(&command(0x01, 0x00, &[], None), &mut TestRng);
        assert_eq!(response.data, &[0x01]);
        assert_eq!(response.sw, Sw::OK);
    }

    #[test]
    fn reports_unsupported_instructions() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let response = router.command(&command(0xFF, 0x00, &[], None), &mut TestRng);
        assert_eq!(response.sw, Sw::INS_NOT_SUPPORTED);
    }

    #[test]
    fn rejects_proprietary_class_bytes() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        let frame = [0x80, 0x01, 0x00, 0x00];
        let response = router.command(&frame, &mut TestRng);
        assert_eq!(response.sw, Sw::CLA_NOT_SUPPORTED);
    }

    #[test]
    fn rejects_malformed_apdus() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        assert_eq!(
            router.command(&[0x00, 0x01], &mut TestRng).sw,
            Sw::WRONG_LENGTH
        );
    }

    #[test]
    fn chains_responses_larger_than_le() {
        let mut applet = TestApplet::new(aid::PIV);
        applet.payload.extend_from_slice(&[0xAB; 300]).unwrap();
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<512>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let first = router.command(&command(0x02, 0x00, &[], Some(0x00)), &mut TestRng);
        assert_eq!(first.data.len(), 256);
        assert_eq!(first.sw, Sw::bytes_remaining(44));

        let second = router.command(
            &command(INS_GET_RESPONSE, 0x00, &[], Some(0x00)),
            &mut TestRng,
        );
        assert_eq!(second.data.len(), 44);
        assert_eq!(second.sw, Sw::OK);
        assert_eq!(second.data, &[0xAB; 44]);
    }

    #[test]
    fn send_remaining_without_pending_is_forwarded_to_applet() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        // No chained bytes pending: 0xA5 must reach the applet (OpenPGP
        // SELECT DATA) instead of being swallowed as SEND REMAINING.
        // TestApplet rejects it, proving it was forwarded.
        let response = router.command(&command(INS_SEND_REMAINING, 0x00, &[], None), &mut TestRng);
        assert_eq!(response.sw, Sw::INS_NOT_SUPPORTED);
    }

    #[test]
    fn send_remaining_with_pending_drains_chain() {
        let mut applet = TestApplet::new(aid::PIV);
        applet.payload.extend_from_slice(&[0xAB; 300]).unwrap();
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<512>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let first = router.command(&command(0x02, 0x00, &[], Some(0x00)), &mut TestRng);
        assert!(first.sw.is_bytes_remaining());

        let second = router.command(
            &command(INS_SEND_REMAINING, 0x00, &[], Some(0x00)),
            &mut TestRng,
        );
        assert_eq!(second.sw, Sw::OK);
        assert_eq!(second.data, &[0xAB; 44]);
    }

    #[test]
    fn send_remaining_is_forwarded_after_pending_chain_is_drained() {
        let mut applet = TestApplet::new(aid::PIV);
        applet.payload.extend_from_slice(&[0xAB; 300]).unwrap();
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<512>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let first = router.command(&command(0x02, 0x00, &[], Some(0x00)), &mut TestRng);
        assert!(first.sw.is_bytes_remaining());

        let final_chunk = router.command(
            &command(INS_SEND_REMAINING, 0x00, &[], Some(0x00)),
            &mut TestRng,
        );
        assert_eq!(final_chunk.sw, Sw::OK);
        assert_eq!(final_chunk.data, &[0xAB; 44]);

        // Once the chain is empty, the same instruction belongs to the
        // selected applet again rather than the transport chainer.
        let forwarded = router.command(&command(INS_SEND_REMAINING, 0x00, &[], None), &mut TestRng);
        assert_eq!(forwarded.sw, Sw::INS_NOT_SUPPORTED);
    }

    #[test]
    fn send_remaining_without_pending_still_requires_a_selected_applet() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        let response = router.command(&command(INS_SEND_REMAINING, 0x00, &[], None), &mut TestRng);
        assert_eq!(response.sw, Sw::CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn get_response_without_pending_is_rejected() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<64>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let response = router.command(
            &command(INS_GET_RESPONSE, 0x00, &[], Some(0x00)),
            &mut TestRng,
        );
        assert_eq!(response.sw, Sw::CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn selecting_again_clears_pending_bytes() {
        let mut applet = TestApplet::new(aid::PIV);
        applet.payload.extend_from_slice(&[0xCD; 300]).unwrap();
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<512>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let first = router.command(&command(0x02, 0x00, &[], Some(0x00)), &mut TestRng);
        assert!(first.sw.is_bytes_remaining());

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let response = router.command(
            &command(INS_GET_RESPONSE, 0x00, &[], Some(0x00)),
            &mut TestRng,
        );
        assert_eq!(response.sw, Sw::CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn reset_drops_selection_and_chaining() {
        let mut applet = TestApplet::new(aid::PIV);
        applet.payload.extend_from_slice(&[0x11; 300]).unwrap();
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<512>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        router.command(&command(0x02, 0x00, &[], Some(0x00)), &mut TestRng);
        router.reset();
        assert!(!router.is_selected());
        assert_eq!(
            router
                .command(
                    &command(INS_GET_RESPONSE, 0x00, &[], Some(0x00)),
                    &mut TestRng
                )
                .sw,
            Sw::CONDITIONS_NOT_SATISFIED
        );
    }

    #[test]
    fn failed_responses_are_not_chained() {
        let mut applet = TestApplet::new(aid::PIV);
        let mut applets: [&mut dyn Applet; 1] = [&mut applet];
        let mut router = Router::<512>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        let response = router.command(&command(0xFF, 0x00, &[], Some(0x00)), &mut TestRng);
        assert_eq!(response.sw, Sw::INS_NOT_SUPPORTED);
        assert_eq!(
            router
                .command(
                    &command(INS_GET_RESPONSE, 0x00, &[], Some(0x00)),
                    &mut TestRng
                )
                .sw,
            Sw::CONDITIONS_NOT_SATISFIED
        );
    }

    #[test]
    fn routes_between_multiple_applets() {
        let mut piv = TestApplet::new(aid::PIV);
        let mut oath = TestApplet::new(aid::OATH);
        let mut applets: [&mut dyn Applet; 2] = [&mut piv, &mut oath];
        let mut router = Router::<64>::new(&mut applets);

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::OATH, None),
            &mut TestRng,
        );
        assert_eq!(router.selected_aid(), Some(aid::OATH));
        assert_eq!(
            router
                .command(&command(0x01, 0x00, &[], None), &mut TestRng)
                .data,
            &[0x01]
        );

        router.command(
            &command(INS_SELECT, SELECT_BY_DF_NAME, aid::PIV, None),
            &mut TestRng,
        );
        assert_eq!(router.selected_aid(), Some(aid::PIV));
        assert_eq!(oath.selections, 1);
        assert_eq!(piv.selections, 1);
    }
}
