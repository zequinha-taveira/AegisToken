//! Placeholder applets that answer `SELECT` and reject every other command.
//!
//! While the PIV, OpenPGP and OATH applets are implemented (roadmap phases
//! 12-14), the firmware registers a [`Placeholder`] per AID so the CCID
//! interface enumerates, selects applications and returns the standard
//! "instruction not supported" status for the rest.

use crate::apdu::{Apdu, Response, Sw};
use crate::router::Applet;
use aegis_core::authenticator::Rng;

/// An applet that handles selection only.
#[derive(Debug, Clone, Copy)]
pub struct Placeholder {
    aid: &'static [u8],
}

impl Placeholder {
    /// Create a placeholder for `aid`.
    #[must_use]
    pub const fn new(aid: &'static [u8]) -> Self {
        Self { aid }
    }
}

impl Applet for Placeholder {
    fn aid(&self) -> &'static [u8] {
        self.aid
    }

    fn process(&mut self, _apdu: &Apdu<'_>, _rng: &mut dyn Rng) -> Response<'_> {
        Response::status(Sw::INS_NOT_SUPPORTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng;

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
    }

    #[test]
    fn placeholder_selects_and_rejects_commands() {
        let mut applet = Placeholder::new(crate::aid::PIV);
        assert_eq!(applet.aid(), crate::aid::PIV);
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            applet.process(
                &Apdu::parse(&[0x00, 0xCB, 0x3F, 0xFF]).unwrap(),
                &mut TestRng
            ),
            Response::status(Sw::INS_NOT_SUPPORTED)
        );
    }
}
