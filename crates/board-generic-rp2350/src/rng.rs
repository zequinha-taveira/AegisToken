//! Hardware randomness for credential key and id generation (PRD §15, §25).
//!
//! Wraps the RP2350 true random number generator so the authenticator core can
//! draw key material from a [`aegis_core::authenticator::Rng`].

use embassy_rp::Peri;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::TRNG;
use embassy_rp::trng::{Config, InterruptHandler, Trng};

bind_interrupts!(struct Irqs {
    TRNG_IRQ => InterruptHandler<TRNG>;
});

/// RP2350 true-random source.
pub struct HardwareRng {
    trng: Trng<'static, TRNG>,
}

impl HardwareRng {
    /// Initialize the TRNG.
    pub fn new(trng: Peri<'static, TRNG>) -> Self {
        Self {
            trng: Trng::new(trng, Irqs, Config::default()),
        }
    }
}

impl aegis_core::authenticator::Rng for HardwareRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.trng.blocking_fill_bytes(dest);
    }
}
