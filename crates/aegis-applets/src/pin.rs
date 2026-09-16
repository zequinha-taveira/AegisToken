//! Shared PIN/retry framework for the applets.
//!
//! PIV, OpenPGP and OATH all authenticate with a PIN that is stored only as a
//! hash and that has a limited number of verification attempts. This module
//! owns that behaviour once: length policy, fail-closed retry counters
//! (`63Cx`, then `6983`), change and unblock, and a fixed-size encoding so the
//! state can be sealed and persisted by the storage layer.
//!
//! The framework never stores or returns the PIN itself; only a
//! [`PinHash`] exists after provisioning, and it is redacted from `Debug`.

use crate::apdu::Sw;
use sha2::{Digest, Sha256};

/// Length of a PIN hash in bytes (SHA-256).
pub const PIN_HASH_LEN: usize = 32;

/// Encoded size of a [`PinSlot`]: version, format, retries, flags, hash.
pub const PIN_STATE_LEN: usize = 4 + PIN_HASH_LEN;

/// On-flash encoding version of a [`PinSlot`].
pub const PIN_STATE_VERSION: u8 = 1;

/// Hash construction used by a PIN slot.
///
/// Only formats whose exact specification is implemented are listed; decoding
/// an unknown format fails closed, so adding a format is a deliberate version
/// bump rather than silent acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinHashFormat {
    /// `SHA-256(PIN)`.
    Sha256 = 1,
}

impl PinHashFormat {
    /// Stable code used in the persistent encoding.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Sha256 => 1,
        }
    }

    /// Parse a persistent encoding code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Sha256),
            _ => None,
        }
    }
}

/// Length and retry policy of a PIN slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinPolicy {
    /// Minimum accepted PIN length, in bytes.
    pub min_len: usize,
    /// Maximum accepted PIN length, in bytes.
    pub max_len: usize,
    /// Attempts granted when the PIN is set.
    pub max_attempts: u8,
    /// Hash construction used for this slot.
    pub format: PinHashFormat,
}

impl PinPolicy {
    /// Build a policy.
    #[must_use]
    pub const fn new(
        min_len: usize,
        max_len: usize,
        max_attempts: u8,
        format: PinHashFormat,
    ) -> Self {
        Self {
            min_len,
            max_len,
            max_attempts,
            format,
        }
    }
}

/// A PIN hash. The PIN itself is never retained.
#[derive(Clone)]
pub struct PinHash([u8; PIN_HASH_LEN]);

impl PinHash {
    /// Hash `pin` with `format`.
    #[must_use]
    pub fn of(pin: &[u8], format: PinHashFormat) -> Self {
        let digest = match format {
            PinHashFormat::Sha256 => Sha256::digest(pin),
        };
        let mut bytes = [0u8; PIN_HASH_LEN];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// Compare `pin` against this hash.
    #[must_use]
    pub fn verify(&self, pin: &[u8], format: PinHashFormat) -> bool {
        let candidate = Self::of(pin, format);
        constant_time_eq(&self.0, &candidate.0)
    }

    /// Raw hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PIN_HASH_LEN] {
        &self.0
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; PIN_HASH_LEN] = bytes.try_into().ok()?;
        Some(Self(bytes))
    }
}

impl PartialEq for PinHash {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for PinHash {}

impl core::fmt::Debug for PinHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PinHash([redacted])")
    }
}

/// Compare two byte slices without an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// One PIN slot with persistent retry tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinSlot {
    policy: PinPolicy,
    hash: Option<PinHash>,
    retries_remaining: u8,
}

impl PinSlot {
    /// Create an unset slot with full retries.
    #[must_use]
    pub const fn new(policy: PinPolicy) -> Self {
        Self {
            policy,
            hash: None,
            retries_remaining: policy.max_attempts,
        }
    }

    /// Policy this slot enforces.
    #[must_use]
    pub const fn policy(&self) -> PinPolicy {
        self.policy
    }

    /// Whether a PIN has been provisioned.
    #[must_use]
    pub const fn is_set(&self) -> bool {
        self.hash.is_some()
    }

    /// Whether all attempts are exhausted.
    #[must_use]
    pub const fn is_blocked(&self) -> bool {
        self.is_set() && self.retries_remaining == 0
    }

    /// Attempts left before the slot blocks.
    #[must_use]
    pub const fn retries_remaining(&self) -> u8 {
        self.retries_remaining
    }

    /// Install (or replace) the PIN without verifying the current one.
    ///
    /// Only provisioning paths that already authorized the change (commission
    /// defaults, a verified unblock) may call this.
    pub fn set(&mut self, pin: &[u8]) -> Result<(), Sw> {
        self.check_length(pin)?;
        self.hash = Some(PinHash::of(pin, self.policy.format));
        self.retries_remaining = self.policy.max_attempts;
        Ok(())
    }

    /// Change the PIN after verifying `current`.
    pub fn change(&mut self, current: &[u8], new: &[u8]) -> Result<(), Sw> {
        self.verify(current)?;
        self.set(new)
    }

    /// Verify a candidate PIN, decrementing the retry counter on failure.
    ///
    /// Failures report `63Cx` with the attempts left; once the counter reaches
    /// zero the slot reports `6983` on subsequent attempts until unblocked.
    pub fn verify(&mut self, pin: &[u8]) -> Result<(), Sw> {
        let Some(hash) = &self.hash else {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        };
        if self.retries_remaining == 0 {
            return Err(Sw::AUTHENTICATION_BLOCKED);
        }
        if hash.verify(pin, self.policy.format) {
            return Ok(());
        }
        self.retries_remaining -= 1;
        Err(Sw::retries_left(self.retries_remaining))
    }

    /// Unblock the slot with a new PIN, restoring the retry counter.
    ///
    /// The caller must have verified the unblocking authority (PUK, PW3 or the
    /// management key) first.
    pub fn unblock(&mut self, new: &[u8]) -> Result<(), Sw> {
        self.set(new)
    }

    /// Encode the slot state for sealed persistence.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Sw> {
        if out.len() < PIN_STATE_LEN {
            return Err(Sw::NO_PRECISE_DIAGNOSIS);
        }
        out[0] = PIN_STATE_VERSION;
        out[1] = self.policy.format.code();
        out[2] = self.retries_remaining;
        out[3] = u8::from(self.hash.is_some());
        let hash: &[u8; PIN_HASH_LEN] = match &self.hash {
            Some(hash) => hash.as_bytes(),
            None => &[0u8; PIN_HASH_LEN],
        };
        out[4..PIN_STATE_LEN].copy_from_slice(hash);
        Ok(PIN_STATE_LEN)
    }

    /// Decode a sealed slot state, rejecting tampered or unknown encodings.
    pub fn decode(policy: PinPolicy, buf: &[u8]) -> Result<Self, Sw> {
        if buf.len() != PIN_STATE_LEN {
            return Err(Sw::NO_PRECISE_DIAGNOSIS);
        }
        if buf[0] != PIN_STATE_VERSION {
            return Err(Sw::NO_PRECISE_DIAGNOSIS);
        }
        if PinHashFormat::from_code(buf[1]) != Some(policy.format) {
            return Err(Sw::NO_PRECISE_DIAGNOSIS);
        }
        let retries_remaining = buf[2];
        if retries_remaining > policy.max_attempts {
            return Err(Sw::NO_PRECISE_DIAGNOSIS);
        }
        let hash = if buf[3] & 0x01 != 0 {
            Some(PinHash::from_bytes(&buf[4..]).ok_or(Sw::NO_PRECISE_DIAGNOSIS)?)
        } else {
            None
        };
        Ok(Self {
            policy,
            hash,
            retries_remaining,
        })
    }

    fn check_length(&self, pin: &[u8]) -> Result<(), Sw> {
        if pin.len() < self.policy.min_len || pin.len() > self.policy.max_len {
            return Err(Sw::WRONG_LENGTH);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Sw;

    fn policy() -> PinPolicy {
        PinPolicy::new(6, 8, 3, PinHashFormat::Sha256)
    }

    #[test]
    fn hash_matches_a_known_sha256_vector() {
        let hash = PinHash::of(b"123456", PinHashFormat::Sha256);
        assert_eq!(
            hash.as_bytes(),
            &hex_literal::hex!("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92")
        );
        assert_eq!(
            hash.as_bytes(),
            PinHash::of(b"123456", PinHashFormat::Sha256).as_bytes()
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let hash = PinHash::of(b"secret", PinHashFormat::Sha256);
        let rendered = format!("{hash:?}");
        assert_eq!(rendered, "PinHash([redacted])");
    }

    #[test]
    fn verify_accepts_and_rejects() {
        let mut slot = PinSlot::new(policy());
        assert!(!slot.is_set());
        assert_eq!(slot.verify(b"123456"), Err(Sw::CONDITIONS_NOT_SATISFIED));
        slot.set(b"123456").unwrap();
        assert!(slot.is_set());
        assert_eq!(slot.verify(b"123456"), Ok(()));
        assert_eq!(slot.verify(b"123457"), Err(Sw::retries_left(2)));
        assert_eq!(slot.verify(b"123458"), Err(Sw::retries_left(1)));
        assert_eq!(slot.verify(b"123459"), Err(Sw::retries_left(0)));
        assert!(slot.is_blocked());
        assert_eq!(slot.verify(b"123456"), Err(Sw::AUTHENTICATION_BLOCKED));
    }

    #[test]
    fn a_successful_verify_does_not_reset_retries() {
        let mut slot = PinSlot::new(policy());
        slot.set(b"123456").unwrap();
        assert_eq!(slot.verify(b"wrong!"), Err(Sw::retries_left(2)));
        assert_eq!(slot.verify(b"123456"), Ok(()));
        assert_eq!(slot.retries_remaining(), 2);
    }

    #[test]
    fn set_validates_length() {
        let mut slot = PinSlot::new(policy());
        assert_eq!(slot.set(b"12345"), Err(Sw::WRONG_LENGTH));
        assert_eq!(slot.set(b"123456789"), Err(Sw::WRONG_LENGTH));
        assert!(slot.set(b"12345678").is_ok());
    }

    #[test]
    fn change_requires_the_current_pin() {
        let mut slot = PinSlot::new(policy());
        slot.set(b"123456").unwrap();
        assert_eq!(slot.change(b"000000", b"654321"), Err(Sw::retries_left(2)));
        assert_eq!(slot.change(b"123456", b"654321"), Ok(()));
        assert_eq!(slot.verify(b"654321"), Ok(()));
    }

    #[test]
    fn unblock_restores_retries_and_replaces_the_pin() {
        let mut slot = PinSlot::new(policy());
        slot.set(b"123456").unwrap();
        for _ in 0..3 {
            let _ = slot.verify(b"000000");
        }
        assert!(slot.is_blocked());
        slot.unblock(b"999999").unwrap();
        assert!(!slot.is_blocked());
        assert_eq!(slot.retries_remaining(), 3);
        assert_eq!(slot.verify(b"999999"), Ok(()));
        assert_eq!(slot.verify(b"123456"), Err(Sw::retries_left(2)));
    }

    #[test]
    fn encoding_round_trips() {
        let mut slot = PinSlot::new(policy());
        slot.set(b"123456").unwrap();
        let _ = slot.verify(b"000000");
        let mut buf = [0u8; PIN_STATE_LEN];
        assert_eq!(slot.encode(&mut buf), Ok(PIN_STATE_LEN));
        let mut decoded = PinSlot::decode(policy(), &buf).unwrap();
        assert_eq!(decoded, slot);
        assert_eq!(decoded.retries_remaining(), 2);
        assert!(decoded.verify(b"123456").is_ok());
    }

    #[test]
    fn encoding_round_trips_an_unset_slot() {
        let slot = PinSlot::new(policy());
        let mut buf = [0u8; PIN_STATE_LEN];
        slot.encode(&mut buf).unwrap();
        let decoded = PinSlot::decode(policy(), &buf).unwrap();
        assert!(!decoded.is_set());
        assert_eq!(decoded.retries_remaining(), 3);
    }

    #[test]
    fn decoding_rejects_tampered_state() {
        let mut slot = PinSlot::new(policy());
        slot.set(b"123456").unwrap();
        let mut buf = [0u8; PIN_STATE_LEN];
        slot.encode(&mut buf).unwrap();

        let mut wrong_version = buf;
        wrong_version[0] = 99;
        assert_eq!(
            PinSlot::decode(policy(), &wrong_version),
            Err(Sw::NO_PRECISE_DIAGNOSIS)
        );

        let mut wrong_format = buf;
        wrong_format[1] = 99;
        assert_eq!(
            PinSlot::decode(policy(), &wrong_format),
            Err(Sw::NO_PRECISE_DIAGNOSIS)
        );

        let mut too_many_retries = buf;
        too_many_retries[2] = 4;
        assert_eq!(
            PinSlot::decode(policy(), &too_many_retries),
            Err(Sw::NO_PRECISE_DIAGNOSIS)
        );

        assert_eq!(
            PinSlot::decode(policy(), &buf[..PIN_STATE_LEN - 1]),
            Err(Sw::NO_PRECISE_DIAGNOSIS)
        );
    }

    #[test]
    fn encoding_requires_room() {
        let slot = PinSlot::new(policy());
        let mut tiny = [0u8; PIN_STATE_LEN - 1];
        assert_eq!(slot.encode(&mut tiny), Err(Sw::NO_PRECISE_DIAGNOSIS));
    }
}
