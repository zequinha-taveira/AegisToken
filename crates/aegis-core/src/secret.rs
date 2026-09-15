//! Sealed secret storage (PRD §25).
//!
//! Cryptographic material is sealed with AES-256-GCM under a device root key
//! that never leaves the chip. The root key is delivered by a
//! [`RootKeyProvider`] (on hardware, derived from OTP). There is no API that
//! exposes plaintext secrets outside the firmware.

use crate::error::CoreError;

/// Root key length, in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length, in bytes.
pub const NONCE_LEN: usize = 12;
/// Authentication tag length, in bytes.
pub const TAG_LEN: usize = 16;
/// Additional authenticated data binding seals to this product.
pub const AAD: &[u8] = b"aegistoken/secret/v1";

/// Supplies the device root key.
///
/// On real hardware this is derived from OTP; the key must never be persisted
/// to flash in the clear or exported.
pub trait RootKeyProvider {
    /// Return the 256-bit device root key.
    fn root_key(&mut self) -> Result<[u8; KEY_LEN], CoreError>;
}

/// AES-256-GCM sealer.
pub struct AesGcmSealer {
    cipher: aes_gcm::Aes256Gcm,
}

impl AesGcmSealer {
    /// Create a sealer from a root key.
    pub fn new(key: &[u8; KEY_LEN]) -> Result<Self, CoreError> {
        use aes_gcm::KeyInit;
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::CryptoError)?;
        Ok(Self { cipher })
    }

    /// Seal `plaintext` into `out`, returning the sealed length
    /// (`plaintext.len() + TAG_LEN`).
    ///
    /// `out` must be at least `plaintext.len() + TAG_LEN` bytes.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CoreError> {
        use aes_gcm::aead::AeadInOut;
        let sealed_len = plaintext.len() + TAG_LEN;
        if out.len() < sealed_len {
            return Err(CoreError::CryptoError);
        }
        out[..plaintext.len()].copy_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_inout_detached(
                &aes_gcm::Nonce::try_from(&nonce[..]).map_err(|_| CoreError::CryptoError)?,
                AAD,
                (&mut out[..plaintext.len()]).into(),
            )
            .map_err(|_| CoreError::CryptoError)?;
        out[plaintext.len()..sealed_len].copy_from_slice(&tag);
        Ok(sealed_len)
    }

    /// Open a sealed blob into `out`, returning the plaintext length.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        sealed: &[u8],
        out: &mut [u8],
    ) -> Result<usize, CoreError> {
        use aes_gcm::aead::AeadInOut;
        if sealed.len() < TAG_LEN {
            return Err(CoreError::CryptoError);
        }
        let plaintext_len = sealed.len() - TAG_LEN;
        if out.len() < plaintext_len {
            return Err(CoreError::CryptoError);
        }
        out[..plaintext_len].copy_from_slice(&sealed[..plaintext_len]);
        let tag =
            aes_gcm::Tag::try_from(&sealed[plaintext_len..]).map_err(|_| CoreError::CryptoError)?;
        self.cipher
            .decrypt_inout_detached(
                &aes_gcm::Nonce::try_from(&nonce[..]).map_err(|_| CoreError::CryptoError)?,
                AAD,
                (&mut out[..plaintext_len]).into(),
                &tag,
            )
            .map_err(|_| CoreError::CryptoError)?;
        Ok(plaintext_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x11; NONCE_LEN];

    #[test]
    fn seal_then_open_round_trips() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let plaintext = b"private key material";
        let mut sealed = [0u8; 64];
        let sealed_len = sealer.seal(&NONCE, plaintext, &mut sealed).unwrap();
        assert_eq!(sealed_len, plaintext.len() + TAG_LEN);
        assert_ne!(&sealed[..plaintext.len()], &plaintext[..]);

        let mut opened = [0u8; 64];
        let opened_len = sealer
            .open(&NONCE, &sealed[..sealed_len], &mut opened)
            .unwrap();
        assert_eq!(&opened[..opened_len], plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let mut sealed = [0u8; 32];
        let sealed_len = sealer.seal(&NONCE, b"secret", &mut sealed).unwrap();

        let other = AesGcmSealer::new(&[0x43; KEY_LEN]).unwrap();
        let mut opened = [0u8; 32];
        assert_eq!(
            other.open(&NONCE, &sealed[..sealed_len], &mut opened),
            Err(CoreError::CryptoError)
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let mut sealed = [0u8; 32];
        let sealed_len = sealer.seal(&NONCE, b"secret", &mut sealed).unwrap();
        sealed[0] ^= 0x01;
        let mut opened = [0u8; 32];
        assert_eq!(
            sealer.open(&NONCE, &sealed[..sealed_len], &mut opened),
            Err(CoreError::CryptoError)
        );
    }

    #[test]
    fn tampered_tag_fails() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let mut sealed = [0u8; 32];
        let sealed_len = sealer.seal(&NONCE, b"secret", &mut sealed).unwrap();
        let last = sealed_len - 1;
        sealed[last] ^= 0x80;
        let mut opened = [0u8; 32];
        assert_eq!(
            sealer.open(&NONCE, &sealed[..sealed_len], &mut opened),
            Err(CoreError::CryptoError)
        );
    }

    #[test]
    fn too_small_output_is_rejected() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let mut sealed = [0u8; 4];
        assert_eq!(
            sealer.seal(&NONCE, b"secret", &mut sealed),
            Err(CoreError::CryptoError)
        );
    }

    #[test]
    fn short_sealed_blob_is_rejected() {
        let sealer = AesGcmSealer::new(&KEY).unwrap();
        let mut opened = [0u8; 32];
        assert_eq!(
            sealer.open(&NONCE, &[0u8; 8], &mut opened),
            Err(CoreError::CryptoError)
        );
    }
}
