//! The OpenPGP symmetric layer (RFC 4880 §13.9).
//!
//! A Sym. Encrypted Integrity Protected Data packet (tag 18) is the plaintext
//! prefix (BS+2 octets), the data, and the modification detection code packet,
//! encrypted with the OpenPGP variant of CFB. This module implements the
//! decryption side: the feedback register, the resynchronization after the
//! prefix, the quick check of the key and the verification of the
//! modification detection code.

use heapless::Vec;
use sha1::{Digest, Sha1};

/// The AES block size.
const BS: usize = 16;

/// The tag octet of the modification detection code packet (RFC 4880 §5.14).
const MDC_TAG: u8 = 0xD3;

/// The length octet of the modification detection code packet.
const MDC_LENGTH: u8 = 20;

/// The size of the SHA-1 hash of the modification detection code.
const MDC_SIZE: usize = 20;

/// The size of the modification detection code packet body.
const MDC_PACKET: usize = 2 + MDC_SIZE;

/// Maximum size of the decrypted data.
pub const MAX_DATA: usize = 4096;

/// The result of a decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    /// The plaintext, without the modification detection code packet.
    pub data: Vec<u8, MAX_DATA>,
    /// Whether the modification detection code matched.
    pub mdc_verified: bool,
}

/// Decrypt an OpenPGP CFB stream with AES.
///
/// The ciphertext is the encrypted body of a Sym. Encrypted Integrity
/// Protected Data packet: the prefix (BS+2 octets), the data and the
/// modification detection code packet. The decryption fails when the quick
/// check of the key does not hold, which means the session key is wrong.
pub fn decrypt_aes(session_key: &[u8], ciphertext: &[u8]) -> Option<Decrypted> {
    if session_key.len() != 16 && session_key.len() != 24 && session_key.len() != 32 {
        return None;
    }
    if ciphertext.len() < BS + 2 + MDC_PACKET {
        return None;
    }

    // The CFB chain of RFC 4880 section 13.9 starts with an all-zero feedback
    // register and runs over the whole ciphertext with the block boundaries of
    // the stream. The two octets of the prefix that repeat the two before them
    // are part of that stream: they are the quick check of the session key,
    // not a new chain.
    let mut fr = [0u8; BS];
    let mut plaintext: Vec<u8, MAX_DATA> = Vec::new();
    for block in ciphertext.chunks(BS) {
        let fre = encrypt_block(session_key, &fr)?;
        for (index, byte) in block.iter().enumerate() {
            plaintext.push(byte ^ fre[index]).ok()?;
        }
        fr = [0u8; BS];
        fr[..block.len()].copy_from_slice(block);
    }

    // The quick check: the last two octets of the prefix replicate the two
    // before them, which is a cheap check for a correct key.
    if plaintext[BS] != plaintext[BS - 2] || plaintext[BS + 1] != plaintext[BS - 1] {
        return None;
    }

    // The modification detection code packet is the last one: its tag and
    // length octets followed by the SHA-1 hash.
    let mdc_start = plaintext.len().checked_sub(MDC_PACKET)?;
    if plaintext[mdc_start] != MDC_TAG || plaintext[mdc_start + 1] != MDC_LENGTH {
        return None;
    }
    let mdc = &plaintext[mdc_start + 2..];
    let mut digest = Sha1::new();
    digest.update(&plaintext[..mdc_start + 2]);
    let expected = digest.finalize();
    let mdc_verified = mdc == expected.as_slice();

    let mut data = Vec::new();
    // The prefix is not part of the data; the modification detection code
    // packet is stripped as well.
    data.extend_from_slice(&plaintext[BS + 2..mdc_start]).ok()?;
    Some(Decrypted { data, mdc_verified })
}

/// Encrypt an OpenPGP CFB stream with AES.
///
/// This is the sender side of the procedure of RFC 4880 section 13.9. The card
/// never encrypts: the function exists so the tests can act as the sender and
/// so the implementation can be checked against an independent reference.
pub fn encrypt_aes(session_key: &[u8], plaintext: &[u8]) -> Option<Vec<u8, MAX_DATA>> {
    if session_key.len() != 16 && session_key.len() != 24 && session_key.len() != 32 {
        return None;
    }
    if plaintext.len() < BS + 2 {
        return None;
    }

    // The same chain as the decryption: an all-zero feedback register and the
    // block boundaries of the stream, with the two quick-check octets inside
    // the stream (RFC 4880 section 13.9).
    let mut out: Vec<u8, MAX_DATA> = Vec::new();
    let mut fr = [0u8; BS];
    for block in plaintext.chunks(BS) {
        let fre = encrypt_block(session_key, &fr)?;
        let start = out.len();
        for (index, byte) in block.iter().enumerate() {
            out.push(byte ^ fre[index]).ok()?;
        }
        fr = [0u8; BS];
        fr[..block.len()].copy_from_slice(&out[start..]);
    }
    Some(out)
}

/// Encrypt one block: the OpenPGP CFB keystream is the AES encryption of the
/// feedback register.
fn encrypt_block(key: &[u8], block: &[u8; BS]) -> Option<[u8; BS]> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    let mut buf = aes::Block::from(*block);
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).ok()?;
            cipher.encrypt_block(&mut buf);
        }
        24 => {
            let cipher = aes::Aes192::new_from_slice(key).ok()?;
            cipher.encrypt_block(&mut buf);
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).ok()?;
            cipher.encrypt_block(&mut buf);
        }
        _ => return None,
    }
    let mut out = [0u8; BS];
    out.copy_from_slice(&buf);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message encrypted by GnuPG for an ECDH P-256 key (RFC 6637) and the
    /// session key that GnuPG reported for it. The prefix, the literal data
    /// packet (written by GnuPG in the old packet format) and the modification
    /// detection code all come from GnuPG: this is the interoperability vector
    /// of the symmetric layer.
    ///
    /// `gpg --show-session-key --decrypt` printed the session key
    /// `9:0D5A98ADCDFCFB0B8A69AB354440849E828B4CDB592BE01CB30D910BE4F8FCF5`.
    const KEY: [u8; 32] = [
        0x0D, 0x5A, 0x98, 0xAD, 0xCD, 0xFC, 0xFB, 0x0B, 0x8A, 0x69, 0xAB, 0x35, 0x44, 0x40, 0x84,
        0x9E, 0x82, 0x8B, 0x4C, 0xDB, 0x59, 0x2B, 0xE0, 0x1C, 0xB3, 0x0D, 0x91, 0x0B, 0xE4, 0xF8,
        0xFC, 0xF5,
    ];

    /// The encrypted data packet of that message: the prefix, the literal data
    /// packet and the modification detection code, all encrypted.
    const CIPHERTEXT: [u8; 92] = [
        0x0B, 0x7E, 0x36, 0x99, 0x9F, 0xA6, 0x41, 0x14, 0x8C, 0x8D, 0x24, 0xAF, 0x02, 0xD2, 0x07,
        0x86, 0x1C, 0x96, 0x61, 0x53, 0xC5, 0xB4, 0xDE, 0x7A, 0x14, 0xED, 0x2C, 0x8F, 0x0F, 0x2F,
        0x4C, 0x39, 0xB1, 0xF7, 0x93, 0xAB, 0xB5, 0x59, 0x6F, 0xA4, 0x6A, 0xC4, 0x9C, 0xBE, 0xBD,
        0x84, 0x39, 0x13, 0xC9, 0x8D, 0x54, 0xDF, 0xA2, 0xD6, 0xB7, 0xDC, 0xFE, 0xB8, 0xD7, 0xB5,
        0x76, 0x09, 0x35, 0x61, 0xB8, 0x01, 0x98, 0xCA, 0x80, 0x94, 0xC4, 0x85, 0x47, 0xFD, 0xE7,
        0x40, 0x57, 0xBA, 0x3B, 0x4D, 0x70, 0x22, 0x22, 0x04, 0xDF, 0xC7, 0x9E, 0x81, 0xA0, 0x18,
        0xC4, 0x81,
    ];

    /// The plaintext of that message: the random prefix with the two repeated
    /// octets, the literal data packet (format, file name, date and data) and
    /// the modification detection code packet.
    const PLAINTEXT: [u8; 92] = [
        0x5D, 0xE0, 0xEB, 0x52, 0xD4, 0x72, 0xC5, 0x4B, 0x9C, 0xE3, 0x11, 0x96, 0x20, 0x4F, 0x1E,
        0x99, 0x1E, 0x99, 0xAC, 0x32, 0x62, 0x0B, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2E,
        0x74, 0x78, 0x74, 0x6A, 0xD9, 0x70, 0x7D, 0x41, 0x65, 0x67, 0x69, 0x73, 0x54, 0x6F, 0x6B,
        0x65, 0x6E, 0x20, 0x47, 0x6E, 0x75, 0x50, 0x47, 0x20, 0x69, 0x6E, 0x74, 0x65, 0x72, 0x6F,
        0x70, 0x65, 0x72, 0x61, 0x62, 0x69, 0x6C, 0x69, 0x74, 0x79, 0xD3, 0x14, 0xC5, 0x70, 0xA2,
        0x24, 0xB0, 0x62, 0x4E, 0xFD, 0x3C, 0xAD, 0xF3, 0x90, 0xDC, 0x84, 0x42, 0x5C, 0x91, 0x77,
        0x1E, 0x56,
    ];

    #[test]
    fn decrypts_a_message_encrypted_by_gnupg() {
        let decrypted = decrypt_aes(&KEY, &CIPHERTEXT).expect("decrypts");
        assert!(decrypted.mdc_verified, "the modification code of GnuPG");
        assert_eq!(
            decrypted.data.as_slice(),
            &PLAINTEXT[BS + 2..PLAINTEXT.len() - MDC_PACKET]
        );
    }

    #[test]
    fn encrypts_to_the_gnupg_ciphertext() {
        // The same message, encrypted again, must reproduce the ciphertext of
        // GnuPG octet by octet.
        let ciphertext = encrypt_aes(&KEY, &PLAINTEXT).expect("encrypts");
        assert_eq!(ciphertext.as_slice(), &CIPHERTEXT[..]);
    }

    #[test]
    fn a_wrong_key_fails_the_quick_check() {
        let mut key = KEY;
        key[0] ^= 0x01;
        assert!(decrypt_aes(&key, &CIPHERTEXT).is_none());
    }

    #[test]
    fn a_tampered_ciphertext_fails_the_modification_code() {
        let mut ciphertext = CIPHERTEXT;
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        let decrypted = decrypt_aes(&KEY, &ciphertext).expect("decrypts");
        assert!(!decrypted.mdc_verified);
    }

    #[test]
    fn rejects_short_or_invalid_inputs() {
        assert!(decrypt_aes(&KEY, &CIPHERTEXT[..10]).is_none());
        assert!(decrypt_aes(&[0u8; 15], &CIPHERTEXT).is_none());
    }
}
