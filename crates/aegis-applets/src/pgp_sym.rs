//! The OpenPGP symmetric layer (RFC 4880 Â§13.9).
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

/// The tag octet of the modification detection code packet (RFC 4880 Â§5.14).
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

    // The feedback register starts as the all-zero IV (RFC 4880 Â§13.9).
    let mut fr = [0u8; BS];
    let mut plaintext: Vec<u8, MAX_DATA> = Vec::new();

    // The first BS octets of the prefix.
    let fre = encrypt_block(session_key, &fr)?;
    for index in 0..BS {
        plaintext.push(ciphertext[index] ^ fre[index]).ok()?;
    }
    fr.copy_from_slice(&ciphertext[..BS]);

    // The two quick-check octets of the prefix.
    let fre = encrypt_block(session_key, &fr)?;
    for index in 0..2 {
        plaintext.push(ciphertext[BS + index] ^ fre[index]).ok()?;
    }

    // The quick check: the last two octets of the prefix replicate the two
    // before them, which is a cheap check for a correct key.
    if plaintext[BS] != plaintext[BS - 2] || plaintext[BS + 1] != plaintext[BS - 1] {
        return None;
    }

    // The resynchronization: the feedback register is loaded with the last BS
    // octets of the encrypted prefix.
    fr.copy_from_slice(&ciphertext[2..BS + 2]);

    // The remaining data, block by block.
    let rest = &ciphertext[BS + 2..];
    for block in rest.chunks(BS) {
        let fre = encrypt_block(session_key, &fr)?;
        for (index, byte) in block.iter().enumerate() {
            plaintext.push(byte ^ fre[index]).ok()?;
        }
        fr[..block.len()].copy_from_slice(block);
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
/// This is the sender side of the procedure of RFC 4880 Â§13.9, with the
/// resynchronization after the prefix. The card never encrypts: the function
/// exists so the tests can act as the sender and so the implementation can be
/// checked against the independent reference.
pub fn encrypt_aes(session_key: &[u8], plaintext: &[u8]) -> Option<Vec<u8, MAX_DATA>> {
    if session_key.len() != 16 && session_key.len() != 24 && session_key.len() != 32 {
        return None;
    }
    if plaintext.len() < BS + 2 {
        return None;
    }
    let mut out: Vec<u8, MAX_DATA> = Vec::new();
    let mut fr = [0u8; BS];

    // The first BS octets of the prefix.
    let fre = encrypt_block(session_key, &fr)?;
    for index in 0..BS {
        out.push(plaintext[index] ^ fre[index]).ok()?;
    }
    fr.copy_from_slice(&out[..BS]);

    // The two quick-check octets of the prefix.
    let fre = encrypt_block(session_key, &fr)?;
    for index in 0..2 {
        out.push(plaintext[BS + index] ^ fre[index]).ok()?;
    }

    // The resynchronization: the feedback register is loaded with the last BS
    // octets of the encrypted prefix.
    fr.copy_from_slice(&out[2..BS + 2]);

    // The remaining data, block by block.
    let rest = &plaintext[BS + 2..];
    for block in rest.chunks(BS) {
        let fre = encrypt_block(session_key, &fr)?;
        for (index, byte) in block.iter().enumerate() {
            out.push(byte ^ fre[index]).ok()?;
        }
        fr[..block.len()].copy_from_slice(&out[out.len() - block.len()..]);
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

    /// The session key of the reference vector.
    const KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F,
    ];

    /// The plaintext of the reference vector: prefix, data and the
    /// modification detection code packet.
    const PLAINTEXT: [u8; 91] = [
        0xA2, 0xEC, 0xC3, 0x30, 0x8A, 0x13, 0xD7, 0x85, 0x4F, 0xA9, 0xB6, 0xCE, 0xF3, 0xF5, 0xF3,
        0xF5, 0xF3, 0xF5, 0x41, 0x65, 0x67, 0x69, 0x73, 0x54, 0x6F, 0x6B, 0x65, 0x6E, 0x20, 0x4F,
        0x70, 0x65, 0x6E, 0x50, 0x47, 0x50, 0x20, 0x73, 0x79, 0x6D, 0x6D, 0x65, 0x74, 0x72, 0x69,
        0x63, 0x20, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x20, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6E,
        0x63, 0x65, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6F, 0x72, 0xD3, 0x14, 0xA5, 0xDD, 0xD0, 0xA5,
        0x4F, 0x62, 0x61, 0x99, 0x61, 0x86, 0x8C, 0xAE, 0x02, 0x55, 0x2B, 0x70, 0x2D, 0xCA, 0x6C,
        0xFF,
    ];

    /// The ciphertext of the reference vector, produced by the independent
    /// implementation in `tests/openpgp_sym_reference.py`.
    const CIPHERTEXT: [u8; 91] = [
        0x4F, 0x4F, 0xF3, 0xC9, 0x84, 0xFF, 0x06, 0xE9, 0x4F, 0x97, 0xE9, 0x7E, 0x68, 0x3A, 0x00,
        0xAD, 0x6B, 0x3C, 0xEE, 0x40, 0x83, 0x49, 0xB1, 0xF4, 0x04, 0xF0, 0x52, 0xD1, 0x20, 0xB7,
        0x79, 0x1E, 0x69, 0xF7, 0xD6, 0x1C, 0xC4, 0x4A, 0xA3, 0xC6, 0xF5, 0x51, 0x63, 0xB6, 0x9D,
        0x15, 0x0B, 0x7C, 0xC5, 0x5E, 0xBE, 0xF2, 0xC1, 0xB8, 0xCA, 0xBC, 0xEF, 0x27, 0x12, 0x5F,
        0xDB, 0x75, 0x6B, 0x1D, 0x47, 0x7B, 0xA0, 0x40, 0x93, 0x8E, 0xBB, 0x7C, 0x4F, 0x12, 0x4F,
        0x2F, 0x47, 0x9A, 0xEA, 0xE0, 0xFE, 0x7C, 0xFA, 0x81, 0x8B, 0x66, 0x5D, 0x1F, 0x78, 0x2A,
        0x72,
    ];

    #[test]
    fn decrypts_the_reference_vector() {
        let decrypted = decrypt_aes(&KEY, &CIPHERTEXT).expect("decrypts");
        assert!(decrypted.mdc_verified);
        assert_eq!(
            decrypted.data.as_slice(),
            &PLAINTEXT[BS + 2..PLAINTEXT.len() - MDC_PACKET]
        );
    }

    #[test]
    fn encrypts_to_the_reference_ciphertext() {
        // The same implementation, from the same RFC text, must produce the
        // ciphertext of the independent reference.
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
