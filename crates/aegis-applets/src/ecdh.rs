//! Elliptic-curve Diffie-Hellman for the OpenPGP card (RFC 6637).
//!
//! The card never hands the shared secret to the host: it derives the key
//! encryption key itself (RFC 6637 Ã‚Â§7) and unwraps the session key that the
//! sender wrapped for it (RFC 3394). This module holds those primitives so
//! they can be tested on the host.

use heapless::Vec;
use sha2::{Digest, Sha256};

/// Length of the "Anonymous Sender    " field of the KDF parameters.
const ANONYMOUS_SENDER: &[u8; 20] = b"Anonymous Sender    ";

/// Maximum size of the KDF parameters.
const MAX_PARAM: usize = 64;

/// Maximum size of an unwrapped key.
const MAX_UNWRAPPED: usize = 64;

/// The NIST P-256 curve OID (RFC 6637 Ã‚Â§11), truncated as the RFC requires.
pub const CURVE_OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// The ECDH public key algorithm ID (RFC 6637 Ã‚Â§5).
pub const ALG_ECDH: u8 = 18;

/// The SHA-256 hash ID used with the KDF (RFC 4880 Ã‚Â§9.4).
pub const HASH_SHA256: u8 = 8;

/// The AES-128 key wrap algorithm ID (RFC 4880 Ã‚Â§9.2).
pub const KEK_AES128: u8 = 7;

/// The default initial value of the AES key wrap (RFC 3394 Ã‚Â§2.2.3.1).
const KEY_WRAP_IV: [u8; 8] = [0xA6; 8];

/// The KDF parameters of RFC 6637 Ã‚Â§8.
///
/// The layout is `len(curve_oid) || curve_oid || public_key_alg_ID ||
/// 0x03 || 0x01 || KDF_hash_ID || KEK_alg_ID || "Anonymous Sender    " ||
/// recipient_fingerprint`.
///
/// The one-octet size in front of the three KDF parameter octets counts
/// those three octets; the values 0 and 0xff are reserved by the RFC.
pub fn param(
    curve_oid: &[u8],
    alg_id: u8,
    kdf_hash_id: u8,
    kek_alg_id: u8,
    fingerprint: &[u8; 20],
) -> Option<Vec<u8, MAX_PARAM>> {
    if curve_oid.is_empty() || curve_oid.len() > 0xFE {
        return None;
    }
    let mut out: Vec<u8, MAX_PARAM> = Vec::new();
    out.push(curve_oid.len() as u8).ok()?;
    out.extend_from_slice(curve_oid).ok()?;
    out.push(alg_id).ok()?;
    out.push(0x03).ok()?;
    out.push(0x01).ok()?;
    out.push(kdf_hash_id).ok()?;
    out.push(kek_alg_id).ok()?;
    out.extend_from_slice(ANONYMOUS_SENDER).ok()?;
    out.extend_from_slice(fingerprint).ok()?;
    Some(out)
}

/// The key derivation function of RFC 6637 Ã‚Â§7.
///
/// It is the concatenation KDF of NIST SP 800-56A (alternative 1) with
/// SHA-256: `SHA-256(00 00 00 01 || ZB || Param)`, where `ZB` is the `x`
/// coordinate of the shared point. Longer outputs continue with the counter
/// in `00 00 00 02` and so on.
#[must_use]
pub fn kdf(param: &[u8], zb: &[u8], out_len: usize) -> Option<Vec<u8, 64>> {
    if out_len == 0 || out_len > 64 {
        return None;
    }
    let mut out: Vec<u8, 64> = Vec::new();
    let mut counter: u32 = 1;
    while out.len() < out_len {
        let mut digest = Sha256::new();
        digest.update(counter.to_be_bytes());
        digest.update(zb);
        digest.update(param);
        out.extend_from_slice(&digest.finalize()).ok()?;
        counter += 1;
    }
    out.truncate(out_len);
    Some(out)
}

/// Decrypt one block with the key-encryption key.
///
/// The key wrap works on single blocks; the cipher is used in CBC mode with a
/// zero IV, which is exactly one ECB decryption.
fn decrypt_block(kek: &[u8], block: &mut [u8; 16]) -> bool {
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockModeDecrypt, KeyIvInit};

    let iv: [u8; 16] = [0u8; 16];
    let result = match kek.len() {
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(kek, &iv)
            .ok()
            .map(|decryptor| decryptor.decrypt_padded::<NoPadding>(block.as_mut_slice())),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(kek, &iv)
            .ok()
            .map(|decryptor| decryptor.decrypt_padded::<NoPadding>(block.as_mut_slice())),
        32 => cbc::Decryptor::<aes::Aes256>::new_from_slices(kek, &iv)
            .ok()
            .map(|decryptor| decryptor.decrypt_padded::<NoPadding>(block.as_mut_slice())),
        _ => return false,
    };
    matches!(result, Some(Ok(_)))
}

/// Encrypt one block with the key-encryption key.
pub(crate) fn encrypt_block(kek: &[u8], block: &mut [u8; 16]) -> bool {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    let mut buf = aes::Block::from(*block);
    match kek.len() {
        16 => {
            let Ok(cipher) = aes::Aes128::new_from_slice(kek) else {
                return false;
            };
            cipher.encrypt_block(&mut buf);
        }
        24 => {
            let Ok(cipher) = aes::Aes192::new_from_slice(kek) else {
                return false;
            };
            cipher.encrypt_block(&mut buf);
        }
        32 => {
            let Ok(cipher) = aes::Aes256::new_from_slice(kek) else {
                return false;
            };
            cipher.encrypt_block(&mut buf);
        }
        _ => return false,
    }
    block.copy_from_slice(&buf);
    true
}

/// Wrap a key with the AES key wrap algorithm (RFC 3394).
///
/// This is the sender side: the card only unwraps. The function exists so the
/// tests can act as the sender of an OpenPGP message and so the wrapping can
/// be checked against the vectors of the RFC.
#[must_use]
pub fn aes_key_wrap(kek: &[u8], data: &[u8]) -> Option<Vec<u8, MAX_UNWRAPPED>> {
    if kek.len() != 16 && kek.len() != 24 && kek.len() != 32 {
        return None;
    }
    if data.len() < 16 || data.len() % 8 != 0 {
        return None;
    }
    let n = data.len() / 8;
    let mut a = KEY_WRAP_IV;
    let mut r: Vec<[u8; 8], 8> = Vec::new();
    for index in 0..n {
        let mut block = [0u8; 8];
        block.copy_from_slice(&data[8 * index..8 * (index + 1)]);
        r.push(block).ok()?;
    }

    for round in 0..6 {
        for index in 0..n {
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a);
            block[8..].copy_from_slice(&r[index]);
            if !encrypt_block(kek, &mut block) {
                return None;
            }
            a.copy_from_slice(&block[..8]);
            r[index].copy_from_slice(&block[8..]);
            // A = MSB(64, B) XOR t, with t = n * j + i.
            let mut t = (n * round + index + 1) as u32;
            for byte in a.iter_mut().rev() {
                *byte ^= (t & 0xff) as u8;
                t >>= 8;
            }
        }
    }

    let mut out: Vec<u8, MAX_UNWRAPPED> = Vec::new();
    out.extend_from_slice(&a).ok()?;
    for block in &r {
        out.extend_from_slice(block).ok()?;
    }
    Some(out)
}

/// Unwrap a key with the AES key wrap algorithm (RFC 3394).
///
/// The wrapped key is a multiple of eight octets; the last block carries the
/// integrity check value, and a wrong one is rejected without returning any
/// part of the key.
#[must_use]
pub fn aes_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Option<Vec<u8, MAX_UNWRAPPED>> {
    if wrapped.len() < 16 || wrapped.len() % 8 != 0 {
        return None;
    }
    // n is the number of 64-bit key data blocks; the wrapped key carries the
    // integrity check in one more block.
    let n = wrapped.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut r: Vec<[u8; 8], 8> = Vec::new();
    for index in 0..n {
        let mut block = [0u8; 8];
        block.copy_from_slice(&wrapped[8 * (index + 1)..8 * (index + 2)]);
        r.push(block).ok()?;
    }

    for round in (0..6).rev() {
        for index in (0..n).rev() {
            // B = AES-1(K, (A ^ t) | R[i]), with t = n * j + i: the counter
            // is XORed into A before the decryption (RFC 3394 Ã‚Â§2.2.2).
            let mut t = (n * round + index + 1) as u32;
            let mut a_xor = a;
            for byte in a_xor.iter_mut().rev() {
                *byte ^= (t & 0xff) as u8;
                t >>= 8;
            }
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&a_xor);
            block[8..].copy_from_slice(&r[index]);
            if !decrypt_block(kek, &mut block) {
                return None;
            }
            a.copy_from_slice(&block[..8]);
            r[index].copy_from_slice(&block[8..]);
        }
    }

    // Integrity check: the recovered A must be the default initial value.
    if a != KEY_WRAP_IV {
        return None;
    }

    let mut out: Vec<u8, MAX_UNWRAPPED> = Vec::new();
    for block in &r {
        out.extend_from_slice(block).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3394 Ã‚Â§4.1: 128 bits of key data with a 128-bit KEK.
    const RFC3394_128: (&[u8; 16], &[u8; 16], &[u8; 24]) = (
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ],
        &[
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ],
    );

    /// RFC 3394 Ã‚Â§4.2: 128 bits of key data with a 192-bit KEK.
    const RFC3394_192_KEK: (&[u8; 24], &[u8; 16], &[u8; 24]) = (
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ],
        &[
            0x96, 0x77, 0x8B, 0x25, 0xAE, 0x6C, 0xA4, 0x35, 0xF9, 0x2B, 0x5B, 0x97, 0xC0, 0x50,
            0xAE, 0xD2, 0x46, 0x8A, 0xB8, 0xA1, 0x7A, 0xD8, 0x4E, 0x5D,
        ],
    );
    /// RFC 3394 Ã‚Â§4.3: 128 bits of key data with a 256-bit KEK.
    const RFC3394_256_KEK: (&[u8; 32], &[u8; 16], &[u8; 24]) = (
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ],
        &[
            0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2, 0x63, 0xE9, 0x77, 0x79, 0x05, 0x81,
            0x8A, 0x2A, 0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7,
        ],
    );
    /// RFC 3394 Ã‚Â§4.4: 192 bits of key data with a 192-bit KEK.
    const RFC3394_192: (&[u8; 24], &[u8; 24], &[u8; 32]) = (
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ],
        &[
            0x03, 0x1D, 0x33, 0x26, 0x4E, 0x15, 0xD3, 0x32, 0x68, 0xF2, 0x4E, 0xC2, 0x60, 0x74,
            0x3E, 0xDC, 0xE1, 0xC6, 0xC7, 0xDD, 0xEE, 0x72, 0x5A, 0x93, 0x6B, 0xA8, 0x14, 0x91,
            0x5C, 0x67, 0x62, 0xD2,
        ],
    );

    #[test]
    fn unwraps_the_rfc3394_vectors() {
        let (kek, expected, wrapped) = RFC3394_128;
        assert_eq!(aes_key_unwrap(kek, wrapped).unwrap().as_slice(), expected);
        let (kek, expected, wrapped) = RFC3394_192_KEK;
        assert_eq!(aes_key_unwrap(kek, wrapped).unwrap().as_slice(), expected);
        let (kek, expected, wrapped) = RFC3394_256_KEK;
        assert_eq!(aes_key_unwrap(kek, wrapped).unwrap().as_slice(), expected);
        let (kek, expected, wrapped) = RFC3394_192;
        assert_eq!(aes_key_unwrap(kek, wrapped).unwrap().as_slice(), expected);
    }

    #[test]
    fn wraps_to_the_rfc3394_vectors() {
        // The sender side must produce the ciphertexts of the RFC.
        let (kek, data, wrapped) = RFC3394_128;
        assert_eq!(aes_key_wrap(kek, data).unwrap().as_slice(), wrapped);
        let (kek, data, wrapped) = RFC3394_192_KEK;
        assert_eq!(aes_key_wrap(kek, data).unwrap().as_slice(), wrapped);
        let (kek, data, wrapped) = RFC3394_256_KEK;
        assert_eq!(aes_key_wrap(kek, data).unwrap().as_slice(), wrapped);
        let (kek, data, wrapped) = RFC3394_192;
        assert_eq!(aes_key_wrap(kek, data).unwrap().as_slice(), wrapped);
    }

    #[test]
    fn rejects_a_tampered_wrapping() {
        let (kek, _, wrapped) = RFC3394_128;
        let mut tampered = *wrapped;
        tampered[0] ^= 0x01;
        assert!(aes_key_unwrap(kek, &tampered).is_none());

        // The integrity check lives in the last block.
        let mut tampered = *wrapped;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(aes_key_unwrap(kek, &tampered).is_none());
    }

    #[test]
    fn rejects_invalid_lengths() {
        let (kek, _, wrapped) = RFC3394_128;
        assert!(aes_key_unwrap(kek, &wrapped[..20]).is_none());
        assert!(aes_key_unwrap(kek, &[]).is_none());
        assert!(aes_key_unwrap(&[0u8; 15], wrapped).is_none());
    }

    #[test]
    fn the_kdf_matches_the_reference_value() {
        // Reference: SHA-256(00 00 00 01 || ZB || Param) with the parameters
        // of RFC 6637 Ã‚Â§8 for P-256, SHA-256 and AES-128, computed by an
        // independent implementation of the RFC text.
        let fingerprint = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04,
        ];
        let param = param(
            CURVE_OID_P256,
            ALG_ECDH,
            HASH_SHA256,
            KEK_AES128,
            &fingerprint,
        )
        .unwrap();
        assert_eq!(param.len(), 54);
        let zb = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00,
        ];
        let derived = kdf(&param, &zb, 32).unwrap();
        assert_eq!(
            derived.as_slice(),
            &[
                0xcf, 0x68, 0x63, 0xd8, 0x56, 0xb1, 0x44, 0xfc, 0xc6, 0x3b, 0x70, 0x49, 0x13, 0x61,
                0xbe, 0x41, 0x92, 0x5d, 0xfd, 0xd5, 0xb4, 0xa7, 0x01, 0xe9, 0xb6, 0xd1, 0x5b, 0xd2,
                0x3d, 0x6a, 0x1e, 0xa6
            ]
        );
    }

    #[test]
    fn the_parameters_follow_the_rfc_layout() {
        let fingerprint = [0x42u8; 20];
        let param = param(
            CURVE_OID_P256,
            ALG_ECDH,
            HASH_SHA256,
            KEK_AES128,
            &fingerprint,
        )
        .unwrap();
        assert_eq!(param[0], 8);
        assert_eq!(&param[1..9], CURVE_OID_P256);
        assert_eq!(param[9], ALG_ECDH);
        assert_eq!(&param[10..12], &[0x03, 0x01]);
        assert_eq!(param[12], HASH_SHA256);
        assert_eq!(param[13], KEK_AES128);
        assert_eq!(&param[14..34], ANONYMOUS_SENDER);
        assert_eq!(&param[34..54], &fingerprint);
    }
}
