//! RSA-2048 primitives for the PIV and OpenPGP applets (roadmap Phase 16a).
//!
//! Fixed-size RSA over [`crypto_bigint`] (`U1024`/`U2048`) with PKCS#1 v1.5
//! message encoding (RFC 8017 §8–§9): EMSA-PKCS1-v1_5 signing with SHA-256
//! and type-2 decryption. Private operations use CRT (Garner) with
//! multiplicative blinding and re-verify signatures before returning them
//! (fault-injection guard).
//!
//! The module is `no_std` and `no_alloc`: every integer has a compile-time
//! size and every output is a caller-provided array. Secrets are plain byte
//! arrays; call [`Rsa2048PrivateKey::clear`] when they are no longer needed.
//!
//! Security notes (accepted limitations of this slice):
//!
//! - Primality is Miller-Rabin with [`MILLER_RABIN_ROUNDS`] random bases
//!   after trial division, not a FIPS 186-5 certified generator. Error
//!   probability for random candidates is negligible; generations that fail
//!   any check are retried.
//! - Montgomery setup (`FixedMontyParams::new`) runs over secret moduli
//!   during CRT. Blinding protects the exponent; setup timing is a residual
//!   side channel, as is the single-pass (non-constant-time-index) PKCS#1
//!   unpad scan. All applet failures collapse to one status word.
//! - On-device key generation takes on the order of seconds on the RP2350.
//!   Callers must feed the watchdog between attempts (firmware concern,
//!   handled when the applets are wired in Phase 16b/16c).

use crypto_bigint::{
    NonZero, Odd, U1024, U2048,
    modular::{FixedMontyForm, FixedMontyParams},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use aegis_core::authenticator::Rng;

/// Modulus size of the supported RSA keys, in bytes.
pub const RSA2048_BYTES: usize = 256;
/// Prime factor size of the supported RSA keys, in bytes.
pub const RSA1024_BYTES: usize = 128;
/// Public exponent used by on-device key generation.
pub const RSA_PUBLIC_EXPONENT: u32 = 65537;
/// Miller-Rabin rounds per prime candidate (random bases from the caller RNG).
pub const MILLER_RABIN_ROUNDS: usize = 12;
/// Prime candidates examined before giving up on one prime.
const PRIME_CANDIDATE_ATTEMPTS: usize = 4096;
/// Full key generations attempted before giving up.
const KEYGEN_ATTEMPTS: usize = 16;

/// DER `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2, note 1).
const SHA256_DER_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Small primes for trial division before Miller-Rabin (all primes ≤ 251;
/// candidates are odd by construction, so 2 is not listed).
const SMALL_PRIMES: [u16; 53] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// Serialized [`Rsa2048PrivateKey`] size: `n` (256) + `d` (256) +
/// `p`/`q`/`dp`/`dq`/`qinv` (5 × 128) + `e` as big-endian `u32` (4).
pub const RSA_BLOB_BYTES: usize = 256 + 256 + 5 * 128 + 4;

/// RSA-2048 public key (big-endian modulus, integer exponent).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsa2048PublicKey {
    /// Modulus `n`, big-endian.
    pub n: [u8; RSA2048_BYTES],
    /// Public exponent `e` (65537 for on-device keys).
    pub e: u32,
}

/// RSA-2048 private key with CRT parameters (all big-endian).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rsa2048PrivateKey {
    /// Modulus `n`.
    pub n: [u8; RSA2048_BYTES],
    /// Public exponent `e`.
    pub e: u32,
    /// Private exponent `d`.
    pub d: [u8; RSA2048_BYTES],
    /// Prime factor `p`.
    pub p: [u8; RSA1024_BYTES],
    /// Prime factor `q`.
    pub q: [u8; RSA1024_BYTES],
    /// `d mod (p - 1)`.
    pub dp: [u8; RSA1024_BYTES],
    /// `d mod (q - 1)`.
    pub dq: [u8; RSA1024_BYTES],
    /// `q^-1 mod p`.
    pub qinv: [u8; RSA1024_BYTES],
}

impl Rsa2048PrivateKey {
    /// Split off the public half of this key.
    pub fn public(&self) -> Rsa2048PublicKey {
        Rsa2048PublicKey {
            n: self.n,
            e: self.e,
        }
    }

    /// Overwrite every secret and public component of this key.
    pub fn clear(&mut self) {
        self.n.zeroize();
        self.e = 0;
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }

    /// Serialize into the fixed [`RSA_BLOB_BYTES`] layout applets persist:
    /// `n || d || p || q || dp || dq || qinv || e_be`.
    pub fn to_blob(&self, out: &mut [u8; RSA_BLOB_BYTES]) {
        out[0..256].copy_from_slice(&self.n);
        out[256..512].copy_from_slice(&self.d);
        out[512..640].copy_from_slice(&self.p);
        out[640..768].copy_from_slice(&self.q);
        out[768..896].copy_from_slice(&self.dp);
        out[896..1024].copy_from_slice(&self.dq);
        out[1024..1152].copy_from_slice(&self.qinv);
        out[1152..1156].copy_from_slice(&self.e.to_be_bytes());
    }

    /// Parse a blob written by [`Self::to_blob`]; `None` on any length or
    /// value mismatch (even modulus, zero factor, trivial exponent).
    pub fn from_blob(blob: &[u8]) -> Option<Self> {
        if blob.len() != RSA_BLOB_BYTES {
            return None;
        }
        let mut n = [0u8; RSA2048_BYTES];
        let mut d = [0u8; RSA2048_BYTES];
        n.copy_from_slice(&blob[0..256]);
        d.copy_from_slice(&blob[256..512]);
        let mut p = [0u8; RSA1024_BYTES];
        let mut q = [0u8; RSA1024_BYTES];
        let mut dp = [0u8; RSA1024_BYTES];
        let mut dq = [0u8; RSA1024_BYTES];
        let mut qinv = [0u8; RSA1024_BYTES];
        p.copy_from_slice(&blob[512..640]);
        q.copy_from_slice(&blob[640..768]);
        dp.copy_from_slice(&blob[768..896]);
        dq.copy_from_slice(&blob[896..1024]);
        qinv.copy_from_slice(&blob[1024..1152]);
        let e = u32::from_be_bytes([blob[1152], blob[1153], blob[1154], blob[1155]]);
        if e < 3 || e & 1 == 0 {
            return None;
        }
        Odd::new(U2048::from_be_slice(&n)).into_option()?;
        if p == [0u8; RSA1024_BYTES] || q == [0u8; RSA1024_BYTES] {
            return None;
        }
        Some(Self {
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qinv,
        })
    }
}

/// Generate an RSA-2048 key pair (`e` = 65537) from the caller RNG.
///
/// Returns `None` when the RNG keeps producing unusable candidates.
pub fn generate_key(rng: &mut dyn Rng) -> Option<Rsa2048PrivateKey> {
    let mut attempts = 0usize;
    while attempts < KEYGEN_ATTEMPTS {
        attempts += 1;
        let p_bytes = generate_prime(rng)?;
        let q_bytes = generate_prime(rng)?;
        if p_bytes == q_bytes {
            continue;
        }
        let p = U1024::from_be_slice(&p_bytes);
        let q = U1024::from_be_slice(&q_bytes);
        let p_wide: U2048 = p.resize();
        let q_wide: U2048 = q.resize();
        let n = p_wide.wrapping_mul(&q_wide);
        if n.bits() != 2048 {
            continue;
        }
        let p_minus_1 = p.wrapping_sub(&U1024::ONE);
        let q_minus_1 = q.wrapping_sub(&U1024::ONE);
        let e_small = U1024::from_u32(RSA_PUBLIC_EXPONENT);
        if e_small.gcd(&p_minus_1) != U1024::ONE || e_small.gcd(&q_minus_1) != U1024::ONE {
            continue;
        }
        let p1_wide: U2048 = p_minus_1.resize();
        let q1_wide: U2048 = q_minus_1.resize();
        let phi = p1_wide.wrapping_mul(&q1_wide);
        // Note: phi is even, so `d` needs the general inverter, not the
        // odd-modulus one.
        let phi_nz = NonZero::new(phi).into_option()?;
        let e = U2048::from_u32(RSA_PUBLIC_EXPONENT);
        let d = e.invert_mod(&phi_nz).into_option()?;
        let nz_p1w = NonZero::new(p1_wide).into_option()?;
        let nz_q1w = NonZero::new(q1_wide).into_option()?;
        let dp_wide = d.rem(&nz_p1w);
        let dq_wide = d.rem(&nz_q1w);
        let dp: U1024 = dp_wide.resize();
        let dq: U1024 = dq_wide.resize();
        let p_odd = Odd::new(p).into_option()?;
        let qinv = q.invert_odd_mod(&p_odd).into_option()?;
        let _ = p_odd;

        let mut key = Rsa2048PrivateKey {
            n: [0u8; RSA2048_BYTES],
            e: RSA_PUBLIC_EXPONENT,
            d: [0u8; RSA2048_BYTES],
            p: [0u8; RSA1024_BYTES],
            q: [0u8; RSA1024_BYTES],
            dp: [0u8; RSA1024_BYTES],
            dq: [0u8; RSA1024_BYTES],
            qinv: [0u8; RSA1024_BYTES],
        };
        key.n.copy_from_slice(n.to_be_bytes().as_slice());
        key.d.copy_from_slice(d.to_be_bytes().as_slice());
        key.p.copy_from_slice(p_bytes.as_slice());
        key.q.copy_from_slice(q_bytes.as_slice());
        key.dp.copy_from_slice(dp.to_be_bytes().as_slice());
        key.dq.copy_from_slice(dq.to_be_bytes().as_slice());
        key.qinv.copy_from_slice(qinv.to_be_bytes().as_slice());
        return Some(key);
    }
    None
}

/// Sign `message` with EMSA-PKCS1-v1_5 (SHA-256) and write the 256-byte
/// signature to `sig`. Returns `false` without partial output on failure.
pub fn sign_pkcs1_v15_sha256(
    key: &Rsa2048PrivateKey,
    message: &[u8],
    rng: &mut dyn Rng,
    sig: &mut [u8; RSA2048_BYTES],
) -> bool {
    let digest = Sha256::digest(message);
    let mut em = [0u8; RSA2048_BYTES];
    if !emsa_pkcs1_v15_encode(&SHA256_DER_PREFIX, &digest, &mut em) {
        return false;
    }
    let Some(mut s) = apply_private(key, &em, rng) else {
        return false;
    };
    // Fault-injection guard: the signature must verify under the public key.
    if public_op(&key.n, key.e, &s) != Some(em) {
        s.zeroize();
        return false;
    }
    *sig = s;
    true
}

/// Verify an EMSA-PKCS1-v1_5 (SHA-256) signature.
pub fn verify_pkcs1_v15_sha256(
    pubkey: &Rsa2048PublicKey,
    message: &[u8],
    sig: &[u8; RSA2048_BYTES],
) -> bool {
    let digest = Sha256::digest(message);
    let mut em = [0u8; RSA2048_BYTES];
    if !emsa_pkcs1_v15_encode(&SHA256_DER_PREFIX, &digest, &mut em) {
        return false;
    }
    match public_op(&pubkey.n, pubkey.e, sig) {
        Some(m) => constant_time_eq(&m, &em),
        None => false,
    }
}

/// Apply the public operation `base^e mod n` (`e` must be odd and ≥ 3).
pub fn public_op(
    n_be: &[u8; RSA2048_BYTES],
    e: u32,
    base_be: &[u8; RSA2048_BYTES],
) -> Option<[u8; RSA2048_BYTES]> {
    if e < 3 || e & 1 == 0 {
        return None;
    }
    let n = U2048::from_be_slice(n_be);
    let n_odd = Odd::new(n).into_option()?;
    let base = U2048::from_be_slice(base_be);
    if base >= n {
        return None;
    }
    let exp = U2048::from_u32(e);
    let bits = 32 - e.leading_zeros();
    let params = FixedMontyParams::new(n_odd);
    let out = FixedMontyForm::new(&base, &params)
        .pow_bounded_exp(&exp, bits)
        .retrieve();
    let mut bytes = [0u8; RSA2048_BYTES];
    bytes.copy_from_slice(out.to_be_bytes().as_slice());
    Some(bytes)
}

/// Decrypt a PKCS#1 v1.5 type-2 block and copy the message into `out`,
/// returning its length. Returns `None` for any malformed block.
pub fn decrypt_pkcs1_v15(
    key: &Rsa2048PrivateKey,
    ciphertext: &[u8; RSA2048_BYTES],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Option<usize> {
    let mut m = apply_private(key, ciphertext, rng)?;
    let result = unpad_type2(&m, out);
    m.zeroize();
    result
}

/// Raw private operation `base^d mod n` with blinded CRT (Garner).
///
/// This is the primitive PIV `SIGN`/`AUTHENTICATE` and OpenPGP `PSO` build
/// on: the caller supplies the already-encoded block (EMSA or host-framed
/// challenge) and receives the raw modular exponentiation. Fresh blinding
/// comes from `rng` on every call.
pub fn apply_private(
    key: &Rsa2048PrivateKey,
    base_be: &[u8; RSA2048_BYTES],
    rng: &mut dyn Rng,
) -> Option<[u8; RSA2048_BYTES]> {
    if key.e < 3 || key.e & 1 == 0 {
        return None;
    }
    let n = U2048::from_be_slice(&key.n);
    let n_odd = Odd::new(n).into_option()?;
    let c = U2048::from_be_slice(base_be);
    if c >= n {
        return None;
    }
    let params_n = FixedMontyParams::new(n_odd);

    // Blinding: r uniform in [1, n) with gcd(r, n) == 1.
    let r = random_coprime(rng, &n)?;
    let e = U2048::from_u32(key.e);
    let e_bits = 32 - key.e.leading_zeros();
    let r_enc = FixedMontyForm::new(&r, &params_n)
        .pow_bounded_exp(&e, e_bits)
        .retrieve();
    let blinded = FixedMontyForm::new(&c, &params_n)
        .mul(&FixedMontyForm::new(&r_enc, &params_n))
        .retrieve();

    // CRT halves: m1 = blinded^dp mod p, m2 = blinded^dq mod q.
    let p = U1024::from_be_slice(&key.p);
    let q = U1024::from_be_slice(&key.q);
    let dp = U1024::from_be_slice(&key.dp);
    let dq = U1024::from_be_slice(&key.dq);
    let qinv = U1024::from_be_slice(&key.qinv);
    let p_odd = Odd::new(p).into_option()?;
    let q_odd = Odd::new(q).into_option()?;
    let params_p = FixedMontyParams::new(p_odd);
    let params_q = FixedMontyParams::new(q_odd);
    let p_wide: U2048 = p.resize();
    let q_wide: U2048 = q.resize();
    let nz_p_wide = NonZero::new(p_wide).into_option()?;
    let nz_q_wide = NonZero::new(q_wide).into_option()?;
    let blinded_p: U1024 = blinded.rem(&nz_p_wide).resize();
    let blinded_q: U1024 = blinded.rem(&nz_q_wide).resize();
    let m1 = FixedMontyForm::new(&blinded_p, &params_p)
        .pow(&dp)
        .retrieve();
    let m2 = FixedMontyForm::new(&blinded_q, &params_q)
        .pow(&dq)
        .retrieve();

    // Garner: h = qinv * (m1 - m2) mod p; m = m2 + h * q (< p*q = n).
    let p_nz = p_odd.as_nz_ref();
    let diff = m1.sub_mod(&m2, p_nz);
    let h = diff.mul_mod(&qinv, p_nz);
    let h_wide: U2048 = h.resize();
    let m2_wide: U2048 = m2.resize();
    let m_blinded = m2_wide.wrapping_add(&h_wide.wrapping_mul(&q_wide));

    // Unblind: m = m_blinded * r^-1 mod n.
    let r_inv = r.invert_odd_mod(&n_odd).into_option()?;
    let m = FixedMontyForm::new(&m_blinded, &params_n)
        .mul(&FixedMontyForm::new(&r_inv, &params_n))
        .retrieve();
    let mut out = [0u8; RSA2048_BYTES];
    out.copy_from_slice(m.to_be_bytes().as_slice());
    Some(out)
}

/// Raw modular exponentiation `base^exp mod modulus` (generic width).
#[cfg(test)]
fn modpow<const LIMBS: usize>(
    base: &crypto_bigint::Uint<LIMBS>,
    exp: &crypto_bigint::Uint<LIMBS>,
    modulus: &Odd<crypto_bigint::Uint<LIMBS>>,
) -> crypto_bigint::Uint<LIMBS> {
    let params = FixedMontyParams::new(*modulus);
    FixedMontyForm::new(base, &params).pow(exp).retrieve()
}

/// EMSA-PKCS1-v1_5-encode a DER `DigestInfo` (RFC 8017 §9.2).
///
/// Validates the `SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING hash }`
/// structure with exact length fit, then wraps the whole `DigestInfo` as
/// `00 || 01 || PS || 00 || T`. This is the input shape GnuPG uses for
/// OpenPGP-card RSA signatures; hosts that already frame the full encoded
/// block call [`apply_private`] directly instead.
pub fn emsa_encode_digestinfo(info: &[u8]) -> Option<[u8; RSA2048_BYTES]> {
    if !is_digestinfo(info) {
        return None;
    }
    let mut em = [0u8; RSA2048_BYTES];
    if !emsa_pkcs1_v15_encode(&[], info, &mut em) {
        return None;
    }
    Some(em)
}

/// Check `SEQUENCE { SEQUENCE { OID, NULL 05 00 }, OCTET STRING }` with the
/// lengths fitting `info` exactly (short, `81` and `82` length forms).
fn is_digestinfo(info: &[u8]) -> bool {
    let Some((outer, _)) = read_tlv_header(info, 0) else {
        return false;
    };
    if outer.tag != 0x30 || outer.end != info.len() {
        return false;
    }
    let Some((inner, _)) = read_tlv_header(info, outer.value) else {
        return false;
    };
    if inner.tag != 0x30 {
        return false;
    }
    // AlgorithmIdentifier: OID followed by NULL.
    let Some((oid, _)) = read_tlv_header(info, inner.value) else {
        return false;
    };
    if oid.tag != 0x06 || oid.len == 0 || oid.len > 16 {
        return false;
    }
    let mut cursor = oid.end;
    if info.get(cursor..cursor + 2) != Some(&[0x05, 0x00][..]) {
        return false;
    }
    cursor += 2;
    // The hash follows the inner AlgorithmIdentifier sequence directly.
    if cursor != inner.end {
        return false;
    }
    let Some((hash, _)) = read_tlv_header(info, cursor) else {
        return false;
    };
    if hash.tag != 0x04 || hash.len < 20 || hash.len > 64 {
        return false;
    }
    hash.end == outer.end
}

/// Minimal DER header view: tag, value offset/length and end offset.
struct TlvHeader {
    tag: u8,
    value: usize,
    len: usize,
    end: usize,
}

/// Parse one DER tag + definite length at `offset`.
fn read_tlv_header(bytes: &[u8], offset: usize) -> Option<(TlvHeader, usize)> {
    let tag = *bytes.get(offset)?;
    let first = *bytes.get(offset + 1)?;
    let (len, header_len) = if first < 0x80 {
        (usize::from(first), 2)
    } else if first == 0x81 {
        (usize::from(*bytes.get(offset + 2)?), 3)
    } else if first == 0x82 {
        let hi = *bytes.get(offset + 2)?;
        let lo = *bytes.get(offset + 3)?;
        (usize::from(u16::from_be_bytes([hi, lo])), 4)
    } else {
        return None;
    };
    let value = offset.checked_add(header_len)?;
    let end = value.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    Some((
        TlvHeader {
            tag,
            value,
            len,
            end,
        },
        end,
    ))
}
/// EMSA-PKCS1-v1_5 encoding: `00 || 01 || PS || 00 || prefix || hash`.
fn emsa_pkcs1_v15_encode(prefix: &[u8], hash: &[u8], em: &mut [u8; RSA2048_BYTES]) -> bool {
    let t_len = prefix.len() + hash.len();
    if t_len + 11 > RSA2048_BYTES {
        return false;
    }
    let ps_len = RSA2048_BYTES - t_len - 3;
    if ps_len < 8 {
        return false;
    }
    em[0] = 0x00;
    em[1] = 0x01;
    em[2..2 + ps_len].fill(0xFF);
    em[2 + ps_len] = 0x00;
    em[3 + ps_len..3 + ps_len + prefix.len()].copy_from_slice(prefix);
    em[3 + ps_len + prefix.len()..].copy_from_slice(hash);
    true
}

/// Remove PKCS#1 v1.5 type-2 padding in a single pass, copying the message
/// into `out`. Callers must map every failure to one error.
fn unpad_type2(em: &[u8; RSA2048_BYTES], out: &mut [u8]) -> Option<usize> {
    let mut ok = ct_eq(em[0], 0x00) & ct_eq(em[1], 0x02);
    let mut sep = 0usize;
    let mut found = 0u8;
    let mut i = 2usize;
    while i < RSA2048_BYTES {
        let is_zero = ct_eq(em[i], 0x00);
        let past_min = if i >= 2 + 8 { 1 } else { 0 };
        let not_found = found ^ 1;
        ok &= (is_zero & not_found & (past_min ^ 1)) ^ 1;
        let take = is_zero & not_found & past_min;
        if take == 1 {
            sep = i;
        }
        found |= take;
        i += 1;
    }
    ok &= found;
    if ok != 1 {
        return None;
    }
    let msg = &em[sep + 1..];
    if msg.len() > out.len() {
        return None;
    }
    out[..msg.len()].copy_from_slice(msg);
    Some(msg.len())
}

/// Branchless byte equality: 1 when equal, 0 otherwise.
fn ct_eq(a: u8, b: u8) -> u8 {
    let x = (a ^ b) as u16;
    ((x.wrapping_sub(1) >> 8) & 1) as u8
}

/// Compare two 256-byte slices without an early exit.
fn constant_time_eq(a: &[u8; RSA2048_BYTES], b: &[u8; RSA2048_BYTES]) -> bool {
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < RSA2048_BYTES {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    core::hint::black_box(diff) == 0
}

/// Sample `r` uniform in `[1, n)` with `gcd(r, n) == 1`.
fn random_coprime(rng: &mut dyn Rng, n: &U2048) -> Option<U2048> {
    let mut tries = 0usize;
    while tries < 64 {
        tries += 1;
        let mut bytes = [0u8; RSA2048_BYTES];
        rng.fill_bytes(&mut bytes);
        let r = U2048::from_be_slice(&bytes);
        if r == U2048::ZERO || r >= *n {
            continue;
        }
        if r.gcd(n) != U2048::ONE {
            continue;
        }
        return Some(r);
    }
    None
}

/// Generate one 1024-bit prime (top two bits set, odd) or `None`.
fn generate_prime(rng: &mut dyn Rng) -> Option<[u8; RSA1024_BYTES]> {
    let mut attempts = 0usize;
    while attempts < PRIME_CANDIDATE_ATTEMPTS {
        attempts += 1;
        let mut bytes = [0u8; RSA1024_BYTES];
        rng.fill_bytes(&mut bytes);
        bytes[0] |= 0xC0;
        bytes[RSA1024_BYTES - 1] |= 0x01;
        let candidate = U1024::from_be_slice(&bytes);
        if !trial_division_ok(&candidate)? {
            continue;
        }
        if is_probable_prime(&candidate, rng)? {
            return Some(bytes);
        }
    }
    None
}

/// Reject candidates divisible by a small prime (caller guarantees odd).
/// `None` only when a divisor fails to build, which cannot happen here but
/// keeps the call chain total without panics.
fn trial_division_ok(candidate: &U1024) -> Option<bool> {
    let mut i = 0usize;
    while i < SMALL_PRIMES.len() {
        let divisor = NonZero::new(U1024::from_u16(SMALL_PRIMES[i])).into_option()?;
        if candidate.rem(&divisor) == U1024::ZERO {
            return Some(false);
        }
        i += 1;
    }
    Some(true)
}

/// Miller-Rabin with random bases from `rng`: `None` on RNG exhaustion.
fn is_probable_prime(candidate: &U1024, rng: &mut dyn Rng) -> Option<bool> {
    let one = U1024::ONE;
    let c_minus_1 = candidate.wrapping_sub(&one);
    let s = c_minus_1.trailing_zeros();
    if s == 0 {
        return Some(false);
    }
    let d = c_minus_1.shr(s);
    let odd = Odd::new(*candidate).into_option()?;
    let c_nz = *odd.as_nz_ref();
    let params = FixedMontyParams::new(odd);
    let mut round = 0usize;
    while round < MILLER_RABIN_ROUNDS {
        let a = random_base(rng, candidate)?;
        let mut x = FixedMontyForm::new(&a, &params).pow(&d).retrieve();
        if x != one && x != c_minus_1 {
            let mut r = 1u32;
            let mut witness = true;
            while r < s {
                x = x.square_mod(&c_nz);
                if x == c_minus_1 {
                    witness = false;
                    break;
                }
                if x == one {
                    return Some(false);
                }
                r += 1;
            }
            if witness {
                return Some(false);
            }
        }
        round += 1;
    }
    Some(true)
}

/// Sample a Miller-Rabin base uniform in `[2, candidate)`.
fn random_base(rng: &mut dyn Rng, candidate: &U1024) -> Option<U1024> {
    let bits = candidate.bits();
    if !(3..=1024).contains(&bits) {
        return None;
    }
    let byte_len = bits.div_ceil(8) as usize;
    let excess = byte_len as u32 * 8 - bits;
    let two = U1024::from_u16(2);
    let mut tries = 0usize;
    while tries < 64 {
        tries += 1;
        let mut bytes = [0u8; RSA1024_BYTES];
        rng.fill_bytes(&mut bytes[RSA1024_BYTES - byte_len..]);
        bytes[RSA1024_BYTES - byte_len] &= 0xFF >> excess;
        let a = U1024::from_be_slice(&bytes);
        if a >= two && a < *candidate {
            return Some(a);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* RNG for tests (never on-device).
    struct TestRng(u64);

    impl TestRng {
        fn new(seed: u64) -> Self {
            Self(if seed == 0 {
                0x243F_6A88_85A3_08D3
            } else {
                seed
            })
        }
    }

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                self.0 ^= self.0 >> 12;
                self.0 ^= self.0 << 25;
                self.0 ^= self.0 >> 27;
                let v = self.0.wrapping_mul(0x2545_F491_4F6C_DD1D);
                chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
            }
        }
    }

    /// Pad a message the way a host encrypts to us (test helper only).
    fn pad_type2(message: &[u8], rng: &mut dyn Rng, em: &mut [u8; RSA2048_BYTES]) -> bool {
        if message.len() + 11 > RSA2048_BYTES {
            return false;
        }
        em[0] = 0x00;
        em[1] = 0x02;
        let ps_len = RSA2048_BYTES - message.len() - 3;
        let mut i = 0usize;
        while i < ps_len {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            if b[0] == 0x00 {
                continue;
            }
            em[2 + i] = b[0];
            i += 1;
        }
        em[2 + ps_len] = 0x00;
        em[3 + ps_len..].copy_from_slice(message);
        true
    }

    #[test]
    fn emsa_sha256_has_pkcs1_shape() {
        let digest = Sha256::digest(b"abc");
        let mut em = [0u8; RSA2048_BYTES];
        assert!(emsa_pkcs1_v15_encode(&SHA256_DER_PREFIX, &digest, &mut em));
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        let ps_len = RSA2048_BYTES - SHA256_DER_PREFIX.len() - digest.len() - 3;
        assert!(em[2..2 + ps_len].iter().all(|b| *b == 0xFF));
        assert_eq!(em[2 + ps_len], 0x00);
        assert_eq!(
            &em[3 + ps_len..3 + ps_len + SHA256_DER_PREFIX.len()],
            &SHA256_DER_PREFIX
        );
        assert_eq!(&em[3 + ps_len + SHA256_DER_PREFIX.len()..], &digest[..]);
    }

    #[test]
    fn trial_division_and_mr_on_small_values() {
        let mut rng = TestRng::new(3);
        // 257 is prime (and above the trial-division bound); 91 = 7 * 13
        // and 2047 = 23 * 89 are composite.
        assert_eq!(trial_division_ok(&U1024::from_u32(257)), Some(true));
        assert_eq!(trial_division_ok(&U1024::from_u32(91)), Some(false));
        assert_eq!(
            is_probable_prime(&U1024::from_u32(257), &mut rng),
            Some(true)
        );
        assert_eq!(
            is_probable_prime(&U1024::from_u32(91), &mut rng),
            Some(false)
        );
        assert_eq!(
            is_probable_prime(&U1024::from_u32(2047), &mut rng),
            Some(false)
        );
        assert_eq!(
            is_probable_prime(&U1024::from_u32(65537), &mut rng),
            Some(true)
        );
    }

    #[test]
    fn key_blob_round_trips() {
        let mut rng = TestRng::new(0xB10B_FEED);
        let key = generate_key(&mut rng).expect("keygen");
        let mut blob = [0u8; RSA_BLOB_BYTES];
        key.to_blob(&mut blob);
        let parsed = Rsa2048PrivateKey::from_blob(&blob).expect("parse");
        assert_eq!(parsed, key);
        assert!(Rsa2048PrivateKey::from_blob(&blob[..RSA_BLOB_BYTES - 1]).is_none());
        let mut bad = blob;
        bad[RSA_BLOB_BYTES - 1] = 0x04;
        assert!(Rsa2048PrivateKey::from_blob(&bad).is_none());
        let mut even_n = blob;
        even_n[RSA2048_BYTES - 1] &= 0xFE;
        assert!(Rsa2048PrivateKey::from_blob(&even_n).is_none());
    }

    #[test]
    fn digestinfo_encodes_and_malformed_inputs_reject() {
        // DigestInfo(SHA-256("abc")).
        let digest = Sha256::digest(b"abc");
        let mut full = [0u8; 51];
        full[..19].copy_from_slice(&SHA256_DER_PREFIX);
        full[19..].copy_from_slice(&digest);
        let em = emsa_encode_digestinfo(&full).expect("valid DigestInfo");
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        assert_eq!(&em[256 - full.len()..], &full);

        // Round trip through the raw operation.
        let mut rng = TestRng::new(0xD1_6357_17F0);
        let key = generate_key(&mut rng).expect("keygen");
        let sig = apply_private(&key, &em, &mut rng).expect("sign");
        assert_eq!(public_op(&key.n, key.e, &sig), Some(em));

        // Malformed inputs.
        assert!(emsa_encode_digestinfo(&[]).is_none());
        assert!(emsa_encode_digestinfo(&full[..50]).is_none());
        let mut bad_tag = full;
        bad_tag[0] = 0x31;
        assert!(emsa_encode_digestinfo(&bad_tag).is_none());
        let mut bad_null = full;
        bad_null[full.len() - 34] = 0x01;
        assert!(emsa_encode_digestinfo(&bad_null).is_none());
        // Trailing garbage breaks the exact fit.
        let mut trailed = [0u8; 52];
        trailed[..51].copy_from_slice(&full);
        assert!(emsa_encode_digestinfo(&trailed).is_none());
    }

    #[test]
    fn textbook_rsa_raw_round_trip() {
        // p = 61, q = 53, n = 3233, e = 17, d = 2753.
        let n = crypto_bigint::U64::from_u32(3233);
        let odd = Odd::new(n).into_option().expect("odd");
        let e = crypto_bigint::U64::from_u32(17);
        let d = crypto_bigint::U64::from_u32(2753);
        let m = crypto_bigint::U64::from_u32(65);
        let c = modpow(&m, &e, &odd);
        assert_eq!(c, crypto_bigint::U64::from_u32(2790));
        assert_eq!(modpow(&c, &d, &odd), m);
    }

    #[test]
    fn public_op_rejects_bad_inputs() {
        let n = [0xFFu8; RSA2048_BYTES];
        let base = [0x01u8; RSA2048_BYTES];
        assert!(public_op(&n, 2, &base).is_none());
        assert!(public_op(&n, 0, &base).is_none());
        let mut even_n = [0u8; RSA2048_BYTES];
        even_n[RSA2048_BYTES - 1] = 0x02;
        assert!(public_op(&even_n, 65537, &base).is_none());
        // base >= n is rejected.
        assert!(public_op(&n, 65537, &n).is_none());
    }

    #[test]
    fn unpad_rejects_malformed_blocks() {
        let mut rng = TestRng::new(7);
        let mut em = [0u8; RSA2048_BYTES];
        assert!(pad_type2(b"hello", &mut rng, &mut em));
        let mut out = [0u8; RSA2048_BYTES];
        assert_eq!(unpad_type2(&em, &mut out), Some(5));
        assert_eq!(&out[..5], b"hello");

        let mut bad = em;
        bad[1] = 0x01;
        assert_eq!(unpad_type2(&bad, &mut out), None);
        let mut bad = em;
        bad[0] = 0x01;
        assert_eq!(unpad_type2(&bad, &mut out), None);
        // Zero inside the first 8 pad bytes.
        let mut bad = em;
        bad[5] = 0x00;
        assert_eq!(unpad_type2(&bad, &mut out), None);
        // No zero separator at all.
        let mut bad = [0xFFu8; RSA2048_BYTES];
        bad[0] = 0x00;
        bad[1] = 0x02;
        assert_eq!(unpad_type2(&bad, &mut out), None);
        // Output too small.
        let mut tiny = [0u8; 2];
        assert_eq!(unpad_type2(&em, &mut tiny), None);
    }

    #[test]
    fn keygen_sign_verify_decrypt_round_trip() {
        let mut rng = TestRng::new(0xA35A_5ED0_16A0);
        let mut key = generate_key(&mut rng).expect("keygen");
        assert_eq!(key.e, RSA_PUBLIC_EXPONENT);
        let n = U2048::from_be_slice(&key.n);
        assert_eq!(n.bits(), 2048);

        // e*d = 1 mod phi(p, q).
        let p = U1024::from_be_slice(&key.p);
        let q = U1024::from_be_slice(&key.q);
        let p1w: U2048 = p.wrapping_sub(&U1024::ONE).resize();
        let q1w: U2048 = q.wrapping_sub(&U1024::ONE).resize();
        let phi = p1w.wrapping_mul(&q1w);
        let d = U2048::from_be_slice(&key.d);
        let ed = d.mul_mod(
            &U2048::from_u32(key.e),
            &NonZero::new(phi).into_option().expect("phi"),
        );
        assert_eq!(ed, U2048::ONE);

        // Sign / verify, including an empty message and a long one.
        for message in [b"".as_slice(), b"abc".as_slice(), [0x5Au8; 1024].as_slice()].iter() {
            let mut sig = [0u8; RSA2048_BYTES];
            assert!(sign_pkcs1_v15_sha256(&key, message, &mut rng, &mut sig));
            assert!(verify_pkcs1_v15_sha256(&key.public(), message, &sig));
            let mut tampered = sig;
            tampered[RSA2048_BYTES - 1] ^= 0x01;
            assert!(!verify_pkcs1_v15_sha256(&key.public(), message, &tampered));
            assert!(!verify_pkcs1_v15_sha256(&key.public(), b"other", &sig));
        }

        // Encrypt-to-self / decrypt round trip.
        let mut em = [0u8; RSA2048_BYTES];
        assert!(pad_type2(b"pin-1234", &mut rng, &mut em));
        let ct = public_op(&key.n, key.e, &em).expect("encrypt");
        let mut out = [0u8; RSA2048_BYTES];
        let len = decrypt_pkcs1_v15(&key, &ct, &mut rng, &mut out).expect("decrypt");
        assert_eq!(&out[..len], b"pin-1234");

        // Ciphertext >= n is rejected.
        assert!(decrypt_pkcs1_v15(&key, &key.n, &mut rng, &mut out).is_none());

        key.clear();
        assert!(key.d.iter().all(|b| *b == 0));
        assert!(key.p.iter().all(|b| *b == 0));
    }

    #[test]
    fn blinded_crt_matches_full_private_op() {
        let mut rng = TestRng::new(0xC0FF_EE11);
        let key = generate_key(&mut rng).expect("keygen");
        let n = U2048::from_be_slice(&key.n);
        let odd = Odd::new(n).into_option().expect("odd");
        let d = U2048::from_be_slice(&key.d);
        let mut base = [0u8; RSA2048_BYTES];
        TestRng::new(99).fill_bytes(&mut base);
        let mut base_u = U2048::from_be_slice(&base);
        if base_u >= n {
            let nz = NonZero::new(n).into_option().expect("nonzero modulus");
            base_u = base_u.rem(&nz);
        }
        let mut base_be = [0u8; RSA2048_BYTES];
        base_be.copy_from_slice(base_u.to_be_bytes().as_slice());
        let via_crt = apply_private(&key, &base_be, &mut rng).expect("crt");
        let expected = modpow(&base_u, &d, &odd);
        let mut expected_be = [0u8; RSA2048_BYTES];
        expected_be.copy_from_slice(expected.to_be_bytes().as_slice());
        assert_eq!(via_crt, expected_be);
    }

    #[test]
    fn signatures_are_deterministic_despite_blinding() {
        let mut rng = TestRng::new(0xB11D_ED42);
        let key = generate_key(&mut rng).expect("keygen");
        let mut first = [0u8; RSA2048_BYTES];
        let mut second = [0u8; RSA2048_BYTES];
        assert!(sign_pkcs1_v15_sha256(
            &key,
            b"same message",
            &mut TestRng::new(1),
            &mut first
        ));
        assert!(sign_pkcs1_v15_sha256(
            &key,
            b"same message",
            &mut TestRng::new(2),
            &mut second
        ));
        assert_eq!(first, second);
    }
}
