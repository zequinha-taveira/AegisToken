//! OpenPGP Card v3.4 applet over ISO 7816-4.
//!
//! Portable, host-testable OpenPGP Card application: PW1/PW3 verification
//! and retry counters, the mandatory application data objects, on-card key
//! generation (P-256, Ed25519/X25519, RSA-2048), signatures, internal
//! authentication and decryption. Secure messaging and private-key import
//! are deliberately left for later phases (keys are generated on-card and
//! never leave it).

use aegis_core::authenticator::Rng;
use heapless::Vec;

use crate::apdu::{Apdu, Response, Sw};
use crate::ecdh;
use crate::pgp_sym;
use crate::pin::{PinHashFormat, PinPolicy, PinSlot};
use crate::router::Applet;
use crate::rsa;
use crate::tlv;

/// OpenPGP Card AID, including a stable v3.4/default-device suffix.
pub const AID: &[u8] = &[
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

pub const RECORD_PIN: u16 = 1;
pub const RECORD_PW3: u16 = 2;
pub const RECORD_STATE: u16 = 3;

const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
const INS_RESET_RETRY_COUNTER: u8 = 0x2C;
const INS_GET_DATA: u8 = 0xCA;
const INS_PUT_DATA: u8 = 0xDA;
const INS_PSO: u8 = 0x2A;
const INS_INTERNAL_AUTHENTICATE: u8 = 0x88;
const INS_GENERATE: u8 = 0x47;
const INS_GET_CHALLENGE: u8 = 0x84;
const INS_SELECT_DATA: u8 = 0xA5;
const INS_ACTIVATE_FILE: u8 = 0x44;

const TAG_AID: u32 = 0x4F;
const TAG_HISTORICAL: u32 = 0x5F52;
const TAG_APP_DATA: u32 = 0x6E;
const TAG_EXTENDED_LENGTH: u32 = 0x7F66;
const TAG_DISCRETIONARY: u32 = 0x73;
const TAG_EXTENDED_CAPS: u32 = 0xC0;
const TAG_ALGO_SIG: u32 = 0xC1;
const TAG_ALGO_DEC: u32 = 0xC2;
const TAG_ALGO_AUTH: u32 = 0xC3;
const TAG_PW_STATUS: u32 = 0xC4;
const TAG_FINGERPRINTS: u32 = 0xC5;
const TAG_FP_SIG: u32 = 0xC7;
const TAG_FP_DEC: u32 = 0xC8;
const TAG_FP_AUT: u32 = 0xC9;
const TAG_GENERATION_DATES: u32 = 0xCD;
const TAG_KEY_INFO: u32 = 0xDE;
const TAG_NAME: u32 = 0x5B;
const TAG_LANGUAGE: u32 = 0x5F2D;
const TAG_SEX: u32 = 0x5F35;
const TAG_URL: u32 = 0x5F50;
const TAG_CERTIFICATE: u32 = 0x7F21;
const TAG_SECURITY_TEMPLATE: u32 = 0x7A;
const TAG_SIGNATURE_COUNTER: u32 = 0x93;

const PW_POLICY: PinPolicy = PinPolicy::new(6, 127, 3, PinHashFormat::Sha256);
const MAX_CERTIFICATE: usize = 1152;
const MAX_NAME: usize = 39;
const MAX_URL: usize = 255;
const STATE_BYTES: usize = 8192;
const STATE_VERSION: u8 = 3;
/// State encoding with per-slot algorithms and 48-byte scalars (v2).
const STATE_VERSION_V2: u8 = 2;
/// State encoding before per-slot algorithms (all slots ECDSA/ECDH P-256).
const STATE_VERSION_V1: u8 = 1;

/// Key material bytes per slot: either an ECC/EdDSA scalar prefix or a
/// serialized [`rsa::Rsa2048PrivateKey`] blob.
const SLOT_MATERIAL_BYTES: usize = rsa::RSA_BLOB_BYTES;
/// Worst-case v3 state size: version + PINs + 3 RSA slots + DOs + certs.
const STATE_V3_MAX: usize = 1
    + 2 * crate::pin::PIN_STATE_LEN
    + 3 * (1 + 2 + 1 + SLOT_MATERIAL_BYTES)
    + (1 + MAX_NAME)
    + (1 + 8)
    + 1
    + (1 + MAX_URL)
    + 3 * (2 + MAX_CERTIFICATE)
    + 4;
const _: () = assert!(STATE_V3_MAX <= STATE_BYTES);

/// OpenPGP algorithm IDs (RFC 4880/6637).
const ALGO_RSA: u8 = 0x01;
const ALGO_ECDH: u8 = 0x12;
const ALGO_ECDSA: u8 = 0x13;
const ALGO_EDDSA: u8 = 0x16;
/// Truncated curve OIDs (without DER tag/length).
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_X25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// Persistent state abstraction for OpenPGP Card data.
pub trait OpenPgpStore {
    fn load(&mut self, out: &mut [u8]) -> Option<usize>;
    fn save(&mut self, data: &[u8]) -> bool;
    fn clear(&mut self) -> bool;
}

/// Volatile store used by tests and firmware until sealed-flash sharing is
/// implemented.
pub struct MemoryOpenPgpStore {
    data: [u8; STATE_BYTES],
    len: usize,
}

impl Default for MemoryOpenPgpStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryOpenPgpStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: [0; STATE_BYTES],
            len: 0,
        }
    }
}

impl OpenPgpStore for MemoryOpenPgpStore {
    fn load(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.len == 0 || out.len() < self.len {
            return None;
        }
        out[..self.len].copy_from_slice(&self.data[..self.len]);
        Some(self.len)
    }

    fn save(&mut self, data: &[u8]) -> bool {
        if data.len() > STATE_BYTES {
            return false;
        }
        self.data[..data.len()].copy_from_slice(data);
        self.len = data.len();
        true
    }

    fn clear(&mut self) -> bool {
        self.data.fill(0);
        self.len = 0;
        true
    }
}

#[derive(Clone, Copy)]
struct KeySlot {
    present: bool,
    /// Meaningful bytes in `material` (32/48 for ECC/EdDSA, 1156 for RSA).
    len: usize,
    /// Key algorithm code (0 = unset, interpreted as the slot default).
    algo: u8,
    /// ECC/EdDSA scalar prefix, or the full RSA private-key blob.
    material: [u8; SLOT_MATERIAL_BYTES],
}

/// Per-slot key algorithm codes.
const KEY_ALGO_UNSET: u8 = 0;
const KEY_ALGO_ECDSA_P256: u8 = 1;
const KEY_ALGO_ECDH_P256: u8 = 2;
const KEY_ALGO_EDDSA: u8 = 3;
const KEY_ALGO_ECDH_X25519: u8 = 4;
const KEY_ALGO_RSA2048: u8 = 5;

/// The size of the ECDH private key (P-256 scalar).
const ECDH_KEY_BYTES: usize = 32;

/// The maximum size of a wrapped session key (AES-256 key wrap).
const ECDH_WRAPPED_MAX: usize = 48;

/// The size of the RFC 6637 material that follows the private key in the
/// slot: the length of the wrapped key, the wrapped key itself, the hash id
/// of the KDF, the id of the key encryption algorithm, a presence flag and the
/// recipient fingerprint that the sender used.
const ECDH_MATERIAL_BYTES: usize = 1 + ECDH_WRAPPED_MAX + 2 + 1 + 20;

/// The RFC 6637 material of a decryption slot.
///
/// The private key stays on the device: what is imported is the session key
/// already wrapped by the sender, which is ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EcdhMaterial {
    /// The session key wrapped with the key encryption key.
    wrapped: Vec<u8, ECDH_WRAPPED_MAX>,
    /// The hash id used by the KDF of RFC 6637 section 7.
    kdf_hash: u8,
    /// The id of the key encryption algorithm (7 = AES-128, 8 = AES-192,
    /// 9 = AES-256).
    kek_alg: u8,
    /// The fingerprint of the recipient key as the sender used it.
    ///
    /// The RFC 6637 section 8 parameters carry the fingerprint of the key, and
    /// a fingerprint includes the creation time of the key: the card has no
    /// clock and computes its own fingerprints with a zero creation time, so
    /// the sender has to provision the value it used. Without it the card
    /// falls back to the computed fingerprint.
    fingerprint: Option<[u8; 20]>,
}

impl EcdhMaterial {
    /// Read the material from a slot, when it is provisioned.
    fn from_slot(slot: &KeySlot) -> Option<Self> {
        if slot.len < ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES {
            return None;
        }
        let material = &slot.material[ECDH_KEY_BYTES..ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES];
        let wrapped_len = usize::from(material[0]);
        if wrapped_len == 0 || wrapped_len > ECDH_WRAPPED_MAX {
            return None;
        }
        let mut wrapped = Vec::new();
        wrapped
            .extend_from_slice(&material[1..1 + wrapped_len])
            .ok()?;
        let mut fingerprint = None;
        let flag = material[3 + ECDH_WRAPPED_MAX];
        if flag == 1 {
            let mut value = [0u8; 20];
            value.copy_from_slice(&material[4 + ECDH_WRAPPED_MAX..][..20]);
            fingerprint = Some(value);
        }
        Some(Self {
            wrapped,
            kdf_hash: material[1 + ECDH_WRAPPED_MAX],
            kek_alg: material[2 + ECDH_WRAPPED_MAX],
            fingerprint,
        })
    }

    /// Write the material into a slot, keeping the private key.
    fn store(&self, slot: &mut KeySlot) {
        let mut material = [0u8; ECDH_MATERIAL_BYTES];
        material[0] = self.wrapped.len() as u8;
        material[1..1 + self.wrapped.len()].copy_from_slice(&self.wrapped);
        material[1 + ECDH_WRAPPED_MAX] = self.kdf_hash;
        material[2 + ECDH_WRAPPED_MAX] = self.kek_alg;
        if let Some(fingerprint) = self.fingerprint {
            material[3 + ECDH_WRAPPED_MAX] = 1;
            material[4 + ECDH_WRAPPED_MAX..].copy_from_slice(&fingerprint);
        }
        slot.material[ECDH_KEY_BYTES..ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES]
            .copy_from_slice(&material);
        slot.len = ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES;
    }
}

/// The external public key of a PSO:DECIPHER command.
///
/// The OpenPGP card specification wraps it in a cipher DO (`A6`) with a public
/// key DO (`7F49`); the tag is also accepted at the top level.
fn external_public_key(input: &[u8]) -> Option<&[u8]> {
    if let Some(point) = tlv::find(input, 0x86) {
        return Some(point);
    }
    let cipher = tlv::find(input, 0xA6)?;
    if let Some(point) = tlv::find(cipher, 0x86) {
        return Some(point);
    }
    let public_template = tlv::find(cipher, 0x7F49)?;
    tlv::find(public_template, 0x86)
}

/// The session key of a wrapped OpenPGP session key.
///
/// RFC 6637 section 8 wraps `m = symm_alg_ID || session key || checksum ||
/// PKCS#5 padding`; the checksum is the sum of the session key octets modulo
/// 65536 (RFC 4880 section 5.1).
fn session_key_from_wrapped(unwrapped: &[u8]) -> Option<heapless::Vec<u8, 32>> {
    if unwrapped.len() < 8 {
        return None;
    }
    let symm_alg = unwrapped[0];
    let key_len = match symm_alg {
        7 => 16,
        8 => 24,
        9 => 32,
        _ => return None,
    };
    // The wrapped value is the session key, the checksum and the padding to
    // the 8 octet granularity.
    if unwrapped.len() < 1 + key_len + 2 {
        return None;
    }
    let key = &unwrapped[1..1 + key_len];
    let checksum = u16::from_be_bytes([unwrapped[1 + key_len], unwrapped[2 + key_len]]);
    let sum = key
        .iter()
        .fold(0u16, |acc, byte| acc.wrapping_add(u16::from(*byte)));
    if sum != checksum {
        return None;
    }
    let mut out = heapless::Vec::new();
    out.extend_from_slice(key).ok()?;
    Some(out)
}

impl KeySlot {
    const EMPTY: Self = Self {
        present: false,
        len: 0,
        algo: KEY_ALGO_UNSET,
        material: [0; SLOT_MATERIAL_BYTES],
    };

    /// RSA private key parsed from the material, or `None`.
    ///
    /// RSA slots always carry the explicit algorithm code (set by
    /// `PUT DATA C1`/`C3` before `GENERATE`), so no slot default applies.
    fn rsa_key(&self) -> Option<rsa::Rsa2048PrivateKey> {
        if self.algo != KEY_ALGO_RSA2048 {
            return None;
        }
        rsa::Rsa2048PrivateKey::from_blob(&self.material[..self.len.min(SLOT_MATERIAL_BYTES)])
    }

    /// Effective algorithm: stored code, or the slot default when unset.
    const fn effective_algo(self, slot: usize) -> u8 {
        if self.algo != KEY_ALGO_UNSET {
            return self.algo;
        }
        // Slot 1 is the decryption slot (ECDH); the others sign (ECDSA).
        if slot == 1 {
            KEY_ALGO_ECDH_P256
        } else {
            KEY_ALGO_ECDSA_P256
        }
    }
}

/// OpenPGP Card applet state.
pub struct OpenPgp<S: OpenPgpStore> {
    store: S,
    pw1: PinSlot,
    pw3: PinSlot,
    /// Sticky floor of the PW1 retry counter this session: the lowest
    /// counter known to be persisted or consumed. A failed save keeps the
    /// RAM state (restrictive) and lowers the floor, so a reload can never
    /// restore a more permissive counter than the one already lost.
    pw1_floor: u8,
    /// Sticky floor of the PW3 retry counter this session.
    pw3_floor: u8,
    pw1_signature_verified: bool,
    pw1_other_verified: bool,
    pw3_verified: bool,
    keys: [KeySlot; 3],
    name: Vec<u8, MAX_NAME>,
    language: Vec<u8, 8>,
    sex: u8,
    url: Vec<u8, MAX_URL>,
    certificates: [Vec<u8, MAX_CERTIFICATE>; 3],
    signature_counter: u32,
    out: Vec<u8, 2048>,
    state: Vec<u8, STATE_BYTES>,
    loaded: bool,
}

impl<S: OpenPgpStore> OpenPgp<S> {
    /// Create an OpenPGP applet over `store`.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self {
            store,
            pw1: PinSlot::new(PW_POLICY),
            pw3: PinSlot::new(PW_POLICY),
            pw1_floor: PW_POLICY.max_attempts,
            pw3_floor: PW_POLICY.max_attempts,
            pw1_signature_verified: false,
            pw1_other_verified: false,
            pw3_verified: false,
            keys: [KeySlot::EMPTY; 3],
            name: Vec::new(),
            language: Vec::new(),
            sex: 0,
            url: Vec::new(),
            certificates: [const { Vec::new() }; 3],
            signature_counter: 0,
            out: Vec::new(),
            state: Vec::new(),
            loaded: false,
        }
    }

    /// Mutable access to the backing store.
    #[must_use]
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    fn ensure_loaded(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let mut bytes = [0u8; STATE_BYTES];
        if let Some(len) = self.store.load(&mut bytes) {
            if self.decode_state(&bytes[..len]) {
                return;
            }
        }
        let _ = self.pw1.set(b"123456");
        let _ = self.pw3.set(b"12345678");
        self.clamp_to_floors();
        let _ = self.save_state();
    }

    /// Persist the state and anchor the session floors of both slots to the
    /// truth the store now holds.
    ///
    /// `save_state` serializes the two PIN slots together, so one save moves
    /// both floors: a failed save keeps the RAM state of the slots
    /// (restrictive) and lowers each floor to the counter still in RAM, while
    /// a successful one re-anchors both to the current counter. The floors
    /// are volatile session state: they survive `select()` but not a power
    /// cycle, and every reload is clamped to them.
    fn persist_state(&mut self) -> bool {
        let saved = self.save_state();
        let pw1_retries = self.pw1.retries_remaining();
        let pw3_retries = self.pw3.retries_remaining();
        if saved {
            self.pw1_floor = pw1_retries;
            self.pw3_floor = pw3_retries;
        } else {
            self.pw1_floor = self.pw1_floor.min(pw1_retries);
            self.pw3_floor = self.pw3_floor.min(pw3_retries);
        }
        saved
    }

    /// Clamp both PIN counters of the shared load path to their session
    /// floors.
    fn clamp_to_floors(&mut self) {
        let pw1_floor = self.pw1_floor;
        let pw3_floor = self.pw3_floor;
        clamp_to_floor(&mut self.pw1, pw1_floor);
        clamp_to_floor(&mut self.pw3, pw3_floor);
    }

    fn save_state(&mut self) -> bool {
        self.state.clear();
        self.push(STATE_VERSION);
        let pw1 = self.pw1.clone();
        let pw3 = self.pw3.clone();
        let keys = self.keys;
        let name = self.name.clone();
        let language = self.language.clone();
        let url = self.url.clone();
        let certificates = self.certificates.clone();
        self.push_slot(&pw1);
        self.push_slot(&pw3);
        for key in keys {
            self.push(u8::from(key.present));
            self.push_u16(key.len as u16);
            self.push(key.algo);
            let _ = self.state.extend_from_slice(&key.material);
        }
        self.push_len_bytes(&name, MAX_NAME);
        self.push_len_bytes(&language, 8);
        self.push(self.sex);
        self.push_len_bytes(&url, MAX_URL);
        for cert in &certificates {
            self.push_u16(cert.len() as u16);
            self.push_fixed(cert, MAX_CERTIFICATE);
        }
        self.push_u32(self.signature_counter);
        self.store.save(&self.state)
    }

    fn push(&mut self, value: u8) {
        let _ = self.state.push(value);
    }

    fn push_u16(&mut self, value: u16) {
        let _ = self.state.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u32(&mut self, value: u32) {
        let _ = self.state.extend_from_slice(&value.to_be_bytes());
    }

    fn push_slot(&mut self, slot: &PinSlot) {
        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        if slot.encode(&mut encoded).is_ok() {
            let _ = self.state.extend_from_slice(&encoded);
        }
    }

    fn push_len_bytes(&mut self, value: &[u8], width: usize) {
        self.push(value.len() as u8);
        let _ = self.state.extend_from_slice(value);
        for _ in value.len()..width {
            self.push(0);
        }
    }

    fn push_fixed(&mut self, value: &[u8], width: usize) {
        let _ = self.state.extend_from_slice(value);
        for _ in value.len()..width {
            self.push(0);
        }
    }

    fn decode_state(&mut self, bytes: &[u8]) -> bool {
        let mut cursor = 0;
        let version = take_u8(bytes, &mut cursor);
        if version != Some(STATE_VERSION)
            && version != Some(STATE_VERSION_V2)
            && version != Some(STATE_VERSION_V1)
        {
            return false;
        }
        let v1 = version == Some(STATE_VERSION_V1);
        let v2 = version == Some(STATE_VERSION_V2);
        let Some(pw1) = decode_pin(bytes, &mut cursor, PW_POLICY) else {
            return false;
        };
        let Some(pw3) = decode_pin(bytes, &mut cursor, PW_POLICY) else {
            return false;
        };
        // A reload never lifts above the session floor: a counter restored
        // from the sealed store must not undo a decrement that failed to
        // persist in this session.
        let mut pw1 = pw1;
        let mut pw3 = pw3;
        let pw1_floor = self.pw1_floor;
        let pw3_floor = self.pw3_floor;
        clamp_to_floor(&mut pw1, pw1_floor);
        clamp_to_floor(&mut pw3, pw3_floor);
        let mut keys = [KeySlot::EMPTY; 3];
        for (index, key) in keys.iter_mut().enumerate() {
            let Some(present) = take_u8(bytes, &mut cursor) else {
                return false;
            };
            // v3 stores the material length as u16; v1/v2 used one byte.
            let len = if v1 || v2 {
                let Some(len) = take_u8(bytes, &mut cursor) else {
                    return false;
                };
                usize::from(len)
            } else {
                let Some(len) = take_u16(bytes, &mut cursor) else {
                    return false;
                };
                usize::from(len)
            };
            // v1 records carry no algorithm byte; every slot was P-256 then.
            let algo = if v1 {
                if index == 1 {
                    KEY_ALGO_ECDH_P256
                } else {
                    KEY_ALGO_ECDSA_P256
                }
            } else {
                let Some(algo) = take_u8(bytes, &mut cursor) else {
                    return false;
                };
                algo
            };
            let width = if v1 || v2 { 48 } else { SLOT_MATERIAL_BYTES };
            let Some(raw) = take(bytes, &mut cursor, width) else {
                return false;
            };
            if len > width {
                return false;
            }
            // RSA slots must decode to a valid private key; anything else
            // fails closed so a torn write can never yield a half key. The
            // one non-RSA width above the 48-octet slab is the RFC 6637
            // material an accepted `PUT DATA D2` writes into the decryption
            // slot (`EcdhMaterial::store`): accepted exactly there, under the
            // only algorithms the import is handled under, so the state the
            // card itself wrote survives to the next session.
            if algo == KEY_ALGO_RSA2048 {
                if len != rsa::RSA_BLOB_BYTES
                    || rsa::Rsa2048PrivateKey::from_blob(&raw[..len]).is_none()
                {
                    return false;
                }
            } else if len > 48 {
                let d2_geometry = len == ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES
                    && index == 1
                    && (algo == KEY_ALGO_UNSET || algo == KEY_ALGO_ECDH_P256);
                if !d2_geometry {
                    return false;
                }
            }
            key.present = present != 0;
            key.len = len;
            key.algo = algo;
            key.material[..len].copy_from_slice(&raw[..len]);
        }
        let Some(name) = decode_len_bytes::<MAX_NAME>(bytes, &mut cursor) else {
            return false;
        };
        let Some(language) = decode_len_bytes::<8>(bytes, &mut cursor) else {
            return false;
        };
        let Some(sex) = take_u8(bytes, &mut cursor) else {
            return false;
        };
        let Some(url) = decode_len_bytes::<MAX_URL>(bytes, &mut cursor) else {
            return false;
        };
        let mut certificates = [const { Vec::new() }; 3];
        for certificate in &mut certificates {
            let Some(len) = take_u16(bytes, &mut cursor) else {
                return false;
            };
            let Some(raw) = take(bytes, &mut cursor, MAX_CERTIFICATE) else {
                return false;
            };
            if usize::from(len) > MAX_CERTIFICATE
                || certificate
                    .extend_from_slice(&raw[..usize::from(len)])
                    .is_err()
            {
                return false;
            }
        }
        let Some(signature_counter) = take_u32(bytes, &mut cursor) else {
            return false;
        };
        self.pw1 = pw1;
        self.pw3 = pw3;
        self.keys = keys;
        self.name = name;
        self.language = language;
        self.sex = sex;
        self.url = url;
        self.certificates = certificates;
        self.signature_counter = signature_counter;
        true
    }

    fn verify(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        let slot = match apdu.p2 {
            0x81 | 0x82 => &mut self.pw1,
            0x83 => &mut self.pw3,
            _ => return Response::status(Sw::INCORRECT_PARAMETERS),
        };
        if apdu.data.is_empty() {
            return Response::status(if slot.is_blocked() {
                Sw::AUTHENTICATION_BLOCKED
            } else {
                Sw::retries_left(slot.retries_remaining())
            });
        }
        let result = slot.verify(apdu.data);
        let Err(error) = result else {
            // A successful verification moves no persistable state: the
            // session flags are RAM-only and success never refills the
            // counter, so no save (and no way to fail one) belongs here.
            match apdu.p2 {
                0x81 => self.pw1_signature_verified = true,
                0x82 => self.pw1_other_verified = true,
                0x83 => self.pw3_verified = true,
                _ => {}
            }
            return Response::status(Sw::OK);
        };
        // Only a consumed attempt mutates the sealed state; the unset and
        // blocked diagnostics leave the counter alone, so they are answered
        // without touching the store.
        if !error.is_retry_indicator() {
            return Response::status(error);
        }
        if self.persist_state() {
            Response::status(error)
        } else {
            // The decrement lives only in RAM and the floor already recorded
            // it: answer with an observable error instead of the retry
            // indicator, which a host would read as "one attempt left" in a
            // state the store no longer holds.
            Response::status(Sw::NOT_ENOUGH_MEMORY)
        }
    }

    fn get_data(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        let tag = (u32::from(apdu.p1) << 8) | u32::from(apdu.p2);
        let name = self.name.clone();
        let language = self.language.clone();
        let url = self.url.clone();
        let certificate = self.certificates[0].clone();
        let sex = self.sex;
        let pw_status = self.pw_status();
        let key_info = self.key_info();
        let mut sig_attrs = [0u8; 11];
        let sig_len = self.slot_attrs(0, &mut sig_attrs);
        let mut dec_attrs = [0u8; 11];
        let dec_len = self.slot_attrs(1, &mut dec_attrs);
        let mut auth_attrs = [0u8; 11];
        let auth_len = self.slot_attrs(2, &mut auth_attrs);
        let fingerprints = self.fingerprints();
        match tag {
            0x004F => self.simple_output(TAG_AID, AID),
            0x005B => self.simple_output(TAG_NAME, &name),
            0x005F2D => self.simple_output(TAG_LANGUAGE, &language),
            0x005F35 => self.simple_output(TAG_SEX, &[sex]),
            0x005F50 => self.simple_output(TAG_URL, &url),
            0x005F52 => self.simple_output(
                TAG_HISTORICAL,
                &[0x00, 0x73, 0x00, 0x00, 0xE0, 0x05, 0x90, 0x00],
            ),
            0x006E => self.application_data(),
            0x007A => self.security_template(),
            0x007F21 => self.constructed_output(TAG_CERTIFICATE, &certificate),
            0x007F66 => self.constructed_output(
                TAG_EXTENDED_LENGTH,
                &[0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00],
            ),
            0x00C1 => self.simple_output(TAG_ALGO_SIG, &sig_attrs[..sig_len]),
            0x00C2 => self.simple_output(TAG_ALGO_DEC, &dec_attrs[..dec_len]),
            0x00C3 => self.simple_output(TAG_ALGO_AUTH, &auth_attrs[..auth_len]),
            0x00C4 => self.simple_output(TAG_PW_STATUS, &pw_status),
            0x00C5 => self.simple_output(TAG_FINGERPRINTS, &fingerprints),
            0x00C7 => self.simple_output(TAG_FP_SIG, &fingerprints[..20]),
            0x00C8 => self.simple_output(TAG_FP_DEC, &fingerprints[20..40]),
            0x00C9 => self.simple_output(TAG_FP_AUT, &fingerprints[40..]),
            0x00CD => self.simple_output(TAG_GENERATION_DATES, &[0; 12]),
            0x00DE => self.simple_output(TAG_KEY_INFO, &key_info),
            _ => Response::status(Sw::FILE_NOT_FOUND),
        }
    }

    fn simple_output(&mut self, tag: u32, value: &[u8]) -> Response<'_> {
        let _ = tag;
        self.out.clear();
        if self.out.extend_from_slice(value).is_err() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn constructed_output(&mut self, tag: u32, value: &[u8]) -> Response<'_> {
        self.out.clear();
        if !append_tlv(&mut self.out, tag, value) {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn application_data(&mut self) -> Response<'_> {
        let mut sig_attrs = [0u8; 11];
        let sig_len = self.slot_attrs(0, &mut sig_attrs);
        let mut dec_attrs = [0u8; 11];
        let dec_len = self.slot_attrs(1, &mut dec_attrs);
        let mut auth_attrs = [0u8; 11];
        let auth_len = self.slot_attrs(2, &mut auth_attrs);
        let pw_status = self.pw_status();
        let key_info = self.key_info();
        self.out.clear();
        let mut discretionary = Vec::<u8, 512>::new();
        append_tlv(
            &mut discretionary,
            TAG_EXTENDED_CAPS,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        append_tlv(&mut discretionary, TAG_ALGO_SIG, &sig_attrs[..sig_len]);
        append_tlv(&mut discretionary, TAG_ALGO_DEC, &dec_attrs[..dec_len]);
        append_tlv(&mut discretionary, TAG_ALGO_AUTH, &auth_attrs[..auth_len]);
        append_tlv(&mut discretionary, TAG_PW_STATUS, &pw_status);
        append_tlv(&mut discretionary, TAG_FINGERPRINTS, &self.fingerprints());
        append_tlv(&mut discretionary, TAG_GENERATION_DATES, &[0; 12]);
        append_tlv(&mut discretionary, TAG_KEY_INFO, &key_info);

        let mut body = Vec::<u8, 1024>::new();
        append_tlv(&mut body, TAG_AID, AID);
        append_tlv(
            &mut body,
            TAG_HISTORICAL,
            &[0x00, 0x73, 0x00, 0x00, 0xE0, 0x05, 0x90, 0x00],
        );
        append_tlv(
            &mut body,
            TAG_EXTENDED_LENGTH,
            &[0x02, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00],
        );
        append_tlv(&mut body, TAG_DISCRETIONARY, &discretionary);
        if !append_tlv(&mut self.out, TAG_APP_DATA, &body) {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn security_template(&mut self) -> Response<'_> {
        let counter = self.signature_counter.to_be_bytes();
        let mut value = Vec::<u8, 16>::new();
        append_tlv(&mut value, TAG_SIGNATURE_COUNTER, &counter[1..]);
        self.constructed_output(TAG_SECURITY_TEMPLATE, &value)
    }

    /// Algorithm attributes (`C1`/`C2`/`C3` value) for a slot: algorithm ID
    /// followed by parameters (curve OID for ECC, modulus/exponent lengths
    /// for RSA).
    fn slot_attrs(&self, slot: usize, out: &mut [u8; 11]) -> usize {
        match self.keys[slot].effective_algo(slot) {
            KEY_ALGO_RSA2048 => {
                out[..6].copy_from_slice(&Self::RSA_ATTRS);
                6
            }
            KEY_ALGO_ECDH_P256 => {
                out[0] = ALGO_ECDH;
                out[1..9].copy_from_slice(OID_P256);
                9
            }
            KEY_ALGO_EDDSA => {
                out[0] = ALGO_EDDSA;
                out[1..10].copy_from_slice(OID_ED25519);
                10
            }
            KEY_ALGO_ECDH_X25519 => {
                out[0] = ALGO_ECDH;
                out[1..11].copy_from_slice(OID_X25519);
                11
            }
            _ => {
                out[0] = ALGO_ECDSA;
                out[1..9].copy_from_slice(OID_P256);
                9
            }
        }
    }

    /// Parse algorithm attributes into a key algorithm code.
    ///
    /// RSA follows OpenPGP Card spec section 7.2.9: `01 || nbits || ebits`
    /// (`0800`/`0020` for RSA-2048/`e` = 65537, minimal `0011` accepted
    /// too), with the optional import-format byte ignored; imported keys are
    /// generated on-card, never imported.
    fn parse_attrs(value: &[u8]) -> Option<u8> {
        if let Some(algo) = Self::parse_rsa_attrs(value) {
            return Some(algo);
        }
        // The import format byte (00 or FF) is optional in the algorithm
        // attributes of the OpenPGP card specification.
        let (&id, oid) = value.split_first()?;
        let oid = match oid {
            [rest @ .., 0x00] | [rest @ .., 0xFF] => rest,
            other => other,
        };
        if id == ALGO_ECDSA && oid == OID_P256 {
            Some(KEY_ALGO_ECDSA_P256)
        } else if id == ALGO_ECDH && oid == OID_P256 {
            Some(KEY_ALGO_ECDH_P256)
        } else if id == ALGO_EDDSA && oid == OID_ED25519 {
            Some(KEY_ALGO_EDDSA)
        } else if id == ALGO_ECDH && oid == OID_X25519 {
            Some(KEY_ALGO_ECDH_X25519)
        } else {
            None
        }
    }

    /// Canonical RSA-2048 attributes reported by `GET DATA C1`/`C3`:
    /// `01 || 0800 (n, 2048 bit) || 0020 (e, 32 bit) || 00 (import fmt)`.
    const RSA_ATTRS: [u8; 6] = [ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00];

    /// Parse RSA algorithm attributes (`01 || nbits || ebits [|| import]`).
    fn parse_rsa_attrs(value: &[u8]) -> Option<u8> {
        if value.len() != 5 && value.len() != 6 {
            return None;
        }
        if value[0] != ALGO_RSA {
            return None;
        }
        let nbits = u16::from_be_bytes([value[1], value[2]]);
        let ebits = u16::from_be_bytes([value[3], value[4]]);
        if nbits != 2048 {
            return None;
        }
        // `e` = 65537: full 32-bit form from GnuPG or the minimal 17-bit one.
        if ebits != 32 && ebits != 17 {
            return None;
        }
        Some(KEY_ALGO_RSA2048)
    }

    fn pw_status(&self) -> [u8; 7] {
        [
            0x00,
            0x7F,
            0x7F,
            0x7F,
            self.pw1.retries_remaining(),
            0x00,
            self.pw3.retries_remaining(),
        ]
    }

    fn key_info(&self) -> [u8; 6] {
        [
            0x01,
            u8::from(self.keys[0].present),
            0x02,
            u8::from(self.keys[1].present),
            0x03,
            u8::from(self.keys[2].present),
        ]
    }

    /// RFC 4880 section 12.2 v4 fingerprint for a slot's public key.
    ///
    /// Packet: version, zero creation time (no RTC on device), algorithm ID,
    /// curve OID, MPI public key, plus KDF parameters for ECDH. Returns
    /// `None` for empty slots.
    fn fingerprint(&self, slot: usize) -> Option<[u8; 20]> {
        use sha1::Digest as _;
        if !self.keys[slot].present {
            return None;
        }
        let algo = self.keys[slot].effective_algo(slot);
        if algo == KEY_ALGO_RSA2048 {
            return self.rsa_fingerprint(slot);
        }
        let mut point = [0u8; 65];
        self.slot_public(slot, &mut point)?;
        // MPI length prefix needs the exact bit length.
        let mut octets = [0u8; 66];
        let (mpi_len, bit_len) = match algo {
            KEY_ALGO_EDDSA => {
                octets[..32].copy_from_slice(&point[..32]);
                (32, mpi_bits(&point[..32]))
            }
            KEY_ALGO_ECDH_X25519 => {
                octets[0] = 0x40;
                octets[1..33].copy_from_slice(&point[..32]);
                (33, mpi_bits(&octets[..33]))
            }
            _ => {
                octets[..65].copy_from_slice(&point[..65]);
                (65, mpi_bits(&point[..65]))
            }
        };
        let (algo_id, oid) = match algo {
            KEY_ALGO_ECDH_P256 | KEY_ALGO_ECDH_X25519 => (0x12u8, Self::curve_oid(algo)),
            KEY_ALGO_EDDSA => (0x16u8, Self::curve_oid(algo)),
            _ => (0x13u8, Self::curve_oid(algo)),
        };
        let kdf: &[u8] = match algo {
            KEY_ALGO_ECDH_P256 => &[0x03, 0x01, 0x08, 0x07],
            KEY_ALGO_ECDH_X25519 => &[0x03, 0x01, 0x0A, 0x09],
            _ => &[],
        };
        // Packet body: version + ctime + algo + oid + MPI [+ KDF].
        let mut body = [0u8; 128];
        body[0] = 0x04;
        let mut cursor = 1;
        // Creation time: zero, the device has no clock.
        body[cursor..cursor + 4].copy_from_slice(&[0, 0, 0, 0]);
        cursor += 4;
        body[cursor] = algo_id;
        cursor += 1;
        body[cursor] = oid.len() as u8;
        cursor += 1;
        body[cursor..cursor + oid.len()].copy_from_slice(oid);
        cursor += oid.len();
        body[cursor..cursor + 2].copy_from_slice(&bit_len.to_be_bytes());
        cursor += 2;
        body[cursor..cursor + mpi_len].copy_from_slice(&octets[..mpi_len]);
        cursor += mpi_len;
        body[cursor..cursor + kdf.len()].copy_from_slice(kdf);
        cursor += kdf.len();

        let mut digest_input = [0u8; 131];
        digest_input[0] = 0x99;
        digest_input[1..3].copy_from_slice(&(cursor as u16).to_be_bytes());
        digest_input[3..3 + cursor].copy_from_slice(&body[..cursor]);
        let hash = sha1::Sha1::digest(&digest_input[..3 + cursor]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash);
        Some(out)
    }

    /// RFC 4880 section 12.2 v4 fingerprint of an RSA slot: `SHA1(99 || len ||
    /// version || ctime || 01 || MPI(n) || MPI(e))`.
    fn rsa_fingerprint(&self, slot: usize) -> Option<[u8; 20]> {
        use sha1::Digest as _;
        let key = self.keys[slot].rsa_key()?;
        let n_start = key
            .n
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(rsa::RSA2048_BYTES - 1);
        let e = key.e.to_be_bytes();
        let e_start = e.iter().position(|byte| *byte != 0).unwrap_or(e.len() - 1);
        let mut body = [0u8; 288];
        body[0] = 0x04;
        body[1..5].copy_from_slice(&[0, 0, 0, 0]);
        body[5] = 0x01;
        let mut cursor = 6;
        for mpi in [&key.n[n_start..], &e[e_start..]] {
            body[cursor..cursor + 2].copy_from_slice(&mpi_bits(mpi).to_be_bytes());
            cursor += 2;
            body[cursor..cursor + mpi.len()].copy_from_slice(mpi);
            cursor += mpi.len();
        }
        let mut digest_input = [0u8; 296];
        digest_input[0] = 0x99;
        digest_input[1..3].copy_from_slice(&(cursor as u16).to_be_bytes());
        digest_input[3..3 + cursor].copy_from_slice(&body[..cursor]);
        let hash = sha1::Sha1::digest(&digest_input[..3 + cursor]);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hash);
        Some(out)
    }

    /// Curve OID for a slot algorithm code.
    fn curve_oid(algo: u8) -> &'static [u8] {
        match algo {
            KEY_ALGO_EDDSA => OID_ED25519,
            KEY_ALGO_ECDH_X25519 => OID_X25519,
            _ => OID_P256,
        }
    }

    /// 60-byte Sig/Dec/Aut fingerprint aggregate (zeros for empty slots).
    fn fingerprints(&self) -> [u8; 60] {
        let mut out = [0u8; 60];
        for (index, chunk) in out.chunks_mut(20).enumerate() {
            if let Some(fingerprint) = self.fingerprint(index) {
                chunk.copy_from_slice(&fingerprint);
            }
        }
        out
    }

    fn put_data(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if !self.pw3_verified {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let tag = (u32::from(apdu.p1) << 8) | u32::from(apdu.p2);
        let accepted = match tag {
            0x005B => replace_vec(&mut self.name, apdu.data, MAX_NAME),
            0x5F2D => replace_vec(&mut self.language, apdu.data, 8),
            0x5F35 if apdu.data.len() == 1 => {
                self.sex = apdu.data[0];
                true
            }
            0x5F50 => replace_vec(&mut self.url, apdu.data, MAX_URL),
            0x7F21 => replace_vec(&mut self.certificates[0], apdu.data, MAX_CERTIFICATE),
            0x00C1 => self.put_algo(0, apdu.data),
            0x00C2 => self.put_algo(1, apdu.data),
            0x00C3 => self.put_algo(2, apdu.data),
            0x00D2 => self.put_ecdh_material(apdu.data),
            _ => false,
        };
        if accepted {
            if self.persist_state() {
                Response::status(Sw::OK)
            } else {
                // The accepted mutation lives only in RAM: never confirm it
                // with a bare `9000`.
                Response::status(Sw::NOT_ENOUGH_MEMORY)
            }
        } else {
            Response::status(Sw::WRONG_DATA)
        }
    }

    /// Import the RFC 6637 material of the decryption slot (admin PIN).
    ///
    /// The body carries the session key already wrapped by the sender, which
    /// is ciphertext, plus the hash id of the KDF and the id of the key
    /// encryption algorithm: `len || wrapped key || KDF hash id || KEK id`.
    /// The private key of the slot stays on the device.
    ///
    /// The format is provisional: it still has to be aligned with the key
    /// import of the OpenPGP card specification, which needs a host that
    /// speaks it (GnuPG) to be validated. The optional trailing 20 octets are
    /// the fingerprint of the key that the sender used in the KDF parameters;
    /// without them the card uses the fingerprint it computes itself.
    ///
    /// The slot only accepts material the decipher can actually consume: the
    /// curve must be P-256 (checked through the algorithm attributes), the KDF
    /// hash must be SHA-256, the KEK one of AES-128/192/256 and the wrapped
    /// key one RFC 3394 block granule — 24/32/40/48 octets, the real AES
    /// session key sizes. The GnuPG interop (SHA-256 and AES-128 for P-256) is
    /// the practical authority: anything outside the domain would be accepted
    /// here and fail only at the first real decipher.
    fn put_ecdh_material(&mut self, value: &[u8]) -> bool {
        if self.keys[1].effective_algo(1) != KEY_ALGO_ECDH_P256 || !self.keys[1].present {
            return false;
        }
        if value.len() < 4 {
            return false;
        }
        let wrapped_len = usize::from(value[0]);
        let base = 1 + wrapped_len + 2;
        // The floor is the smallest real OpenPGP session key block (symm_alg
        // ID + AES-128 key + checksum, one RFC 3394 granule): everything below
        // it, above the cap or off the 8-octet granularity can never unwrap.
        if !(24..=ECDH_WRAPPED_MAX).contains(&wrapped_len)
            || wrapped_len % 8 != 0
            || (value.len() != base && value.len() != base + 20)
        {
            return false;
        }
        let mut wrapped = Vec::new();
        if wrapped
            .extend_from_slice(&value[1..1 + wrapped_len])
            .is_err()
        {
            return false;
        }
        let mut fingerprint = None;
        if value.len() == base + 20 {
            let mut fpr = [0u8; 20];
            fpr.copy_from_slice(&value[base..]);
            fingerprint = Some(fpr);
        }
        let material = EcdhMaterial {
            wrapped,
            kdf_hash: value[1 + wrapped_len],
            kek_alg: value[2 + wrapped_len],
            fingerprint,
        };
        // The card derives the KEK with SHA-256 (the only hash the KDF of
        // RFC 6637 §7 implements) and the key encryption algorithm must be one
        // it supports: anything else would be provisioned and fail closed
        // only at the first real decipher.
        if material.kdf_hash != ecdh::HASH_SHA256 || !(7..=9).contains(&material.kek_alg) {
            return false;
        }
        material.store(&mut self.keys[1]);
        true
    }

    /// Store algorithm attributes for a slot (admin PIN).
    ///
    /// Signature/authentication slots accept ECDSA P-256, Ed25519 and
    /// RSA-2048; the decryption slot accepts ECDH P-256, X25519 and
    /// RSA-2048. Changing the attributes of a slot deletes the key stored
    /// in it.
    fn put_algo(&mut self, slot: usize, value: &[u8]) -> bool {
        let Some(algo) = Self::parse_attrs(value) else {
            return false;
        };
        let accepted = match slot {
            0 | 2 => {
                algo == KEY_ALGO_ECDSA_P256 || algo == KEY_ALGO_EDDSA || algo == KEY_ALGO_RSA2048
            }
            1 => {
                algo == KEY_ALGO_ECDH_P256
                    || algo == KEY_ALGO_ECDH_X25519
                    || algo == KEY_ALGO_RSA2048
            }
            _ => false,
        };
        if !accepted {
            return false;
        }
        self.keys[slot].algo = algo;
        self.keys[slot].present = false;
        self.keys[slot].len = 0;
        self.keys[slot].material.fill(0);
        true
    }

    fn generate(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_> {
        if !self.pw3_verified {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let slot = if tlv::find(apdu.data, 0xB6).is_some() {
            0
        } else if tlv::find(apdu.data, 0xB8).is_some() {
            1
        } else if tlv::find(apdu.data, 0xA4).is_some() {
            2
        } else {
            return Response::status(Sw::WRONG_DATA);
        };
        let algo = self.keys[slot].effective_algo(slot);
        if algo == KEY_ALGO_RSA2048 {
            return self.generate_rsa(slot, rng);
        }
        let mut scalar = [0u8; 48];
        let mut point = [0u8; 65];
        let point_len = match algo {
            KEY_ALGO_EDDSA | KEY_ALGO_ECDH_X25519 => {
                rng.fill_bytes(&mut scalar[..32]);
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&scalar[..32]);
                if algo == KEY_ALGO_EDDSA {
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                    point[..32].copy_from_slice(signing_key.verifying_key().as_bytes());
                    32
                } else {
                    let secret = x25519_dalek::StaticSecret::from(seed);
                    point[..32].copy_from_slice(&x25519_dalek::PublicKey::from(&secret).to_bytes());
                    32
                }
            }
            _ => {
                if !generate_p256(rng, &mut scalar, &mut point) {
                    return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
                }
                65
            }
        };
        self.keys[slot] = KeySlot {
            present: true,
            len: 32,
            algo,
            material: {
                let mut material = [0u8; SLOT_MATERIAL_BYTES];
                material[..32].copy_from_slice(&scalar[..32]);
                material
            },
        };
        self.signature_counter = if slot == 0 { 0 } else { self.signature_counter };
        if !self.save_state() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        public_key_response(&mut self.out, &point[..point_len])
    }

    /// Generate an RSA-2048 key pair on-device for `slot`, answering
    /// `7F49 { 81 modulus, 82 exponent }`.
    fn generate_rsa(&mut self, slot: usize, rng: &mut dyn Rng) -> Response<'_> {
        let Some(key) = rsa::generate_key(rng) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let mut material = [0u8; SLOT_MATERIAL_BYTES];
        key.to_blob(&mut material);
        self.keys[slot] = KeySlot {
            present: true,
            len: rsa::RSA_BLOB_BYTES,
            algo: KEY_ALGO_RSA2048,
            material,
        };
        self.signature_counter = if slot == 0 { 0 } else { self.signature_counter };
        if !self.save_state() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        let public = key.public();
        rsa_public_key_response(&mut self.out, &public.n, public.e)
    }

    fn read_public(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        let slot = if tlv::find(apdu.data, 0xB6).is_some() {
            0
        } else if tlv::find(apdu.data, 0xB8).is_some() {
            1
        } else if tlv::find(apdu.data, 0xA4).is_some() {
            2
        } else {
            return Response::status(Sw::WRONG_DATA);
        };
        if !self.keys[slot].present {
            return Response::status(Sw::FILE_NOT_FOUND);
        }
        if self.keys[slot].effective_algo(slot) == KEY_ALGO_RSA2048 {
            let Some(key) = self.keys[slot].rsa_key() else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            let public = key.public();
            return rsa_public_key_response(&mut self.out, &public.n, public.e);
        }
        let mut point = [0u8; 65];
        let Some(point_len) = self.slot_public(slot, &mut point) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        public_key_response(&mut self.out, &point[..point_len])
    }

    /// Public key bytes for an ECC/EdDSA slot: SEC1 uncompressed for P-256,
    /// raw 32-byte keys for Ed25519/X25519. RSA slots are answered from the
    /// stored blob by the caller and never reach this function.
    fn slot_public(&self, slot: usize, point: &mut [u8; 65]) -> Option<usize> {
        match self.keys[slot].effective_algo(slot) {
            KEY_ALGO_RSA2048 => None,
            KEY_ALGO_EDDSA => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&self.keys[slot].material[..32]);
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                point[..32].copy_from_slice(signing_key.verifying_key().as_bytes());
                Some(32)
            }
            KEY_ALGO_ECDH_X25519 => {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&self.keys[slot].material[..32]);
                let secret = x25519_dalek::StaticSecret::from(seed);
                point[..32].copy_from_slice(&x25519_dalek::PublicKey::from(&secret).to_bytes());
                Some(32)
            }
            _ => {
                let full = public_point(&self.keys[slot].material[..32])?;
                point.copy_from_slice(&full);
                Some(65)
            }
        }
    }

    fn sign(&mut self, input: &[u8], rng: &mut dyn Rng) -> Response<'_> {
        if !self.pw1_signature_verified {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if !self.keys[0].present {
            return Response::status(Sw::FILE_NOT_FOUND);
        }
        let algo = self.keys[0].effective_algo(0);
        if algo == KEY_ALGO_RSA2048 {
            // GnuPG sends either the full 256-byte encoded block or a DER
            // DigestInfo to EMSA-encode on-card; anything else is rejected
            // rather than guessed at.
            let block = if input.len() == rsa::RSA2048_BYTES {
                let mut block = [0u8; rsa::RSA2048_BYTES];
                block.copy_from_slice(input);
                block
            } else if let Some(encoded) = rsa::emsa_encode_digestinfo(input) {
                encoded
            } else {
                return Response::status(Sw::WRONG_DATA);
            };
            let Some(key) = self.keys[0].rsa_key() else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            let Some(raw) = rsa::apply_private(&key, &block, rng) else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            self.signature_counter = self.signature_counter.wrapping_add(1);
            self.pw1_signature_verified = false;
            if !self.save_state() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            self.out.clear();
            if self.out.extend_from_slice(&raw).is_err() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            return Response::ok(&self.out);
        }
        if algo == KEY_ALGO_EDDSA {
            if input.is_empty() {
                return Response::status(Sw::WRONG_DATA);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&self.keys[0].material[..32]);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            seed.fill(0);
            use ed25519_dalek::Signer as _;
            let signature = signing_key.sign(input);
            self.signature_counter = self.signature_counter.wrapping_add(1);
            self.pw1_signature_verified = false;
            if !self.save_state() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            self.out.clear();
            if self.out.extend_from_slice(&signature.to_bytes()).is_err() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            return Response::ok(&self.out);
        }
        if algo != KEY_ALGO_ECDSA_P256 {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        }
        let Some(mut digest) = left_pad_digest(input, 32) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let key = match p256::ecdsa::SigningKey::from_slice(&self.keys[0].material[..32]) {
            Ok(key) => key,
            Err(_) => return Response::status(Sw::NO_PRECISE_DIAGNOSIS),
        };
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: p256::ecdsa::Signature = match key.sign_prehash(&digest) {
            Ok(signature) => signature,
            Err(_) => return Response::status(Sw::NO_PRECISE_DIAGNOSIS),
        };
        digest.fill(0);
        self.signature_counter = self.signature_counter.wrapping_add(1);
        self.pw1_signature_verified = false;
        if !self.save_state() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        // OpenPGP card ECDSA signatures are raw fixed-size r||s, not DER.
        let (r, s) = signature.split_bytes();
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(r.as_slice());
        raw[32..].copy_from_slice(s.as_slice());
        self.out.clear();
        if self.out.extend_from_slice(&raw).is_err() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn internal_authenticate(&mut self, input: &[u8], rng: &mut dyn Rng) -> Response<'_> {
        if !self.pw1_other_verified || !self.keys[2].present {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let algo = self.keys[2].effective_algo(2);
        if algo == KEY_ALGO_RSA2048 {
            // Authentication challenges (e.g. SSH via gpg-agent) are
            // arbitrary host bytes: raw private operation only, never
            // DigestInfo sniffing.
            if input.len() > rsa::RSA2048_BYTES {
                return Response::status(Sw::WRONG_DATA);
            }
            let mut block = [0u8; rsa::RSA2048_BYTES];
            block[rsa::RSA2048_BYTES - input.len()..].copy_from_slice(input);
            let Some(key) = self.keys[2].rsa_key() else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            let Some(raw) = rsa::apply_private(&key, &block, rng) else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            self.out.clear();
            if self.out.extend_from_slice(&raw).is_err() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            return Response::ok(&self.out);
        }
        if algo == KEY_ALGO_EDDSA {
            if input.is_empty() {
                return Response::status(Sw::WRONG_DATA);
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&self.keys[2].material[..32]);
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            seed.fill(0);
            use ed25519_dalek::Signer as _;
            let signature = signing_key.sign(input);
            self.out.clear();
            if self.out.extend_from_slice(&signature.to_bytes()).is_err() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            return Response::ok(&self.out);
        }
        if algo != KEY_ALGO_ECDSA_P256 {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        }
        let Some(digest) = left_pad_digest(input, 32) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Ok(key) = p256::ecdsa::SigningKey::from_slice(&self.keys[2].material[..32]) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let signature: p256::ecdsa::Signature = match key.sign_prehash(&digest) {
            Ok(signature) => signature,
            Err(_) => return Response::status(Sw::NO_PRECISE_DIAGNOSIS),
        };
        let (r, s) = signature.split_bytes();
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(r.as_slice());
        raw[32..].copy_from_slice(s.as_slice());
        self.out.clear();
        if self.out.extend_from_slice(&raw).is_err() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn decipher(&mut self, input: &[u8], rng: &mut dyn Rng) -> Response<'_> {
        if !self.pw1_other_verified || !self.keys[1].present {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let algo = self.keys[1].effective_algo(1);
        if algo == KEY_ALGO_RSA2048 {
            let cipher = tlv::find(input, 0xA6).unwrap_or(input);
            let public_template = tlv::find(cipher, 0x7F49).unwrap_or(cipher);
            let payload = tlv::find(public_template, 0x86).unwrap_or(public_template);
            let Some(block) = rsa_cipher_block(payload) else {
                return Response::status(Sw::WRONG_DATA);
            };
            let Some(key) = self.keys[1].rsa_key() else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            let Some(plain) = rsa::apply_private(&key, &block, rng) else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            // Raw 256-byte block: the host (GnuPG) strips PKCS#1 padding
            // itself, so every failure mode stays one status word.
            self.out.clear();
            if self.out.extend_from_slice(&plain).is_err() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            return Response::ok(&self.out);
        }
        // ECDH decryption follows RFC 6637: the card derives the key
        // encryption key from the shared point and unwraps the session key
        // that the sender wrapped for it. The shared secret never leaves the
        // card.
        if algo == KEY_ALGO_ECDH_P256 {
            return self.decipher_ecdh(input);
        }
        // Curve25519 is not covered by RFC 6637 and has no normalised KDF
        // parameters: the card performs the key agreement and returns the
        // shared secret, as the OpenPGP card specification defines for the
        // partial decrypt.
        if algo == KEY_ALGO_ECDH_X25519 {
            return self.decipher_ecdh_x25519(input);
        }
        Response::status(Sw::FUNCTION_NOT_SUPPORTED)
    }

    /// Decrypt with the card-side ECDH flow of RFC 6637 section 8.
    ///
    /// The command carries the ephemeral public key of the sender (`86`) and
    /// the encrypted data (`80`). The card computes the shared point with its
    /// own private key, derives the key encryption key with the KDF of section 7,
    /// unwraps the session key wrapped by the sender (RFC 3394) and decrypts
    /// the data with the OpenPGP symmetric layer.
    ///
    /// When the slot has no RFC 6637 material, the card falls back to the
    /// partial decrypt of the OpenPGP card specification (section 4.4.3.8): the
    /// shared secret is returned and the host does the rest. The release of
    /// the shared secret is gated by the verification of PW1 in mode 82.
    fn decipher_ecdh(&mut self, input: &[u8]) -> Response<'_> {
        if self.ecdh_material().is_none() {
            return self.decipher_ecdh_shared_secret(input);
        }
        let Some(material) = self.ecdh_material() else {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        };
        let Some(point) = external_public_key(input) else {
            return Response::status(Sw::WRONG_DATA);
        };
        if point.len() != 65 {
            return Response::status(Sw::WRONG_DATA);
        }
        let Some(cipher) = tlv::find(input, 0x80).or_else(|| {
            let cipher = tlv::find(input, 0xA6)?;
            tlv::find(cipher, 0x80)
        }) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Ok(public) = p256::PublicKey::from_sec1_bytes(point) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Ok(secret) = p256::SecretKey::from_slice(&self.keys[1].material[..32]) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        let fingerprint = material.fingerprint.or_else(|| self.fingerprint(1));
        let Some(fingerprint) = fingerprint else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let Some(param) = ecdh::param(
            ecdh::CURVE_OID_P256,
            ecdh::ALG_ECDH,
            material.kdf_hash,
            material.kek_alg,
            &fingerprint,
        ) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let kek_len = match material.kek_alg {
            7 => 16,
            8 => 24,
            9 => 32,
            _ => return Response::status(Sw::WRONG_DATA),
        };
        let Some(kek) = ecdh::kdf(&param, shared.raw_secret_bytes().as_slice(), kek_len) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let Some(unwrapped) = ecdh::aes_key_unwrap(&kek, &material.wrapped) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let Some(session_key) = session_key_from_wrapped(&unwrapped) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let Some(decrypted) = pgp_sym::decrypt_aes(&session_key, cipher) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        if !decrypted.mdc_verified {
            // The modification detection code does not match: the data was
            // tampered with or the key is wrong.
            return Response::status(Sw::WRONG_DATA);
        }
        self.out.clear();
        if self.out.extend_from_slice(&decrypted.data).is_err() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    /// The RFC 6637 material of the decryption slot, when it is provisioned.
    fn ecdh_material(&self) -> Option<EcdhMaterial> {
        if !self.keys[1].present || self.keys[1].effective_algo(1) != KEY_ALGO_ECDH_P256 {
            return None;
        }
        EcdhMaterial::from_slot(&self.keys[1])
    }

    /// The partial decrypt of the OpenPGP card specification (section 4.4.3.8).
    ///
    /// The card calculates the shared secret with its own private key and the
    /// external public key of the command, and returns it: the host derives
    /// the session key and decrypts the message. The host cannot compute the
    /// shared secret by itself, because the ephemeral key of the message was
    /// chosen by the sender.
    fn decipher_ecdh_shared_secret(&mut self, input: &[u8]) -> Response<'_> {
        let Some(point) = external_public_key(input) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Ok(public) = p256::PublicKey::from_sec1_bytes(point) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Ok(secret) = p256::SecretKey::from_slice(&self.keys[1].material[..32]) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        self.out.clear();
        if self
            .out
            .extend_from_slice(shared.raw_secret_bytes().as_slice())
            .is_err()
        {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    /// The partial decrypt of the OpenPGP card specification for Curve25519.
    fn decipher_ecdh_x25519(&mut self, input: &[u8]) -> Response<'_> {
        let Some(point) = external_public_key(input) else {
            return Response::status(Sw::WRONG_DATA);
        };
        if point.len() != 32 {
            return Response::status(Sw::WRONG_DATA);
        }
        let mut peer = [0u8; 32];
        peer.copy_from_slice(point);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.keys[1].material[..32]);
        let secret = x25519_dalek::StaticSecret::from(seed);
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        self.out.clear();
        if self.out.extend_from_slice(&shared.to_bytes()).is_err() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn verify_change(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        let admin = apdu.p2 == 0x83;
        if !matches!(apdu.p2, 0x81..=0x83) {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        // Changing the admin PIN is session-gated like `reset_retry`: the
        // authority comes from the session, not only from the body. The
        // refusal happens before the slot is touched, so no attempt is
        // consumed and nothing is persisted.
        if admin && !self.pw3_verified {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if admin {
            if apdu.data.len() != 16 {
                return Response::status(Sw::WRONG_DATA);
            }
            let result = self.pw3.change(&apdu.data[..8], &apdu.data[8..]);
            return self.finish_change(result);
        }
        // The user slot accepts the body shape the OpenPGP Card 7.2.3
        // defines: `current‖new` concatenated with no delimiter, `Lnew =
        // Lc − Lold`, each half inside the slot's policy window. Outside
        // the window the format is refused without touching the slot — no
        // attempt consumed and no save.
        if !(2 * PW_POLICY.min_len..=2 * PW_POLICY.max_len).contains(&apdu.data.len()) {
            return Response::status(Sw::WRONG_DATA);
        }
        let result = self.change_pw1(apdu.data);
        self.finish_change(result)
    }

    /// The user-slot change: the slot delimits the current half by its own
    /// stored hash (the length of the current PIN is known in the card), and
    /// a body no candidate can delimit costs one attempt — the same price a
    /// wrong current PIN on a fixed-width shape always paid.
    fn change_pw1(&mut self, body: &[u8]) -> Result<(), Sw> {
        let split = match self.pw1.resolve_change(body) {
            Ok(Some(split)) => split,
            Ok(None) => {
                return Err(Sw::retries_left(self.pw1.retries_remaining()));
            }
            Err(sw) => return Err(sw),
        };
        self.pw1.change(&body[..split], &body[split..])
    }

    /// The shared tail of both slots: persist under the fail-closed floor
    /// rules and map the change result, so a failed save is never confirmed
    /// as a successful change.
    fn finish_change(&mut self, result: Result<(), Sw>) -> Response<'_> {
        if self.persist_state() {
            Response::status(result.err().unwrap_or(Sw::OK))
        } else {
            // The new hash lives only in RAM: a failed save must never be
            // confirmed as a successful change.
            Response::status(Sw::NOT_ENOUGH_MEMORY)
        }
    }

    fn reset_retry(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        // P1 names the authority: 0x02 = the PW3 verified earlier, 0x00 = the
        // resetting code, which this foundation never provisions.
        if apdu.p1 != 0x02 || apdu.p2 != 0x81 {
            return Response::status(if apdu.p1 == 0x00 {
                Sw::FUNCTION_NOT_SUPPORTED
            } else {
                Sw::INCORRECT_PARAMETERS
            });
        }
        if !self.pw3_verified {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        if apdu.data.len() != 8 {
            return Response::status(Sw::WRONG_DATA);
        }
        let result = self.pw1.unblock(apdu.data);
        if self.persist_state() {
            Response::status(result.err().unwrap_or(Sw::OK))
        } else {
            // The unblock lives only in RAM (and its floor cannot rise above
            // the consumed counter): never confirm it with `9000`.
            Response::status(Sw::NOT_ENOUGH_MEMORY)
        }
    }
}

impl<S: OpenPgpStore> Applet for OpenPgp<S> {
    fn aid(&self) -> &'static [u8] {
        crate::aid::OPENPGP
    }

    fn select(&mut self) -> Response<'_> {
        self.loaded = false;
        // The session floors are deliberately not reset: a re-select reloads
        // the sealed store and must never undo a failed save of this session.
        self.ensure_loaded();
        self.pw1_signature_verified = false;
        self.pw1_other_verified = false;
        self.pw3_verified = false;
        Response::ok(&[])
    }

    fn process(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_> {
        match apdu.ins {
            INS_VERIFY => self.verify(apdu),
            INS_CHANGE_REFERENCE_DATA => self.verify_change(apdu),
            INS_RESET_RETRY_COUNTER => self.reset_retry(apdu),
            INS_GET_DATA => self.get_data(apdu),
            INS_PUT_DATA => self.put_data(apdu),
            INS_PSO if apdu.p1 == 0x9E && apdu.p2 == 0x9A => self.sign(apdu.data, rng),
            INS_PSO if apdu.p1 == 0x80 && apdu.p2 == 0x86 => self.decipher(apdu.data, rng),
            INS_INTERNAL_AUTHENTICATE => self.internal_authenticate(apdu.data, rng),
            INS_GENERATE if apdu.p1 == 0x80 => self.generate(apdu, rng),
            INS_GENERATE if apdu.p1 == 0x81 => self.read_public(apdu),
            INS_GET_CHALLENGE => {
                let length = apdu.expected_len().clamp(1, 64);
                self.out.resize(length, 0).ok();
                rng.fill_bytes(&mut self.out[..length]);
                Response::ok(&self.out)
            }
            INS_SELECT_DATA | INS_ACTIVATE_FILE => Response::status(Sw::OK),
            _ => Response::status(Sw::INS_NOT_SUPPORTED),
        }
    }
}

/// Normalize an RSA decipher payload to the 256-byte ciphertext block:
/// a bare block, a `00|02`-prefixed block (card spec decipher input
/// shape), or an MPI whose bit length matches the trailing octets.
fn rsa_cipher_block(payload: &[u8]) -> Option<[u8; rsa::RSA2048_BYTES]> {
    if payload.len() == rsa::RSA2048_BYTES {
        let mut block = [0u8; rsa::RSA2048_BYTES];
        block.copy_from_slice(payload);
        return Some(block);
    }
    if payload.len() == rsa::RSA2048_BYTES + 1 && (payload[0] == 0x00 || payload[0] == 0x02) {
        let mut block = [0u8; rsa::RSA2048_BYTES];
        block.copy_from_slice(&payload[1..]);
        return Some(block);
    }
    if payload.len() >= 3 && payload.len() <= rsa::RSA2048_BYTES + 2 {
        let bits = u16::from_be_bytes([payload[0], payload[1]]);
        let octets = &payload[2..];
        if usize::from(bits) <= 2048 && usize::from(bits).div_ceil(8) == octets.len() {
            let mut block = [0u8; rsa::RSA2048_BYTES];
            block[rsa::RSA2048_BYTES - octets.len()..].copy_from_slice(octets);
            return Some(block);
        }
    }
    None
}

fn append_tlv<const N: usize>(out: &mut Vec<u8, N>, tag: u32, value: &[u8]) -> bool {
    let needed = tlv::encoded_len(tag, value.len());
    let start = out.len();
    if start + needed > out.capacity() || out.resize(start + needed, 0).is_err() {
        return false;
    }
    tlv::write(tag, value, &mut out[start..]).is_some()
}

fn replace_vec<const N: usize>(target: &mut Vec<u8, N>, value: &[u8], max: usize) -> bool {
    if value.len() > max {
        return false;
    }
    target.clear();
    target.extend_from_slice(value).is_ok()
}

/// Exact bit length of an MPI body (RFC 4880 section 3.2).
fn mpi_bits(octets: &[u8]) -> u16 {
    let mut bits = octets.len() * 8;
    for byte in octets {
        if *byte == 0 {
            bits -= 8;
        } else {
            bits -= byte.leading_zeros() as usize;
            break;
        }
    }
    bits as u16
}

fn public_key_response<'a>(out: &'a mut Vec<u8, 2048>, point: &[u8]) -> Response<'a> {
    let mut body = Vec::<u8, 128>::new();
    // The public key of an EC key is the tag 86 (the tag 81 carries the
    // modulus of an RSA key).
    append_tlv(&mut body, 0x86, point);
    out.clear();
    if !append_tlv(out, 0x7F49, &body) {
        return Response::status(Sw::NOT_ENOUGH_MEMORY);
    }
    Response::ok(out)
}

/// RSA `GENERATE`/`READ PUBLIC` answer: `7F49 { 81 modulus, 82 exponent }`
/// with the minimal big-endian exponent.
fn rsa_public_key_response<'a>(
    out: &'a mut Vec<u8, 2048>,
    modulus: &[u8; rsa::RSA2048_BYTES],
    exponent: u32,
) -> Response<'a> {
    let exp = exponent.to_be_bytes();
    let first = exp
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(exp.len() - 1);
    let mut body = Vec::<u8, 320>::new();
    if !append_tlv(&mut body, 0x81, modulus) || !append_tlv(&mut body, 0x82, &exp[first..]) {
        return Response::status(Sw::NOT_ENOUGH_MEMORY);
    }
    out.clear();
    if !append_tlv(out, 0x7F49, &body) {
        return Response::status(Sw::NOT_ENOUGH_MEMORY);
    }
    Response::ok(out)
}

fn public_point(scalar: &[u8]) -> Option<[u8; 65]> {
    let key = p256::ecdsa::SigningKey::from_slice(&scalar[..32]).ok()?;
    let point = key.verifying_key().to_sec1_point(false);
    let mut output = [0u8; 65];
    output.copy_from_slice(point.as_bytes());
    Some(output)
}

fn generate_p256(rng: &mut dyn Rng, scalar: &mut [u8; 48], point: &mut [u8; 65]) -> bool {
    for _ in 0..64 {
        rng.fill_bytes(&mut scalar[..32]);
        if let Some(public) = public_point(scalar) {
            point.copy_from_slice(&public);
            return true;
        }
    }
    false
}

fn left_pad_digest(input: &[u8], size: usize) -> Option<[u8; 32]> {
    if input.len() > size || size > 32 {
        return None;
    }
    let mut output = [0u8; 32];
    output[size - input.len()..size].copy_from_slice(input);
    Some(output)
}

fn decode_pin(bytes: &[u8], cursor: &mut usize, policy: PinPolicy) -> Option<PinSlot> {
    let len = crate::pin::PIN_STATE_LEN;
    let raw = take(bytes, cursor, len)?;
    PinSlot::decode(policy, raw).ok()
}

/// Lower a reloaded slot counter to `floor` when the store carried a more
/// permissive one.
///
/// [`PinSlot`] does no I/O and exposes no counter setter (the counter only
/// moves through the framework itself), so the clamp goes through the sealed
/// encoding: the floor never exceeds the policy maximum, therefore the
/// re-decoded state stays valid. On any encoding failure the slot is kept as
/// it was: the clamp is already in the restrictive direction.
fn clamp_to_floor(slot: &mut PinSlot, floor: u8) {
    if slot.retries_remaining() <= floor {
        return;
    }
    let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
    if slot.encode(&mut encoded).is_err() {
        return;
    }
    encoded[2] = floor;
    if let Ok(clamped) = PinSlot::decode(slot.policy(), &encoded) {
        *slot = clamped;
    }
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Option<u8> {
    let value = *bytes.get(*cursor)?;
    *cursor += 1;
    Some(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    Some(u16::from_be_bytes(take(bytes, cursor, 2)?.try_into().ok()?))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    Some(u32::from_be_bytes(take(bytes, cursor, 4)?.try_into().ok()?))
}

fn decode_len_bytes<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<Vec<u8, N>> {
    let len = usize::from(take_u8(bytes, cursor)?);
    if len > N {
        return None;
    }
    let raw = take(bytes, cursor, N)?;
    let mut value = Vec::new();
    value.extend_from_slice(&raw[..len]).ok()?;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    mod adversarial_apdu;
    mod gnupg_interop;
    mod response_window;
    mod state_roundtrip;

    /// The OpenPGP Card 3.4.1 section 4.4.3.10 returns the public key of an EC key
    /// under the tag 86; the tag 81 carries the modulus of an RSA key.
    #[test]
    fn ec_public_key_response_uses_the_spec_tag() {
        let mut out = Vec::<u8, 2048>::new();
        let response = public_key_response(&mut out, &[0x04; 65]);
        assert_eq!(response.sw, Sw::OK);
        assert_eq!(&response.data[..2], &[0x7F, 0x49]);
        let template = tlv::find(response.data, 0x7F49).unwrap();
        assert_eq!(tlv::find(template, 0x86).unwrap().len(), 65);
        assert_eq!(tlv::find(template, 0x81), None);
    }

    struct TestRng(u64);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *byte = (self.0 >> 33) as u8;
            }
        }
    }

    fn applet() -> OpenPgp<MemoryOpenPgpStore> {
        let mut applet = OpenPgp::new(MemoryOpenPgpStore::new());
        assert_eq!(applet.select().sw, Sw::OK);
        applet
    }

    /// A store wrapper that delegates to `MemoryOpenPgpStore` and can be
    /// switched to reject every save, standing in for a worn-out flash.
    ///
    /// It counts the observed saves so tests can prove which commands do and
    /// do not touch the store.
    struct FlakyOpenPgpStore {
        inner: MemoryOpenPgpStore,
        save_fails: bool,
        save_calls: u32,
    }

    impl FlakyOpenPgpStore {
        fn new(inner: MemoryOpenPgpStore) -> Self {
            Self {
                inner,
                save_fails: false,
                save_calls: 0,
            }
        }

        fn set_save_fails(&mut self, fails: bool) {
            self.save_fails = fails;
        }
    }

    impl OpenPgpStore for FlakyOpenPgpStore {
        fn load(&mut self, out: &mut [u8]) -> Option<usize> {
            self.inner.load(out)
        }

        fn save(&mut self, data: &[u8]) -> bool {
            self.save_calls += 1;
            if self.save_fails {
                false
            } else {
                self.inner.save(data)
            }
        }

        fn clear(&mut self) -> bool {
            self.inner.clear()
        }
    }

    fn frame(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8, 2048> {
        let mut output = Vec::new();
        output.extend_from_slice(&[0x00, ins, p1, p2]).unwrap();
        if data.is_empty() {
            // Case 1.
        } else if data.len() < 256 {
            output.push(data.len() as u8).unwrap();
            output.extend_from_slice(data).unwrap();
        } else {
            // Extended Lc (RSA decipher blocks exceed one short length).
            let len = data.len() as u16;
            output
                .extend_from_slice(&[0x00, (len >> 8) as u8, len as u8])
                .unwrap();
            output.extend_from_slice(data).unwrap();
        }
        output
    }

    fn run<S: OpenPgpStore>(
        applet: &mut OpenPgp<S>,
        rng: &mut TestRng,
        frame: &[u8],
    ) -> (Vec<u8, 2048>, Sw) {
        let command = Apdu::parse(frame).unwrap();
        let response = applet.process(&command, rng);
        let mut data = Vec::new();
        data.extend_from_slice(response.data).unwrap();
        (data, response.sw)
    }

    fn verify_pw3<S: OpenPgpStore>(applet: &mut OpenPgp<S>, rng: &mut TestRng) {
        assert_eq!(
            run(applet, rng, &frame(INS_VERIFY, 0, 0x83, b"12345678")).1,
            Sw::OK
        );
    }

    fn verify_pw1_sig(applet: &mut OpenPgp<MemoryOpenPgpStore>, rng: &mut TestRng) {
        assert_eq!(
            run(applet, rng, &frame(INS_VERIFY, 0, 0x81, b"123456")).1,
            Sw::OK
        );
    }

    fn generate<S: OpenPgpStore>(
        applet: &mut OpenPgp<S>,
        rng: &mut TestRng,
        tag: u8,
    ) -> Vec<u8, 2048> {
        let data = [tag, 0x00];
        let (response, status) = run(applet, rng, &frame(INS_GENERATE, 0x80, 0, &data));
        assert_eq!(status, Sw::OK);
        response
    }

    #[test]
    fn select_and_application_data_are_available() {
        let mut applet = applet();
        assert_eq!(applet.aid(), crate::aid::OPENPGP);
        let mut rng = TestRng(1);
        let command = [0x00, INS_GET_DATA, 0x00, 0x6E, 0x00];
        let (data, status) = run(&mut applet, &mut rng, &command);
        assert_eq!(status, Sw::OK);
        assert!(tlv::find(&data, TAG_APP_DATA).is_some());
        let app_data = tlv::find(&data, TAG_APP_DATA).unwrap();
        assert!(tlv::find(app_data, TAG_AID).is_some());
        assert!(
            tlv::find(
                tlv::find(app_data, TAG_DISCRETIONARY).unwrap(),
                TAG_ALGO_SIG
            )
            .is_some()
        );
        assert!(
            tlv::find(
                tlv::find(app_data, TAG_DISCRETIONARY).unwrap(),
                TAG_PW_STATUS
            )
            .is_some()
        );
    }

    #[test]
    fn default_passwords_verify_and_c4_reports_retries() {
        let mut applet = applet();
        let mut rng = TestRng(2);
        let command = [0x00, INS_GET_DATA, 0x00, 0xC4, 0x00];
        let (data, status) = run(&mut applet, &mut rng, &command);
        assert_eq!(status, Sw::OK);
        assert_eq!(data.len(), 7);
        assert_eq!(data[4..], [3, 0, 3]);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x83, b"wrong")).1,
            Sw::retries_left(2)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn generate_p256_and_compute_signature() {
        let mut applet = applet();
        let mut rng = TestRng(3);
        verify_pw3(&mut applet, &mut rng);
        let public = generate(&mut applet, &mut rng, 0xB6);
        let public_template = tlv::find(&public, 0x7F49).unwrap();
        let point = tlv::find(public_template, 0x86).unwrap();
        assert_eq!(point.len(), 65);

        verify_pw1_sig(&mut applet, &mut rng);
        let digest = [0xA5; 32];
        let (signature, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x9E, 0x9A, &digest));
        assert_eq!(status, Sw::OK);
        // OpenPGP card ECDSA signatures are raw fixed-size r||s, not DER.
        assert_eq!(signature.len(), 64);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&signature).unwrap();
        key.verify_prehash(&digest, &sig).unwrap();
    }

    #[test]
    fn internal_authenticate_uses_the_authentication_key() {
        let mut applet = applet();
        let mut rng = TestRng(4);
        verify_pw3(&mut applet, &mut rng);
        let public = generate(&mut applet, &mut rng, 0xA4);
        let public_template = tlv::find(&public, 0x7F49).unwrap();
        let point = tlv::find(public_template, 0x86).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );
        let digest = [0x11; 32];
        let (signature, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_INTERNAL_AUTHENTICATE, 0, 0, &digest),
        );
        assert_eq!(status, Sw::OK);
        assert_eq!(signature.len(), 64);
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&signature).unwrap();
        key.verify_prehash(&digest, &sig).unwrap();
    }

    #[test]
    fn pso_decipher_unwraps_the_session_key_and_decrypts() {
        let (mut applet, mut rng, command, plaintext) = decipher_fixture();
        let (plain, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
        assert_eq!(status, Sw::OK);
        assert_eq!(&plain[..], &plaintext[18..plaintext.len() - 22]);
    }

    /// An applet provisioned exactly as the full decipher flow above: the
    /// card has an ECDH P-256 key, the sender wrapped its session key with
    /// the KDF parameters of an imported fingerprint and the message is the
    /// prefix, the literal data and the modification detection code.
    ///
    /// Returns the applet, its RNG and the `PSO: DECIPHER` command with the
    /// well-formed ciphertext.
    fn decipher_fixture() -> (
        OpenPgp<MemoryOpenPgpStore>,
        TestRng,
        Vec<u8, 512>,
        Vec<u8, 256>,
    ) {
        use p256::elliptic_curve::sec1::ToSec1Point;
        use sha1::Digest as _;

        let mut applet = applet();
        let mut rng = TestRng(5);
        verify_pw3(&mut applet, &mut rng);
        let public = generate(&mut applet, &mut rng, 0xB8);
        let card_point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap();
        assert_eq!(card_point.len(), 65);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );

        let ephemeral = p256::SecretKey::from_slice(&[9u8; 32]).unwrap();
        let ephemeral_point = ephemeral.public_key().to_sec1_point(false);
        let card_public = p256::PublicKey::from_sec1_bytes(card_point).unwrap();
        let shared =
            p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card_public.as_affine());
        let mut fingerprint = applet.fingerprint(1).expect("the slot has a fingerprint");
        fingerprint[0] ^= 0xFF;
        let param = ecdh::param(
            ecdh::CURVE_OID_P256,
            ecdh::ALG_ECDH,
            ecdh::HASH_SHA256,
            ecdh::KEK_AES128,
            &fingerprint,
        )
        .unwrap();
        let kek = ecdh::kdf(&param, shared.raw_secret_bytes().as_slice(), 16).unwrap();
        let session_key = adversarial_apdu::session_key(&mut rng);
        let checksum = session_key
            .iter()
            .fold(0u16, |acc, byte| acc.wrapping_add(u16::from(*byte)));
        let mut m: Vec<u8, 64> = Vec::new();
        m.push(7u8).unwrap();
        m.extend_from_slice(&session_key).unwrap();
        m.extend_from_slice(&checksum.to_be_bytes()).unwrap();
        m.resize(24, 0x05).unwrap();
        let wrapped = ecdh::aes_key_wrap(&kek, &m).unwrap();

        let mut import: Vec<u8, 64> = Vec::new();
        import.push(wrapped.len() as u8).unwrap();
        import.extend_from_slice(&wrapped).unwrap();
        import.push(ecdh::HASH_SHA256).unwrap();
        import.push(ecdh::KEK_AES128).unwrap();
        import.extend_from_slice(&fingerprint).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );

        let data = b"AegisToken card side ECDH";
        let mut prefix = [0x11u8; 16];
        prefix[14] = prefix[12];
        prefix[15] = prefix[13];
        let mut plaintext: Vec<u8, 256> = Vec::new();
        plaintext.extend_from_slice(&prefix).unwrap();
        plaintext
            .extend_from_slice(&[prefix[14], prefix[15]])
            .unwrap();
        plaintext.extend_from_slice(data).unwrap();
        plaintext.extend_from_slice(&[0xD3, 0x14]).unwrap();
        let mut digest = sha1::Sha1::new();
        digest.update(&plaintext);
        plaintext.extend_from_slice(&digest.finalize()).unwrap();
        let ciphertext = pgp_sym::encrypt_aes(&session_key, &plaintext).unwrap();

        let mut command: Vec<u8, 512> = Vec::new();
        append_tlv(&mut command, 0x86, ephemeral_point.as_bytes());
        append_tlv(&mut command, 0x80, &ciphertext);
        (applet, rng, command, plaintext)
    }

    #[test]
    fn decipher_reports_pro_sw_for_quick_check_mdc_and_success() {
        let (mut applet, mut rng, command, plaintext) = decipher_fixture();

        // The TLV of the ciphertext inside the command: the tag, the length
        // and the 65 bytes of the ephemeral point before it.
        let cipher_start = 1 + 1 + 66 + 2;

        // The happy path: the literal data comes back under 9000.
        let (plain, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
        assert_eq!(sw, Sw::OK);
        assert_eq!(plain.as_slice(), &plaintext[18..plaintext.len() - 22]);

        // A broken quick-check octet: no diagnosis, like every other
        // structural refusal of the decipher.
        let mut broken = command.clone();
        broken[cipher_start] ^= 0x01;
        let (_, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &broken));
        assert_eq!(sw, Sw::NO_PRECISE_DIAGNOSIS);

        // A corrupted modification detection code: the data is recognized,
        // the integrity check fails with the dedicated status.
        let mut corrupted = command.clone();
        corrupted[command.len() - 1] ^= 0x01;
        let (_, sw) = run(
            &mut applet,
            &mut rng,
            &frame(INS_PSO, 0x80, 0x86, &corrupted),
        );
        assert_eq!(sw, Sw::WRONG_DATA);
    }

    #[test]
    fn the_fingerprint_is_an_optional_part_of_the_provisioning() {
        let mut applet = applet();
        let mut rng = TestRng(5);
        verify_pw3(&mut applet, &mut rng);
        let _ = generate(&mut applet, &mut rng, 0xB8);

        // The wrapped session key alone: the card falls back to the
        // fingerprint it computes itself.
        let wrapped = [0x11u8; 24];
        let mut import: Vec<u8, 64> = Vec::new();
        import.push(wrapped.len() as u8).unwrap();
        import.extend_from_slice(&wrapped).unwrap();
        import.push(ecdh::HASH_SHA256).unwrap();
        import.push(ecdh::KEK_AES128).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );
        let material = applet.ecdh_material().expect("the material is provisioned");
        assert_eq!(material.fingerprint, None, "no fingerprint was provisioned");

        // With the 20 octets of the sender the card keeps the value the
        // sender used in the KDF (the end-to-end check is in
        // `pso_decipher_unwraps_the_session_key_and_decrypts`).
        let mut recipient = [0x22u8; 20];
        recipient[0] = 0x01;
        import.extend_from_slice(&recipient).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );
        let material = applet.ecdh_material().expect("the material is provisioned");
        assert_eq!(material.fingerprint, Some(recipient));
        assert_eq!(material.wrapped.as_slice(), &wrapped);
    }

    #[test]
    fn d2_accepts_the_supported_kdf_hash_and_keeps_the_material() {
        let mut applet = applet();
        let mut rng = TestRng(20);
        verify_pw3(&mut applet, &mut rng);
        let _ = generate(&mut applet, &mut rng, 0xB8);

        // The provisioner the interop deems valid: SHA-256 and AES-128. The
        // wrapped session key alone: the card falls back to the fingerprint
        // it computes itself.
        let wrapped = [0x11u8; 24];
        let mut import: Vec<u8, 64> = Vec::new();
        import.push(wrapped.len() as u8).unwrap();
        import.extend_from_slice(&wrapped).unwrap();
        import.push(ecdh::HASH_SHA256).unwrap();
        import.push(ecdh::KEK_AES128).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );
        let material = applet.ecdh_material().expect("the material is provisioned");
        assert_eq!(material.wrapped.as_slice(), &wrapped);
        assert_eq!(material.kdf_hash, ecdh::HASH_SHA256);
        assert_eq!(material.kek_alg, ecdh::KEK_AES128);
        assert_eq!(material.fingerprint, None);

        // With the fingerprint of the sender: every provisioned byte survives.
        let mut recipient = [0x22u8; 20];
        recipient[0] = 0x01;
        import.extend_from_slice(&recipient).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );
        let material = applet.ecdh_material().expect("the material is provisioned");
        assert_eq!(material.wrapped.as_slice(), &wrapped);
        assert_eq!(material.kdf_hash, ecdh::HASH_SHA256);
        assert_eq!(material.kek_alg, ecdh::KEK_AES128);
        assert_eq!(material.fingerprint, Some(recipient));
    }

    #[test]
    fn d2_rejects_unsupported_kdf_hash_without_touching_the_slot() {
        let mut rng = TestRng(21);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_GENERATE, 0x80, 0, &[0xB8, 0x00])
            )
            .1,
            Sw::OK
        );

        // A valid material is anchored first so a refusal has something to
        // leave intact.
        let wrapped = [0x33u8; 32];
        let mut import: Vec<u8, 64> = Vec::new();
        import.push(wrapped.len() as u8).unwrap();
        import.extend_from_slice(&wrapped).unwrap();
        import.push(ecdh::HASH_SHA256).unwrap();
        import.push(ecdh::KEK_AES128).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );
        let material = applet.ecdh_material().expect("the material is anchored");
        let saves_before = applet.store.save_calls;

        // Every hash outside the implemented KDF is refused at the border
        // with `WRONG_DATA`, the slot keeps the anchored material and the
        // refusal emits no save at all.
        for hash in [0x00, 0x02, 0x09, 0x0A, 0xFF] {
            let mut mutant = import.clone();
            mutant[1 + wrapped.len()] = hash;
            assert_eq!(
                run(
                    &mut applet,
                    &mut rng,
                    &frame(INS_PUT_DATA, 0x00, 0xD2, &mutant)
                )
                .1,
                Sw::WRONG_DATA,
                "zero is not a supported hash"
            );
            assert_eq!(
                applet.ecdh_material().expect("the slot is intact"),
                material,
                "the refused import changed nothing"
            );
            assert_eq!(
                applet.store.save_calls, saves_before,
                "no save on a refusal"
            );
        }
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            applet
                .ecdh_material()
                .expect("the reload recovers the material"),
            material,
            "the reload never resurrects the refused material"
        );
    }

    #[test]
    fn d2_rejects_wrapped_len_outside_the_key_wrap_domain() {
        let mut applet = applet();
        let mut rng = TestRng(22);
        verify_pw3(&mut applet, &mut rng);
        let _ = generate(&mut applet, &mut rng, 0xB8);

        // A valid material anchored to prove the refusals never overwrite it.
        let wrapped = [0x44u8; 24];
        let mut import: Vec<u8, 64> = Vec::new();
        import.push(wrapped.len() as u8).unwrap();
        import.extend_from_slice(&wrapped).unwrap();
        import.push(ecdh::HASH_SHA256).unwrap();
        import.push(ecdh::KEK_AES128).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );
        let material = applet.ecdh_material().expect("the material is anchored");

        // The consumers only ever see RFC 3394 blocks of a real session key:
        // zero (regression), 8 and 16 (below the smallest real block, new),
        // 25 (off the 8-octet granularity, new) and 49 (above the cap,
        // regression) are all refused with the slot intact.
        for wrapped_len in [0, 8, 16, 25, 49] {
            let mut mutant: Vec<u8, 64> = Vec::new();
            mutant.push(wrapped_len as u8).unwrap();
            mutant.resize(1 + wrapped_len, 0x55).unwrap();
            mutant.push(ecdh::HASH_SHA256).unwrap();
            mutant.push(ecdh::KEK_AES128).unwrap();
            assert_eq!(
                run(
                    &mut applet,
                    &mut rng,
                    &frame(INS_PUT_DATA, 0x00, 0xD2, &mutant)
                )
                .1,
                Sw::WRONG_DATA,
                "the wrapped length leaves the key wrap domain"
            );
            assert_eq!(
                applet.ecdh_material().expect("the slot is intact"),
                material,
                "the refused import changed nothing"
            );
        }

        // Total length off `base`/`base + 20` stays refused (regression).
        let mut off_base = import.clone();
        off_base.push(0x01).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &off_base)
            )
            .1,
            Sw::WRONG_DATA,
            "the body length still has to match the declared one"
        );
        assert_eq!(
            applet.ecdh_material().expect("the slot is intact"),
            material
        );
    }

    #[test]
    fn decipher_fails_closed_without_the_provisioned_fingerprint() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        use sha1::Digest as _;

        let mut applet = applet();
        let mut rng = TestRng(23);
        verify_pw3(&mut applet, &mut rng);
        let public = generate(&mut applet, &mut rng, 0xB8);
        let card_point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap();
        assert_eq!(card_point.len(), 65);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );

        let ephemeral = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
        let ephemeral_point = ephemeral.public_key().to_sec1_point(false);
        let card_public = p256::PublicKey::from_sec1_bytes(card_point).unwrap();
        let shared =
            p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card_public.as_affine());
        // The sender used a fingerprint that the card does not hold: without
        // the provisioned value the card cannot reconstruct the KDF
        // parameters, and it must not guess them (the interop exercises the
        // same case against a real GnuPG).
        let mut fingerprint = applet.fingerprint(1).expect("the slot has a fingerprint");
        fingerprint[0] ^= 0xFF;
        let param = ecdh::param(
            ecdh::CURVE_OID_P256,
            ecdh::ALG_ECDH,
            ecdh::HASH_SHA256,
            ecdh::KEK_AES128,
            &fingerprint,
        )
        .unwrap();
        let kek = ecdh::kdf(&param, shared.raw_secret_bytes().as_slice(), 16).unwrap();

        let session_key = adversarial_apdu::session_key(&mut rng);
        let checksum = session_key
            .iter()
            .fold(0u16, |acc, byte| acc.wrapping_add(u16::from(*byte)));
        let mut m: Vec<u8, 64> = Vec::new();
        m.push(7u8).unwrap();
        m.extend_from_slice(&session_key).unwrap();
        m.extend_from_slice(&checksum.to_be_bytes()).unwrap();
        m.resize(24, 0x05).unwrap();
        let wrapped = ecdh::aes_key_wrap(&kek, &m).unwrap();

        // The import is valid on its own, but carries no fingerprint.
        let mut import: Vec<u8, 64> = Vec::new();
        import.push(wrapped.len() as u8).unwrap();
        import.extend_from_slice(&wrapped).unwrap();
        import.push(ecdh::HASH_SHA256).unwrap();
        import.push(ecdh::KEK_AES128).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );

        let data = b"nothing leaves without the fingerprint";
        let mut prefix = [0x11u8; 16];
        prefix[14] = prefix[12];
        prefix[15] = prefix[13];
        let mut plaintext: Vec<u8, 256> = Vec::new();
        plaintext.extend_from_slice(&prefix).unwrap();
        plaintext
            .extend_from_slice(&[prefix[14], prefix[15]])
            .unwrap();
        plaintext.extend_from_slice(data).unwrap();
        plaintext.extend_from_slice(&[0xD3, 0x14]).unwrap();
        let mut digest = sha1::Sha1::new();
        digest.update(&plaintext);
        plaintext.extend_from_slice(&digest.finalize()).unwrap();
        let ciphertext = pgp_sym::encrypt_aes(&session_key, &plaintext).unwrap();

        let mut command: Vec<u8, 512> = Vec::new();
        append_tlv(&mut command, 0x86, ephemeral_point.as_bytes());
        append_tlv(&mut command, 0x80, &ciphertext);
        let (plain, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
        assert_ne!(status, Sw::OK, "the card does not guess the KDF parameters");
        assert!(plain.is_empty(), "the card returns nothing on the failure");
    }

    #[test]
    fn the_decryption_slot_exports_the_nist_kdf_parameters() {
        use sha1::Digest as _;

        let mut applet = applet();
        let mut rng = TestRng(24);
        verify_pw3(&mut applet, &mut rng);
        let public = generate(&mut applet, &mut rng, 0xB8);
        let (response, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_GENERATE, 0x81, 0, &[0xB8, 0x00]),
        );
        assert_eq!(status, Sw::OK);
        let template = tlv::find(&response, 0x7F49).unwrap();
        let point = tlv::find(template, 0x86).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(
            point,
            tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap(),
            "the export is stable"
        );

        // The v4 fingerprint of the slot covers the KDF-DO of NIST P-256
        // (SHA-256 and AES-128), the parameters the interop provisions
        // against: rebuild the expected value independently of the applet.
        let mut body: Vec<u8, 128> = Vec::new();
        body.push(0x04).unwrap();
        body.extend_from_slice(&[0; 4]).unwrap();
        body.push(0x12).unwrap();
        body.push(ecdh::CURVE_OID_P256.len() as u8).unwrap();
        body.extend_from_slice(ecdh::CURVE_OID_P256).unwrap();
        // 515 bits: the MPI of a P-256 point (65 octets with the leading
        // `0x04` of the SEC1 uncompressed form).
        body.extend_from_slice(&0x0203u16.to_be_bytes()).unwrap();
        body.extend_from_slice(point).unwrap();
        body.extend_from_slice(&[0x03, 0x01, 0x08, 0x07]).unwrap();
        let mut input: Vec<u8, 136> = Vec::new();
        input.push(0x99).unwrap();
        input
            .extend_from_slice(&(body.len() as u16).to_be_bytes())
            .unwrap();
        input.extend_from_slice(&body).unwrap();
        let expected: [u8; 20] = sha1::Sha1::digest(&input).into();
        assert_eq!(
            applet.fingerprint(1).expect("the slot has a fingerprint"),
            expected
        );

        // The fingerprint DO carries it as the DEC entry of the aggregate.
        let (c5, status) = run(&mut applet, &mut rng, &frame(INS_GET_DATA, 0x00, 0xC5, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(&c5[20..40], &expected[..]);
    }

    #[test]
    fn pso_decipher_returns_the_shared_secret_per_the_card_spec() {
        let mut applet = applet();
        let mut rng = TestRng(5);
        verify_pw3(&mut applet, &mut rng);
        let _ = generate(&mut applet, &mut rng, 0xB8);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );

        let external = p256::SecretKey::from_slice(&[1u8; 32]).unwrap();
        use p256::elliptic_curve::sec1::ToSec1Point;
        let external_point = external.public_key().to_sec1_point(false);
        let mut point_tlv = Vec::<u8, 128>::new();
        append_tlv(&mut point_tlv, 0x86, external_point.as_bytes());
        let mut public_template = Vec::<u8, 160>::new();
        append_tlv(&mut public_template, 0x7F49, &point_tlv);
        let mut cipher = Vec::<u8, 192>::new();
        append_tlv(&mut cipher, 0xA6, &public_template);
        let (shared, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &cipher));
        // The OpenPGP card specification defines the ECDH decipher as a
        // partial decrypt: the card returns the shared secret and the host
        // does the rest. The host cannot compute it by itself, because the
        // ephemeral key of the message was chosen by the sender.
        assert_eq!(status, Sw::OK);
        assert_eq!(shared.len(), 32);
    }

    #[test]
    fn admin_data_write_requires_pw3() {
        let mut applet = applet();
        let mut rng = TestRng(6);
        let (data, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_PUT_DATA, 0x00, 0x5B, b"Alice"),
        );
        assert!(data.is_empty());
        assert_eq!(status, Sw::SECURITY_STATUS_NOT_SATISFIED);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0x5B, b"Alice")
            )
            .1,
            Sw::OK
        );
        let command = [0x00, INS_GET_DATA, 0x00, 0x5B, 0x00];
        assert_eq!(run(&mut applet, &mut rng, &command).0, b"Alice".as_slice());
    }

    #[test]
    fn state_survives_reopen() {
        let mut applet = applet();
        let mut rng = TestRng(7);
        verify_pw3(&mut applet, &mut rng);
        let _ = generate(&mut applet, &mut rng, 0xB6);
        let store = core::mem::take(applet.store_mut());
        let mut reopened = OpenPgp::new(store);
        assert_eq!(reopened.select().sw, Sw::OK);
        assert!(reopened.keys[0].present);
    }

    const ATTRS_ED25519: &[u8] = &[0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
    const ATTRS_X25519: &[u8] = &[
        0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
    ];
    const ATTRS_RSA2048: &[u8] = &[0x01, 0x08, 0x00, 0x00, 0x20];
    const ATTRS_RSA2048_IMPORT_FMT: &[u8] = &[0x01, 0x08, 0x00, 0x00, 0x20, 0x02];
    const ATTRS_RSA1024: &[u8] = &[0x01, 0x04, 0x00, 0x00, 0x20];

    fn put_attrs(
        applet: &mut OpenPgp<MemoryOpenPgpStore>,
        rng: &mut TestRng,
        tag: u8,
        attrs: &[u8],
    ) -> Sw {
        run(applet, rng, &frame(INS_PUT_DATA, 0x00, tag, attrs)).1
    }

    fn get_do(
        applet: &mut OpenPgp<MemoryOpenPgpStore>,
        rng: &mut TestRng,
        tag: u8,
    ) -> Vec<u8, 2048> {
        let command = [0x00, INS_GET_DATA, 0x00, tag, 0x00];
        let (data, status) = run(applet, rng, &command);
        assert_eq!(status, Sw::OK);
        data
    }

    #[test]
    fn put_data_c1_accepts_ed25519_rsa_and_rejects_others() {
        let mut applet = applet();
        let mut rng = TestRng(8);
        // Admin PIN required.
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_ED25519),
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        verify_pw3(&mut applet, &mut rng);
        // RSA-2048 (5-byte and 6-byte with import-format forms) is accepted
        // in the signature slot; other modulus sizes are not.
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_RSA1024),
            Sw::WRONG_DATA
        );
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_RSA2048),
            Sw::OK
        );
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_RSA2048_IMPORT_FMT),
            Sw::OK
        );
        assert_eq!(
            get_do(&mut applet, &mut rng, 0xC1),
            [0x01, 0x08, 0x00, 0x00, 0x20, 0x00]
        );
        // ECDH does not belong in the signature slot.
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_X25519),
            Sw::WRONG_DATA
        );
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_ED25519),
            Sw::OK
        );
        assert_eq!(get_do(&mut applet, &mut rng, 0xC1), ATTRS_ED25519);
        // RSA belongs in the decryption slot too, Ed25519 does not.
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_RSA2048),
            Sw::OK
        );
        assert_eq!(
            get_do(&mut applet, &mut rng, 0xC2),
            [0x01, 0x08, 0x00, 0x00, 0x20, 0x00]
        );
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_ED25519),
            Sw::WRONG_DATA
        );
        assert_eq!(put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_X25519), Sw::OK);
        assert_eq!(get_do(&mut applet, &mut rng, 0xC2), ATTRS_X25519);
    }

    /// DER DigestInfo for SHA-256 (RFC 8017 section 9.2) over `message`.
    fn digestinfo_sha256(message: &[u8]) -> Vec<u8, 64> {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(message);
        let mut info = Vec::new();
        info.extend_from_slice(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ])
        .unwrap();
        info.extend_from_slice(&hash).unwrap();
        info
    }

    /// PKCS#1 v1.5 type-2 padded block for decipher tests (host-side framing).
    fn pad_type2(message: &[u8], rng: &mut TestRng) -> Vec<u8, 300> {
        let mut block = Vec::new();
        block.extend_from_slice(&[0x00, 0x02]).unwrap();
        while block.len() < 256 - message.len() - 1 {
            let mut byte = [0u8; 1];
            rng.fill_bytes(&mut byte);
            if byte[0] != 0x00 {
                block.push(byte[0]).unwrap();
            }
        }
        block.push(0x00).unwrap();
        block.extend_from_slice(message).unwrap();
        block
    }

    fn rsa_modulus(public: &[u8]) -> [u8; crate::rsa::RSA2048_BYTES] {
        let template = tlv::find(public, 0x7F49).expect("key template");
        let modulus = tlv::find(template, 0x81).expect("modulus");
        assert_eq!(modulus.len(), crate::rsa::RSA2048_BYTES);
        let exponent = tlv::find(template, 0x82).expect("exponent");
        assert_eq!(exponent, &[0x01, 0x00, 0x01][..]);
        let mut n = [0u8; crate::rsa::RSA2048_BYTES];
        n.copy_from_slice(modulus);
        n
    }

    #[test]
    fn generate_rsa_and_sign_digestinfo() {
        let mut applet = applet();
        let mut rng = TestRng(20);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_RSA2048),
            Sw::OK
        );
        let public = generate(&mut applet, &mut rng, 0xB6);
        let n = rsa_modulus(&public);

        // PW1 (signature) gates PSO:CDS.
        let info = digestinfo_sha256(b"abc");
        let (_, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x9E, 0x9A, &info));
        assert_eq!(status, Sw::SECURITY_STATUS_NOT_SATISFIED);
        verify_pw1_sig(&mut applet, &mut rng);

        let (signature, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x9E, 0x9A, &info));
        assert_eq!(status, Sw::OK);
        assert_eq!(signature.len(), crate::rsa::RSA2048_BYTES);
        let mut sig = [0u8; crate::rsa::RSA2048_BYTES];
        sig.copy_from_slice(&signature);
        let expected = crate::rsa::emsa_encode_digestinfo(&info).expect("encode");
        assert_eq!(
            crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &sig),
            Some(expected),
            "card signature verifies as EMSA-PKCS1-v1_5"
        );

        // A full 256-byte encoded block passes through the raw operation.
        verify_pw1_sig(&mut applet, &mut rng);
        let (signature, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_PSO, 0x9E, 0x9A, &expected),
        );
        assert_eq!(status, Sw::OK);
        let mut sig = [0u8; crate::rsa::RSA2048_BYTES];
        sig.copy_from_slice(&signature);
        assert_eq!(
            crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &sig),
            Some(expected)
        );

        // Bare hashes are rejected rather than guessed at.
        verify_pw1_sig(&mut applet, &mut rng);
        let (_, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_PSO, 0x9E, 0x9A, &[0x5Au8; 32]),
        );
        assert_eq!(status, Sw::WRONG_DATA);
    }

    #[test]
    fn rsa_internal_authenticate_signs_raw_challenge() {
        let mut applet = applet();
        let mut rng = TestRng(21);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC3, ATTRS_RSA2048),
            Sw::OK
        );
        let public = generate(&mut applet, &mut rng, 0xA4);
        let n = rsa_modulus(&public);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );

        let challenge = [0x11u8; 32];
        let (response, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_INTERNAL_AUTHENTICATE, 0, 0, &challenge),
        );
        assert_eq!(status, Sw::OK);
        let mut sig = [0u8; crate::rsa::RSA2048_BYTES];
        sig.copy_from_slice(&response);
        let mut expected = [0u8; crate::rsa::RSA2048_BYTES];
        expected[crate::rsa::RSA2048_BYTES - challenge.len()..].copy_from_slice(&challenge);
        assert_eq!(
            crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &sig),
            Some(expected)
        );
    }

    #[test]
    fn rsa_decipher_returns_the_raw_block() {
        let mut applet = applet();
        let mut rng = TestRng(22);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_RSA2048),
            Sw::OK
        );
        let public = generate(&mut applet, &mut rng, 0xB8);
        let n = rsa_modulus(&public);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );

        let padded = pad_type2(b"session-key", &mut rng);
        let mut em = [0u8; crate::rsa::RSA2048_BYTES];
        em.copy_from_slice(&padded);
        let cipher = crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &em)
            .expect("encrypt to card");

        // `02 || ciphertext` (card-spec input shape).
        let mut prefixed = Vec::<u8, 300>::new();
        prefixed.push(0x02).unwrap();
        prefixed.extend_from_slice(&cipher).unwrap();
        let (plain, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_PSO, 0x80, 0x86, &prefixed),
        );
        assert_eq!(status, Sw::OK);
        assert_eq!(&plain[..], &em[..]);

        // Bare block and MPI framing are accepted too.
        let (plain, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &cipher));
        assert_eq!(status, Sw::OK);
        assert_eq!(&plain[..], &em[..]);

        let mut mpi = Vec::<u8, 300>::new();
        mpi.extend_from_slice(&[0x08, 0x00]).unwrap();
        mpi.extend_from_slice(&cipher).unwrap();
        let (plain, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &mpi));
        assert_eq!(status, Sw::OK);
        assert_eq!(&plain[..], &em[..]);

        // Truncated input is rejected.
        let (_, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_PSO, 0x80, 0x86, &cipher[..100]),
        );
        assert_eq!(status, Sw::WRONG_DATA);
    }

    #[test]
    fn generate_ed25519_and_sign_raw() {
        use ed25519_dalek::{Verifier as _, VerifyingKey};
        let mut applet = applet();
        let mut rng = TestRng(9);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_ED25519),
            Sw::OK
        );
        let public = generate(&mut applet, &mut rng, 0xB6);
        let point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap();
        assert_eq!(point.len(), 32);

        verify_pw1_sig(&mut applet, &mut rng);
        let message = [0x5Au8; 48];
        let (signature, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x9E, 0x9A, &message));
        assert_eq!(status, Sw::OK);
        // EdDSA signatures are raw 64-byte R||S.
        assert_eq!(signature.len(), 64);
        let key =
            VerifyingKey::from_bytes(point.try_into().expect("32-byte Ed25519 point")).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        key.verify(&message, &sig).unwrap();
    }

    #[test]
    fn internal_authenticate_with_ed25519() {
        use ed25519_dalek::{Verifier as _, VerifyingKey};
        let mut applet = applet();
        let mut rng = TestRng(10);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC3, ATTRS_ED25519),
            Sw::OK
        );
        let public = generate(&mut applet, &mut rng, 0xA4);
        let point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );
        let message = [0x11u8; 32];
        let (signature, status) = run(
            &mut applet,
            &mut rng,
            &frame(INS_INTERNAL_AUTHENTICATE, 0, 0, &message),
        );
        assert_eq!(status, Sw::OK);
        assert_eq!(signature.len(), 64);
        let key =
            VerifyingKey::from_bytes(point.try_into().expect("32-byte Ed25519 point")).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&signature).unwrap();
        key.verify(&message, &sig).unwrap();
    }

    #[test]
    fn x25519_decipher_returns_the_shared_secret() {
        let mut applet = applet();
        let mut rng = TestRng(11);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_X25519), Sw::OK);
        let public = generate(&mut applet, &mut rng, 0xB8);
        let card_point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap();
        assert_eq!(card_point.len(), 32);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );

        let peer_secret = x25519_dalek::StaticSecret::from([0x77u8; 32]);
        let peer_point = x25519_dalek::PublicKey::from(&peer_secret);
        let mut point_tlv = Vec::<u8, 64>::new();
        append_tlv(&mut point_tlv, 0x86, &peer_point.to_bytes());
        let mut public_template = Vec::<u8, 96>::new();
        append_tlv(&mut public_template, 0x7F49, &point_tlv);
        let mut cipher = Vec::<u8, 128>::new();
        append_tlv(&mut cipher, 0xA6, &public_template);
        let (shared, status) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &cipher));
        assert_eq!(status, Sw::OK);
        assert_eq!(shared.len(), 32);

        // DH symmetry: peer(card_pub) must equal card(peer_pub).
        let card_public = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(card_point).unwrap());
        let expected = peer_secret.diffie_hellman(&card_public);
        assert_eq!(&shared[..], &expected.to_bytes());
    }

    #[test]
    fn fingerprints_follow_slot_keys() {
        // Empty slots read back as zeros.
        let mut applet = applet();
        let mut rng = TestRng(12);
        assert_eq!(get_do(&mut applet, &mut rng, 0xC7), [0u8; 20]);
        assert_eq!(get_do(&mut applet, &mut rng, 0xC5).len(), 60);

        verify_pw3(&mut applet, &mut rng);
        let _ = generate(&mut applet, &mut rng, 0xB6);
        let sig_fp = get_do(&mut applet, &mut rng, 0xC7);
        assert_ne!(sig_fp, [0u8; 20]);
        // C5 aggregates Sig/Dec/Aut in order.
        let aggregate = get_do(&mut applet, &mut rng, 0xC5);
        assert_eq!(&aggregate[..20], &sig_fp[..]);
        assert_eq!(&aggregate[20..], &[0u8; 40]);
        // Fingerprints are stable across reads.
        assert_eq!(get_do(&mut applet, &mut rng, 0xC7), sig_fp);
        // Regenerating the key changes the fingerprint.
        let _ = generate(&mut applet, &mut rng, 0xB6);
        assert_ne!(get_do(&mut applet, &mut rng, 0xC7), sig_fp);
    }

    #[test]
    fn fingerprint_packet_layout_matches_rfc4880() {
        use sha1::Digest as _;
        let mut applet = applet();
        let mut rng = TestRng(13);
        verify_pw3(&mut applet, &mut rng);
        let public = generate(&mut applet, &mut rng, 0xB6);
        let point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap();

        // Independently rebuild the hashed packet: version, zero ctime,
        // ECDSA algorithm, P-256 OID, MPI of the uncompressed point.
        let mut body = heapless::Vec::<u8, 128>::new();
        body.push(0x04).unwrap();
        body.extend_from_slice(&[0, 0, 0, 0]).unwrap();
        body.push(0x13).unwrap();
        body.push(8).unwrap();
        body.extend_from_slice(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
            .unwrap();
        // MPI bit length is significant bits: 65-byte point starting with
        // 0x04 carries 515 bits, matching GnuPG's MPI encoding.
        body.extend_from_slice(&[0x02, 0x03]).unwrap();
        body.extend_from_slice(point).unwrap();
        let mut input = heapless::Vec::<u8, 135>::new();
        input.push(0x99).unwrap();
        input
            .extend_from_slice(&(body.len() as u16).to_be_bytes())
            .unwrap();
        input.extend_from_slice(&body).unwrap();
        let expected = sha1::Sha1::digest(&input);

        let card_fp = get_do(&mut applet, &mut rng, 0xC7);
        assert_eq!(&card_fp[..], &expected[..]);
    }

    #[test]
    fn rsa_fingerprint_matches_rfc4880() {
        use sha1::Digest as _;
        let mut applet = applet();
        let mut rng = TestRng(23);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            put_attrs(&mut applet, &mut rng, 0xC1, ATTRS_RSA2048),
            Sw::OK
        );
        let public = generate(&mut applet, &mut rng, 0xB6);
        let template = tlv::find(&public, 0x7F49).unwrap();
        let modulus = tlv::find(template, 0x81).unwrap();
        let exponent = tlv::find(template, 0x82).unwrap();

        // Independently rebuild the hashed packet: version, zero ctime,
        // RSA algorithm, MPI(n), MPI(e).
        let mut body = heapless::Vec::<u8, 288>::new();
        body.push(0x04).unwrap();
        body.extend_from_slice(&[0, 0, 0, 0]).unwrap();
        body.push(0x01).unwrap();
        let n_start = modulus.iter().position(|b| *b != 0).unwrap();
        let n_bits =
            ((modulus.len() - n_start) * 8 - modulus[n_start].leading_zeros() as usize) as u16;
        body.extend_from_slice(&n_bits.to_be_bytes()).unwrap();
        body.extend_from_slice(&modulus[n_start..]).unwrap();
        let e_bits = (exponent.len() * 8 - exponent[0].leading_zeros() as usize) as u16;
        body.extend_from_slice(&e_bits.to_be_bytes()).unwrap();
        body.extend_from_slice(exponent).unwrap();
        let mut input = heapless::Vec::<u8, 296>::new();
        input.push(0x99).unwrap();
        input
            .extend_from_slice(&(body.len() as u16).to_be_bytes())
            .unwrap();
        input.extend_from_slice(&body).unwrap();
        let expected = sha1::Sha1::digest(&input);

        let card_fp = get_do(&mut applet, &mut rng, 0xC7);
        assert_eq!(&card_fp[..], &expected[..]);
    }

    #[test]
    fn state_v2_migrates_to_v3() {
        use crate::pin::PinSlot;
        // Hand-build a v2 state: version 2, two PIN slots, one EdDSA key and
        // two P-256 keys with explicit algorithm bytes, empty DOs.
        let mut bytes = heapless::Vec::<u8, 8192>::new();
        bytes.push(2).unwrap();
        let mut pin = PinSlot::new(PW_POLICY);
        pin.set(b"123456").unwrap();
        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        pin.encode(&mut encoded).unwrap();
        bytes.extend_from_slice(&encoded).unwrap();
        bytes.extend_from_slice(&encoded).unwrap();
        let algos = [KEY_ALGO_EDDSA, KEY_ALGO_ECDH_P256, KEY_ALGO_ECDSA_P256];
        for algo in algos {
            bytes.push(1).unwrap();
            bytes.push(32).unwrap();
            bytes.push(algo).unwrap();
            bytes.extend_from_slice(&[0x44; 48]).unwrap();
        }
        bytes.push(0).unwrap();
        bytes.extend_from_slice(&[0u8; MAX_NAME]).unwrap();
        bytes.push(0).unwrap();
        bytes.extend_from_slice(&[0u8; 8]).unwrap();
        bytes.push(0).unwrap();
        bytes.push(0).unwrap();
        bytes.extend_from_slice(&[0u8; MAX_URL]).unwrap();
        for _ in 0..3 {
            bytes.extend_from_slice(&0u16.to_be_bytes()).unwrap();
            bytes.extend_from_slice(&[0u8; MAX_CERTIFICATE]).unwrap();
        }
        bytes.extend_from_slice(&0u32.to_be_bytes()).unwrap();

        let mut applet = OpenPgp::new(MemoryOpenPgpStore::new());
        assert!(applet.decode_state(&bytes));
        assert_eq!(applet.keys[0].algo, KEY_ALGO_EDDSA);
        assert_eq!(applet.keys[0].material[..32], [0x44; 32]);
        // Re-saving upgrades the encoding to v3 and reloads cleanly.
        assert!(applet.save_state());
        assert_eq!(applet.state[0], STATE_VERSION);
        let saved = applet.state.clone();
        let mut reopened = OpenPgp::new(MemoryOpenPgpStore::new());
        assert!(reopened.decode_state(&saved));
        assert_eq!(reopened.keys[0].algo, KEY_ALGO_EDDSA);
        assert_eq!(reopened.keys[0].material[..32], [0x44; 32]);
        assert_eq!(reopened.keys[1].algo, KEY_ALGO_ECDH_P256);
    }

    #[test]
    fn state_v1_migrates_to_p256_defaults() {
        use crate::pin::PinSlot;
        // Hand-build a v1 state: version 1, two PIN slots, three P-256 keys,
        // empty DOs. v1 key records carry no algorithm byte.
        let mut bytes = heapless::Vec::<u8, 8192>::new();
        bytes.push(1).unwrap();
        let mut pin = PinSlot::new(PW_POLICY);
        pin.set(b"123456").unwrap();
        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        pin.encode(&mut encoded).unwrap();
        bytes.extend_from_slice(&encoded).unwrap();
        bytes.extend_from_slice(&encoded).unwrap();
        for _ in 0..3 {
            bytes.push(1).unwrap();
            bytes.push(32).unwrap();
            bytes.extend_from_slice(&[0x33; 48]).unwrap();
        }
        bytes.push(0).unwrap();
        bytes.extend_from_slice(&[0u8; MAX_NAME]).unwrap();
        bytes.push(0).unwrap();
        bytes.extend_from_slice(&[0u8; 8]).unwrap();
        bytes.push(0).unwrap();
        bytes.push(0).unwrap();
        bytes.extend_from_slice(&[0u8; MAX_URL]).unwrap();
        for _ in 0..3 {
            bytes.extend_from_slice(&0u16.to_be_bytes()).unwrap();
            bytes.extend_from_slice(&[0u8; MAX_CERTIFICATE]).unwrap();
        }
        bytes.extend_from_slice(&0u32.to_be_bytes()).unwrap();

        let mut applet = OpenPgp::new(MemoryOpenPgpStore::new());
        assert!(applet.decode_state(&bytes));
        assert!(applet.keys[0].present);
        // v1 records resolve to explicit P-256 algorithms on load.
        assert_eq!(applet.keys[0].algo, KEY_ALGO_ECDSA_P256);
        assert_eq!(applet.keys[0].effective_algo(0), KEY_ALGO_ECDSA_P256);
        assert_eq!(applet.keys[1].effective_algo(1), KEY_ALGO_ECDH_P256);
        assert_eq!(applet.keys[2].effective_algo(2), KEY_ALGO_ECDSA_P256);
        // Re-saving upgrades the encoding to v3.
        assert!(applet.save_state());
        assert_eq!(applet.state[0], STATE_VERSION);
    }

    #[test]
    fn reset_retry_requires_pw3_and_leaves_state_untouched() {
        let mut applet = applet();
        let mut rng = TestRng(30);
        // One failed PW1 attempt fixes the observable state (63C2).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::retries_left(2)
        );
        // Without a verified PW3 the request is refused and nothing moves.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"66666666")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        // The counter shows the same single failed attempt as before.
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(2)
        );
        // The PW1 signature session is exactly where it was: unreached.
        let digest = [0xA5u8; 32];
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_PSO, 0x9E, 0x9A, &digest)).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        // The original PW1 still verifies; the requested hash never landed.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"66666666")
            )
            .1,
            Sw::retries_left(1)
        );
    }

    #[test]
    fn reset_retry_with_pw3_sets_new_pw1_and_restores_retries() {
        let mut applet = applet();
        let mut rng = TestRng(31);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"99999999")
            )
            .1,
            Sw::OK
        );
        // The new PW1 verifies with a counter back at the policy maximum.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(3)
        );
        // The admin PIN is untouched by the command.
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x83, &[])).1,
            Sw::retries_left(3)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn reset_retry_does_not_end_the_pw3_session() {
        let mut applet = applet();
        let mut rng = TestRng(32);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"99999999")
            )
            .1,
            Sw::OK
        );
        // An administrative command keeps working without a new VERIFY PW3.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0x5B, b"Alice")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn reset_retry_rejects_unknown_p2() {
        let mut applet = applet();
        let mut rng = TestRng(33);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x82, b"99999999")
            )
            .1,
            Sw::INCORRECT_PARAMETERS
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x83, b"99999999")
            )
            .1,
            Sw::INCORRECT_PARAMETERS
        );
        // State untouched: the usage PW1 keeps its hash.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn reset_retry_rejects_the_resetting_code_path() {
        let mut applet = applet();
        let mut rng = TestRng(34);
        // The resetting code (P1=0x00) is not provisioned in this foundation.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x00, 0x81, b"99999999")
            )
            .1,
            Sw::FUNCTION_NOT_SUPPORTED
        );
        // State untouched: the requested hash never landed and the original
        // PW1 keeps verifying.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::retries_left(2)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn select_clears_pw3_and_reset_retry_requires_it_again() {
        let mut applet = applet();
        let mut rng = TestRng(35);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"88888888")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"88888888")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn blocked_pw1_stays_blocked_until_authenticated_unblock() {
        let mut applet = applet();
        let mut rng = TestRng(36);
        for _ in 0..3 {
            let _ = run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999"),
            );
        }
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::AUTHENTICATION_BLOCKED
        );
        // The unauthenticated request leaves the slot blocked, not overwritten.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"66666666")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"66666666")
            )
            .1,
            Sw::AUTHENTICATION_BLOCKED
        );
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"66666666")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"66666666")
            )
            .1,
            Sw::OK
        );
    }
    #[test]
    fn verify_failure_with_failing_store_reports_the_save_error() {
        let mut rng = TestRng(50);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        applet.store.set_save_fails(true);
        // A consumed attempt with a failing store is reported as a memory
        // error, never as the retry indicator `63Cx` (AC-1).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        // The decrement stays in RAM: the next empty VERIFY shows `63C2`, and
        // the slot blocks with `6983` once the counter is exhausted (AC-1).
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(2)
        );
        for _ in 0..2 {
            assert_eq!(
                run(
                    &mut applet,
                    &mut rng,
                    &frame(INS_VERIFY, 0, 0x81, b"99999999")
                )
                .1,
                Sw::NOT_ENOUGH_MEMORY
            );
        }
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::AUTHENTICATION_BLOCKED
        );
    }

    #[test]
    fn sticky_floor_survives_reselect() {
        let mut rng = TestRng(51);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        applet.store.set_save_fails(true);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        // The floor recorded the consumed attempt, so a re-select that
        // reloads the (still permissive) store cannot refill the counter:
        // the empty VERIFY stays `63C2` (AC-2).
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(2)
        );
    }

    #[test]
    fn power_cycle_restores_the_persisted_counter_as_documented() {
        let mut rng = TestRng(52);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        applet.store.set_save_fails(true);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        // Documented residue (AC-8): the floor is session-volatile, so a new
        // instantiation (a power cycle) re-arms the counter from the
        // provisioning defaults when no good save ever re-anchored it.
        let store = core::mem::replace(
            applet.store_mut(),
            FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()),
        );
        let mut rebooted = OpenPgp::new(store);
        assert_eq!(rebooted.select().sw, Sw::OK);
        assert_eq!(
            run(&mut rebooted, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(3)
        );
    }

    #[test]
    fn change_with_failing_store_reports_the_save_error_and_never_fakes_success() {
        let mut rng = TestRng(53);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        applet.store.set_save_fails(true);
        // The admin session opens the gate before the change is attempted.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        // The change is refused with the memory error instead of `9000` (AC-3).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        // Sticky: the new PIN verifies in-session despite the failed save.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::OK
        );
        // After a re-select the persisted state governs: the old PIN verifies
        // again and the never-persisted hash is gone: no ghost upgrade (AC-3).
        applet.store.set_save_fails(false);
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::retries_left(2)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn unblock_with_failing_store_keeps_the_persisted_blocked_state() {
        let mut rng = TestRng(54);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        // Drain PW1 while the store is healthy, so the blocked state persists.
        for remaining in [2, 1, 0] {
            assert_eq!(
                run(
                    &mut applet,
                    &mut rng,
                    &frame(INS_VERIFY, 0, 0x81, b"99999999")
                )
                .1,
                Sw::retries_left(remaining)
            );
        }
        applet.store.set_save_fails(true);
        // The admin PIN verifies (success emits no save) and the unblock is
        // refused with the memory error (AC-4).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"66666666")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        // The persisted state governs after the re-select: PW1 stays blocked
        // and the new hash never landed (AC-4).
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::AUTHENTICATION_BLOCKED
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"66666666")
            )
            .1,
            Sw::AUTHENTICATION_BLOCKED
        );
    }

    #[test]
    fn put_data_with_failing_store_reports_the_save_error() {
        let mut rng = TestRng(55);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0x5B, b"Alice")
            )
            .1,
            Sw::OK
        );
        // Anchor a persisted old DO.
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        applet.store.set_save_fails(true);
        // An accepted PUT DATA with a failing store is refused with `6A84`
        // (AC-5).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0x5B, b"Bob")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_GET_DATA, 0x00, 0x5B, &[])).0,
            b"Alice".as_slice()
        );
        // A rejected PUT DATA (`WRONG_DATA`) emits no save at all (AC-5).
        applet.store.set_save_fails(true);
        let saves_before = applet.store.save_calls;
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xC4, b"junk")
            )
            .1,
            Sw::WRONG_DATA
        );
        assert_eq!(applet.store.save_calls, saves_before);
    }

    #[test]
    fn reload_never_climbs_above_the_session_floor() {
        let mut rng = TestRng(56);
        let mut applet = applet();
        // A healthy applet consumes an attempt and anchors the persisted
        // counter at 2.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::retries_left(2)
        );
        let stored = core::mem::take(applet.store_mut());
        // A new applet whose session floor sits below the persisted counter
        // loads the clamped one: `min(Y, X)` for PW1 and PW3 alike (AC-6).
        let mut reloaded = OpenPgp::new(stored);
        reloaded.pw1_floor = 1;
        reloaded.pw3_floor = 1;
        assert_eq!(reloaded.select().sw, Sw::OK);
        assert_eq!(
            run(&mut reloaded, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(1)
        );
        assert_eq!(
            run(&mut reloaded, &mut rng, &frame(INS_VERIFY, 0, 0x83, &[])).1,
            Sw::retries_left(1)
        );
    }

    #[test]
    fn happy_path_persists_assertions_are_unchanged_under_a_healthy_store() {
        let mut rng = TestRng(57);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        // A consumed attempt persists as before: the re-select keeps `63C2`.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"99999999")
            )
            .1,
            Sw::retries_left(2)
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(2)
        );
        // The admin session opens the gate before the change is attempted.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        // The admin change persists: the new PW3 verifies after the reopen.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::OK
        );
        // The authenticated unblock persists: the new PW1 verifies with a
        // full counter after the reopen.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"88888888")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"88888888")
            )
            .1,
            Sw::OK
        );
        // The accepted PUT DATA persists: the DO survives the reopen.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0x5B, b"Alice")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_GET_DATA, 0x00, 0x5B, &[])).0,
            b"Alice".as_slice()
        );
    }

    #[test]
    fn successful_verify_does_not_call_save() {
        let mut rng = TestRng(58);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        // The initial provisioning already wrote the defaults once.
        let saves_before = applet.store.save_calls;
        assert!(saves_before > 0);
        // A successful VERIFY moves nothing persistable: it must not touch
        // the store (AC-7).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.store.save_calls, saves_before);
        // Same for the unset/blocked diagnostics: no state, no save.
        applet.store.set_save_fails(true);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(3)
        );
        assert_eq!(applet.store.save_calls, saves_before);
    }

    #[test]
    fn provisioning_defaults_survive_a_failing_store() {
        let mut rng = TestRng(59);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        applet.store.set_save_fails(true);
        assert_eq!(applet.select().sw, Sw::OK);
        // The interop defaults are provisioned in RAM even though their save
        // failed (regression for the `ensure_loaded` fallback of R1).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn pw3_change_requires_the_admin_session_and_leaves_the_state_untouched() {
        let mut rng = TestRng(61);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        // The initial provisioning already wrote the defaults once.
        let saves_before = applet.store.save_calls;
        // Without an admin session the change is refused out of hand, no
        // matter that the body carries the correct PIN.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        // The refusal is a session verdict: the store never saw a save.
        assert_eq!(applet.store.save_calls, saves_before);
        // The hash is intact: the requested PIN does not verify (one spent
        // attempt) and the original one still does.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::retries_left(2)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn pw1_verification_does_not_authorize_the_pw3_change() {
        let mut applet = applet();
        let mut rng = TestRng(62);
        // Both PW1 sessions are open; the admin slot stays fenced: only the
        // VERIFY 0x83 session opens the gate.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x82, b"123456")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
    }

    #[test]
    fn pw3_change_with_session_swaps_the_pin_and_keeps_the_session() {
        let mut applet = applet();
        let mut rng = TestRng(63);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::OK
        );
        // The swap did not consume the session: an admin operation answers
        // without a fresh VERIFY.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0x5B, b"Alice")
            )
            .1,
            Sw::OK
        );
        // The new PIN verifies (fresh counter) and the old one is gone (the
        // failed probe above costs one attempt).
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::retries_left(2)
        );
        // A wrong current PIN under a live session still follows the slot
        // contract (63Cx, persisted) — and the session survives that too.
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"8765432199999999")
            )
            .1,
            Sw::retries_left(1)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0x5B, b"Bob")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn select_clears_pw3_and_change_requires_it_again() {
        let mut applet = applet();
        let mut rng = TestRng(64);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::OK
        );
        // A re-select drops the session: the same command shape is refused
        // until the admin verifies again.
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"9999999988888888")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"9999999988888888")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn pw1_change_still_works_without_a_session() {
        let mut applet = applet();
        let mut rng = TestRng(65);
        // The 6-byte default is changeable on the public path now; an
        // 8-byte current installed through the admin door keeps exercising
        // the fixed 8+8 shape against a slot that is not 6 bytes.
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        // An out-of-format body is refused regardless.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"AAAAAAAAAAA")
            )
            .1,
            Sw::WRONG_DATA
        );
        // Both modes swap the PW1 on the strength of the current PIN alone,
        // with no admin session at all.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"9999999977777777")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x82, b"7777777755555555")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"55555555")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn refused_pw3_change_never_consumes_a_retry() {
        let mut applet = applet();
        let mut rng = TestRng(66);
        // The refusal is identical whether the body guesses the PIN right
        // or wrong: a session-less change never reaches the slot.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"0000000099999999")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        // The counter is untouched…
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x83, &[])).1,
            Sw::retries_left(3)
        );
        // …and the slot still takes its legitimate verification.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn pw1_default_of_six_octets_is_changeable_on_the_public_path() {
        let mut applet = applet();
        let mut rng = TestRng(67);
        // The factory PIN changes on the public path: no admin session and
        // no unblock, just the 12-octet body the scdaemon actually sends.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"123456654321")
            )
            .1,
            Sw::OK
        );
        // A successful change refills the retry counter.
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(3)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"654321")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::retries_left(2)
        );
        // The change was persisted: a re-select keeps the new PIN usable.
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"654321")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn pw1_change_follows_the_exact_lengths_of_the_command_body() {
        let mut rng = TestRng(68);
        let mut applet = applet();
        // 6-byte current, 8-byte new: a 14-octet body.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"12345688888888")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"88888888")
            )
            .1,
            Sw::OK
        );
        // Same 14-octet shape with an 8-byte current installed through the
        // admin door: the delimitation follows the stored hash, not a fixed
        // index, so Lnew = Lc − Lold holds in both directions.
        let mut applet = OpenPgp::new(MemoryOpenPgpStore::new());
        assert_eq!(applet.select().sw, Sw::OK);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"99999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"99999999777777")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"777777")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn pw1_change_rejects_bodies_outside_the_policy_range_without_tuning() {
        let mut rng = TestRng(69);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        let baseline = applet.store.save_calls;
        // 0, 11 and 255 octets sit outside the `2·6 ≤ Lc ≤ 2·127` format
        // window: refused before any slot work.
        let oversized = [b'A'; 255];
        for body in [&b""[..], &b"AAAAAAAAAAA"[..], &oversized[..]] {
            assert_eq!(
                run(
                    &mut applet,
                    &mut rng,
                    &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, body)
                )
                .1,
                Sw::WRONG_DATA
            );
        }
        // No attempt was consumed and no save was emitted.
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(3)
        );
        assert_eq!(applet.store.save_calls, baseline);
    }

    #[test]
    fn pw1_change_consumes_one_attempt_per_mismatched_body() {
        let mut applet = applet();
        let mut rng = TestRng(70);
        // No candidate length of these in-format bodies hashes to the
        // stored 6-byte current: one attempt per command, exactly as a
        // fixed-width change always charged for a wrong current PIN —
        // including shapes the previous fixed 8+8 oracle refused outright.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"111111888888")
            )
            .1,
            Sw::retries_left(2)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x82, b"111111888888")
            )
            .1,
            Sw::retries_left(1)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"111111888888888")
            )
            .1,
            Sw::retries_left(0)
        );
        // The new hash was never installed, and once the counter is spent
        // the change refuses without touching anything.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"111111888888")
            )
            .1,
            Sw::AUTHENTICATION_BLOCKED
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::AUTHENTICATION_BLOCKED
        );
    }

    #[test]
    fn pw1_change_fail_closed_on_failing_store() {
        let mut rng = TestRng(71);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        applet.store.set_save_fails(true);
        // A valid 6-byte change with a failing store reports the memory
        // error, never a faked `9000`.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"123456654321")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        // The new PIN lives in RAM until the save succeeds.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"654321")
            )
            .1,
            Sw::OK
        );
        // After a re-select the persisted state governs: the ghost upgrade
        // is gone and the old PIN governs again.
        applet.store.set_save_fails(false);
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"654321")
            )
            .1,
            Sw::retries_left(2)
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn pw3_change_body_format_is_unchanged() {
        let mut applet = applet();
        let mut rng = TestRng(72);
        // No session: the gate fires before the slot is touched, regardless
        // of the body length.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"123456654321")
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x83, &[])).1,
            Sw::retries_left(3)
        );
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"1234567899999999")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"99999999")
            )
            .1,
            Sw::OK
        );
        // The variable-length body rule does not extend to the admin slot:
        // with a session open, anything that is not 16 octets stays a
        // format refusal.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x83, b"123456789999")
            )
            .1,
            Sw::WRONG_DATA
        );
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x83, &[])).1,
            Sw::retries_left(3)
        );
    }

    #[test]
    fn sticky_floor_survives_pw1_variable_length_change() {
        let mut rng = TestRng(73);
        let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
        assert_eq!(applet.select().sw, Sw::OK);
        applet.store.set_save_fails(true);
        // A mismatched body consumes its attempt; with a failing store the
        // consumption is still reported as the save error, never masked.
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"111111888888")
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        // The floor keeps the counter across a re-select.
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
            Sw::retries_left(2)
        );
        // Once the store accepts saves again, a legitimate change persists
        // and the new PIN is pinned on the public path.
        applet.store.set_save_fails(false);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_CHANGE_REFERENCE_DATA, 0, 0x81, b"123456654321")
            )
            .1,
            Sw::OK
        );
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"654321")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x81, b"123456")
            )
            .1,
            Sw::retries_left(2)
        );
    }
}
