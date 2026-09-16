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
    /// `PUT DATA C1`–`C3` before `GENERATE`), so no slot default applies.
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
        let _ = self.save_state();
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
            // fails closed so a torn write can never yield a half key.
            if algo == KEY_ALGO_RSA2048 {
                if len != rsa::RSA_BLOB_BYTES
                    || rsa::Rsa2048PrivateKey::from_blob(&raw[..len]).is_none()
                {
                    return false;
                }
            } else if len > 48 {
                return false;
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
        let success = result.is_ok();
        self.save_state();
        if success {
            match apdu.p2 {
                0x81 => self.pw1_signature_verified = true,
                0x82 => self.pw1_other_verified = true,
                0x83 => self.pw3_verified = true,
                _ => {}
            }
        }
        Response::status(result.err().unwrap_or(Sw::OK))
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
    /// RSA follows OpenPGP Card spec §7.2.9: `01 || nbits || ebits`
    /// (`0800`/`0020` for RSA-2048/`e` = 65537, minimal `0011` accepted
    /// too), with the optional import-format byte ignored — keys are
    /// generated on-card, never imported.
    fn parse_attrs(value: &[u8]) -> Option<u8> {
        if let Some(algo) = Self::parse_rsa_attrs(value) {
            return Some(algo);
        }
        let (&id, oid) = value.split_first()?;
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

    /// Canonical RSA-2048 attributes reported by `GET DATA C1`–`C3`:
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

    /// RFC 4880 §12.2 v4 fingerprint for a slot's public key.
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

    /// RFC 4880 §12.2 v4 fingerprint of an RSA slot: `SHA1(99 || len ||
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
            _ => false,
        };
        if accepted {
            self.save_state();
            Response::status(Sw::OK)
        } else {
            Response::status(Sw::WRONG_DATA)
        }
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
        let cipher = tlv::find(input, 0xA6).unwrap_or(input);
        let public_template = tlv::find(cipher, 0x7F49).unwrap_or(cipher);
        if algo == KEY_ALGO_RSA2048 {
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
        let Some(point) = tlv::find(public_template, 0x86) else {
            return Response::status(Sw::WRONG_DATA);
        };
        if algo == KEY_ALGO_ECDH_X25519 {
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
            return Response::ok(&self.out);
        }
        if algo != KEY_ALGO_ECDH_P256 {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        }
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

    fn verify_change(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        let slot = match apdu.p2 {
            0x81 | 0x82 => &mut self.pw1,
            0x83 => &mut self.pw3,
            _ => return Response::status(Sw::INCORRECT_PARAMETERS),
        };
        if apdu.data.len() != 16 {
            return Response::status(Sw::WRONG_DATA);
        }
        let result = slot.change(&apdu.data[..8], &apdu.data[8..]);
        self.save_state();
        Response::status(result.err().unwrap_or(Sw::OK))
    }

    fn reset_retry(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if apdu.p2 != 0x81 || apdu.data.len() != 8 {
            return Response::status(Sw::WRONG_DATA);
        }
        let result = self.pw1.unblock(apdu.data);
        self.save_state();
        Response::status(result.err().unwrap_or(Sw::OK))
    }
}

impl<S: OpenPgpStore> Applet for OpenPgp<S> {
    fn aid(&self) -> &'static [u8] {
        crate::aid::OPENPGP
    }

    fn select(&mut self) -> Response<'_> {
        self.loaded = false;
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

/// Exact bit length of an MPI body (RFC 4880 §3.2).
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
    append_tlv(&mut body, 0x81, point);
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

    fn run(
        applet: &mut OpenPgp<MemoryOpenPgpStore>,
        rng: &mut TestRng,
        frame: &[u8],
    ) -> (Vec<u8, 2048>, Sw) {
        let command = Apdu::parse(frame).unwrap();
        let response = applet.process(&command, rng);
        let mut data = Vec::new();
        data.extend_from_slice(response.data).unwrap();
        (data, response.sw)
    }

    fn verify_pw3(applet: &mut OpenPgp<MemoryOpenPgpStore>, rng: &mut TestRng) {
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

    fn generate(
        applet: &mut OpenPgp<MemoryOpenPgpStore>,
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
        let point = tlv::find(public_template, 0x81).unwrap();
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
        let point = tlv::find(public_template, 0x81).unwrap();
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
    fn pso_decipher_returns_the_p256_shared_secret() {
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

    /// DER DigestInfo for SHA-256 (RFC 8017 §9.2) over `message`.
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
        let point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x81).unwrap();
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
        let point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x81).unwrap();
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
    fn x25519_decipher_agrees_with_peer() {
        let mut applet = applet();
        let mut rng = TestRng(11);
        verify_pw3(&mut applet, &mut rng);
        assert_eq!(put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_X25519), Sw::OK);
        let public = generate(&mut applet, &mut rng, 0xB8);
        let card_point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x81).unwrap();
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
        let point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x81).unwrap();

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
}
