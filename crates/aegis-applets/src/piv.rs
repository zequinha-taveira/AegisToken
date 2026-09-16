//! PIV card applet (NIST SP 800-73-4) over ISO 7816-4.
//!
//! The applet implements the NIST PIV command set the host tooling actually
//! uses — `SELECT`, `GET DATA`/`PUT DATA`, `VERIFY`, `CHANGE REFERENCE DATA`,
//! `RESET RETRY COUNTER`, `GENERATE ASYMMETRIC KEY PAIR` and
//! `GENERAL AUTHENTICATE` (management-key authentication and ECDSA signing) —
//! with P-256 and P-384 keys generated on-card from the caller's RNG.
//!
//! Everything is `no_std` and deterministic: the applet receives an
//! [`Rng`], talks to a [`PivStore`] for persistence, and returns APDU
//! responses. Vendor extensions (Yubico metadata, retired keys and ECDH)
//! are out of scope and answer the standard "function not supported" status.
//!
//! Defaults follow common PIV provisioning: PIN `123456`, PUK `12345678` and
//! the default 3DES management key `0102..08` repeated three times; all three
//! are persisted on first selection, so retry counters survive power cycles
//! wherever the store does.

use aegis_core::authenticator::Rng;
use heapless::Vec;

use crate::apdu::{Apdu, Response, Sw};
use crate::pin::{PinHashFormat, PinPolicy, PinSlot};
use crate::router::Applet;
use crate::rsa;
use crate::tlv;

/// PIV application identifier.
pub const AID: &[u8] = crate::aid::PIV;

/// Record holding the encoded PIN slot.
pub const RECORD_PIN: u16 = 1;
/// Record holding the encoded PUK slot.
pub const RECORD_PUK: u16 = 2;
/// Record holding the management key (algorithm, length, key).
pub const RECORD_MGMT_KEY: u16 = 3;
/// First record holding an ECC private key entry.
pub const RECORD_KEY_BASE: u16 = 10;
/// First record holding a data object.
pub const RECORD_OBJECT_BASE: u16 = 30;
/// Largest value stored in one record.
pub const MAX_RECORD_BYTES: usize = 1536;

/// Key record buffer: the 6-byte RSA header plus the serialized
/// [`rsa::Rsa2048PrivateKey`] blob. ECC records (`4 + scalar`) reuse the
/// same buffer. Must stay within [`MAX_RECORD_BYTES`].
const KEY_RECORD_BYTES: usize = 6 + rsa::RSA_BLOB_BYTES;
const _: () = assert!(KEY_RECORD_BYTES <= MAX_RECORD_BYTES);

/// Scratch size for one APDU response (object value plus its envelope).
const SCRATCH_BYTES: usize = MAX_RECORD_BYTES + 16;
/// Records a [`MemoryPivStore`] can hold.
const MEMORY_RECORDS: usize = 16;

// Instructions.
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;
const INS_RESET_RETRY_COUNTER: u8 = 0x2C;
const INS_GENERATE_ASYMMETRIC_KEY_PAIR: u8 = 0x47;
const INS_GENERAL_AUTHENTICATE: u8 = 0x87;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;

// Key references (P2).
const REF_PIN: u8 = 0x80;
const REF_PUK: u8 = 0x81;
const REF_PIV_AUTH: u8 = 0x9A;
const REF_MANAGEMENT: u8 = 0x9B;
const REF_SIGNATURE: u8 = 0x9C;
const REF_CARD_AUTH: u8 = 0x9E;

/// Triple-DES management key algorithm reference.
pub const ALG_TDES: u8 = 0x03;
/// RSA-2048 algorithm reference.
pub const ALG_RSA2048: u8 = 0x07;
/// AES-128 management key algorithm reference.
pub const ALG_AES128: u8 = 0x08;
/// AES-192 management key algorithm reference.
pub const ALG_AES192: u8 = 0x0A;
/// AES-256 management key algorithm reference.
pub const ALG_AES256: u8 = 0x0C;
/// ECC P-256 algorithm reference.
pub const ALG_ECCP256: u8 = 0x11;
/// ECC P-384 algorithm reference.
pub const ALG_ECCP384: u8 = 0x14;

// Data object identifiers (the PIV object tags).
const OBJECT_CARD_AUTH_CERT: u32 = 0x005F_C101;
const OBJECT_CHUID: u32 = 0x005F_C102;
const OBJECT_PIV_AUTH_CERT: u32 = 0x005F_C105;
const OBJECT_CCC: u32 = 0x005F_C107;
const OBJECT_PRINTED: u32 = 0x005F_C109;
const OBJECT_SIGNATURE_CERT: u32 = 0x005F_C10A;
const OBJECT_KEY_MGMT_CERT: u32 = 0x005F_C10B;
const OBJECT_KEY_HISTORY: u32 = 0x005F_C10C;
const OBJECT_RETIRED_AUTH_CERT: u32 = 0x005F_C10D;
const OBJECT_RETIRED_SIGNATURE_CERT: u32 = 0x005F_C10E;
const OBJECT_RETIRED_KEY_MGMT_CERT: u32 = 0x005F_C10F;

/// Application properties returned by `SELECT`.
pub const FCI: &[u8] = &[
    0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00,
    0x00, 0x03, 0x08,
];

/// Default CHUID: FASC-N `30 19 ..`, expiry `34 10 ..`, issuer `35 08 20300101`.
const DEFAULT_CHUID: &[u8] = &[
    0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39, 0xCE, 0x73, 0x9D, 0x83, 0x68, 0x58,
    0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x38, 0x42, 0x10, 0xC3, 0xF5, 0x34, 0x10, 0xAD, 0x64, 0xBE,
    0xAC, 0x16, 0x11, 0x4A, 0x56, 0x93, 0xA2, 0x9D, 0x58, 0x3B, 0x74, 0xCB, 0x44, 0x35, 0x08, 0x32,
    0x30, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x3E, 0x00, 0xFE, 0x00,
];

/// Default Card Capability Container (the value wrapped by `53`).
const DEFAULT_CCC: &[u8] = &[
    0xF0, 0x15, 0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF1, 0x01, 0x21, 0xF2, 0x01, 0x21, 0xF3, 0x00, 0xF4,
    0x01, 0x00, 0xF5, 0x01, 0x10, 0xF6, 0x00, 0xF7, 0x00, 0xFA, 0x00, 0xFB, 0x00, 0xFC, 0x00, 0xFD,
    0x00, 0xFE, 0x00,
];

/// Key history with no retired keys.
const KEY_HISTORY: &[u8] = &[0xC1, 0x01, 0x00, 0xC2, 0x01, 0x00, 0xC3, 0x01, 0x00];

/// Generate a 3DES management key.
fn default_mgmt_key(rng: &mut impl Rng) -> [u8; 24] {
    let mut key = [0u8; 24];
    rng.fill_bytes(&mut key);
    key
}

/// Default PIV PIN (`123456`).
pub const DEFAULT_PIN: &[u8] = b"123456";
/// Default PIV PUK (`12345678`).
pub const DEFAULT_PUK: &[u8] = b"12345678";

/// PIN and PUK policy: 6-8 bytes, three attempts, `SHA-256` of the padded value.
const PIV_PIN_POLICY: PinPolicy = PinPolicy::new(6, 8, 3, PinHashFormat::Sha256);

/// What a key slot requires from its user before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPolicyCode {
    /// No PIN required.
    Never = 1,
    /// PIN verified once per session.
    Once = 2,
    /// PIN verified for every signature.
    Always = 3,
}

impl PinPolicyCode {
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Never),
            2 => Some(Self::Once),
            3 => Some(Self::Always),
            _ => None,
        }
    }
}

/// Whether a key slot requires User Presence before signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchPolicy {
    /// No presence required.
    Never = 1,
    /// Presence required for every signature.
    Always = 2,
    /// Presence required once per session.
    Cached = 3,
}

impl TouchPolicy {
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Never),
            2 => Some(Self::Always),
            3 => Some(Self::Cached),
            _ => None,
        }
    }
}

/// Key slots that hold ECC private keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// PIV authentication key (`9A`).
    PivAuth = 0x9A,
    /// Digital signature key (`9C`).
    Signature = 0x9C,
    /// Card authentication key (`9E`).
    CardAuth = 0x9E,
}

impl KeySlot {
    const fn from_code(code: u8) -> Option<Self> {
        match code {
            REF_PIV_AUTH => Some(Self::PivAuth),
            REF_SIGNATURE => Some(Self::Signature),
            REF_CARD_AUTH => Some(Self::CardAuth),
            _ => None,
        }
    }

    const fn record(self) -> u16 {
        match self {
            Self::PivAuth => RECORD_KEY_BASE,
            Self::Signature => RECORD_KEY_BASE + 1,
            Self::CardAuth => RECORD_KEY_BASE + 2,
        }
    }

    const fn curve_bytes(algorithm: u8) -> Option<usize> {
        match algorithm {
            ALG_ECCP256 => Some(32),
            ALG_ECCP384 => Some(48),
            _ => None,
        }
    }
}

/// Whether `algorithm` names a key type this applet signs with.
const fn supports_algorithm(algorithm: u8) -> bool {
    KeySlot::curve_bytes(algorithm).is_some() || algorithm == ALG_RSA2048
}

/// Persistent records the applet needs.
///
/// The firmware implements this over sealed flash; tests and the current
/// firmware wiring use [`MemoryPivStore`].
pub trait PivStore {
    /// Read `record` into `out`, returning its length.
    fn read(&mut self, record: u16, out: &mut [u8]) -> Option<usize>;
    /// Create or replace `record`.
    fn write(&mut self, record: u16, data: &[u8]) -> bool;
    /// Remove `record`.
    fn erase(&mut self, record: u16) -> bool;
}

/// Volatile store used by tests and by the firmware until the sealed storage
/// adapter lands (see `roadmap.md`, Phase 12 pendencies).
pub struct MemoryPivStore {
    records: [Option<Record>; MEMORY_RECORDS],
}

struct Record {
    id: u16,
    len: usize,
    data: [u8; MAX_RECORD_BYTES],
}

impl Default for MemoryPivStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryPivStore {
    /// Create an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: [const { None }; MEMORY_RECORDS],
        }
    }

    fn slot(&self, record: u16) -> Option<usize> {
        self.records
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.id == record))
    }

    fn free_slot(&self) -> Option<usize> {
        self.records.iter().position(Option::is_none)
    }
}

impl PivStore for MemoryPivStore {
    fn read(&mut self, record: u16, out: &mut [u8]) -> Option<usize> {
        let index = self.slot(record)?;
        let entry = self.records[index].as_ref()?;
        if out.len() < entry.len {
            return None;
        }
        out[..entry.len].copy_from_slice(&entry.data[..entry.len]);
        Some(entry.len)
    }

    fn write(&mut self, record: u16, data: &[u8]) -> bool {
        if data.len() > MAX_RECORD_BYTES {
            return false;
        }
        let index = match self.slot(record) {
            Some(index) => index,
            None => match self.free_slot() {
                Some(index) => index,
                None => return false,
            },
        };
        let mut entry = Record {
            id: record,
            len: data.len(),
            data: [0; MAX_RECORD_BYTES],
        };
        entry.data[..data.len()].copy_from_slice(data);
        self.records[index] = Some(entry);
        true
    }

    fn erase(&mut self, record: u16) -> bool {
        match self.slot(record) {
            Some(index) => {
                self.records[index] = None;
                true
            }
            None => false,
        }
    }
}

/// Management key and its algorithm.
struct MgmtKey {
    algorithm: u8,
    len: usize,
    key: [u8; 32],
}

impl MgmtKey {
    const fn default_key() -> Self {
        let mut key = [0u8; 32];
        let mut index = 0;
        while index < DEFAULT_MGMT_KEY.len() {
            key[index] = DEFAULT_MGMT_KEY[index];
            index += 1;
        }
        Self {
            algorithm: ALG_TDES,
            len: DEFAULT_MGMT_KEY.len(),
            key,
        }
    }

    const fn block_len(&self) -> usize {
        match self.algorithm {
            ALG_TDES => 8,
            ALG_AES128 | ALG_AES192 | ALG_AES256 => 16,
            _ => 0,
        }
    }

    const fn key_len(&self) -> usize {
        match self.algorithm {
            ALG_TDES => 24,
            ALG_AES128 => 16,
            ALG_AES192 => 24,
            ALG_AES256 => 32,
            _ => 0,
        }
    }

    fn encrypt(&self, block: &mut [u8]) -> bool {
        if block.len() != self.block_len() || self.len != self.key_len() {
            return false;
        }
        match self.algorithm {
            ALG_TDES => tdes_ecb_encrypt(&self.key[..self.len], block),
            ALG_AES128 | ALG_AES192 | ALG_AES256 => aes_ecb_encrypt(&self.key[..self.len], block),
            _ => false,
        }
    }

    fn encode(&self, out: &mut [u8]) -> Option<usize> {
        if out.len() < 2 + self.len {
            return None;
        }
        out[0] = self.algorithm;
        out[1] = self.len as u8;
        out[2..2 + self.len].copy_from_slice(&self.key[..self.len]);
        Some(2 + self.len)
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let algorithm = *bytes.first()?;
        let len = usize::from(*bytes.get(1)?);
        let mut key = [0u8; 32];
        let mut candidate = Self {
            algorithm,
            len,
            key: [0; 32],
        };
        if len != candidate.key_len() || bytes.len() < 2 + len {
            return None;
        }
        key[..len].copy_from_slice(&bytes[2..2 + len]);
        candidate.key = key;
        Some(candidate)
    }
}

/// In-flight management-key authentication.
struct Witness {
    mutual: bool,
    nonce: Vec<u8, 16>,
}

/// A signature awaiting User Presence (ECC digest or 256-byte RSA block).
struct PendingSign {
    slot: KeySlot,
    digest: Vec<u8, 256>,
}

/// PIV applet over a persistent store.
pub struct Piv<S: PivStore> {
    store: S,
    value: Vec<u8, MAX_RECORD_BYTES>,
    out: Vec<u8, SCRATCH_BYTES>,
    pin: PinSlot,
    puk: PinSlot,
    mgmt: MgmtKey,
    pin_verified: bool,
    mgmt_authenticated: bool,
    witness: Option<Witness>,
    pending_sign: Option<PendingSign>,
    presence_cached: bool,
    provisioned: bool,
}

impl<S: PivStore> Piv<S> {
    /// Create the applet over `store`.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self {
            store,
            value: Vec::new(),
            out: Vec::new(),
            pin: PinSlot::new(PIV_PIN_POLICY),
            puk: PinSlot::new(PIV_PIN_POLICY),
            mgmt: MgmtKey::default_key(),
            pin_verified: false,
            mgmt_authenticated: false,
            witness: None,
            pending_sign: None,
            presence_cached: false,
            provisioned: false,
        }
    }

    /// Borrow the underlying store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Borrow the underlying store mutably.
    #[must_use]
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Install factory defaults when the card is blank.
    fn provision(&mut self) {
        if self.provisioned {
            return;
        }
        self.provisioned = true;

        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        if self.store.read(RECORD_PIN, &mut encoded).is_none() {
            let mut slot = PinSlot::new(PIV_PIN_POLICY);
            let _ = slot.set(&padded_pin(DEFAULT_PIN));
            self.write_pin_slot(RECORD_PIN, &slot);
        }
        if self.store.read(RECORD_PUK, &mut encoded).is_none() {
            let mut slot = PinSlot::new(PIV_PIN_POLICY);
            let _ = slot.set(&padded_pin(DEFAULT_PUK));
            self.write_pin_slot(RECORD_PUK, &slot);
        }
        let mut record = [0u8; 34];
        if self.store.read(RECORD_MGMT_KEY, &mut record).is_none() {
            if let Some(len) = self.mgmt.encode(&mut record) {
                self.store.write(RECORD_MGMT_KEY, &record[..len]);
            }
        }
    }

    fn write_pin_slot(&mut self, record: u16, slot: &PinSlot) -> bool {
        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        match slot.encode(&mut encoded) {
            Ok(len) => self.store.write(record, &encoded[..len]),
            Err(_) => false,
        }
    }

    fn load_state(&mut self) -> bool {
        self.provision();
        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        let Some(len) = self.store.read(RECORD_PIN, &mut encoded) else {
            return false;
        };
        let Ok(pin) = PinSlot::decode(PIV_PIN_POLICY, &encoded[..len]) else {
            return false;
        };
        self.pin = pin;

        let Some(len) = self.store.read(RECORD_PUK, &mut encoded) else {
            return false;
        };
        let Ok(puk) = PinSlot::decode(PIV_PIN_POLICY, &encoded[..len]) else {
            return false;
        };
        self.puk = puk;

        let mut record = [0u8; 34];
        let Some(len) = self.store.read(RECORD_MGMT_KEY, &mut record) else {
            return false;
        };
        let Some(key) = MgmtKey::decode(&record[..len]) else {
            return false;
        };
        self.mgmt = key;
        true
    }

    fn persist_pin(&mut self) {
        let pin = self.pin.clone();
        let puk = self.puk.clone();
        self.write_pin_slot(RECORD_PIN, &pin);
        self.write_pin_slot(RECORD_PUK, &puk);
    }

    // ----- command handling -------------------------------------------------

    fn get_data(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        let Some(oid) = request_object_id(apdu.data) else {
            return Response::status(Sw::WRONG_DATA);
        };
        match oid {
            OBJECT_CHUID => self.stored_or_default(OBJECT_CHUID, DEFAULT_CHUID),
            OBJECT_CCC => self.stored_or_default(OBJECT_CCC, DEFAULT_CCC),
            OBJECT_KEY_HISTORY => wrap_object(&mut self.out, None, KEY_HISTORY),
            _ => {
                let Some(index) = object_index(oid) else {
                    return Response::status(Sw::FILE_NOT_FOUND);
                };
                let record = RECORD_OBJECT_BASE + index;
                let mut value = [0u8; MAX_RECORD_BYTES];
                match self.store.read(record, &mut value) {
                    Some(len) => {
                        let inner = object_is_certificate(oid).then_some(0x70);
                        wrap_object(&mut self.out, inner, &value[..len])
                    }
                    None => Response::status(Sw::FILE_NOT_FOUND),
                }
            }
        }
    }

    fn stored_or_default(&mut self, oid: u32, default: &[u8]) -> Response<'_> {
        let Some(index) = object_index(oid) else {
            return Response::status(Sw::FILE_NOT_FOUND);
        };
        match self.store.read(RECORD_OBJECT_BASE + index, &mut self.value) {
            Some(len) => {
                let out = &mut self.out;
                let value = &self.value[..len];
                wrap_object(out, None, value)
            }
            None => wrap_object(&mut self.out, None, default),
        }
    }

    fn put_data(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        if !self.mgmt_authenticated {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let mut reader = tlv::Reader::new(apdu.data);
        let Some(identifier) = reader.next() else {
            return Response::status(Sw::WRONG_DATA);
        };
        if identifier.tag != 0x5C {
            return Response::status(Sw::WRONG_DATA);
        }
        let Some((oid, _)) = tlv::read_tag(identifier.value) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(content) = reader.next() else {
            return Response::status(Sw::WRONG_DATA);
        };
        if !reader.is_empty() {
            return Response::status(Sw::WRONG_DATA);
        }
        if oid == OBJECT_KEY_HISTORY {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        }
        let Some(index) = object_index(oid) else {
            return Response::status(Sw::FILE_NOT_FOUND);
        };
        if content.value.len() > MAX_RECORD_BYTES {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        if self.store.write(RECORD_OBJECT_BASE + index, content.value) {
            Response::status(Sw::OK)
        } else {
            Response::status(Sw::NOT_ENOUGH_MEMORY)
        }
    }

    fn verify(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if apdu.p1 != 0x00 {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        let result = match apdu.p2 {
            REF_PIN => {
                if apdu.data.is_empty() {
                    return Response::status(Sw::retries_left(self.pin.retries_remaining()));
                }
                if apdu.data.len() != 8 {
                    return Response::status(Sw::WRONG_LENGTH);
                }
                let result = self.pin.verify(apdu.data);
                self.persist_pin();
                if result.is_ok() {
                    self.pin_verified = true;
                }
                result
            }
            REF_PUK => {
                if apdu.data.is_empty() {
                    return Response::status(Sw::retries_left(self.puk.retries_remaining()));
                }
                if apdu.data.len() != 8 {
                    return Response::status(Sw::WRONG_LENGTH);
                }
                let result = self.puk.verify(apdu.data);
                self.persist_pin();
                result
            }
            _ => return Response::status(Sw::INCORRECT_PARAMETERS),
        };
        Response::status(result.err().unwrap_or(Sw::OK))
    }

    fn change_reference_data(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if apdu.p1 != 0x00 {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        if apdu.p2 != REF_PIN && apdu.p2 != REF_PUK {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        }
        if apdu.data.len() != 16 {
            return Response::status(Sw::WRONG_DATA);
        }
        if effective_pin_len(&apdu.data[8..]) < PIV_PIN_POLICY.min_len {
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        }
        let result = if apdu.p2 == REF_PIN {
            self.pin.change(&apdu.data[..8], &apdu.data[8..])
        } else {
            self.puk.change(&apdu.data[..8], &apdu.data[8..])
        };
        self.persist_pin();
        if result.is_ok() && apdu.p2 == REF_PIN {
            self.pin_verified = true;
        }
        Response::status(result.err().unwrap_or(Sw::OK))
    }

    fn reset_retry_counter(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if apdu.p1 != 0x00 || apdu.p2 != REF_PIN {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        if apdu.data.len() != 16 {
            return Response::status(Sw::WRONG_DATA);
        }
        if let Err(sw) = self.puk.verify(&apdu.data[..8]) {
            self.persist_pin();
            return Response::status(sw);
        }
        if effective_pin_len(&apdu.data[8..]) < PIV_PIN_POLICY.min_len {
            self.persist_pin();
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        }
        let result = self.pin.unblock(&apdu.data[8..]);
        self.persist_pin();
        self.pin_verified = false;
        Response::status(result.err().unwrap_or(Sw::OK))
    }

    fn generate_key_pair(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_> {
        if apdu.p1 != 0x00 {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        if !self.mgmt_authenticated {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let Some(slot) = KeySlot::from_code(apdu.p2) else {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        };
        let Some(template) = tlv::find(apdu.data, 0xAC) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(algorithm) = tlv::find(template, 0x80).and_then(one_byte) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let pin_policy = match tlv::find(template, 0xAA).and_then(one_byte) {
            Some(code) => match PinPolicyCode::from_code(code) {
                Some(policy) => policy,
                None => return Response::status(Sw::WRONG_DATA),
            },
            None => PinPolicyCode::Once,
        };
        let touch_policy = match tlv::find(template, 0xAB).and_then(one_byte) {
            Some(code) => match TouchPolicy::from_code(code) {
                Some(policy) => policy,
                None => return Response::status(Sw::WRONG_DATA),
            },
            None => TouchPolicy::Never,
        };
        if algorithm == ALG_RSA2048 {
            return self.generate_rsa_key_pair(slot, pin_policy, touch_policy, rng);
        }
        let Some(key_len) = KeySlot::curve_bytes(algorithm) else {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        };

        let mut scalar = [0u8; 48];
        if !generate_scalar(rng, algorithm, &mut scalar) {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        let mut point = [0u8; 97];
        let Some(point_len) = public_point(algorithm, &scalar[..key_len], &mut point) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };

        let mut record = [0u8; 4 + 48];
        record[0] = algorithm;
        record[1] = pin_policy as u8;
        record[2] = touch_policy as u8;
        record[3] = key_len as u8;
        record[4..4 + key_len].copy_from_slice(&scalar[..key_len]);
        if !self.store.write(slot.record(), &record[..4 + key_len]) {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }

        wrap_public_key(&mut self.out, &point[..point_len])
    }

    /// Generate an RSA-2048 key pair on-device and answer `7F49 { 81 n, 82 e }`.
    ///
    /// The persisted record is `[algo, pin, touch, 0x00, len_lo, len_hi]`
    /// followed by the [`rsa::Rsa2048PrivateKey`] blob; the zero key-length
    /// byte marks the extended header (ECC records store the scalar length
    /// there instead).
    fn generate_rsa_key_pair(
        &mut self,
        slot: KeySlot,
        pin_policy: PinPolicyCode,
        touch_policy: TouchPolicy,
        rng: &mut dyn Rng,
    ) -> Response<'_> {
        let Some(key) = rsa::generate_key(rng) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        let mut blob = [0u8; rsa::RSA_BLOB_BYTES];
        key.to_blob(&mut blob);
        let mut record = [0u8; KEY_RECORD_BYTES];
        record[0] = ALG_RSA2048;
        record[1] = pin_policy as u8;
        record[2] = touch_policy as u8;
        record[3] = 0x00;
        let len = rsa::RSA_BLOB_BYTES as u16;
        record[4] = (len & 0xFF) as u8;
        record[5] = (len >> 8) as u8;
        record[6..6 + rsa::RSA_BLOB_BYTES].copy_from_slice(&blob);
        if !self
            .store
            .write(slot.record(), &record[..6 + rsa::RSA_BLOB_BYTES])
        {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }

        let public = key.public();
        wrap_rsa_public_key(&mut self.out, &public.n, public.e)
    }

    fn general_authenticate(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_> {
        match apdu.p2 {
            REF_MANAGEMENT => self.authenticate_management(apdu, rng),
            REF_PIV_AUTH | REF_SIGNATURE | REF_CARD_AUTH => self.sign(apdu, rng),
            _ => Response::status(Sw::INCORRECT_PARAMETERS),
        }
    }

    fn authenticate_management(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_> {
        // Hosts send both 0x03 (the standard value) and 0x00 for 3DES.
        let accepted_algorithm =
            apdu.p1 == self.mgmt.algorithm || (self.mgmt.algorithm == ALG_TDES && apdu.p1 == 0x00);
        if !accepted_algorithm {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        let Some(template) = tlv::find(apdu.data, 0x7C) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let witness = tlv::find(template, 0x80);
        let challenge = tlv::find(template, 0x81);
        let response = tlv::find(template, 0x82);

        if let Some(pending) = self.witness.take() {
            // Second step: the host proves knowledge of the key by returning
            // the nonce the card sent encrypted.
            let submitted = if pending.mutual { witness } else { response };
            let Some(submitted) = submitted else {
                return Response::status(Sw::WRONG_DATA);
            };
            if !constant_time_eq(submitted, &pending.nonce) {
                return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            self.mgmt_authenticated = true;
            if pending.mutual {
                let Some(challenge) = challenge else {
                    return Response::status(Sw::WRONG_DATA);
                };
                return self.encrypted_challenge_response(challenge);
            }
            return Response::status(Sw::OK);
        }

        // First step: an empty witness (mutual) or challenge (single) asks the
        // card for its encrypted nonce.
        let mutual = matches!(witness, Some([]));
        if !mutual && !matches!(challenge, Some([])) {
            return Response::status(Sw::WRONG_DATA);
        }
        let block_len = self.mgmt.block_len();
        if block_len == 0 {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        }
        let mut nonce = Vec::new();
        if nonce.resize(block_len, 0).is_err() {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        rng.fill_bytes(&mut nonce);
        let mut encrypted = nonce.clone();
        if !self.mgmt.encrypt(&mut encrypted) {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        let tag = if mutual { 0x80 } else { 0x81 };
        if wrap_challenge(&mut self.out, tag, &encrypted)
            .sw
            .is_success()
        {
            self.witness = Some(Witness { mutual, nonce });
            wrap_challenge(&mut self.out, tag, &encrypted)
        } else {
            Response::status(Sw::NO_PRECISE_DIAGNOSIS)
        }
    }

    fn encrypted_challenge_response(&mut self, challenge: &[u8]) -> Response<'_> {
        if challenge.len() != self.mgmt.block_len() {
            return Response::status(Sw::WRONG_DATA);
        }
        let mut encrypted = [0u8; 16];
        encrypted[..challenge.len()].copy_from_slice(challenge);
        if !self.mgmt.encrypt(&mut encrypted[..challenge.len()]) {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        wrap_challenge(&mut self.out, 0x82, &encrypted[..challenge.len()])
    }

    fn sign(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_> {
        let Some(slot) = KeySlot::from_code(apdu.p2) else {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        };
        let mut record = [0u8; KEY_RECORD_BYTES];
        let Some(len) = self.store.read(slot.record(), &mut record) else {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        };
        if len < 4 {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        }
        let algorithm = record[0];
        if algorithm != apdu.p1 || !supports_algorithm(algorithm) {
            return Response::status(Sw::INCORRECT_PARAMETERS);
        }
        let pin_policy = match PinPolicyCode::from_code(record[1]) {
            Some(policy) => policy,
            None => return Response::status(Sw::REFERENCED_DATA_NOT_FOUND),
        };
        let touch_policy = match TouchPolicy::from_code(record[2]) {
            Some(policy) => policy,
            None => return Response::status(Sw::REFERENCED_DATA_NOT_FOUND),
        };
        if pin_policy != PinPolicyCode::Never && !self.pin_verified {
            return Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let Some(template) = tlv::find(apdu.data, 0x7C) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(digest) = tlv::find(template, 0x81) else {
            return Response::status(Sw::WRONG_DATA);
        };
        if algorithm == ALG_RSA2048 {
            return self.sign_rsa(slot, pin_policy, touch_policy, digest, rng);
        }
        let Some(key_len) = KeySlot::curve_bytes(algorithm) else {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        };
        if digest.len() > key_len {
            return Response::status(Sw::WRONG_DATA);
        }
        let mut padded = [0u8; 48];
        padded[key_len - digest.len()..key_len].copy_from_slice(digest);

        let touch_required = match touch_policy {
            TouchPolicy::Never => false,
            TouchPolicy::Always => true,
            TouchPolicy::Cached => !self.presence_cached,
        };
        if touch_required {
            let mut stashed = Vec::new();
            if stashed.extend_from_slice(&padded[..key_len]).is_err() {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            }
            self.pending_sign = Some(PendingSign {
                slot,
                digest: stashed,
            });
            return Response::presence_required();
        }
        self.complete_sign(
            slot,
            algorithm,
            pin_policy,
            touch_policy,
            &padded[..key_len],
            rng,
        )
    }

    /// RSA `SIGN`: the host supplies the encoded 256-byte block (PKCS#1
    /// padding is the host's job, as with the ECC prehash); shorter inputs
    /// are left-padded, mirroring the ECC path.
    fn sign_rsa(
        &mut self,
        slot: KeySlot,
        pin_policy: PinPolicyCode,
        touch_policy: TouchPolicy,
        digest: &[u8],
        rng: &mut dyn Rng,
    ) -> Response<'_> {
        if digest.len() > rsa::RSA2048_BYTES {
            return Response::status(Sw::WRONG_DATA);
        }
        let mut block = [0u8; rsa::RSA2048_BYTES];
        block[rsa::RSA2048_BYTES - digest.len()..].copy_from_slice(digest);
        let touch_required = match touch_policy {
            TouchPolicy::Never => false,
            TouchPolicy::Always => true,
            TouchPolicy::Cached => !self.presence_cached,
        };
        if touch_required {
            let mut stashed = Vec::new();
            if stashed.extend_from_slice(&block).is_err() {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            }
            self.pending_sign = Some(PendingSign {
                slot,
                digest: stashed,
            });
            return Response::presence_required();
        }
        self.complete_rsa_sign(slot, pin_policy, touch_policy, &block, rng)
    }

    fn complete_sign(
        &mut self,
        slot: KeySlot,
        algorithm: u8,
        pin_policy: PinPolicyCode,
        touch_policy: TouchPolicy,
        digest: &[u8],
        rng: &mut dyn Rng,
    ) -> Response<'_> {
        if algorithm == ALG_RSA2048 {
            if digest.len() != rsa::RSA2048_BYTES {
                return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
            }
            let mut block = [0u8; rsa::RSA2048_BYTES];
            block.copy_from_slice(digest);
            return self.complete_rsa_sign(slot, pin_policy, touch_policy, &block, rng);
        }
        let mut record = [0u8; 4 + 48];
        let Some(len) = self.store.read(slot.record(), &mut record) else {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        };
        let Some(key_len) = KeySlot::curve_bytes(algorithm) else {
            return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
        };
        if len < 4 + key_len || digest.len() != key_len {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        }
        let Some(signature) = sign_prehash(algorithm, &record[4..4 + key_len], digest) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        self.finish_sign(pin_policy, touch_policy);
        wrap_challenge(&mut self.out, 0x82, &signature)
    }

    /// Finish an RSA `SIGN` once PIN and presence are satisfied.
    fn complete_rsa_sign(
        &mut self,
        slot: KeySlot,
        pin_policy: PinPolicyCode,
        touch_policy: TouchPolicy,
        block: &[u8; rsa::RSA2048_BYTES],
        rng: &mut dyn Rng,
    ) -> Response<'_> {
        let mut record = [0u8; KEY_RECORD_BYTES];
        let Some(len) = self.store.read(slot.record(), &mut record) else {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        };
        if len != 6 + rsa::RSA_BLOB_BYTES
            || record[0] != ALG_RSA2048
            || record[3] != 0x00
            || usize::from(record[4]) | (usize::from(record[5]) << 8) != rsa::RSA_BLOB_BYTES
        {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        }
        let Some(key) = rsa::Rsa2048PrivateKey::from_blob(&record[6..6 + rsa::RSA_BLOB_BYTES])
        else {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        };
        let Some(signature) = rsa::apply_private(&key, block, rng) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        self.finish_sign(pin_policy, touch_policy);
        wrap_challenge(&mut self.out, 0x82, &signature)
    }

    /// Apply the PIN-always and touch-cache state transitions shared by
    /// every completed signature.
    fn finish_sign(&mut self, pin_policy: PinPolicyCode, touch_policy: TouchPolicy) {
        if pin_policy == PinPolicyCode::Always {
            self.pin_verified = false;
        }
        match touch_policy {
            TouchPolicy::Cached => self.presence_cached = true,
            TouchPolicy::Always => self.presence_cached = false,
            TouchPolicy::Never => {}
        }
    }

    fn select_response(&mut self) -> Response<'_> {
        self.pin_verified = false;
        self.mgmt_authenticated = false;
        self.witness = None;
        self.pending_sign = None;
        self.presence_cached = false;
        if !self.load_state() {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        Response::ok(FCI)
    }
}

impl<S: PivStore> Applet for Piv<S> {
    fn aid(&self) -> &'static [u8] {
        AID
    }

    fn select(&mut self) -> Response<'_> {
        self.select_response()
    }

    fn process(&mut self, apdu: &Apdu<'_>, rng: &mut dyn Rng) -> Response<'_> {
        match apdu.ins {
            INS_GET_DATA => self.get_data(apdu),
            INS_PUT_DATA => self.put_data(apdu),
            INS_VERIFY => self.verify(apdu),
            INS_CHANGE_REFERENCE_DATA => self.change_reference_data(apdu),
            INS_RESET_RETRY_COUNTER => self.reset_retry_counter(apdu),
            INS_GENERATE_ASYMMETRIC_KEY_PAIR => self.generate_key_pair(apdu, rng),
            INS_GENERAL_AUTHENTICATE => self.general_authenticate(apdu, rng),
            _ => Response::status(Sw::INS_NOT_SUPPORTED),
        }
    }

    fn confirm_presence(&mut self, rng: &mut dyn Rng) -> Response<'_> {
        let Some(pending) = self.pending_sign.take() else {
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        };
        let mut record = [0u8; KEY_RECORD_BYTES];
        let Some(len) = self.store.read(pending.slot.record(), &mut record) else {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        };
        if len < 4 {
            return Response::status(Sw::REFERENCED_DATA_NOT_FOUND);
        }
        let algorithm = record[0];
        let pin_policy = match PinPolicyCode::from_code(record[1]) {
            Some(policy) => policy,
            None => return Response::status(Sw::REFERENCED_DATA_NOT_FOUND),
        };
        let touch_policy = match TouchPolicy::from_code(record[2]) {
            Some(policy) => policy,
            None => return Response::status(Sw::REFERENCED_DATA_NOT_FOUND),
        };
        let digest = pending.digest.clone();
        self.complete_sign(
            pending.slot,
            algorithm,
            pin_policy,
            touch_policy,
            &digest,
            rng,
        )
    }

    fn deny_presence(&mut self) -> Response<'_> {
        self.pending_sign = None;
        Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED)
    }
}

/// Wrap `86 { point }` inside `7F49` for `GENERATE ASYMMETRIC KEY PAIR`.
fn wrap_public_key<'a>(out: &'a mut Vec<u8, SCRATCH_BYTES>, point: &[u8]) -> Response<'a> {
    let inner_len = tlv::encoded_len(0x86, point.len());
    let total = tlv::encoded_len(0x7F49, inner_len);
    if total > SCRATCH_BYTES {
        return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
    }
    out.clear();
    if out.resize(total, 0).is_err() {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    }
    let Some(outer) = tlv::write_header(0x7F49, inner_len, out) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    let Some(inner) = tlv::write_header(0x86, point.len(), &mut out[outer..]) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    out[outer + inner..total].copy_from_slice(point);
    Response::ok(out)
}

/// Wrap `81 { modulus }` + `82 { exponent }` inside `7F49` for RSA
/// `GENERATE ASYMMETRIC KEY PAIR` (NIST SP 800-73-4, Table 11).
fn wrap_rsa_public_key<'a>(
    out: &'a mut Vec<u8, SCRATCH_BYTES>,
    modulus: &[u8],
    exponent: u32,
) -> Response<'a> {
    let exp = exponent.to_be_bytes();
    let first = exp
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(exp.len() - 1);
    let exp = &exp[first..];
    let inner_len = tlv::encoded_len(0x81, modulus.len()) + tlv::encoded_len(0x82, exp.len());
    let total = tlv::encoded_len(0x7F49, inner_len);
    if total > SCRATCH_BYTES {
        return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
    }
    out.clear();
    if out.resize(total, 0).is_err() {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    }
    let Some(mut cursor) = tlv::write_header(0x7F49, inner_len, out) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    let Some(header) = tlv::write_header(0x81, modulus.len(), &mut out[cursor..]) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    cursor += header;
    out[cursor..cursor + modulus.len()].copy_from_slice(modulus);
    cursor += modulus.len();
    let Some(header) = tlv::write_header(0x82, exp.len(), &mut out[cursor..]) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    cursor += header;
    out[cursor..total].copy_from_slice(exp);
    Response::ok(out)
}

/// Wrap `7C { tag { value } }` around a challenge, response or signature.
fn wrap_challenge<'a>(out: &'a mut Vec<u8, SCRATCH_BYTES>, tag: u8, value: &[u8]) -> Response<'a> {
    let inner_len = tlv::encoded_len(u32::from(tag), value.len());
    let total = tlv::encoded_len(0x7C, inner_len);
    if total > SCRATCH_BYTES {
        return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
    }
    out.clear();
    if out.resize(total, 0).is_err() {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    }
    let Some(outer) = tlv::write_header(0x7C, inner_len, out) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    let Some(inner) = tlv::write_header(u32::from(tag), value.len(), &mut out[outer..]) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    out[outer + inner..total].copy_from_slice(value);
    Response::ok(out)
}

/// Build `53 { value }`, or `53 { inner_tag { value } }` when an inner tag is
/// given (certificates use `70`).
fn wrap_object<'a>(
    out: &'a mut Vec<u8, SCRATCH_BYTES>,
    inner_tag: Option<u32>,
    value: &[u8],
) -> Response<'a> {
    let inner_len = match inner_tag {
        Some(tag) => tlv::encoded_len(tag, value.len()),
        None => value.len(),
    };
    let total = tlv::encoded_len(0x53, inner_len);
    if total > SCRATCH_BYTES {
        return Response::status(Sw::FUNCTION_NOT_SUPPORTED);
    }
    out.clear();
    if out.resize(total, 0).is_err() {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    }
    let Some(mut cursor) = tlv::write_header(0x53, inner_len, out) else {
        return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
    };
    if let Some(tag) = inner_tag {
        let Some(header) = tlv::write_header(tag, value.len(), &mut out[cursor..]) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        cursor += header;
    }
    out[cursor..total].copy_from_slice(value);
    Response::ok(out)
}

/// Fill `out` with a valid scalar, retrying until the point is on the curve.
fn generate_scalar(rng: &mut dyn Rng, algorithm: u8, out: &mut [u8; 48]) -> bool {
    let key_len = match algorithm {
        ALG_ECCP256 => 32,
        ALG_ECCP384 => 48,
        _ => return false,
    };
    let mut point = [0u8; 97];
    for _ in 0..64 {
        rng.fill_bytes(&mut out[..key_len]);
        if public_point(algorithm, &out[..key_len], &mut point).is_some() {
            return true;
        }
    }
    false
}

/// Compute the uncompressed SEC1 public point for a scalar.
fn public_point(algorithm: u8, scalar: &[u8], out: &mut [u8; 97]) -> Option<usize> {
    fn copy(bytes: &[u8], out: &mut [u8; 97]) -> Option<usize> {
        if bytes.len() > out.len() {
            return None;
        }
        out[..bytes.len()].copy_from_slice(bytes);
        Some(bytes.len())
    }

    match algorithm {
        ALG_ECCP256 => {
            let key = p256::ecdsa::SigningKey::from_slice(scalar).ok()?;
            let point = key.verifying_key().to_sec1_point(false);
            copy(point.as_bytes(), out)
        }
        ALG_ECCP384 => {
            let key = p384::ecdsa::SigningKey::from_slice(scalar).ok()?;
            let point = key.verifying_key().to_sec1_point(false);
            copy(point.as_bytes(), out)
        }
        _ => None,
    }
}

/// Sign a prehashed digest (already padded to the curve size).
fn sign_prehash(algorithm: u8, scalar: &[u8], digest: &[u8]) -> Option<Vec<u8, 104>> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let mut signature = Vec::new();
    match algorithm {
        ALG_ECCP256 => {
            let key = p256::ecdsa::SigningKey::from_slice(scalar).ok()?;
            let sig: p256::ecdsa::Signature = key.sign_prehash(digest).ok()?;
            signature.extend_from_slice(sig.to_der().as_bytes()).ok()?;
        }
        ALG_ECCP384 => {
            let key = p384::ecdsa::SigningKey::from_slice(scalar).ok()?;
            let sig: p384::ecdsa::Signature = key.sign_prehash(digest).ok()?;
            signature.extend_from_slice(sig.to_der().as_bytes()).ok()?;
        }
        _ => return None,
    }
    Some(signature)
}

/// Length of a PIN value after stripping 0xFF padding.
fn effective_pin_len(padded: &[u8]) -> usize {
    padded
        .iter()
        .rposition(|byte| *byte != 0xFF)
        .map_or(0, |index| index + 1)
}

/// Pad a PIN with 0xFF to the 8-byte PIV representation.
fn padded_pin(pin: &[u8]) -> [u8; 8] {
    let mut out = [0xFF; 8];
    let len = pin.len().min(8);
    out[..len].copy_from_slice(&pin[..len]);
    out
}

/// Read a one-byte TLV value.
fn one_byte(value: &[u8]) -> Option<u8> {
    match value {
        [byte] => Some(*byte),
        _ => None,
    }
}

/// Extract the object identifier from a `5C` request TLV.
fn request_object_id(data: &[u8]) -> Option<u32> {
    let mut reader = tlv::Reader::new(data);
    let identifier = reader.next()?;
    if identifier.tag != 0x5C {
        return None;
    }
    tlv::read_tag(identifier.value).map(|(tag, _)| tag)
}

/// Index of an object in the storage table.
fn object_index(oid: u32) -> Option<u16> {
    let index = match oid {
        OBJECT_CARD_AUTH_CERT => 0,
        OBJECT_CHUID => 1,
        OBJECT_PIV_AUTH_CERT => 2,
        OBJECT_CCC => 3,
        OBJECT_PRINTED => 4,
        OBJECT_SIGNATURE_CERT => 5,
        OBJECT_KEY_MGMT_CERT => 6,
        OBJECT_RETIRED_AUTH_CERT => 7,
        OBJECT_RETIRED_SIGNATURE_CERT => 8,
        OBJECT_RETIRED_KEY_MGMT_CERT => 9,
        _ => return None,
    };
    Some(index)
}

const fn object_is_certificate(oid: u32) -> bool {
    matches!(
        oid,
        OBJECT_CARD_AUTH_CERT
            | OBJECT_PIV_AUTH_CERT
            | OBJECT_SIGNATURE_CERT
            | OBJECT_KEY_MGMT_CERT
            | OBJECT_RETIRED_AUTH_CERT
            | OBJECT_RETIRED_SIGNATURE_CERT
            | OBJECT_RETIRED_KEY_MGMT_CERT
    )
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

/// Single-block Triple-DES ECB encryption.
fn tdes_ecb_encrypt(key: &[u8], block: &mut [u8]) -> bool {
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockEncrypt, KeyInit};
    if key.len() != 24 || block.len() != 8 {
        return false;
    }
    let Ok(cipher) = des::TdesEde3::new_from_slice(key) else {
        return false;
    };
    let mut buffer = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut buffer);
    block.copy_from_slice(&buffer);
    true
}

/// Single-block AES ECB encryption (CBC with a zero IV over one block).
fn aes_ecb_encrypt(key: &[u8], block: &mut [u8]) -> bool {
    use cbc::cipher::block_padding::NoPadding;
    use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
    if block.len() != 16 {
        return false;
    }
    let iv = [0u8; 16];
    let len = block.len();
    let result = match key.len() {
        16 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, &iv)
            .map_err(|_| ())
            .and_then(|cipher| {
                cipher
                    .encrypt_padded::<NoPadding>(block, len)
                    .map_err(|_| ())
            }),
        24 => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, &iv)
            .map_err(|_| ())
            .and_then(|cipher| {
                cipher
                    .encrypt_padded::<NoPadding>(block, len)
                    .map_err(|_| ())
            }),
        32 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &iv)
            .map_err(|_| ())
            .and_then(|cipher| {
                cipher
                    .encrypt_padded::<NoPadding>(block, len)
                    .map_err(|_| ())
            }),
        _ => return false,
    };
    result.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Apdu;
    use heapless::Vec as HeaplessVec;

    struct TestRng(u64);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                *byte = (self.0 >> 33) as u8;
            }
        }
    }

    const PIN: [u8; 8] = [b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF];
    const WRONG_PIN: [u8; 8] = [b'0'; 8];

    fn applet() -> Piv<MemoryPivStore> {
        let mut piv = Piv::new(MemoryPivStore::new());
        let response = piv.select();
        assert_eq!(response.sw, Sw::OK);
        piv
    }

    fn command(ins: u8, p1: u8, p2: u8, data: &[u8]) -> HeaplessVec<u8, 2048> {
        let mut frame = HeaplessVec::new();
        frame.extend_from_slice(&[0x00, ins, p1, p2]).unwrap();
        if data.is_empty() {
            // Case 1.
        } else if data.len() < 256 {
            frame.push(data.len() as u8).unwrap();
            frame.extend_from_slice(data).unwrap();
        } else {
            // Extended Lc.
            let len = data.len() as u16;
            frame
                .extend_from_slice(&[0x00, (len >> 8) as u8, len as u8])
                .unwrap();
            frame.extend_from_slice(data).unwrap();
        }
        frame
    }

    fn run(
        piv: &mut Piv<MemoryPivStore>,
        rng: &mut TestRng,
        frame: &[u8],
    ) -> (HeaplessVec<u8, 2048>, Sw) {
        let apdu = Apdu::parse(frame).expect("valid test APDU");
        let response = piv.process(&apdu, rng);
        let mut data = HeaplessVec::new();
        data.extend_from_slice(response.data).unwrap();
        (data, response.sw)
    }

    fn get_data(
        piv: &mut Piv<MemoryPivStore>,
        rng: &mut TestRng,
        oid: &[u8],
    ) -> (HeaplessVec<u8, 2048>, Sw) {
        let mut data = HeaplessVec::<u8, 16>::new();
        data.push(0x5C).unwrap();
        data.push(oid.len() as u8).unwrap();
        data.extend_from_slice(oid).unwrap();
        run(piv, rng, &command(INS_GET_DATA, 0x3F, 0xFF, &data))
    }

    /// Find `tag` inside the `7C` dynamic authentication template.
    fn find_in_7c(data: &[u8], tag: u32) -> Option<&[u8]> {
        let template = tlv::find(data, 0x7C)?;
        tlv::find(template, tag)
    }

    /// Find `tag` inside the `53` data object wrapper.
    fn find_in_53(data: &[u8], tag: u32) -> Option<&[u8]> {
        let object = tlv::find(data, 0x53)?;
        tlv::find(object, tag)
    }

    /// Authenticate the management key with the default 3DES key.
    fn authenticate_management(piv: &mut Piv<MemoryPivStore>, rng: &mut TestRng) {
        let (data, sw) = run(
            piv,
            rng,
            &command(
                INS_GENERAL_AUTHENTICATE,
                ALG_TDES,
                REF_MANAGEMENT,
                &[0x7C, 0x02, 0x81, 0x00],
            ),
        );
        assert_eq!(sw, Sw::OK);
        let encrypted = find_in_7c(&data, 0x81).expect("challenge present");
        let mgmt_key = default_mgmt_key(rng);
        let nonce = tdes_ecb_decrypt(&mgmt_key, encrypted);
        let mut body = HeaplessVec::<u8, 32>::new();
        body.extend_from_slice(&[0x7C, 0x0A, 0x82, 0x08]).unwrap();
        body.extend_from_slice(&nonce).unwrap();
        let (_, sw) = run(
            piv,
            rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_TDES, REF_MANAGEMENT, &body),
        );
        assert_eq!(sw, Sw::OK, "management key authentication");
    }

    fn generate_key(
        piv: &mut Piv<MemoryPivStore>,
        rng: &mut TestRng,
        slot: u8,
        algorithm: u8,
        touch: Option<u8>,
    ) -> (HeaplessVec<u8, 2048>, Sw) {
        let mut template = HeaplessVec::<u8, 16>::new();
        template
            .extend_from_slice(&[0xAC, 0x06, 0x80, 0x01, algorithm, 0xAA, 0x01, 0x02])
            .unwrap();
        if let Some(touch) = touch {
            template.extend_from_slice(&[0xAB, 0x01, touch]).unwrap();
            template[1] = 0x09;
        }
        run(
            piv,
            rng,
            &command(INS_GENERATE_ASYMMETRIC_KEY_PAIR, 0x00, slot, &template),
        )
    }

    fn tdes_ecb_decrypt(key: &[u8], block: &[u8]) -> [u8; 8] {
        use des::cipher::generic_array::GenericArray;
        use des::cipher::{BlockDecrypt, KeyInit};
        let cipher = des::TdesEde3::new_from_slice(key).unwrap();
        let mut buffer = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut buffer);
        let mut out = [0u8; 8];
        out.copy_from_slice(&buffer);
        out
    }

    #[test]
    fn selecting_returns_fci_and_provisions_defaults() {
        let mut piv = Piv::new(MemoryPivStore::new());
        assert_eq!(piv.aid(), AID);
        assert_eq!(piv.select().sw, Sw::OK);
        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        assert!(piv.store_mut().read(RECORD_PIN, &mut encoded).is_some());
        assert!(
            piv.store_mut()
                .read(RECORD_MGMT_KEY, &mut encoded[..34])
                .is_some()
        );
    }

    #[test]
    fn get_data_returns_defaults_and_wrapped_objects() {
        let mut piv = applet();
        let mut rng = TestRng(1);

        let (data, sw) = get_data(&mut piv, &mut rng, &[0x5F, 0xC1, 0x07]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(data[0], 0x53);
        assert_eq!(tlv::find(&data, 0x53), Some(DEFAULT_CCC));

        let (data, sw) = get_data(&mut piv, &mut rng, &[0x5F, 0xC1, 0x02]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(tlv::find(&data, 0x53), Some(DEFAULT_CHUID));

        let (data, sw) = get_data(&mut piv, &mut rng, &[0x5F, 0xC1, 0x0C]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(tlv::find(&data, 0x53), Some(KEY_HISTORY));
    }

    #[test]
    fn get_data_rejects_unknown_objects() {
        let mut piv = applet();
        let mut rng = TestRng(2);
        let (_, sw) = get_data(&mut piv, &mut rng, &[0x5F, 0xC1, 0x7F]);
        assert_eq!(sw, Sw::FILE_NOT_FOUND);
        let (_, sw) = get_data(&mut piv, &mut rng, &[0x5F, 0xC1, 0x09]);
        assert_eq!(sw, Sw::FILE_NOT_FOUND);
    }

    #[test]
    fn verify_accepts_the_default_pin_and_tracks_retries() {
        let mut piv = applet();
        let mut rng = TestRng(3);

        assert_eq!(
            run(
                &mut piv,
                &mut rng,
                &command(INS_VERIFY, 0, REF_PIN, &WRONG_PIN)
            )
            .1,
            Sw::retries_left(2)
        );
        assert_eq!(
            run(
                &mut piv,
                &mut rng,
                &command(INS_VERIFY, 0, REF_PIN, &WRONG_PIN)
            )
            .1,
            Sw::retries_left(1)
        );
        assert_eq!(
            run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN)).1,
            Sw::OK
        );
        // The empty VERIFY reports the remaining attempts.
        let (_, sw) = run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &[]));
        assert_eq!(sw, Sw::retries_left(1));
    }

    #[test]
    fn retry_counter_survives_a_reopen() {
        let mut piv = applet();
        let mut rng = TestRng(4);
        for _ in 0..3 {
            let _ = run(
                &mut piv,
                &mut rng,
                &command(INS_VERIFY, 0, REF_PIN, &WRONG_PIN),
            );
        }
        let (_, sw) = run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN));
        assert_eq!(sw, Sw::AUTHENTICATION_BLOCKED);

        // A new applet over the same store sees the blocked PIN.
        let store = core::mem::take(piv.store_mut());
        let mut reopened = Piv::new(store);
        assert_eq!(reopened.select().sw, Sw::OK);
        let (_, sw) = run(
            &mut reopened,
            &mut rng,
            &command(INS_VERIFY, 0, REF_PIN, &PIN),
        );
        assert_eq!(sw, Sw::AUTHENTICATION_BLOCKED);
    }

    #[test]
    fn change_pin_requires_the_current_value() {
        let mut piv = applet();
        let mut rng = TestRng(5);
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(&WRONG_PIN);
        data[8..].copy_from_slice(&PIN);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_CHANGE_REFERENCE_DATA, 0, REF_PIN, &data),
        );
        assert_eq!(sw, Sw::retries_left(2));

        data[..8].copy_from_slice(&PIN);
        data[8..].copy_from_slice(&[b'6', b'5', b'4', b'3', b'2', b'1', 0xFF, 0xFF]);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_CHANGE_REFERENCE_DATA, 0, REF_PIN, &data),
        );
        assert_eq!(sw, Sw::OK);
        let (_, sw) = run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN));
        assert_eq!(sw, Sw::retries_left(2));
        let new_pin = [b'6', b'5', b'4', b'3', b'2', b'1', 0xFF, 0xFF];
        assert_eq!(
            run(
                &mut piv,
                &mut rng,
                &command(INS_VERIFY, 0, REF_PIN, &new_pin)
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn reset_retry_counter_unblocks_with_the_puk() {
        let mut piv = applet();
        let mut rng = TestRng(6);
        for _ in 0..3 {
            let _ = run(
                &mut piv,
                &mut rng,
                &command(INS_VERIFY, 0, REF_PIN, &WRONG_PIN),
            );
        }
        let mut data = [0u8; 16];
        data[..8].copy_from_slice(DEFAULT_PUK);
        data[8..].copy_from_slice(&[b'9', b'9', b'9', b'9', b'9', b'9', 0xFF, 0xFF]);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_RESET_RETRY_COUNTER, 0, REF_PIN, &data),
        );
        assert_eq!(sw, Sw::OK);
        let new_pin = [b'9', b'9', b'9', b'9', b'9', b'9', 0xFF, 0xFF];
        assert_eq!(
            run(
                &mut piv,
                &mut rng,
                &command(INS_VERIFY, 0, REF_PIN, &new_pin)
            )
            .1,
            Sw::OK
        );
    }

    #[test]
    fn put_data_requires_management_authentication() {
        let mut piv = applet();
        let mut rng = TestRng(7);
        let mut body = HeaplessVec::<u8, 64>::new();
        body.extend_from_slice(&[0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x70, 0x03, 0x01, 0x02, 0x03])
            .unwrap();
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_PUT_DATA, 0x3F, 0xFF, &body),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);

        authenticate_management(&mut piv, &mut rng);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_PUT_DATA, 0x3F, 0xFF, &body),
        );
        assert_eq!(sw, Sw::OK);

        let (data, sw) = get_data(&mut piv, &mut rng, &[0x5F, 0xC1, 0x05]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_in_53(&data, 0x70), Some(&[0x01, 0x02, 0x03][..]));
    }

    #[test]
    fn generate_and_sign_p256() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let mut piv = applet();
        let mut rng = TestRng(8);
        authenticate_management(&mut piv, &mut rng);

        let (public, sw) = generate_key(&mut piv, &mut rng, REF_SIGNATURE, ALG_ECCP256, None);
        assert_eq!(sw, Sw::OK);
        let template = tlv::find(&public, 0x7F49).expect("public key template");
        let point = tlv::find(template, 0x86).expect("public point");
        assert_eq!(point.len(), 65);

        let digest = [0x5Au8; 32];
        let mut body = HeaplessVec::<u8, 48>::new();
        body.extend_from_slice(&[0x7C, 0x24, 0x82, 0x00, 0x81, 0x20])
            .unwrap();
        body.extend_from_slice(&digest).unwrap();
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_ECCP256, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED, "PIN policy is once");

        assert_eq!(
            run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN)).1,
            Sw::OK
        );
        let (signature, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_ECCP256, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::OK);
        let der = find_in_7c(&signature, 0x82).expect("signature");
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).expect("point");
        let sig = p256::ecdsa::Signature::from_der(der).expect("DER signature");
        key.verify_prehash(&digest, &sig)
            .expect("signature verifies");
    }

    #[test]
    fn touch_policy_requests_presence() {
        let mut piv = applet();
        let mut rng = TestRng(9);
        authenticate_management(&mut piv, &mut rng);
        let (_, sw) = generate_key(
            &mut piv,
            &mut rng,
            REF_SIGNATURE,
            ALG_ECCP256,
            Some(TouchPolicy::Always as u8),
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(
            run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN)).1,
            Sw::OK
        );

        let digest = [0x11u8; 32];
        let mut body = HeaplessVec::<u8, 48>::new();
        body.extend_from_slice(&[0x7C, 0x24, 0x82, 0x00, 0x81, 0x20])
            .unwrap();
        body.extend_from_slice(&digest).unwrap();
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_ECCP256, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::PRESENCE_REQUIRED);

        let confirmed = piv.confirm_presence(&mut rng);
        assert_eq!(confirmed.sw, Sw::OK);
        assert!(find_in_7c(confirmed.data, 0x82).is_some());

        // Denial reports a security status failure.
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_ECCP256, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::PRESENCE_REQUIRED);
        assert_eq!(piv.deny_presence().sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn generate_requires_admin() {
        let mut piv = applet();
        let mut rng = TestRng(10);
        let (_, sw) = generate_key(&mut piv, &mut rng, REF_SIGNATURE, ALG_ECCP256, None);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);

        let (_, sw) = generate_key(&mut piv, &mut rng, REF_SIGNATURE, ALG_RSA2048, None);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn generate_rsa_and_sign_raw_block() {
        let mut piv = applet();
        let mut rng = TestRng(21);
        authenticate_management(&mut piv, &mut rng);

        let (public, sw) = generate_key(&mut piv, &mut rng, REF_SIGNATURE, ALG_RSA2048, None);
        assert_eq!(sw, Sw::OK);
        let template = tlv::find(&public, 0x7F49).expect("public key template");
        let modulus = tlv::find(template, 0x81).expect("modulus");
        let mut n = [0u8; crate::rsa::RSA2048_BYTES];
        n.copy_from_slice(modulus);

        // PIN policy defaults to `once`: signing needs a VERIFY first.
        let block = [0xA5u8; crate::rsa::RSA2048_BYTES];
        let body = sign_body(&block);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_RSA2048, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
        assert_eq!(
            run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN)).1,
            Sw::OK
        );

        let (signature, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_RSA2048, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::OK);
        let raw = find_in_7c(&signature, 0x82).expect("signature bytes");
        assert_eq!(raw.len(), crate::rsa::RSA2048_BYTES);
        let mut sig = [0u8; crate::rsa::RSA2048_BYTES];
        sig.copy_from_slice(raw);
        assert_eq!(
            crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &sig),
            Some(block),
            "raw private operation inverts with the public key"
        );

        // Short inputs are left-padded to the modulus size.
        let short = [0x5Au8; 32];
        let body = sign_body(&short);
        let (signature, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_RSA2048, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::OK);
        let raw = find_in_7c(&signature, 0x82).expect("signature bytes");
        let mut sig = [0u8; crate::rsa::RSA2048_BYTES];
        sig.copy_from_slice(raw);
        let mut expected = [0u8; crate::rsa::RSA2048_BYTES];
        expected[crate::rsa::RSA2048_BYTES - short.len()..].copy_from_slice(&short);
        assert_eq!(
            crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &sig),
            Some(expected)
        );

        // Oversized inputs are rejected.
        let big = [0xFFu8; crate::rsa::RSA2048_BYTES + 1];
        let body = sign_body(&big);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_RSA2048, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::WRONG_DATA);

        // An ECC algorithm byte against an RSA key is a parameter error.
        let body = sign_body(&short);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_ECCP256, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::INCORRECT_PARAMETERS);
    }

    /// Build `7C { 81 block }` for an RSA `SIGN` request.
    fn sign_body(block: &[u8]) -> HeaplessVec<u8, 2048> {
        let mut body = HeaplessVec::new();
        let inner = tlv::encoded_len(0x81, block.len());
        let total = tlv::encoded_len(0x7C, inner);
        body.resize(total, 0).unwrap();
        let outer = tlv::write_header(0x7C, inner, &mut body).unwrap();
        let inner_header = tlv::write_header(0x81, block.len(), &mut body[outer..]).unwrap();
        body[outer + inner_header..].copy_from_slice(block);
        body
    }

    #[test]
    fn generate_rsa_returns_modulus_and_exponent() {
        let mut piv = applet();
        let mut rng = TestRng(20);
        authenticate_management(&mut piv, &mut rng);

        let (public, sw) = generate_key(&mut piv, &mut rng, REF_SIGNATURE, ALG_RSA2048, None);
        assert_eq!(sw, Sw::OK);
        let template = tlv::find(&public, 0x7F49).expect("public key template");
        let modulus = tlv::find(template, 0x81).expect("modulus");
        let exponent = tlv::find(template, 0x82).expect("exponent");
        assert_eq!(modulus.len(), 256);
        assert_eq!(exponent, &[0x01, 0x00, 0x01][..]);
        // A 2048-bit modulus: top bit set, odd.
        assert!(modulus[0] & 0x80 != 0);
        assert!(modulus[255] & 0x01 != 0);
    }

    #[test]
    fn rsa_sign_goes_through_presence_when_touch_is_required() {
        let mut piv = applet();
        let mut rng = TestRng(22);
        authenticate_management(&mut piv, &mut rng);
        let (public, sw) = generate_key(
            &mut piv,
            &mut rng,
            REF_SIGNATURE,
            ALG_RSA2048,
            Some(TouchPolicy::Always as u8),
        );
        assert_eq!(sw, Sw::OK);
        let modulus =
            tlv::find(tlv::find(&public, 0x7F49).expect("template"), 0x81).expect("modulus");
        let mut n = [0u8; crate::rsa::RSA2048_BYTES];
        n.copy_from_slice(modulus);
        assert_eq!(
            run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN)).1,
            Sw::OK
        );

        let block = [0x33u8; crate::rsa::RSA2048_BYTES];
        let body = sign_body(&block);
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_RSA2048, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::PRESENCE_REQUIRED);

        let confirmed = piv.confirm_presence(&mut rng);
        assert_eq!(confirmed.sw, Sw::OK);
        let raw = find_in_7c(confirmed.data, 0x82).expect("signature bytes");
        let mut sig = [0u8; crate::rsa::RSA2048_BYTES];
        sig.copy_from_slice(raw);
        assert_eq!(
            crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &sig),
            Some(block)
        );

        // Denial refuses without touching the key.
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_RSA2048, REF_SIGNATURE, &body),
        );
        assert_eq!(sw, Sw::PRESENCE_REQUIRED);
        assert_eq!(piv.deny_presence().sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn rsa_key_survives_a_reopen() {
        let mut piv = applet();
        let mut rng = TestRng(23);
        authenticate_management(&mut piv, &mut rng);
        let (public, sw) = generate_key(&mut piv, &mut rng, REF_PIV_AUTH, ALG_RSA2048, None);
        assert_eq!(sw, Sw::OK);
        let modulus =
            tlv::find(tlv::find(&public, 0x7F49).expect("template"), 0x81).expect("modulus");
        let mut n = [0u8; crate::rsa::RSA2048_BYTES];
        n.copy_from_slice(modulus);

        let store = core::mem::take(piv.store_mut());
        let mut reopened = Piv::new(store);
        assert_eq!(reopened.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut reopened,
                &mut rng,
                &command(INS_VERIFY, 0, REF_PIN, &PIN)
            )
            .1,
            Sw::OK
        );
        let block = [0x77u8; crate::rsa::RSA2048_BYTES];
        let body = sign_body(&block);
        let (signature, sw) = run(
            &mut reopened,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_RSA2048, REF_PIV_AUTH, &body),
        );
        assert_eq!(sw, Sw::OK);
        let raw = find_in_7c(&signature, 0x82).expect("signature bytes");
        let mut sig = [0u8; crate::rsa::RSA2048_BYTES];
        sig.copy_from_slice(raw);
        assert_eq!(
            crate::rsa::public_op(&n, crate::rsa::RSA_PUBLIC_EXPONENT, &sig),
            Some(block)
        );
    }

    #[test]
    fn management_authentication_rejects_a_wrong_nonce() {
        let mut piv = applet();
        let mut rng = TestRng(11);
        let (data, sw) = run(
            &mut piv,
            &mut rng,
            &command(
                INS_GENERAL_AUTHENTICATE,
                ALG_TDES,
                REF_MANAGEMENT,
                &[0x7C, 0x02, 0x81, 0x00],
            ),
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_in_7c(&data, 0x81).map(|v| v.len()), Some(8));

        let mut body = HeaplessVec::<u8, 32>::new();
        body.extend_from_slice(&[0x7C, 0x0A, 0x82, 0x08]).unwrap();
        body.extend_from_slice(&[0u8; 8]).unwrap();
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_TDES, REF_MANAGEMENT, &body),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn mutual_management_authentication_returns_the_encrypted_challenge() {
        let mut piv = applet();
        let mut rng = TestRng(12);
        let (data, sw) = run(
            &mut piv,
            &mut rng,
            &command(
                INS_GENERAL_AUTHENTICATE,
                ALG_TDES,
                REF_MANAGEMENT,
                &[0x7C, 0x02, 0x80, 0x00],
            ),
        );
        assert_eq!(sw, Sw::OK);
        let witness = find_in_7c(&data, 0x80).expect("witness");
        let nonce = tdes_ecb_decrypt(&DEFAULT_MGMT_KEY, witness);
        let challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let mut body = HeaplessVec::<u8, 48>::new();
        body.extend_from_slice(&[0x7C, 0x16, 0x80, 0x08]).unwrap();
        body.extend_from_slice(&nonce).unwrap();
        body.extend_from_slice(&[0x81, 0x08]).unwrap();
        body.extend_from_slice(&challenge).unwrap();
        body.extend_from_slice(&[0x82, 0x00]).unwrap();
        let (data, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_GENERAL_AUTHENTICATE, ALG_TDES, REF_MANAGEMENT, &body),
        );
        assert_eq!(sw, Sw::OK);
        let encrypted = find_in_7c(&data, 0x82).expect("encrypted challenge");
        assert_eq!(tdes_ecb_decrypt(&DEFAULT_MGMT_KEY, encrypted), challenge);
    }

    #[test]
    fn select_resets_session_state() {
        let mut piv = applet();
        let mut rng = TestRng(13);
        assert_eq!(
            run(&mut piv, &mut rng, &command(INS_VERIFY, 0, REF_PIN, &PIN)).1,
            Sw::OK
        );
        assert_eq!(piv.select_response().sw, Sw::OK);
        authenticate_management(&mut piv, &mut rng);

        // Losing the selection also loses the verified PIN.
        assert_eq!(piv.select_response().sw, Sw::OK);
        let mut body = HeaplessVec::<u8, 64>::new();
        body.extend_from_slice(&[0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x70, 0x03, 0x01, 0x02, 0x03])
            .unwrap();
        let (_, sw) = run(
            &mut piv,
            &mut rng,
            &command(INS_PUT_DATA, 0x3F, 0xFF, &body),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
}
