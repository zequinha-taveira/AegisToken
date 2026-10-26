//! Yubico OATH applet (HOTP/TOTP) over ISO 7816-4.
//!
//! The wire format follows YKOATH: credentials are named TLVs, the key
//! descriptor combines the HOTP/TOTP type and hash algorithm, and calculations
//! return full or truncated response TLVs. The device receives the moving
//! factor from the host, so it does not need an RTC.

use aegis_core::authenticator::Rng;
use heapless::Vec;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::apdu::{Apdu, Response, Sw};
use crate::router::Applet;
use crate::tlv;

/// OATH application identifier.
pub const AID: &[u8] = crate::aid::OATH;

/// Maximum number of stored credentials.
pub const MAX_CREDENTIALS: usize = 16;
/// Maximum credential name length.
pub const MAX_NAME: usize = 64;
/// Maximum secret length.
pub const MAX_SECRET: usize = 64;
/// Serialized state buffer size.
pub const STATE_BYTES: usize = 4096;

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALCULATE_ALL: u8 = 0xA4;

const TAG_NAME: u32 = 0x71;
const TAG_NAME_LIST: u32 = 0x72;
const TAG_KEY: u32 = 0x73;
const TAG_CHALLENGE: u32 = 0x74;
const TAG_RESPONSE: u32 = 0x75;
const TAG_TRUNCATED: u32 = 0x76;
const TAG_HOTP: u32 = 0x77;
const TAG_PROPERTY: u32 = 0x78;
const TAG_VERSION: u32 = 0x79;
const TAG_IMF: u32 = 0x7A;
const TAG_TOUCH: u32 = 0x7C;

const TYPE_HOTP: u8 = 0x10;
const TYPE_TOTP: u8 = 0x20;
const ALGORITHM_SHA1: u8 = 0x01;
const ALGORITHM_SHA256: u8 = 0x02;
const ALGORITHM_SHA512: u8 = 0x03;
const PROPERTY_ONLY_INCREASING: u8 = 0x01;
const PROPERTY_TOUCH: u8 = 0x02;

const STATE_VERSION: u8 = 1;
const DEVICE_ID: [u8; 8] = *b"AegisOAT";
const DEFAULT_CHALLENGE: [u8; 8] = [0xA5; 8];

/// Persistent storage for the OATH serialized state.
pub trait OathStore {
    /// Load the state into `out`.
    ///
    /// `Some(len)` is the stored state length, `Some(0)` means there is no
    /// state (virgin region or an erased record) and `None` means the read
    /// failed (IO, corruption or an undecryptable record). The applet fails
    /// closed on `None`; an implementation that cannot tell the two cases
    /// apart returns `None`.
    fn load(&mut self, out: &mut [u8]) -> Option<usize>;
    /// Replace the state.
    fn save(&mut self, data: &[u8]) -> bool;
    /// Remove all state.
    fn clear(&mut self) -> bool;
}

/// Volatile store used by host tests and the current firmware integration.
pub struct MemoryOathStore {
    data: [u8; STATE_BYTES],
    len: usize,
}

impl Default for MemoryOathStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryOathStore {
    /// Create an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: [0; STATE_BYTES],
            len: 0,
        }
    }
}

impl OathStore for MemoryOathStore {
    fn load(&mut self, out: &mut [u8]) -> Option<usize> {
        if self.len == 0 {
            return Some(0);
        }
        if out.len() < self.len {
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

#[derive(Clone)]
struct Credential {
    name: Vec<u8, MAX_NAME>,
    kind: u8,
    algorithm: u8,
    digits: u8,
    property: u8,
    counter: u32,
    period: u32,
    secret: Vec<u8, MAX_SECRET>,
}

/// Armed touch request.
///
/// `index` is re-validated against the credential set when the request is
/// consumed, and every handler that mutates the set drops the request first:
/// the authorization belongs to the credential that asked for it.
struct PendingCalculation {
    index: usize,
    challenge: [u8; 8],
    truncated: bool,
}

/// OATH applet state.
pub struct Oath<S: OathStore> {
    store: S,
    credentials: Vec<Credential, MAX_CREDENTIALS>,
    auth_key: Vec<u8, MAX_SECRET>,
    auth_algorithm: u8,
    auth_challenge: [u8; 8],
    authenticated: bool,
    out: Vec<u8, 2048>,
    state: Vec<u8, STATE_BYTES>,
    pending: Option<PendingCalculation>,
    loaded: bool,
    closed: bool,
}

impl<S: OathStore> Oath<S> {
    /// Create an OATH applet over `store`.
    #[must_use]
    pub const fn new(store: S) -> Self {
        Self {
            store,
            credentials: Vec::new(),
            auth_key: Vec::new(),
            auth_algorithm: ALGORITHM_SHA1,
            auth_challenge: DEFAULT_CHALLENGE,
            authenticated: false,
            out: Vec::new(),
            state: Vec::new(),
            pending: None,
            loaded: false,
            closed: false,
        }
    }

    /// Mutable access to the backing store, useful for integration tests.
    #[must_use]
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    fn load_state(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let mut encoded = [0u8; STATE_BYTES];
        match self.store.load(&mut encoded) {
            None => self.close(),
            Some(0) => self.reset_volatile_state(),
            Some(len) => {
                if self.decode_state(&encoded[..len]) {
                    self.closed = false;
                } else {
                    self.close();
                }
            }
        }
    }

    /// Normalize the volatile state to the boot state.
    ///
    /// The empty OATH state is the permissive side (`require_auth` releases
    /// without an access code), so it is only served once a store read proved
    /// it; `closed` is the authority that refuses it after a failed read.
    fn reset_volatile_state(&mut self) {
        self.credentials.clear();
        self.auth_key.clear();
        self.auth_algorithm = ALGORITHM_SHA1;
        self.auth_challenge = DEFAULT_CHALLENGE;
        self.authenticated = false;
        self.pending = None;
        self.closed = false;
    }

    fn close(&mut self) {
        self.reset_volatile_state();
        self.closed = true;
    }

    fn state_available(&mut self) -> bool {
        self.load_state();
        !self.closed
    }

    fn save_state(&mut self) -> bool {
        self.state.clear();
        self.push_state(STATE_VERSION);
        self.push_state(self.credentials.len() as u8);
        self.push_state(u8::from(!self.auth_key.is_empty()));
        self.push_state(self.auth_algorithm);
        self.push_state(self.auth_key.len() as u8);
        let auth_key = self.auth_key.clone();
        let auth_challenge = self.auth_challenge;
        self.push_fixed(&auth_key, MAX_SECRET);
        self.push_fixed(&auth_challenge, 8);

        for index in 0..self.credentials.len() {
            let credential = self.credentials[index].clone();
            self.push_state(credential.kind);
            self.push_state(credential.algorithm);
            self.push_state(credential.digits);
            self.push_state(credential.property);
            self.push_state_bytes(&credential.counter.to_be_bytes());
            self.push_state_bytes(&credential.period.to_be_bytes());
            self.push_state(credential.name.len() as u8);
            self.push_fixed(&credential.name, MAX_NAME);
            self.push_state(credential.secret.len() as u8);
            self.push_fixed(&credential.secret, MAX_SECRET);
        }
        self.store.save(&self.state)
    }

    fn push_state(&mut self, byte: u8) {
        let _ = self.state.push(byte);
    }

    fn push_state_bytes(&mut self, bytes: &[u8]) {
        let _ = self.state.extend_from_slice(bytes);
    }

    fn push_fixed(&mut self, value: &[u8], width: usize) {
        let _ = self.state.extend_from_slice(value);
        for _ in value.len()..width {
            self.push_state(0);
        }
    }

    fn decode_state(&mut self, bytes: &[u8]) -> bool {
        let mut cursor = 0;
        let Some(version) = take_u8(bytes, &mut cursor) else {
            return false;
        };
        if version != STATE_VERSION {
            return false;
        }
        let Some(count) = take_u8(bytes, &mut cursor) else {
            return false;
        };
        if usize::from(count) > MAX_CREDENTIALS {
            return false;
        }
        let Some(auth_present) = take_u8(bytes, &mut cursor) else {
            return false;
        };
        let Some(auth_algorithm) = take_u8(bytes, &mut cursor) else {
            return false;
        };
        let Some(auth_len) = take_u8(bytes, &mut cursor) else {
            return false;
        };
        let Some(auth_bytes) = take(bytes, &mut cursor, MAX_SECRET) else {
            return false;
        };
        let Some(challenge) = take(bytes, &mut cursor, 8) else {
            return false;
        };
        if usize::from(auth_len) > MAX_SECRET {
            return false;
        }

        self.credentials.clear();
        self.auth_key.clear();
        if auth_present != 0 {
            let _ = self
                .auth_key
                .extend_from_slice(&auth_bytes[..usize::from(auth_len)]);
        }
        self.auth_algorithm = auth_algorithm;
        self.auth_challenge.copy_from_slice(challenge);

        for _ in 0..count {
            let Some(kind) = take_u8(bytes, &mut cursor) else {
                return false;
            };
            let Some(algorithm) = take_u8(bytes, &mut cursor) else {
                return false;
            };
            let Some(digits) = take_u8(bytes, &mut cursor) else {
                return false;
            };
            let Some(property) = take_u8(bytes, &mut cursor) else {
                return false;
            };
            let Some(counter_bytes) = take(bytes, &mut cursor, 4) else {
                return false;
            };
            let Some(period_bytes) = take(bytes, &mut cursor, 4) else {
                return false;
            };
            let Some(name_len) = take_u8(bytes, &mut cursor) else {
                return false;
            };
            let Some(name_bytes) = take(bytes, &mut cursor, MAX_NAME) else {
                return false;
            };
            let Some(secret_len) = take_u8(bytes, &mut cursor) else {
                return false;
            };
            let Some(secret_bytes) = take(bytes, &mut cursor, MAX_SECRET) else {
                return false;
            };
            if usize::from(name_len) > MAX_NAME || usize::from(secret_len) > MAX_SECRET {
                return false;
            }
            let mut name = Vec::new();
            let mut secret = Vec::new();
            if name
                .extend_from_slice(&name_bytes[..usize::from(name_len)])
                .is_err()
                || secret
                    .extend_from_slice(&secret_bytes[..usize::from(secret_len)])
                    .is_err()
            {
                return false;
            }
            if self
                .credentials
                .push(Credential {
                    name,
                    kind,
                    algorithm,
                    digits,
                    property,
                    counter: u32::from_be_bytes(counter_bytes.try_into().ok().unwrap()),
                    period: u32::from_be_bytes(period_bytes.try_into().ok().unwrap()),
                    secret,
                })
                .is_err()
            {
                return false;
            }
        }
        true
    }

    fn require_auth(&self) -> Result<(), Sw> {
        if self.auth_key.is_empty() || self.authenticated {
            Ok(())
        } else {
            Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        self.credentials
            .iter()
            .position(|credential| credential.name == name)
    }

    fn put(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        // A write can swap the secret behind the armed request, so the armed
        // touch never survives it, even when the command is refused.
        self.pending = None;
        if let Err(status) = self.require_auth() {
            return Response::status(status);
        }
        let Some((name, key, property, counter)) = parse_put(apdu.data) else {
            return Response::status(Sw::WRONG_DATA);
        };
        if name.is_empty() || name.len() > MAX_NAME || key.secret.is_empty() {
            return Response::status(Sw::WRONG_DATA);
        }
        let period = credential_period(name);
        let mut credential_name = Vec::new();
        if credential_name.extend_from_slice(name).is_err() {
            return Response::status(Sw::WRONG_DATA);
        }
        let credential = Credential {
            name: credential_name,
            kind: key.kind,
            algorithm: key.algorithm,
            digits: key.digits,
            property,
            counter,
            period,
            secret: key.secret,
        };
        if let Some(index) = self.find(name) {
            self.credentials[index] = credential;
        } else if self.credentials.push(credential).is_err() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        if !self.save_state() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::status(Sw::OK)
    }

    fn delete(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        // Unconditional, before any refusal and before `swap_remove`: a
        // request belongs to the set as it was read, and a save that fails
        // after the removal would otherwise leave it pointing at a shifted
        // set (or past its end).
        self.pending = None;
        if let Err(status) = self.require_auth() {
            return Response::status(status);
        }
        let Some(name) = tlv::find(apdu.data, TAG_NAME) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(index) = self.find(name) else {
            return Response::status(Sw::OATH_OBJECT_NOT_FOUND);
        };
        self.credentials.swap_remove(index);
        if !self.save_state() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::status(Sw::OK)
    }

    fn list(&mut self) -> Response<'_> {
        if let Err(status) = self.require_auth() {
            return Response::status(status);
        }
        self.out.clear();
        for credential in &self.credentials {
            let mut value = [0u8; MAX_NAME + 1];
            value[0] = credential.kind | credential.algorithm;
            value[1..1 + credential.name.len()].copy_from_slice(&credential.name);
            if !append_tlv(
                &mut self.out,
                TAG_NAME_LIST,
                &value[..1 + credential.name.len()],
            ) {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
        }
        Response::ok(&self.out)
    }

    fn calculate(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if let Err(status) = self.require_auth() {
            return Response::status(status);
        }
        let Some(name) = tlv::find(apdu.data, TAG_NAME) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let challenge = tlv::find(apdu.data, TAG_CHALLENGE).unwrap_or(&[]);
        let Some(index) = self.find(name) else {
            return Response::status(Sw::OATH_OBJECT_NOT_FOUND);
        };
        if self.credentials[index].property & PROPERTY_TOUCH != 0 {
            let mut challenge_bytes = [0u8; 8];
            if challenge.len() > 8 {
                return Response::status(Sw::WRONG_DATA);
            }
            challenge_bytes[8 - challenge.len()..].copy_from_slice(challenge);
            self.pending = Some(PendingCalculation {
                index,
                challenge: challenge_bytes,
                truncated: apdu.p2 == 0x01,
            });
            return Response::presence_required();
        }
        self.calculate_index(index, challenge, apdu.p2 == 0x01)
    }

    fn calculate_all(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        // Read-only over the credential set (an HOTP entry is reported without
        // computing it), so this is the state command that leaves an armed
        // touch alone.
        if let Err(status) = self.require_auth() {
            return Response::status(status);
        }
        let Some(challenge) = tlv::find(apdu.data, TAG_CHALLENGE) else {
            return Response::status(Sw::WRONG_DATA);
        };
        if challenge.len() != 8 {
            return Response::status(Sw::WRONG_DATA);
        }
        self.out.clear();
        for index in 0..self.credentials.len() {
            let credential = &self.credentials[index];
            if !append_tlv(&mut self.out, TAG_NAME, &credential.name) {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
            if credential.kind == TYPE_HOTP {
                if !append_tlv(&mut self.out, TAG_HOTP, &[]) {
                    return Response::status(Sw::NOT_ENOUGH_MEMORY);
                }
                continue;
            }
            if credential.property & PROPERTY_TOUCH != 0 {
                if !append_tlv(&mut self.out, TAG_TOUCH, &[]) {
                    return Response::status(Sw::NOT_ENOUGH_MEMORY);
                }
                continue;
            }
            let Some(code) = compute_credential(credential, challenge, apdu.p2 == 0x01) else {
                return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
            };
            let tag = if apdu.p2 == 0x01 {
                TAG_TRUNCATED
            } else {
                TAG_RESPONSE
            };
            if !append_tlv(&mut self.out, tag, &code) {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
        }
        Response::ok(&self.out)
    }

    fn calculate_index(&mut self, index: usize, challenge: &[u8], truncated: bool) -> Response<'_> {
        let Some(code) = compute_credential(&self.credentials[index], challenge, truncated) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        if self.credentials[index].kind == TYPE_HOTP {
            self.credentials[index].counter = self.credentials[index].counter.wrapping_add(1);
            if !self.save_state() {
                return Response::status(Sw::NOT_ENOUGH_MEMORY);
            }
        }
        let tag = if truncated {
            TAG_TRUNCATED
        } else {
            TAG_RESPONSE
        };
        self.out.clear();
        if !append_tlv(&mut self.out, tag, &code) {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn set_code(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if let Err(status) = self.require_auth() {
            return Response::status(status);
        }
        if apdu.data.is_empty() {
            self.auth_key.clear();
            self.authenticated = false;
            return Response::status(if self.save_state() {
                Sw::OK
            } else {
                Sw::NOT_ENOUGH_MEMORY
            });
        }
        let Some(key_data) = tlv::find(apdu.data, TAG_KEY) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some((&algorithm, key)) = key_data.split_first() else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(challenge) = tlv::find(apdu.data, TAG_CHALLENGE) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(response) = tlv::find(apdu.data, TAG_RESPONSE) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(expected) = hmac_digest(algorithm, key, challenge) else {
            return Response::status(Sw::WRONG_DATA);
        };
        if !constant_time_eq(&expected, response) {
            return Response::status(Sw::AUTHENTICATION_FAILED);
        }
        self.auth_key.clear();
        if self.auth_key.extend_from_slice(key).is_err() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        self.auth_algorithm = algorithm;
        self.auth_challenge = derive_challenge(challenge, key);
        self.authenticated = true;
        if !self.save_state() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::status(Sw::OK)
    }

    fn validate(&mut self, apdu: &Apdu<'_>) -> Response<'_> {
        if self.auth_key.is_empty() {
            return Response::status(Sw::AUTH_NOT_ENABLED);
        }
        let Some(response) = tlv::find(apdu.data, TAG_RESPONSE) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(challenge) = tlv::find(apdu.data, TAG_CHALLENGE) else {
            return Response::status(Sw::WRONG_DATA);
        };
        let Some(expected) = hmac_digest(self.auth_algorithm, &self.auth_key, &self.auth_challenge)
        else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        if !constant_time_eq(&expected, response) {
            return Response::status(Sw::AUTHENTICATION_FAILED);
        }
        let Some(verification) = hmac_digest(self.auth_algorithm, &self.auth_key, challenge) else {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        };
        self.auth_challenge = derive_challenge(&self.auth_challenge, challenge);
        self.authenticated = true;
        if !self.save_state() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        self.out.clear();
        if !append_tlv(&mut self.out, TAG_RESPONSE, &verification) {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }

    fn reset(&mut self) -> Response<'_> {
        // The empty RAM state is the permissive side (`require_auth` releases
        // without an access code), so the erase must persist before it is
        // applied; `clear` commits a torn-safe empty generation, which makes
        // its boolean exact.
        self.pending = None;
        if !self.store.clear() {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        self.credentials.clear();
        self.auth_key.clear();
        self.authenticated = false;
        self.auth_challenge = DEFAULT_CHALLENGE;
        self.loaded = true;
        self.closed = false;
        Response::status(Sw::OK)
    }

    fn select_response(&mut self) -> Response<'_> {
        self.authenticated = !self.closed && self.auth_key.is_empty();
        self.pending = None;
        self.out.clear();
        let version = [5, 0, 0];
        if !append_tlv(&mut self.out, TAG_VERSION, &version)
            || !append_tlv(&mut self.out, TAG_NAME, &DEVICE_ID)
        {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        if !self.closed
            && !self.auth_key.is_empty()
            && (!append_tlv(&mut self.out, TAG_CHALLENGE, &self.auth_challenge)
                || !append_tlv(&mut self.out, 0x7B, &[self.auth_algorithm]))
        {
            return Response::status(Sw::NOT_ENOUGH_MEMORY);
        }
        Response::ok(&self.out)
    }
}

impl<S: OathStore> Applet for Oath<S> {
    fn aid(&self) -> &'static [u8] {
        AID
    }

    fn select(&mut self) -> Response<'_> {
        self.loaded = false;
        self.load_state();
        self.select_response()
    }

    fn select_with_rng(&mut self, rng: &mut dyn Rng) -> Response<'_> {
        self.loaded = false;
        self.load_state();
        if !self.auth_key.is_empty() {
            rng.fill_bytes(&mut self.auth_challenge);
        }
        self.select_response()
    }

    fn process(&mut self, apdu: &Apdu<'_>, _rng: &mut dyn Rng) -> Response<'_> {
        // A closed applet never serves state; `RESET` is the deliberate
        // exception because it erases and reveals nothing.
        if !self.state_available() && apdu.ins != INS_RESET {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        match apdu.ins {
            INS_PUT => self.put(apdu),
            INS_DELETE => self.delete(apdu),
            INS_SET_CODE => self.set_code(apdu),
            INS_RESET if apdu.p1 == 0xDE && apdu.p2 == 0xAD => self.reset(),
            INS_LIST if apdu.p1 == 0 && apdu.p2 == 0 => self.list(),
            INS_CALCULATE => self.calculate(apdu),
            INS_VALIDATE => self.validate(apdu),
            INS_CALCULATE_ALL => self.calculate_all(apdu),
            _ => Response::status(Sw::INS_NOT_SUPPORTED),
        }
    }

    fn confirm_presence(&mut self, _rng: &mut dyn Rng) -> Response<'_> {
        if !self.state_available() {
            return Response::status(Sw::NO_PRECISE_DIAGNOSIS);
        }
        let Some(pending) = self.pending.take() else {
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        };
        // A stale index must never be indexed (a panic here halts the whole
        // firmware) nor retargeted onto a stranger; it collapses into the same
        // "no pending request" refusal.
        if pending.index >= self.credentials.len() {
            return Response::status(Sw::CONDITIONS_NOT_SATISFIED);
        }
        self.calculate_index(pending.index, &pending.challenge, pending.truncated)
    }

    fn deny_presence(&mut self) -> Response<'_> {
        self.pending = None;
        Response::status(Sw::SECURITY_STATUS_NOT_SATISFIED)
    }
}

#[derive(Clone)]
struct ParsedKey {
    kind: u8,
    algorithm: u8,
    digits: u8,
    secret: Vec<u8, MAX_SECRET>,
}

fn parse_put(data: &[u8]) -> Option<(&[u8], ParsedKey, u8, u32)> {
    let name = tlv::find(data, TAG_NAME)?;
    let key_value = tlv::find(data, TAG_KEY)?;
    if key_value.len() < 3 {
        return None;
    }
    let kind = key_value[0] & 0xF0;
    let algorithm = key_value[0] & 0x0F;
    if kind != TYPE_HOTP && kind != TYPE_TOTP {
        return None;
    }
    if algorithm != ALGORITHM_SHA1 && algorithm != ALGORITHM_SHA256 && algorithm != ALGORITHM_SHA512
    {
        return None;
    }
    if key_value[1] != 6 && key_value[1] != 7 && key_value[1] != 8 {
        return None;
    }
    let mut secret = Vec::new();
    secret.extend_from_slice(&key_value[2..]).ok()?;
    let property = tlv::find(data, TAG_PROPERTY).map_or(0, |v| v.first().copied().unwrap_or(0));
    if property & !(PROPERTY_ONLY_INCREASING | PROPERTY_TOUCH) != 0 {
        return None;
    }
    let counter = match tlv::find(data, TAG_IMF) {
        Some(value) if value.len() == 4 => u32::from_be_bytes(value.try_into().ok()?),
        Some(_) => return None,
        None => 0,
    };
    if kind == TYPE_TOTP && tlv::find(data, TAG_IMF).is_some() {
        return None;
    }
    Some((
        name,
        ParsedKey {
            kind,
            algorithm,
            digits: key_value[1],
            secret,
        },
        property,
        counter,
    ))
}

fn credential_period(name: &[u8]) -> u32 {
    let Some(separator) = name.iter().position(|byte| *byte == b'/') else {
        return 30;
    };
    if separator == 0 {
        return 30;
    }
    let mut period = 0u32;
    for byte in &name[..separator] {
        if !byte.is_ascii_digit() {
            return 30;
        }
        period = period
            .saturating_mul(10)
            .saturating_add(u32::from(byte - b'0'));
    }
    if period == 0 { 30 } else { period }
}

fn compute_credential(
    credential: &Credential,
    challenge: &[u8],
    truncated: bool,
) -> Option<Vec<u8, 65>> {
    let moving_factor = if credential.kind == TYPE_HOTP {
        u64::from(credential.counter).to_be_bytes()
    } else {
        if challenge.len() != 8 {
            return None;
        }
        challenge.try_into().ok()?
    };
    let digest = hmac_digest(credential.algorithm, &credential.secret, &moving_factor)?;
    let mut output = Vec::new();
    output.push(credential.digits).ok()?;
    if !truncated {
        output.extend_from_slice(&digest).ok()?;
        return Some(output);
    }
    let offset = usize::from(*digest.last()? & 0x0F);
    if offset + 4 > digest.len() {
        return None;
    }
    let binary = (u32::from(digest[offset]) & 0x7F) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    // The wire carries the full 31-bit dynamic truncation; the host applies
    // modulo 10^digits when displaying the decimal OTP.
    output.extend_from_slice(&binary.to_be_bytes()).ok()?;
    Some(output)
}

fn hmac_digest(algorithm: u8, key: &[u8], data: &[u8]) -> Option<Vec<u8, 64>> {
    let mut output = Vec::new();
    match algorithm {
        ALGORITHM_SHA1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
            mac.update(data);
            output
                .extend_from_slice(&mac.finalize().into_bytes())
                .ok()?;
        }
        ALGORITHM_SHA256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
            mac.update(data);
            output
                .extend_from_slice(&mac.finalize().into_bytes())
                .ok()?;
        }
        ALGORITHM_SHA512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).ok()?;
            mac.update(data);
            output
                .extend_from_slice(&mac.finalize().into_bytes())
                .ok()?;
        }
        _ => return None,
    }
    Some(output)
}

fn derive_challenge(previous: &[u8], input: &[u8]) -> [u8; 8] {
    let mut hash = Sha256::new();
    hash.update(previous);
    hash.update(input);
    let digest = hash.finalize();
    let mut output = [0u8; 8];
    output.copy_from_slice(&digest[..8]);
    output
}

fn append_tlv<const N: usize>(out: &mut Vec<u8, N>, tag: u32, value: &[u8]) -> bool {
    let needed = tlv::encoded_len(tag, value.len());
    let start = out.len();
    if start + needed > out.capacity() || out.resize(start + needed, 0).is_err() {
        return false;
    }
    tlv::write(tag, value, &mut out[start..]).is_some()
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b) {
        difference |= left ^ right;
    }
    core::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Apdu;

    struct TestRng;

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0x42);
        }
    }

    fn applet_with<S: OathStore>(store: S) -> Oath<S> {
        let mut oath = Oath::new(store);
        assert_eq!(oath.select().sw, Sw::OK);
        oath
    }

    fn applet() -> Oath<MemoryOathStore> {
        applet_with(MemoryOathStore::new())
    }

    /// A store wrapper that delegates to [`MemoryOathStore`] and can be
    /// switched to reject `clear`, `save` or `load`, standing in for a
    /// worn-out flash.
    ///
    /// It counts the observed calls per operation so tests can prove which
    /// commands do and do not touch the store, and it is `Default` so a power
    /// cycle can swap the store out with `core::mem::take`.
    struct FailingOathStore {
        inner: MemoryOathStore,
        clear_fails: bool,
        save_fails: bool,
        load_fails: bool,
        clears: u32,
        saves: u32,
        loads: u32,
    }

    impl FailingOathStore {
        fn new(inner: MemoryOathStore) -> Self {
            Self {
                inner,
                clear_fails: false,
                save_fails: false,
                load_fails: false,
                clears: 0,
                saves: 0,
                loads: 0,
            }
        }

        fn set_clear_fails(&mut self, fails: bool) {
            self.clear_fails = fails;
        }

        fn set_save_fails(&mut self, fails: bool) {
            self.save_fails = fails;
        }

        fn set_load_fails(&mut self, fails: bool) {
            self.load_fails = fails;
        }

        fn reset_calls(&mut self) {
            self.clears = 0;
            self.saves = 0;
            self.loads = 0;
        }

        fn clears(&self) -> u32 {
            self.clears
        }

        fn saves(&self) -> u32 {
            self.saves
        }

        fn loads(&self) -> u32 {
            self.loads
        }
    }

    impl Default for FailingOathStore {
        fn default() -> Self {
            Self::new(MemoryOathStore::new())
        }
    }

    impl OathStore for FailingOathStore {
        fn load(&mut self, out: &mut [u8]) -> Option<usize> {
            self.loads += 1;
            if self.load_fails {
                None
            } else {
                self.inner.load(out)
            }
        }

        fn save(&mut self, data: &[u8]) -> bool {
            self.saves += 1;
            if self.save_fails {
                false
            } else {
                self.inner.save(data)
            }
        }

        fn clear(&mut self) -> bool {
            self.clears += 1;
            if self.clear_fails {
                false
            } else {
                self.inner.clear()
            }
        }
    }

    fn frame(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8, 512> {
        let mut output = Vec::new();
        output.extend_from_slice(&[0x00, ins, p1, p2]).unwrap();
        if !data.is_empty() {
            output.push(data.len() as u8).unwrap();
            output.extend_from_slice(data).unwrap();
        }
        output
    }

    fn run<S: OathStore>(
        oath: &mut Oath<S>,
        rng: &mut TestRng,
        frame: &[u8],
    ) -> (Vec<u8, 2048>, Sw) {
        let apdu = Apdu::parse(frame).unwrap();
        let response = oath.process(&apdu, rng);
        let mut data = Vec::new();
        data.extend_from_slice(response.data).unwrap();
        (data, response.sw)
    }

    fn put_data(
        name: &[u8],
        kind: u8,
        algorithm: u8,
        digits: u8,
        secret: &[u8],
        counter: Option<u32>,
        property: u8,
    ) -> Vec<u8, 512> {
        let mut data = Vec::new();
        append_tlv(&mut data, TAG_NAME, name);
        let mut key = Vec::<u8, 128>::new();
        key.push(kind | algorithm).unwrap();
        key.push(digits).unwrap();
        key.extend_from_slice(secret).unwrap();
        append_tlv(&mut data, TAG_KEY, &key);
        if property != 0 {
            append_tlv(&mut data, TAG_PROPERTY, &[property]);
        }
        if let Some(counter) = counter {
            append_tlv(&mut data, TAG_IMF, &counter.to_be_bytes());
        }
        data
    }

    fn calculate_data(name: &[u8], challenge: Option<&[u8]>) -> Vec<u8, 128> {
        let mut data = Vec::<u8, 128>::new();
        append_tlv(&mut data, TAG_NAME, name);
        if let Some(challenge) = challenge {
            append_tlv(&mut data, TAG_CHALLENGE, challenge);
        }
        data
    }

    fn code(response: &[u8], tag: u32) -> u32 {
        let value = tlv::find(response, tag).unwrap();
        assert_eq!(value.len(), 5);
        u32::from_be_bytes(value[1..5].try_into().unwrap()) % 10u32.pow(u32::from(value[0]))
    }

    fn set_access_code<S: OathStore>(oath: &mut Oath<S>, rng: &mut TestRng, key: &[u8]) -> Sw {
        let challenge = b"12345678";
        let response = hmac_digest(ALGORITHM_SHA1, key, challenge).unwrap();
        let mut data = Vec::<u8, 256>::new();
        let mut key_data = Vec::<u8, 128>::new();
        key_data.push(ALGORITHM_SHA1).unwrap();
        key_data.extend_from_slice(key).unwrap();
        append_tlv(&mut data, TAG_KEY, &key_data);
        append_tlv(&mut data, TAG_CHALLENGE, challenge);
        append_tlv(&mut data, TAG_RESPONSE, &response);
        run(oath, rng, &frame(INS_SET_CODE, 0, 0, &data)).1
    }

    fn validate_access_code<S: OathStore>(oath: &mut Oath<S>, rng: &mut TestRng, key: &[u8]) -> Sw {
        let response = hmac_digest(ALGORITHM_SHA1, key, &oath.auth_challenge).unwrap();
        let mut validate = Vec::<u8, 128>::new();
        append_tlv(&mut validate, TAG_RESPONSE, &response);
        append_tlv(&mut validate, TAG_CHALLENGE, b"87654321");
        run(oath, rng, &frame(INS_VALIDATE, 0, 0, &validate)).1
    }

    #[test]
    fn rfc4226_hotp_vectors() {
        let mut oath = applet();
        let mut rng = TestRng;
        let secret = b"12345678901234567890";
        let data = put_data(b"hotp", TYPE_HOTP, ALGORITHM_SHA1, 6, secret, Some(0), 0);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );

        let expected = [755224, 287082, 359152, 969429, 338314, 254676];
        for value in expected {
            let data = calculate_data(b"hotp", None);
            let (response, status) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &data));
            assert_eq!(status, Sw::OK);
            assert_eq!(code(&response, TAG_TRUNCATED), value);
        }
    }

    #[test]
    fn rfc6238_sha1_sha256_sha512_vectors() {
        let mut oath = applet();
        let mut rng = TestRng;
        // YKOATH receives the moving factor (Unix time / period), not the raw
        // Unix timestamp. RFC 6238 time 59 with a 30-second period is 1.
        let timestamp = 1u64.to_be_bytes();
        let vectors = [
            (
                b"30/sha1".as_slice(),
                ALGORITHM_SHA1,
                b"12345678901234567890".as_slice(),
                94287082,
            ),
            (
                b"30/sha256".as_slice(),
                ALGORITHM_SHA256,
                b"12345678901234567890123456789012".as_slice(),
                46119246,
            ),
            (
                b"30/sha512".as_slice(),
                ALGORITHM_SHA512,
                b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
                90693936,
            ),
        ];
        for (name, algorithm, secret, expected) in vectors {
            let data = put_data(name, TYPE_TOTP, algorithm, 8, secret, None, 0);
            assert_eq!(
                run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
                Sw::OK
            );
            let data = calculate_data(name, Some(&timestamp));
            let (response, status) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &data));
            assert_eq!(status, Sw::OK);
            assert_eq!(code(&response, TAG_TRUNCATED), expected);
        }
    }

    #[test]
    fn list_delete_and_state_persist() {
        let mut oath = applet();
        let mut rng = TestRng;
        let data = put_data(
            b"issuer:account",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            b"secret",
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(
            tlv::find(&list, TAG_NAME_LIST).unwrap()[1..],
            *b"issuer:account"
        );

        let store = core::mem::take(oath.store_mut());
        let mut reopened = Oath::new(store);
        assert_eq!(reopened.select().sw, Sw::OK);
        let (list, status) = run(&mut reopened, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(tlv::find(&list, TAG_NAME_LIST).is_some());

        let mut delete = Vec::<u8, 128>::new();
        append_tlv(&mut delete, TAG_NAME, b"issuer:account");
        assert_eq!(
            run(&mut reopened, &mut rng, &frame(INS_DELETE, 0, 0, &delete)).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut reopened, &mut rng, &frame(INS_LIST, 0, 0, &[]))
                .0
                .len(),
            0
        );
    }

    #[test]
    fn access_code_validate_round_trips() {
        let mut oath = applet();
        let mut rng = TestRng;
        let mut key = [0u8; 10];
        rng.fill_bytes(&mut key);
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);

        assert_eq!(oath.select().sw, Sw::OK);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        let response = hmac_digest(ALGORITHM_SHA1, &key, &oath.auth_challenge).unwrap();
        let new_challenge = b"87654321";
        let mut validate = Vec::<u8, 128>::new();
        append_tlv(&mut validate, TAG_RESPONSE, &response);
        append_tlv(&mut validate, TAG_CHALLENGE, new_challenge);
        let (data, status) = run(&mut oath, &mut rng, &frame(INS_VALIDATE, 0, 0, &validate));
        assert_eq!(status, Sw::OK);
        assert_eq!(
            tlv::find(&data, TAG_RESPONSE),
            Some(&hmac_digest(ALGORITHM_SHA1, &key, new_challenge).unwrap()[..])
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::OK
        );
    }

    #[test]
    fn ykoath_wire_returns_raw_truncation_or_full_digest() {
        let mut oath = applet();
        let mut rng = TestRng;
        let mut secret = Vec::<u8, 20>::new();
        secret.resize(20, 0).unwrap();
        rng.fill_bytes(&mut secret);
        let put = put_data(b"totp", TYPE_TOTP, ALGORITHM_SHA1, 8, &secret, None, 0);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &put)).1,
            Sw::OK
        );
        let challenge = 1u64.to_be_bytes();
        let request = calculate_data(b"totp", Some(&challenge));
        let (truncated, sw) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request));
        assert_eq!(sw, Sw::OK);
        let value = tlv::find(&truncated, TAG_TRUNCATED).unwrap();
        assert_eq!(value[0], 8);
        let digest = hmac_digest(ALGORITHM_SHA1, &secret, &challenge).unwrap();
        let offset = usize::from(*digest.last().unwrap() & 0x0F);
        let expected_truncation = (u32::from(digest[offset]) & 0x7F) << 24
            | u32::from(digest[offset + 1]) << 16
            | u32::from(digest[offset + 2]) << 8
            | u32::from(digest[offset + 3]);
        assert_eq!(
            u32::from_be_bytes(value[1..].try_into().unwrap()),
            expected_truncation
        );
        let (full, sw) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 0, &request));
        assert_eq!(sw, Sw::OK);
        let value = tlv::find(&full, TAG_RESPONSE).unwrap();
        assert_eq!(value.len(), 21);
        assert_eq!(value[0], 8);
        assert_eq!(
            &value[1..],
            &hmac_digest(ALGORITHM_SHA1, &secret, &challenge).unwrap()
        );
        let mut all = Vec::<u8, 32>::new();
        append_tlv(&mut all, TAG_CHALLENGE, &challenge);
        let (list, sw) = run(&mut oath, &mut rng, &frame(INS_CALCULATE_ALL, 0, 1, &all));
        assert_eq!(sw, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_TRUNCATED), Some(&truncated[2..7]));
    }

    #[test]
    fn protected_access_code_cannot_be_replaced_or_cleared_without_validation() {
        let mut oath = applet();
        let mut rng = TestRng;
        let mut key_bytes = Vec::<u8, 20>::new();
        key_bytes.resize(20, 0).unwrap();
        rng.fill_bytes(&mut key_bytes);
        let key = key_bytes.as_slice();
        let challenge = b"abcdefgh";
        let mut body = Vec::<u8, 128>::new();
        let mut descriptor = Vec::<u8, 32>::new();
        descriptor.push(ALGORITHM_SHA1).unwrap();
        descriptor.extend_from_slice(key).unwrap();
        append_tlv(&mut body, TAG_KEY, &descriptor);
        append_tlv(&mut body, TAG_CHALLENGE, challenge);
        append_tlv(
            &mut body,
            TAG_RESPONSE,
            &hmac_digest(ALGORITHM_SHA1, key, challenge).unwrap(),
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_SET_CODE, 0, 0, &body)).1,
            Sw::OK
        );
        let select = oath.select_with_rng(&mut rng);
        assert_eq!(select.sw, Sw::OK);
        assert_eq!(
            tlv::find(select.data, TAG_CHALLENGE),
            Some(&b"BBBBBBBB"[..])
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_SET_CODE, 0, 0, &[])).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_SET_CODE, 0, 0, &body)).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        let mut validate = Vec::<u8, 128>::new();
        append_tlv(
            &mut validate,
            TAG_RESPONSE,
            &hmac_digest(ALGORITHM_SHA1, key, b"BBBBBBBB").unwrap(),
        );
        append_tlv(&mut validate, TAG_CHALLENGE, b"87654321");
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_VALIDATE, 0, 0, &validate)).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_SET_CODE, 0, 0, &[])).1,
            Sw::OK
        );
    }

    #[test]
    fn touch_required_calculation_uses_card_presence_flow() {
        let mut oath = applet();
        let mut rng = TestRng;
        let data = put_data(
            b"touch",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            b"secret",
            None,
            PROPERTY_TOUCH,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        let data = calculate_data(b"touch", Some(&1u64.to_be_bytes()));
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &data)).1,
            Sw::PRESENCE_REQUIRED
        );
        assert_eq!(oath.confirm_presence(&mut rng).sw, Sw::OK);
        assert!(oath.deny_presence().sw == Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn reset_removes_credentials_and_authentication() {
        let mut oath = applet();
        let mut rng = TestRng;
        let data = put_data(
            b"reset-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            b"secret",
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]))
                .0
                .len(),
            0
        );
    }

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn reset_with_failing_store_reports_6a84_and_keeps_the_session_state() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let data = put_data(
            b"reset-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            8,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        oath.store_mut().set_clear_fails(true);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::NOT_ENOUGH_MEMORY
        );
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *b"reset-me");
        let request = calculate_data(b"reset-me", Some(&1u64.to_be_bytes()));
        let (response, status) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request));
        assert_eq!(status, Sw::OK);
        assert_eq!(code(&response, TAG_TRUNCATED), 94287082);

        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut key = Vec::<u8, 10>::new();
        let mut random_key = [0u8; 10];
        rng.fill_bytes(&mut random_key);
        key.extend_from_slice(&random_key).unwrap();
        let data = put_data(
            b"reset-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);
        oath.store_mut().set_clear_fails(true);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::NOT_ENOUGH_MEMORY
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        let request = calculate_data(b"reset-me", Some(&1u64.to_be_bytes()));
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request)).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );

        let mut healthy = applet();
        let data = put_data(
            b"reset-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut healthy, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut healthy, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut healthy, &mut rng, &frame(INS_LIST, 0, 0, &[]))
                .0
                .len(),
            0
        );
    }

    #[test]
    fn reset_retries_successfully_after_the_store_recovers() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let key = rng.gen_array::<10>();
        let data = put_data(
            b"reset-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);
        oath.store_mut().set_clear_fails(true);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::NOT_ENOUGH_MEMORY
        );

        oath.store_mut().set_clear_fails(false);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]))
                .0
                .len(),
            0
        );
        let select = oath.select();
        assert_eq!(select.sw, Sw::OK);
        assert!(tlv::find(select.data, TAG_CHALLENGE).is_none());
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]))
                .0
                .len(),
            0
        );
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
    }

    #[test]
    fn failed_reset_leaves_the_persisted_state_reachable_from_a_reload() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let mut key = Vec::<u8, 10>::new();
        for _ in 0..10 {
            key.push(rng.next_u32() as u8).unwrap();
        }
        let data = put_data(
            b"keep-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);
        oath.store_mut().set_clear_fails(true);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::NOT_ENOUGH_MEMORY
        );

        let select = oath.select();
        assert_eq!(select.sw, Sw::OK);
        assert!(tlv::find(select.data, TAG_CHALLENGE).is_some());
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(validate_access_code(&mut oath, &mut rng, &key), Sw::OK);
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *b"keep-me");

        let store = core::mem::take(oath.store_mut());
        let mut reopened = applet_with(store);
        assert_eq!(
            run(&mut reopened, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(validate_access_code(&mut reopened, &mut rng, &key), Sw::OK);
        let (list, status) = run(&mut reopened, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *b"keep-me");
        let request = calculate_data(b"keep-me", Some(&1u64.to_be_bytes()));
        let (response, status) = run(
            &mut reopened,
            &mut rng,
            &frame(INS_CALCULATE, 0, 1, &request),
        );
        assert_eq!(status, Sw::OK);
        assert_eq!(code(&response, TAG_TRUNCATED), 287082);

        let mut encoded = [0u8; STATE_BYTES];
        let len = reopened.store_mut().load(&mut encoded).unwrap();
        assert!(len > 0);
    }

    #[test]
    fn successful_reset_persists_the_erase_across_reopen() {
        let mut oath = applet();
        let mut rng = TestRng;
        let data = put_data(
            b"erase-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());

        let store = core::mem::take(oath.store_mut());
        let mut reopened = applet_with(store);
        let (list, status) = run(&mut reopened, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());
    }

    #[test]
    fn reset_parameters_outside_de_ad_do_not_touch_the_store() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let data = put_data(
            b"keep-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        oath.store_mut().reset_calls();
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0x00, 0x00, &[])).1,
            Sw::INS_NOT_SUPPORTED
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0x00, &[])).1,
            Sw::INS_NOT_SUPPORTED
        );
        assert_eq!(oath.store_mut().clears(), 0);
        assert_eq!(oath.store_mut().saves(), 0);
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *b"keep-me");
    }

    #[test]
    fn reset_writes_once_and_never_saves() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let data = put_data(
            b"reset-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        oath.store_mut().reset_calls();
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        assert_eq!(oath.store_mut().clears(), 1);
        assert_eq!(oath.store_mut().saves(), 0);
        assert_eq!(oath.store_mut().loads(), 0);

        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let data = put_data(
            b"reset-me",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        oath.store_mut().set_clear_fails(true);
        oath.store_mut().reset_calls();
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::NOT_ENOUGH_MEMORY
        );
        assert_eq!(oath.store_mut().clears(), 1);
        assert_eq!(oath.store_mut().saves(), 0);
        assert_eq!(oath.store_mut().loads(), 0);

        oath.store_mut().set_clear_fails(false);
        oath.store_mut().set_save_fails(true);
        oath.store_mut().reset_calls();
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        assert_eq!(oath.store_mut().saves(), 0);
    }

    #[test]
    fn reset_drops_the_pending_touch_in_both_paths() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let data = put_data(
            b"touch",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            PROPERTY_TOUCH,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        let request = calculate_data(b"touch", Some(&1u64.to_be_bytes()));
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request)).1,
            Sw::PRESENCE_REQUIRED
        );
        oath.store_mut().set_clear_fails(true);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::NOT_ENOUGH_MEMORY
        );
        assert_eq!(
            oath.confirm_presence(&mut rng).sw,
            Sw::CONDITIONS_NOT_SATISFIED
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request)).1,
            Sw::PRESENCE_REQUIRED
        );
        assert_eq!(oath.confirm_presence(&mut rng).sw, Sw::OK);

        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let data = put_data(
            b"touch",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            PROPERTY_TOUCH,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request)).1,
            Sw::PRESENCE_REQUIRED
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        assert_eq!(
            oath.confirm_presence(&mut rng).sw,
            Sw::CONDITIONS_NOT_SATISFIED
        );
    }

    fn put_totp<S: OathStore>(oath: &mut Oath<S>, rng: &mut TestRng, name: &[u8]) {
        let data = put_data(name, TYPE_TOTP, ALGORITHM_SHA1, 6, RFC_SECRET, None, 0);
        assert_eq!(run(oath, rng, &frame(INS_PUT, 0, 0, &data)).1, Sw::OK);
    }

    fn set_code_body(key: &[u8], challenge: &[u8]) -> Vec<u8, 256> {
        let mut data = Vec::<u8, 256>::new();
        let mut key_data = Vec::<u8, 128>::new();
        key_data.push(ALGORITHM_SHA1).unwrap();
        key_data.extend_from_slice(key).unwrap();
        append_tlv(&mut data, TAG_KEY, &key_data);
        append_tlv(&mut data, TAG_CHALLENGE, challenge);
        append_tlv(
            &mut data,
            TAG_RESPONSE,
            &hmac_digest(ALGORITHM_SHA1, key, challenge).unwrap(),
        );
        data
    }

    fn validate_body(key: &[u8], challenge: &[u8]) -> Vec<u8, 128> {
        let mut data = Vec::<u8, 128>::new();
        append_tlv(
            &mut data,
            TAG_RESPONSE,
            &hmac_digest(ALGORITHM_SHA1, key, challenge).unwrap(),
        );
        append_tlv(&mut data, TAG_CHALLENGE, b"87654321");
        data
    }

    #[test]
    fn failed_load_closes_the_applet_and_never_confirms_state_commands() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let key = rng.array::<10>();
        put_totp(&mut oath, &mut rng, b"30/closed");
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);
        let challenge = oath.auth_challenge;

        oath.store_mut().reset_calls();
        oath.store_mut().set_load_fails(true);
        let select = oath.select();
        assert_eq!(select.sw, Sw::OK);
        assert!(tlv::find(select.data, TAG_VERSION).is_some());
        assert!(tlv::find(select.data, TAG_NAME).is_some());
        assert!(tlv::find(select.data, TAG_CHALLENGE).is_none());
        assert!(tlv::find(select.data, 0x7B).is_none());

        let request = calculate_data(b"30/closed", Some(&1u64.to_be_bytes()));
        let touch = put_data(
            b"touch",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            PROPERTY_TOUCH,
        );
        let touch_request = calculate_data(b"touch", Some(&1u64.to_be_bytes()));
        let mut calculate_all = Vec::<u8, 32>::new();
        append_tlv(&mut calculate_all, TAG_CHALLENGE, &1u64.to_be_bytes());
        let mut delete = Vec::<u8, 128>::new();
        append_tlv(&mut delete, TAG_NAME, b"30/closed");
        let set_code = set_code_body(&key, b"abcdefgh");
        let validate = validate_body(&key, &challenge);

        let commands: [(&str, Vec<u8, 512>); 11] = [
            ("list", frame(INS_LIST, 0, 0, &[])),
            ("calculate", frame(INS_CALCULATE, 0, 1, &request)),
            (
                "calculate touch",
                frame(INS_CALCULATE, 0, 1, &touch_request),
            ),
            (
                "calculate all",
                frame(INS_CALCULATE_ALL, 0, 1, &calculate_all),
            ),
            ("put", frame(INS_PUT, 0, 0, &touch)),
            ("delete", frame(INS_DELETE, 0, 0, &delete)),
            ("set code empty", frame(INS_SET_CODE, 0, 0, &[])),
            ("set code key", frame(INS_SET_CODE, 0, 0, &set_code)),
            ("validate", frame(INS_VALIDATE, 0, 0, &validate)),
            ("unknown", frame(0xEE, 0, 0, &[])),
            ("list again", frame(INS_LIST, 0, 0, &[])),
        ];
        for (label, command) in commands {
            assert_eq!(
                run(&mut oath, &mut rng, &command).1,
                Sw::NO_PRECISE_DIAGNOSIS,
                "{label} must fail closed"
            );
        }
        assert_eq!(oath.store_mut().saves(), 0);
        assert_eq!(oath.store_mut().clears(), 0);
    }

    #[test]
    fn closed_applet_never_writes_or_overwrites_the_blob() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let key = rng.random::<[u8; 10]>();
        put_totp(&mut oath, &mut rng, b"30/keep");
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);

        let mut snapshot = [0u8; STATE_BYTES];
        let snapshot_len = oath.store_mut().load(&mut snapshot).unwrap();
        assert!(snapshot_len > 0);

        oath.store_mut().reset_calls();
        oath.store_mut().set_load_fails(true);
        assert_eq!(oath.select().sw, Sw::OK);

        let other = put_data(
            b"30/other",
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            b"different",
            None,
            0,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &other)).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        let mut delete = Vec::<u8, 128>::new();
        append_tlv(&mut delete, TAG_NAME, b"30/keep");
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_DELETE, 0, 0, &delete)).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_SET_CODE, 0, 0, &[])).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(oath.store_mut().saves(), 0);
        assert_eq!(oath.store_mut().clears(), 0);

        oath.store_mut().set_load_fails(false);
        let mut reread = [0u8; STATE_BYTES];
        let reread_len = oath.store_mut().load(&mut reread).unwrap();
        assert_eq!(reread_len, snapshot_len);
        assert_eq!(&reread[..reread_len], &snapshot[..snapshot_len]);
    }

    #[test]
    fn reset_stays_available_and_fail_closed_while_the_read_fails() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let key = rng.random::<[u8; 10]>();
        put_totp(&mut oath, &mut rng, b"30/reset");
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);

        oath.store_mut().reset_calls();
        oath.store_mut().set_load_fails(true);
        assert_eq!(oath.select().sw, Sw::OK);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        assert_eq!(oath.store_mut().clears(), 1);
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_SET_CODE, 0, 0, &[])).1,
            Sw::OK
        );

        oath.store_mut().set_load_fails(false);
        let select = oath.select();
        assert_eq!(select.sw, Sw::OK);
        assert!(tlv::find(select.data, TAG_CHALLENGE).is_none());
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());

        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        put_totp(&mut oath, &mut rng, b"30/keep");
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);
        oath.store_mut().set_load_fails(true);
        assert_eq!(oath.select().sw, Sw::OK);
        oath.store_mut().set_clear_fails(true);
        oath.store_mut().reset_calls();
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::NOT_ENOUGH_MEMORY
        );
        assert_eq!(oath.store_mut().clears(), 1);
        assert_eq!(oath.store_mut().loads(), 0);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(oath.store_mut().loads(), 0);

        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        oath.store_mut().set_load_fails(true);
        assert_eq!(oath.select().sw, Sw::OK);
        oath.store_mut().reset_calls();
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0xDE, 0x00, &[])).1,
            Sw::INS_NOT_SUPPORTED
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_RESET, 0x00, 0xAD, &[])).1,
            Sw::INS_NOT_SUPPORTED
        );
        assert_eq!(oath.store_mut().clears(), 0);
        assert_eq!(oath.store_mut().loads(), 0);

        let mut healthy = applet();
        assert_eq!(
            run(&mut healthy, &mut rng, &frame(INS_RESET, 0xDE, 0xAD, &[])).1,
            Sw::OK
        );
        let (list, status) = run(&mut healthy, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());
    }

    #[test]
    fn a_good_reselect_reopens_and_preserves_credentials_and_access_code() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let mut key = [0u8; 10];
        rng.fill_bytes(&mut key);
        let name = b"30/persist";
        put_totp(&mut oath, &mut rng, name);
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);
        assert_eq!(validate_access_code(&mut oath, &mut rng, &key), Sw::OK);
        let request = calculate_data(name, Some(&1u64.to_be_bytes()));
        let (response, status) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request));
        assert_eq!(status, Sw::OK);
        let expected = code(&response, TAG_TRUNCATED);
        assert_eq!(expected, 287082);

        assert_eq!(oath.select().sw, Sw::OK);
        let mut snapshot = [0u8; STATE_BYTES];
        let snapshot_len = oath.store_mut().load(&mut snapshot).unwrap();
        oath.store_mut().reset_calls();

        oath.store_mut().set_load_fails(true);
        let select = oath.select();
        assert_eq!(select.sw, Sw::OK);
        assert!(tlv::find(select.data, TAG_CHALLENGE).is_none());
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(oath.store_mut().loads(), 1);

        oath.store_mut().set_load_fails(false);
        let select = oath.select();
        assert_eq!(select.sw, Sw::OK);
        assert!(tlv::find(select.data, TAG_CHALLENGE).is_some());
        assert_eq!(oath.store_mut().loads(), 2);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_eq!(oath.store_mut().loads(), 2);

        let mut reread = [0u8; STATE_BYTES];
        let reread_len = oath.store_mut().load(&mut reread).unwrap();
        assert_eq!(reread_len, snapshot_len);
        assert_eq!(&reread[..reread_len], &snapshot[..snapshot_len]);

        assert_eq!(validate_access_code(&mut oath, &mut rng, &key), Sw::OK);
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *name);
        let (response, status) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request));
        assert_eq!(status, Sw::OK);
        assert_eq!(code(&response, TAG_TRUNCATED), expected);
    }

    #[test]
    fn repeated_failed_loads_stay_closed_without_leaking_ram() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let mut key = [0u8; 10];
        rng.fill_bytes(&mut key);
        put_totp(&mut oath, &mut rng, b"30/ram");
        assert_eq!(set_access_code(&mut oath, &mut rng, &key), Sw::OK);
        assert_eq!(oath.select().sw, Sw::OK);
        let validate = validate_body(&key, &oath.auth_challenge);

        oath.store_mut().set_load_fails(true);
        oath.store_mut().reset_calls();
        for _ in 0..3 {
            assert_eq!(oath.select().sw, Sw::OK);
        }
        assert_eq!(oath.store_mut().loads(), 3);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_VALIDATE, 0, 0, &validate)).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(oath.confirm_presence(&mut rng).sw, Sw::NO_PRECISE_DIAGNOSIS);
        assert_eq!(oath.store_mut().loads(), 3);
        // Closing normalizes the volatile state to the boot state: a closed
        // applet must not keep the credentials, the validated session or a
        // challenge it can no longer vouch for in RAM.
        assert!(oath.credentials.is_empty());
        assert!(oath.auth_key.is_empty());
        assert!(oath.pending.is_none());
        assert!(!oath.authenticated);
        assert_eq!(oath.auth_algorithm, ALGORITHM_SHA1);
        assert_eq!(oath.auth_challenge, DEFAULT_CHALLENGE);
    }

    #[test]
    fn undecodable_blob_closes_and_reopens_with_a_valid_one() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let name = b"30/corrupt";
        put_totp(&mut oath, &mut rng, name);
        assert_eq!(oath.select().sw, Sw::OK);

        let mut snapshot = [0u8; STATE_BYTES];
        let snapshot_len = oath.store_mut().load(&mut snapshot).unwrap();
        assert!(snapshot_len > 0);
        assert!(oath.store_mut().save(&[0xFF; 8]));

        oath.store_mut().reset_calls();
        assert_eq!(oath.select().sw, Sw::OK);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(oath.store_mut().saves(), 0);
        assert_eq!(oath.store_mut().clears(), 0);

        assert!(oath.store_mut().save(&snapshot[..snapshot_len]));
        assert_eq!(oath.select().sw, Sw::OK);
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *name);

        // A closed applet reopens on a blank store too: `Some(0)` is a
        // readable empty state, not a read failure, so degrading to blank
        // after an `Err` must not leave the card stuck until `RESET`.
        assert!(oath.store_mut().save(&[0xFF; 8]));
        assert_eq!(oath.select().sw, Sw::OK);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert!(oath.store_mut().clear());
        assert_eq!(oath.select().sw, Sw::OK);
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());
    }

    #[test]
    fn process_before_select_reads_before_serving_or_fails_closed() {
        // The guard must read the store before serving, not only honour the
        // flag set by a previous `SELECT`: an applet reached through the
        // public entry point with an unread store must not answer `9000`.
        let mut unread = Oath::new(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        unread.store_mut().set_load_fails(true);
        assert_eq!(
            run(&mut unread, &mut rng, &frame(INS_LIST, 0, 0, &[])).1,
            Sw::NO_PRECISE_DIAGNOSIS
        );
        assert_eq!(unread.store_mut().loads(), 1);
        assert_eq!(unread.store_mut().saves(), 0);
        assert_eq!(unread.store_mut().clears(), 0);

        let mut fresh = Oath::new(FailingOathStore::new(MemoryOathStore::new()));
        let (list, status) = run(&mut fresh, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());
        assert_eq!(fresh.store_mut().loads(), 1);
    }

    #[test]
    fn blank_store_still_serves_an_empty_applet() {
        let mut store = MemoryOathStore::new();
        let mut encoded = [0u8; STATE_BYTES];
        assert_eq!(store.load(&mut encoded), Some(0));

        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        assert_eq!(oath.select().sw, Sw::OK);
        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert!(list.is_empty());
        put_totp(&mut oath, &mut rng, b"30/blank");
    }

    fn put_touch_totp<S: OathStore>(oath: &mut Oath<S>, rng: &mut TestRng, name: &[u8]) {
        let data = put_data(
            name,
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            PROPERTY_TOUCH,
        );
        assert_eq!(run(oath, rng, &frame(INS_PUT, 0, 0, &data)).1, Sw::OK);
    }

    fn arm_touch<S: OathStore>(
        oath: &mut Oath<S>,
        rng: &mut TestRng,
        name: &[u8],
        challenge: &[u8],
    ) {
        let request = calculate_data(name, Some(challenge));
        assert_eq!(
            run(oath, rng, &frame(INS_CALCULATE, 0, 1, &request)).1,
            Sw::PRESENCE_REQUIRED
        );
    }

    fn assert_touch_disarmed<S: OathStore>(oath: &mut Oath<S>, rng: &mut TestRng) {
        let response = oath.confirm_presence(rng);
        assert_eq!(response.sw, Sw::CONDITIONS_NOT_SATISFIED);
        assert!(response.data.is_empty());
    }

    fn delete_data(name: &[u8]) -> Vec<u8, 128> {
        let mut data = Vec::new();
        append_tlv(&mut data, TAG_NAME, name);
        data
    }

    #[test]
    fn delete_of_another_credential_disarms_the_armed_touch() {
        let mut oath = applet();
        let mut rng = TestRng;
        let armed = b"30/armed";
        let other = b"30/other";
        put_touch_totp(&mut oath, &mut rng, armed);
        let data = put_data(other, TYPE_TOTP, ALGORITHM_SHA1, 6, b"different", None, 0);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );

        let challenge = 1u64.to_be_bytes();
        arm_touch(&mut oath, &mut rng, armed, &challenge);
        let response = oath.confirm_presence(&mut rng);
        assert_eq!(response.sw, Sw::OK);
        let expected = code(response.data, TAG_TRUNCATED);

        // `other` is last, so removing it only truncates the vector: `armed`
        // keeps its index and the refusal can only come from the disarm.
        arm_touch(&mut oath, &mut rng, armed, &challenge);
        assert_eq!(
            run(
                &mut oath,
                &mut rng,
                &frame(INS_DELETE, 0, 0, &delete_data(other))
            )
            .1,
            Sw::OK
        );
        assert_touch_disarmed(&mut oath, &mut rng);

        arm_touch(&mut oath, &mut rng, armed, &challenge);
        let response = oath.confirm_presence(&mut rng);
        assert_eq!(response.sw, Sw::OK);
        assert_eq!(code(response.data, TAG_TRUNCATED), expected);
    }

    #[test]
    fn deleting_the_armed_credential_never_returns_another_code_or_panics() {
        let mut rng = TestRng;
        let armed = b"30/armed";
        let kept = b"30/kept";
        let challenge = 1u64.to_be_bytes();

        // Both geometries a raw index gets wrong: (a) `armed` is not last, so
        // `swap_remove` moves `kept` into `pending.index` and the confirmation
        // used to return `kept`'s code; (b) `armed` is last, so the stored
        // index ends up equal to the new length and used to panic.
        for armed_is_last in [false, true] {
            let mut oath = applet();
            if armed_is_last {
                put_totp(&mut oath, &mut rng, kept);
                put_touch_totp(&mut oath, &mut rng, armed);
            } else {
                put_touch_totp(&mut oath, &mut rng, armed);
                put_totp(&mut oath, &mut rng, kept);
            }
            arm_touch(&mut oath, &mut rng, armed, &challenge);
            assert_eq!(
                run(
                    &mut oath,
                    &mut rng,
                    &frame(INS_DELETE, 0, 0, &delete_data(armed))
                )
                .1,
                Sw::OK
            );
            assert_touch_disarmed(&mut oath, &mut rng);

            let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
            assert_eq!(status, Sw::OK);
            assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *kept);
            assert!(oath.find(armed).is_none());
            let (_, status) = run(
                &mut oath,
                &mut rng,
                &frame(INS_CALCULATE, 0, 1, &calculate_data(kept, Some(&challenge))),
            );
            assert_eq!(status, Sw::OK, "armed is last: {armed_is_last}");
        }
    }

    #[test]
    fn deleting_another_credential_while_the_armed_one_is_last_does_not_panic() {
        let mut oath = applet();
        let mut rng = TestRng;
        let armed = b"30/armed";
        let removed = b"30/removed";
        let challenge = 1u64.to_be_bytes();
        put_totp(&mut oath, &mut rng, removed);
        put_touch_totp(&mut oath, &mut rng, armed);

        // `armed` is last: removing the first entry moves it down and leaves
        // `pending.index == len`, the other geometry that used to panic.
        arm_touch(&mut oath, &mut rng, armed, &challenge);
        assert_eq!(
            run(
                &mut oath,
                &mut rng,
                &frame(INS_DELETE, 0, 0, &delete_data(removed))
            )
            .1,
            Sw::OK
        );
        assert_touch_disarmed(&mut oath, &mut rng);

        let (list, status) = run(&mut oath, &mut rng, &frame(INS_LIST, 0, 0, &[]));
        assert_eq!(status, Sw::OK);
        assert_eq!(tlv::find(&list, TAG_NAME_LIST).unwrap()[1..], *armed);
        arm_touch(&mut oath, &mut rng, armed, &challenge);
        assert_eq!(oath.confirm_presence(&mut rng).sw, Sw::OK);
    }

    #[test]
    fn refused_delete_and_put_disarm_the_armed_touch() {
        let mut rng = TestRng;
        let armed = b"30/armed";
        let other = b"30/other";
        let challenge = 1u64.to_be_bytes();

        let mut oath = applet();
        put_touch_totp(&mut oath, &mut rng, armed);
        put_totp(&mut oath, &mut rng, other);

        arm_touch(&mut oath, &mut rng, armed, &challenge);
        assert_eq!(
            run(
                &mut oath,
                &mut rng,
                &frame(INS_DELETE, 0, 0, &delete_data(b"absent"))
            )
            .1,
            Sw::OATH_OBJECT_NOT_FOUND
        );
        assert_touch_disarmed(&mut oath, &mut rng);

        arm_touch(&mut oath, &mut rng, armed, &challenge);
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_DELETE, 0, 0, &[])).1,
            Sw::WRONG_DATA
        );
        assert_touch_disarmed(&mut oath, &mut rng);

        arm_touch(&mut oath, &mut rng, armed, &challenge);
        put_totp(&mut oath, &mut rng, b"30/added");
        assert_touch_disarmed(&mut oath, &mut rng);

        arm_touch(&mut oath, &mut rng, armed, &challenge);
        let data = put_data(
            armed,
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            b"fresh-secret",
            None,
            PROPERTY_TOUCH,
        );
        assert_eq!(
            run(&mut oath, &mut rng, &frame(INS_PUT, 0, 0, &data)).1,
            Sw::OK
        );
        assert_touch_disarmed(&mut oath, &mut rng);

        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        put_touch_totp(&mut oath, &mut rng, armed);
        put_totp(&mut oath, &mut rng, other);
        oath.store_mut().reset_calls();
        oath.store_mut().set_save_fails(true);
        arm_touch(&mut oath, &mut rng, armed, &challenge);
        assert_eq!(
            run(
                &mut oath,
                &mut rng,
                &frame(INS_DELETE, 0, 0, &delete_data(other))
            )
            .1,
            Sw::NOT_ENOUGH_MEMORY
        );
        assert_eq!(oath.store_mut().saves(), 1);
        assert_eq!(oath.store_mut().clears(), 0);
        assert_touch_disarmed(&mut oath, &mut rng);
        oath.store_mut().set_save_fails(false);

        // The disarm happens before authentication: a refused DELETE/PUT
        // (`6982`) must not leave a request a later confirm could serve.
        let mut authed = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        put_touch_totp(&mut authed, &mut rng, armed);
        put_totp(&mut authed, &mut rng, other);
        let key = rng.bytes::<10>();
        assert_eq!(set_access_code(&mut authed, &mut rng, &key), Sw::OK);
        assert_eq!(authed.select().sw, Sw::OK);
        assert_eq!(validate_access_code(&mut authed, &mut rng, &key), Sw::OK);

        arm_touch(&mut authed, &mut rng, armed, &challenge);
        authed.authenticated = false;
        assert_eq!(
            run(
                &mut authed,
                &mut rng,
                &frame(INS_DELETE, 0, 0, &delete_data(other))
            )
            .1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_touch_disarmed(&mut authed, &mut rng);

        assert_eq!(validate_access_code(&mut authed, &mut rng, &key), Sw::OK);
        arm_touch(&mut authed, &mut rng, armed, &challenge);
        authed.authenticated = false;
        let blocked = put_data(
            other,
            TYPE_TOTP,
            ALGORITHM_SHA1,
            6,
            RFC_SECRET,
            None,
            PROPERTY_TOUCH,
        );
        assert_eq!(
            run(&mut authed, &mut rng, &frame(INS_PUT, 0, 0, &blocked)).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        assert_touch_disarmed(&mut authed, &mut rng);
    }

    #[test]
    fn out_of_bounds_pending_answers_6985_without_touching_the_store() {
        let mut oath = applet_with(FailingOathStore::new(MemoryOathStore::new()));
        let mut rng = TestRng;
        let name = b"30/bounded";
        put_totp(&mut oath, &mut rng, name);
        oath.store_mut().reset_calls();

        let len = oath.credentials.len();
        for index in [len, MAX_CREDENTIALS, 99] {
            oath.pending = Some(PendingCalculation {
                index,
                challenge: [0u8; 8],
                truncated: true,
            });
            assert_touch_disarmed(&mut oath, &mut rng);
            assert!(oath.pending.is_none());
            assert_touch_disarmed(&mut oath, &mut rng);
        }
        assert_eq!(oath.credentials.len(), len);
        assert_eq!(oath.find(name), Some(0));
        assert_eq!(oath.store_mut().saves(), 0);
        assert_eq!(oath.store_mut().clears(), 0);

        let request = calculate_data(name, Some(&1u64.to_be_bytes()));
        let (_, status) = run(&mut oath, &mut rng, &frame(INS_CALCULATE, 0, 1, &request));
        assert_eq!(status, Sw::OK);
        assert_eq!(
            oath.confirm_presence(&mut rng).sw,
            Sw::CONDITIONS_NOT_SATISFIED
        );
    }
}
