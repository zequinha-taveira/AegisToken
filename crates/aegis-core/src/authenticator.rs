//! CTAP2 authenticator logic: makeCredential and getAssertion (PRD §15).
//!
//! Pure, host-testable implementation of credential creation and assertion
//! signing with P-256 / ES256 and packed self-attestation. Persistence and
//! `clientPIN` are layered on top in later slices; credentials are held in a
//! [`CredentialStore`].

use minicbor::encode::{Encoder, Write};
use p256::FieldBytes;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::codec;
use crate::configuration::FixedString;
use crate::ctap2::{
    AAGUID, COSE_ALG_ES256, COSE_CURVE_P256, CredentialDescriptor, Ctap2Status, Ec2PublicKey,
    GetAssertionRequest, MakeCredentialRequest,
};
use crate::error::CoreError;

/// Maximum number of stored credentials.
pub const MAX_CREDENTIALS: usize = 8;
/// Credential id length in bytes.
pub const CREDENTIAL_ID_LEN: usize = 16;
/// Maximum authenticator-data length.
pub const MAX_AUTH_DATA: usize = 256;
/// Maximum signature length (DER-encoded ES256).
pub const MAX_SIGNATURE: usize = 80;
/// Scratch length for signing input (auth data plus client data hash).
const MAX_SIGNING_INPUT: usize = MAX_AUTH_DATA + 32;

/// Authenticator data flag: user present.
pub const FLAG_UP: u8 = 0x01;
/// Authenticator data flag: user verified.
pub const FLAG_UV: u8 = 0x04;
/// Authenticator data flag: attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Authenticator data flag: extension data included.
pub const FLAG_ED: u8 = 0x80;

/// Randomness source for credential id and key generation.
pub trait Rng {
    /// Fill `dest` with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

/// A stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Credential id.
    pub id: heapless::Vec<u8, 32>,
    /// Relying party identifier.
    pub rp_id: FixedString<64>,
    /// User handle.
    pub user_id: heapless::Vec<u8, 64>,
    /// P-256 private scalar.
    pub private_key: [u8; 32],
    /// Signature counter.
    pub sign_count: u32,
    /// Whether this is a discoverable (resident) credential.
    pub discoverable: bool,
}

impl<C> minicbor::Encode<C> for Credential {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(6)?;
        e.u8(0)?;
        e.bytes(&self.id)?;
        e.u8(1)?;
        e.str(self.rp_id.as_str())?;
        e.u8(2)?;
        e.bytes(&self.user_id)?;
        e.u8(3)?;
        e.bytes(&self.private_key)?;
        e.u8(4)?;
        e.u32(self.sign_count)?;
        e.u8(5)?;
        e.bool(self.discoverable)?;
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Credential {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let length = d
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite map"))?;
        let mut credential = Credential {
            id: heapless::Vec::new(),
            rp_id: FixedString::new("").expect("empty string fits"),
            user_id: heapless::Vec::new(),
            private_key: [0u8; 32],
            sign_count: 0,
            discoverable: false,
        };
        for _ in 0..length {
            match d.u8()? {
                0 => {
                    let bytes = d.bytes()?;
                    credential.id = heapless::Vec::from_slice(bytes)
                        .map_err(|_| minicbor::decode::Error::message("id too long"))?;
                }
                1 => {
                    credential.rp_id = FixedString::new(d.str()?)
                        .map_err(|_| minicbor::decode::Error::message("rp_id too long"))?;
                }
                2 => {
                    let bytes = d.bytes()?;
                    credential.user_id = heapless::Vec::from_slice(bytes)
                        .map_err(|_| minicbor::decode::Error::message("user_id too long"))?;
                }
                3 => {
                    let bytes = d.bytes()?;
                    if bytes.len() != 32 {
                        return Err(minicbor::decode::Error::message("bad key length"));
                    }
                    credential.private_key.copy_from_slice(bytes);
                }
                4 => credential.sign_count = d.u32()?,
                5 => credential.discoverable = d.bool()?,
                _ => d.skip()?,
            }
        }
        Ok(credential)
    }
}

/// Storage for credentials.
pub trait CredentialStore {
    /// Fetch a credential by id.
    fn get(&self, credential_id: &[u8]) -> Option<Credential>;
    /// Fetch a credential for a relying party, preferring discoverable ones.
    fn find_by_rp(&self, rp_id: &str) -> Option<Credential>;
    /// Insert or replace a credential.
    fn insert(&mut self, credential: Credential) -> Result<(), CoreError>;
    /// Increment and return the signature counter for a credential.
    fn next_sign_count(&mut self, credential_id: &[u8]) -> Option<u32>;
    /// Remove a credential.
    fn remove(&mut self, credential_id: &[u8]) -> Result<(), CoreError>;
    /// Number of stored credentials.
    fn count(&self) -> usize;
    /// Remove all credentials.
    fn clear(&mut self);
}

/// In-memory credential store with in-memory PIN state.
#[derive(Debug)]
pub struct MemoryCredentialStore {
    credentials: heapless::Vec<Credential, MAX_CREDENTIALS>,
    pin_hash: Option<[u8; 32]>,
    pin_retries: u8,
}

impl Default for MemoryCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryCredentialStore {
    /// Create an empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            credentials: heapless::Vec::new(),
            pin_hash: None,
            pin_retries: crate::pin::DEFAULT_RETRIES,
        }
    }
}

impl crate::pin::PinState for MemoryCredentialStore {
    fn pin_hash(&self) -> Option<[u8; 32]> {
        self.pin_hash
    }
    fn pin_retries(&self) -> u8 {
        self.pin_retries
    }
    fn set_pin_hash(&mut self, hash: [u8; 32]) -> Result<(), CoreError> {
        self.pin_hash = Some(hash);
        self.pin_retries = crate::pin::DEFAULT_RETRIES;
        Ok(())
    }
    fn set_pin_retries(&mut self, retries: u8) -> Result<(), CoreError> {
        self.pin_retries = retries;
        Ok(())
    }
    fn clear_pin_state(&mut self) -> Result<(), CoreError> {
        self.pin_hash = None;
        self.pin_retries = crate::pin::DEFAULT_RETRIES;
        Ok(())
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn get(&self, credential_id: &[u8]) -> Option<Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.id.as_slice() == credential_id)
            .cloned()
    }

    fn find_by_rp(&self, rp_id: &str) -> Option<Credential> {
        self.credentials
            .iter()
            .filter(|credential| credential.rp_id.as_str() == rp_id)
            .max_by_key(|credential| credential.discoverable)
            .cloned()
    }

    fn insert(&mut self, credential: Credential) -> Result<(), CoreError> {
        if let Some(slot) = self
            .credentials
            .iter_mut()
            .find(|existing| existing.id == credential.id)
        {
            *slot = credential;
            return Ok(());
        }
        self.credentials
            .push(credential)
            .map_err(|_| CoreError::StorageError)
    }

    fn next_sign_count(&mut self, credential_id: &[u8]) -> Option<u32> {
        let credential = self
            .credentials
            .iter_mut()
            .find(|credential| credential.id.as_slice() == credential_id)?;
        credential.sign_count = credential.sign_count.saturating_add(1);
        Some(credential.sign_count)
    }

    fn count(&self) -> usize {
        self.credentials.len()
    }

    fn remove(&mut self, credential_id: &[u8]) -> Result<(), CoreError> {
        if let Some(index) = self
            .credentials
            .iter()
            .position(|credential| credential.id.as_slice() == credential_id)
        {
            self.credentials.swap_remove(index);
        }
        Ok(())
    }

    fn clear(&mut self) {
        self.credentials.clear();
    }
}

/// `authenticatorMakeCredential` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialResponse {
    /// Authenticator data.
    pub auth_data: heapless::Vec<u8, MAX_AUTH_DATA>,
    /// Attestation signature.
    pub signature: heapless::Vec<u8, MAX_SIGNATURE>,
}

impl<C> minicbor::Encode<C> for MakeCredentialResponse {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(3)?;
        e.u8(1)?;
        e.str("packed")?;
        e.u8(2)?;
        e.bytes(&self.auth_data)?;
        e.u8(3)?;
        e.map(2)?;
        e.str("alg")?;
        e.i64(COSE_ALG_ES256)?;
        e.str("sig")?;
        e.bytes(&self.signature)?;
        Ok(())
    }
}

/// `authenticatorGetAssertion` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionResponse {
    /// Credential id.
    pub credential_id: heapless::Vec<u8, 32>,
    /// Authenticator data.
    pub auth_data: heapless::Vec<u8, MAX_AUTH_DATA>,
    /// Assertion signature.
    pub signature: heapless::Vec<u8, MAX_SIGNATURE>,
    /// User handle.
    pub user_id: heapless::Vec<u8, 64>,
}

impl<C> minicbor::Encode<C> for GetAssertionResponse {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(4)?;
        // credential: PublicKeyCredentialDescriptor (text keys, canonical order).
        e.u8(1)?;
        e.map(2)?;
        e.str("id")?;
        e.bytes(&self.credential_id)?;
        e.str("type")?;
        e.str("public-key")?;
        e.u8(2)?;
        e.bytes(&self.auth_data)?;
        e.u8(3)?;
        e.bytes(&self.signature)?;
        // user: PublicKeyCredentialUserEntity (text keys).
        e.u8(4)?;
        e.map(1)?;
        e.str("id")?;
        e.bytes(&self.user_id)?;
        Ok(())
    }
}

fn generate_signing_key<R: Rng>(rng: &mut R) -> Result<SigningKey, Ctap2Status> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = SigningKey::from_bytes(FieldBytes::from_slice(&bytes)) {
            return Ok(key);
        }
    }
    Err(Ctap2Status::Other)
}

fn build_attested_credential_data(
    credential_id: &[u8],
    cose_key: &Ec2PublicKey,
) -> Result<heapless::Vec<u8, 200>, Ctap2Status> {
    let mut out: heapless::Vec<u8, 200> = heapless::Vec::new();
    out.extend_from_slice(&AAGUID)
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes())
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    out.extend_from_slice(credential_id)
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    let mut buf = [0u8; 128];
    let len = codec::encode_into(cose_key, &mut buf).map_err(|_| Ctap2Status::Other)?;
    out.extend_from_slice(&buf[..len])
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    Ok(out)
}

fn build_auth_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested: Option<&[u8]>,
) -> Result<heapless::Vec<u8, MAX_AUTH_DATA>, Ctap2Status> {
    let mut data: heapless::Vec<u8, MAX_AUTH_DATA> = heapless::Vec::new();
    let rp_hash = Sha256::digest(rp_id.as_bytes());
    data.extend_from_slice(rp_hash.as_slice())
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    data.push(flags).map_err(|_| Ctap2Status::LimitExceeded)?;
    data.extend_from_slice(&sign_count.to_be_bytes())
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    if let Some(attested) = attested {
        data.extend_from_slice(attested)
            .map_err(|_| Ctap2Status::LimitExceeded)?;
    }
    Ok(data)
}

fn sign(
    private_key: &[u8; 32],
    auth_data: &[u8],
    client_data_hash: &[u8; 32],
) -> Result<heapless::Vec<u8, MAX_SIGNATURE>, Ctap2Status> {
    let mut message: heapless::Vec<u8, MAX_SIGNING_INPUT> = heapless::Vec::new();
    message
        .extend_from_slice(auth_data)
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    message
        .extend_from_slice(client_data_hash)
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    sign_message(private_key, &message)
}

/// Sign an arbitrary message with a credential key (ES256, DER-encoded).
///
/// Shared by CTAP2 assertions and the U2F authenticate command.
pub fn sign_message(
    private_key: &[u8; 32],
    message: &[u8],
) -> Result<heapless::Vec<u8, MAX_SIGNATURE>, Ctap2Status> {
    let signing_key = SigningKey::from_bytes(FieldBytes::from_slice(private_key))
        .map_err(|_| Ctap2Status::Other)?;
    let signature: Signature = signing_key.sign(message);
    let der = signature.to_der();
    heapless::Vec::from_slice(der.as_bytes()).map_err(|_| Ctap2Status::LimitExceeded)
}

/// CTAP2 `authenticatorMakeCredential`.
///
/// `up_confirmed` reflects that User Presence was obtained in
/// `FidoWaitPresence`; the firmware enforces that context. `uv_confirmed`
/// reflects that a valid `pinUvAuthParam` was verified against the active
/// PIN/UV auth token.
pub fn make_credential<S: CredentialStore, R: Rng>(
    store: &mut S,
    rng: &mut R,
    request: &MakeCredentialRequest,
    up_confirmed: bool,
    uv_confirmed: bool,
) -> Result<MakeCredentialResponse, Ctap2Status> {
    if !up_confirmed {
        return Err(Ctap2Status::UpRequired);
    }
    if request.uv && !uv_confirmed {
        return Err(Ctap2Status::PinAuthInvalid);
    }

    for descriptor in &request.exclude_list {
        if let Some(existing) = store.get(&descriptor.id) {
            if existing.rp_id.as_str() == request.rp_id.as_str() {
                return Err(Ctap2Status::CredentialExcluded);
            }
        }
    }

    let signing_key = generate_signing_key(rng)?;

    let mut credential_id: heapless::Vec<u8, 32> = heapless::Vec::new();
    let mut id_bytes = [0u8; CREDENTIAL_ID_LEN];
    rng.fill_bytes(&mut id_bytes);
    credential_id
        .extend_from_slice(&id_bytes)
        .map_err(|_| Ctap2Status::Other)?;

    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(point.x().ok_or(Ctap2Status::Other)?);
    y.copy_from_slice(point.y().ok_or(Ctap2Status::Other)?);
    let cose_key = Ec2PublicKey {
        crv: COSE_CURVE_P256,
        x,
        y,
    };

    let flags = FLAG_UP | FLAG_AT | if uv_confirmed { FLAG_UV } else { 0 };
    let attested = build_attested_credential_data(&credential_id, &cose_key)?;
    let auth_data = build_auth_data(request.rp_id.as_str(), flags, 0, Some(&attested))?;

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&signing_key.to_bytes());
    let signature = sign(&private_key, &auth_data, &request.client_data_hash)?;

    store
        .insert(Credential {
            id: credential_id,
            rp_id: request.rp_id.clone(),
            user_id: request.user_id.clone(),
            private_key,
            sign_count: 0,
            discoverable: request.rk,
        })
        .map_err(|_| Ctap2Status::LimitExceeded)?;

    Ok(MakeCredentialResponse {
        auth_data,
        signature,
    })
}

/// CTAP2 `authenticatorGetAssertion`.
pub fn get_assertion<S: CredentialStore, R: Rng>(
    store: &mut S,
    _rng: &mut R,
    request: &GetAssertionRequest,
    up_confirmed: bool,
    uv_confirmed: bool,
) -> Result<GetAssertionResponse, Ctap2Status> {
    if !up_confirmed {
        return Err(Ctap2Status::UpRequired);
    }
    if request.uv && !uv_confirmed {
        return Err(Ctap2Status::PinAuthInvalid);
    }

    let credential = if request.allow_list.is_empty() {
        store.find_by_rp(request.rp_id.as_str())
    } else {
        request
            .allow_list
            .iter()
            .find_map(|descriptor: &CredentialDescriptor| {
                store
                    .get(&descriptor.id)
                    .filter(|credential| credential.rp_id.as_str() == request.rp_id.as_str())
            })
    }
    .ok_or(Ctap2Status::NoCredentials)?;

    let sign_count = store
        .next_sign_count(&credential.id)
        .ok_or(Ctap2Status::InvalidCredential)?;

    let flags = FLAG_UP | if uv_confirmed { FLAG_UV } else { 0 };
    let auth_data = build_auth_data(request.rp_id.as_str(), flags, sign_count, None)?;
    let signature = sign(
        &credential.private_key,
        &auth_data,
        &request.client_data_hash,
    )?;

    Ok(GetAssertionResponse {
        credential_id: credential.id,
        auth_data,
        signature,
        user_id: credential.user_id,
    })
}

/// CTAP2 `authenticatorReset`.
pub fn reset<S: CredentialStore + crate::pin::PinState>(
    store: &mut S,
    up_confirmed: bool,
) -> Result<(), Ctap2Status> {
    if !up_confirmed {
        return Err(Ctap2Status::UpRequired);
    }
    store.clear();
    store.clear_pin_state().map_err(|_| Ctap2Status::Other)?;
    Ok(())
}

/// `authenticatorCredentialManagement` subcommand: `getCredsMetadata`.
pub const CRED_MGMT_GET_METADATA: u8 = 0x01;
/// `authenticatorCredentialManagement` subcommand: `deleteCredential`.
pub const CRED_MGMT_DELETE: u8 = 0x06;

/// A parsed `authenticatorCredentialManagement` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialManagementRequest {
    /// Subcommand.
    pub sub_command: u8,
    /// Target credential id, when applicable.
    pub credential_id: Option<heapless::Vec<u8, 32>>,
}

impl CredentialManagementRequest {
    /// Parse from CTAP2 CBOR parameters.
    pub fn parse(params: &[u8]) -> Result<Self, Ctap2Status> {
        let mut decoder = minicbor::Decoder::new(params);
        let length = decoder
            .map()
            .map_err(|_| Ctap2Status::InvalidCbor)?
            .ok_or(Ctap2Status::InvalidCbor)?;
        let mut request = CredentialManagementRequest {
            sub_command: 0,
            credential_id: None,
        };
        for _ in 0..length {
            match decoder.u8().map_err(|_| Ctap2Status::InvalidCbor)? {
                0x01 => request.sub_command = decoder.u8().map_err(|_| Ctap2Status::InvalidCbor)?,
                0x02 => {
                    let bytes = decoder.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                    request.credential_id = Some(
                        heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?,
                    );
                }
                _ => decoder.skip().map_err(|_| Ctap2Status::InvalidCbor)?,
            }
        }
        Ok(request)
    }
}

/// `getCredsMetadata` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredsMetadataResponse {
    /// Number of resident credentials.
    pub existing: u32,
    /// Remaining resident credential slots.
    pub remaining: u32,
}

impl<C> minicbor::Encode<C> for CredsMetadataResponse {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?;
        e.u8(1)?;
        e.u32(self.existing)?;
        e.u8(2)?;
        e.u32(self.remaining)?;
        Ok(())
    }
}

/// Return resident-credential metadata.
#[must_use]
pub fn creds_metadata<S: CredentialStore>(store: &S) -> CredsMetadataResponse {
    let existing = store.count() as u32;
    CredsMetadataResponse {
        existing,
        remaining: (MAX_CREDENTIALS as u32).saturating_sub(existing),
    }
}

/// Delete a credential by id.
pub fn delete_credential<S: CredentialStore>(
    store: &mut S,
    credential_id: &[u8],
) -> Result<(), Ctap2Status> {
    if store.get(credential_id).is_none() {
        return Err(Ctap2Status::NoCredentials);
    }
    store.remove(credential_id).map_err(|_| Ctap2Status::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    struct TestRng(u32);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (self.0 >> 24) as u8;
            }
        }
    }

    fn make_request(rp_id: &str, user_id: &[u8]) -> MakeCredentialRequest {
        MakeCredentialRequest {
            client_data_hash: [0x11; 32],
            rp_id: FixedString::new(rp_id).unwrap(),
            user_id: heapless::Vec::from_slice(user_id).unwrap(),
            exclude_list: heapless::Vec::new(),
            rk: true,
            uv: false,
            pin_uv_auth_param: None,
        }
    }

    fn assertion_request(rp_id: &str) -> GetAssertionRequest {
        GetAssertionRequest {
            rp_id: FixedString::new(rp_id).unwrap(),
            client_data_hash: [0x22; 32],
            allow_list: heapless::Vec::new(),
            up: true,
            uv: false,
            pin_uv_auth_param: None,
        }
    }

    fn verify(
        private_key: &[u8; 32],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        der: &[u8],
    ) -> bool {
        let signing_key = SigningKey::from_bytes(FieldBytes::from_slice(private_key)).unwrap();
        let verifying_key = signing_key.verifying_key();
        let signature = Signature::from_der(der).unwrap();
        let mut message = heapless::Vec::<u8, MAX_SIGNING_INPUT>::new();
        message.extend_from_slice(auth_data).unwrap();
        message.extend_from_slice(client_data_hash).unwrap();
        verifying_key.verify(&message, &signature).is_ok()
    }

    fn credential_id_from_auth_data(auth_data: &[u8]) -> heapless::Vec<u8, 32> {
        // rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + idLen(2) + id
        let length = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        heapless::Vec::from_slice(&auth_data[55..55 + length]).unwrap()
    }

    #[test]
    fn make_credential_builds_valid_attestation() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(1);
        let request = make_request("example.com", &[1, 2, 3, 4]);

        let response = make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(store.count(), 1);

        // rpIdHash and flags.
        assert_eq!(
            &response.auth_data[0..32],
            Sha256::digest(b"example.com").as_slice()
        );
        assert_eq!(response.auth_data[32] & FLAG_UP, FLAG_UP);
        assert_eq!(response.auth_data[32] & FLAG_AT, FLAG_AT);
        // aaguid.
        assert_eq!(&response.auth_data[37..53], &AAGUID);

        let credential_id = credential_id_from_auth_data(&response.auth_data);
        let credential = store.get(&credential_id).unwrap();
        assert!(verify(
            &credential.private_key,
            &response.auth_data,
            &request.client_data_hash,
            &response.signature
        ));
    }

    #[test]
    fn make_credential_requires_user_presence() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(2);
        let request = make_request("example.com", &[1]);
        assert_eq!(
            make_credential(&mut store, &mut rng, &request, false, false),
            Err(Ctap2Status::UpRequired)
        );
    }

    #[test]
    fn make_credential_uv_requires_confirmation() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(8);
        let mut request = make_request("example.com", &[1]);
        request.uv = true;

        assert_eq!(
            make_credential(&mut store, &mut rng, &request, true, false),
            Err(Ctap2Status::PinAuthInvalid)
        );

        let response = make_credential(&mut store, &mut rng, &request, true, true).unwrap();
        assert_eq!(response.auth_data[32] & FLAG_UV, FLAG_UV);
    }

    #[test]
    fn excluded_credential_is_rejected() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(3);
        let request = make_request("example.com", &[1]);
        let response = make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        let credential_id = credential_id_from_auth_data(&response.auth_data);

        let mut excluded = make_request("example.com", &[1]);
        excluded
            .exclude_list
            .push(CredentialDescriptor {
                id: heapless::Vec::from_slice(&credential_id).unwrap(),
            })
            .unwrap();
        assert_eq!(
            make_credential(&mut store, &mut rng, &excluded, true, false),
            Err(Ctap2Status::CredentialExcluded)
        );
    }

    #[test]
    fn get_assertion_without_credentials_is_empty() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(4);
        let request = assertion_request("example.com");
        assert_eq!(
            get_assertion(&mut store, &mut rng, &request, true, false),
            Err(Ctap2Status::NoCredentials)
        );
    }

    #[test]
    fn get_assertion_signs_and_increments_counter() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(5);
        make_credential(
            &mut store,
            &mut rng,
            &make_request("example.com", &[7]),
            true,
            false,
        )
        .unwrap();

        let request = assertion_request("example.com");
        let first = get_assertion(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(first.auth_data[32] & FLAG_UP, FLAG_UP);
        assert_eq!(
            u32::from_be_bytes([
                first.auth_data[33],
                first.auth_data[34],
                first.auth_data[35],
                first.auth_data[36]
            ]),
            1
        );
        let credential = store.get(&first.credential_id).unwrap();
        assert_eq!(&first.user_id[..], &[7]);
        assert!(verify(
            &credential.private_key,
            &first.auth_data,
            &request.client_data_hash,
            &first.signature
        ));

        let second = get_assertion(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(
            u32::from_be_bytes([
                second.auth_data[33],
                second.auth_data[34],
                second.auth_data[35],
                second.auth_data[36]
            ]),
            2
        );
    }

    #[test]
    fn get_assertion_requires_user_presence() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(6);
        make_credential(
            &mut store,
            &mut rng,
            &make_request("example.com", &[1]),
            true,
            false,
        )
        .unwrap();
        let request = assertion_request("example.com");
        assert_eq!(
            get_assertion(&mut store, &mut rng, &request, false, false),
            Err(Ctap2Status::UpRequired)
        );
    }

    #[test]
    fn get_assertion_respects_allow_list() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(7);
        make_credential(
            &mut store,
            &mut rng,
            &make_request("example.com", &[1]),
            true,
            false,
        )
        .unwrap();

        let mut request = assertion_request("example.com");
        request
            .allow_list
            .push(CredentialDescriptor {
                id: heapless::Vec::from_slice(&[0u8; 16]).unwrap(),
            })
            .unwrap();
        assert_eq!(
            get_assertion(&mut store, &mut rng, &request, true, false),
            Err(Ctap2Status::NoCredentials)
        );
    }

    #[test]
    fn get_assertion_response_uses_text_key_entities() {
        // Regression: the WebAuthn-derived `credential` and `user` maps must use
        // text keys ("id"/"type"), not integer keys.
        let response = GetAssertionResponse {
            credential_id: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
            auth_data: heapless::Vec::from_slice(&[0x11; 37]).unwrap(),
            signature: heapless::Vec::from_slice(&[0x22; 70]).unwrap(),
            user_id: heapless::Vec::from_slice(&[7]).unwrap(),
        };
        let mut buf = [0u8; 256];
        let len = crate::codec::encode_into(&response, &mut buf).unwrap();
        let encoded = &buf[..len];
        let has = |needle: &[u8]| encoded.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"id"));
        assert!(has(b"type"));
        assert!(has(b"public-key"));
    }
}
