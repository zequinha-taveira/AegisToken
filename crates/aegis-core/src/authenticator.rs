//! CTAP2 authenticator logic: makeCredential and getAssertion (PRD §15).
//!
//! Pure, host-testable implementation of credential creation and assertion
//! signing with P-256 / ES256 and Ed25519 / EdDSA, plus packed
//! self-attestation. Persistence and `clientPIN` are layered on top in later
//! slices; credentials are held in a [`CredentialStore`].

use ed25519_dalek::{Signer as EdSigner, SigningKey as EdSigningKey};
use minicbor::encode::{Encoder, Write};
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::codec;
use crate::configuration::FixedString;
use crate::ctap2::{
    AAGUID, COSE_ALG_EDDSA, COSE_ALG_ES256, COSE_CURVE_ED25519, COSE_CURVE_P256, Ctap2Status,
    Ec2PublicKey, GetAssertionRequest, MakeCredentialRequest, OkpPublicKey,
};
use crate::error::CoreError;

/// Maximum number of stored credentials.
pub const MAX_CREDENTIALS: usize = 8;
/// Credential id length in bytes.
pub const CREDENTIAL_ID_LEN: usize = 16;
/// Maximum authenticator-data length.
pub const MAX_AUTH_DATA: usize = 256;
/// Maximum signature length (DER-encoded ES256 or raw EdDSA).
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
    /// Private key material: P-256 scalar for ES256, seed for EdDSA.
    pub private_key: [u8; 32],
    /// COSE algorithm this credential was created with (`-7` or `-8`).
    pub algorithm: i64,
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
        e.map(7)?;
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
        e.u8(6)?;
        e.i64(self.algorithm)?;
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
            algorithm: COSE_ALG_ES256,
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
                // Absent in records written before EdDSA support; default ES256.
                6 => credential.algorithm = d.i64()?,
                _ => d.skip()?,
            }
        }
        if credential.algorithm != COSE_ALG_ES256 && credential.algorithm != COSE_ALG_EDDSA {
            return Err(minicbor::decode::Error::message("bad algorithm"));
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
    /// Every stored credential, in insertion order.
    fn list(&self) -> &[Credential];
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

    fn list(&self) -> &[Credential] {
        &self.credentials
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
    /// COSE algorithm of the created credential (`-7` or `-8`).
    pub alg: i64,
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
        e.i64(self.alg)?;
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
    /// Total number of credentials matching the request.
    ///
    /// The platform fetches the remaining ones with
    /// `authenticatorGetNextAssertion`.
    pub number_of_credentials: u32,
}

impl<C> minicbor::Encode<C> for GetAssertionResponse {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(5)?;
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
        e.u8(5)?;
        e.u32(self.number_of_credentials)?;
        Ok(())
    }
}

fn generate_signing_key<R: Rng>(rng: &mut R) -> Result<SigningKey, Ctap2Status> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = SigningKey::from_slice(&bytes) {
            return Ok(key);
        }
    }
    Err(Ctap2Status::Other)
}

fn build_attested_credential_data(
    credential_id: &[u8],
    cose_key: &[u8],
) -> Result<heapless::Vec<u8, 200>, Ctap2Status> {
    let mut out: heapless::Vec<u8, 200> = heapless::Vec::new();
    out.extend_from_slice(&AAGUID)
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes())
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    out.extend_from_slice(credential_id)
        .map_err(|_| Ctap2Status::LimitExceeded)?;
    out.extend_from_slice(cose_key)
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
    alg: i64,
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
    if alg == COSE_ALG_EDDSA {
        let signing_key = EdSigningKey::from_bytes(private_key);
        let signature = signing_key.sign(&message);
        return heapless::Vec::from_slice(&signature.to_bytes())
            .map_err(|_| Ctap2Status::LimitExceeded);
    }
    sign_message(private_key, &message)
}

/// Sign an arbitrary message with a credential key (ES256, DER-encoded).
///
/// Shared by CTAP2 assertions and the U2F authenticate command.
pub fn sign_message(
    private_key: &[u8; 32],
    message: &[u8],
) -> Result<heapless::Vec<u8, MAX_SIGNATURE>, Ctap2Status> {
    let signing_key = SigningKey::from_slice(private_key).map_err(|_| Ctap2Status::Other)?;
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

    // Honor the client's algorithm preference order; fall back to ES256 when
    // no list was sent (pre-EdDSA clients and older requests).
    let alg = if request.algs.is_empty() {
        COSE_ALG_ES256
    } else {
        request
            .algs
            .iter()
            .copied()
            .find(|alg| *alg == COSE_ALG_ES256 || *alg == COSE_ALG_EDDSA)
            .ok_or(Ctap2Status::UnsupportedAlgorithm)?
    };

    let mut credential_id: heapless::Vec<u8, 32> = heapless::Vec::new();
    let mut id_bytes = [0u8; CREDENTIAL_ID_LEN];
    rng.fill_bytes(&mut id_bytes);
    credential_id
        .extend_from_slice(&id_bytes)
        .map_err(|_| Ctap2Status::Other)?;

    // Encoded COSE public key plus the private key material (both 32 bytes
    // for P-256 scalars and Ed25519 seeds).
    let mut cose_buf = [0u8; 128];
    let (private_key, cose_len) = if alg == COSE_ALG_EDDSA {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = EdSigningKey::from_bytes(&seed);
        let cose_key = OkpPublicKey {
            crv: COSE_CURVE_ED25519,
            x: signing_key.verifying_key().to_bytes(),
        };
        let len = codec::encode_into(&cose_key, &mut cose_buf).map_err(|_| Ctap2Status::Other)?;
        (seed, len)
    } else {
        let signing_key = generate_signing_key(rng)?;
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().ok_or(Ctap2Status::Other)?);
        y.copy_from_slice(point.y().ok_or(Ctap2Status::Other)?);
        let cose_key = Ec2PublicKey {
            crv: COSE_CURVE_P256,
            x,
            y,
        };
        let len = codec::encode_into(&cose_key, &mut cose_buf).map_err(|_| Ctap2Status::Other)?;
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&signing_key.to_bytes());
        (private_key, len)
    };

    let flags = FLAG_UP | FLAG_AT | if uv_confirmed { FLAG_UV } else { 0 };
    let attested = build_attested_credential_data(&credential_id, &cose_buf[..cose_len])?;
    let auth_data = build_auth_data(request.rp_id.as_str(), flags, 0, Some(&attested))?;
    let signature = sign(&private_key, alg, &auth_data, &request.client_data_hash)?;

    store
        .insert(Credential {
            id: credential_id,
            rp_id: request.rp_id.clone(),
            user_id: request.user_id.clone(),
            private_key,
            algorithm: alg,
            sign_count: 0,
            discoverable: request.rk,
        })
        .map_err(|_| Ctap2Status::LimitExceeded)?;

    Ok(MakeCredentialResponse {
        auth_data,
        signature,
        alg,
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

    let candidates = assertion_candidates(store, request);
    let Some(first) = candidates.first() else {
        return Err(Ctap2Status::NoCredentials);
    };
    let mut response = sign_assertion(
        store,
        first,
        request.rp_id.as_str(),
        &request.client_data_hash,
        uv_confirmed,
    )?;
    response.number_of_credentials = candidates.len() as u32;
    Ok(response)
}

/// The credentials matching an assertion request, in the order the
/// authenticator must return them.
///
/// With an allow list the order follows the list; without one every
/// discoverable credential of the relying party matches.
#[must_use]
pub fn assertion_candidates<S: CredentialStore>(
    store: &S,
    request: &GetAssertionRequest,
) -> heapless::Vec<heapless::Vec<u8, 32>, MAX_CREDENTIALS> {
    let mut candidates: heapless::Vec<heapless::Vec<u8, 32>, MAX_CREDENTIALS> =
        heapless::Vec::new();
    if request.allow_list.is_empty() {
        for credential in store.list() {
            if !credential.discoverable {
                continue;
            }
            if credential.rp_id.as_str() != request.rp_id.as_str() {
                continue;
            }
            let _ = candidates.push(credential.id.clone());
        }
    } else {
        for descriptor in &request.allow_list {
            let Some(credential) = store.get(&descriptor.id) else {
                continue;
            };
            if credential.rp_id.as_str() != request.rp_id.as_str() {
                continue;
            }
            if candidates
                .iter()
                .any(|id| id.as_slice() == descriptor.id.as_slice())
            {
                continue;
            }
            let _ = candidates.push(credential.id.clone());
        }
    }
    candidates
}

/// Sign an assertion for one specific credential.
///
/// The authenticator keeps the request parameters between
/// `authenticatorGetAssertion` and `authenticatorGetNextAssertion`, so the
/// signature covers the same client data hash.
pub fn sign_assertion<S: CredentialStore>(
    store: &mut S,
    credential_id: &[u8],
    rp_id: &str,
    client_data_hash: &[u8; 32],
    uv_confirmed: bool,
) -> Result<GetAssertionResponse, Ctap2Status> {
    let credential = store
        .get(credential_id)
        .ok_or(Ctap2Status::InvalidCredential)?;

    let sign_count = store
        .next_sign_count(&credential.id)
        .ok_or(Ctap2Status::InvalidCredential)?;

    let flags = FLAG_UP | if uv_confirmed { FLAG_UV } else { 0 };
    let auth_data = build_auth_data(rp_id, flags, sign_count, None)?;
    let signature = sign(
        &credential.private_key,
        credential.algorithm,
        &auth_data,
        client_data_hash,
    )?;

    Ok(GetAssertionResponse {
        credential_id: credential.id,
        auth_data,
        signature,
        user_id: credential.user_id,
        number_of_credentials: 1,
    })
}

/// CTAP2 `authenticatorReset`.
///
/// The reset drops every credential, the PIN state and the active PIN/UV
/// auth token: the platform has to fetch a new token.
pub fn reset<S: CredentialStore + crate::pin::PinState>(
    store: &mut S,
    client_pin: &mut crate::pin::ClientPin,
    up_confirmed: bool,
) -> Result<(), Ctap2Status> {
    if !up_confirmed {
        return Err(Ctap2Status::UpRequired);
    }
    store.clear();
    store.clear_pin_state().map_err(|_| Ctap2Status::Other)?;
    client_pin.invalidate_token();
    Ok(())
}

/// `authenticatorCredentialManagement` subcommand: `getCredsMetadata`.
pub const CRED_MGMT_GET_METADATA: u8 = 0x01;
/// `authenticatorCredentialManagement` subcommand: `enumerateRPsBegin`.
pub const CRED_MGMT_ENUMERATE_RPS: u8 = 0x02;
/// `authenticatorCredentialManagement` subcommand: `enumerateRPsGetNextRP`.
pub const CRED_MGMT_ENUMERATE_RPS_NEXT: u8 = 0x03;
/// `authenticatorCredentialManagement` subcommand: `enumerateCredentialsBegin`.
pub const CRED_MGMT_ENUMERATE_CREDENTIALS: u8 = 0x04;
/// `authenticatorCredentialManagement` subcommand:
/// `enumerateCredentialsGetNextCredential`.
pub const CRED_MGMT_ENUMERATE_CREDENTIALS_NEXT: u8 = 0x05;
/// `authenticatorCredentialManagement` subcommand: `deleteCredential`.
pub const CRED_MGMT_DELETE: u8 = 0x06;

/// A parsed `authenticatorCredentialManagement` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialManagementRequest {
    /// Subcommand.
    pub sub_command: u8,
    /// Target credential id, when applicable.
    pub credential_id: Option<heapless::Vec<u8, 32>>,
    /// RP ID hash, for the enumeration subcommands.
    pub rp_id_hash: Option<[u8; 32]>,
    /// PIN/UV auth protocol version chosen by the client.
    pub pin_uv_auth_protocol: Option<u8>,
    /// PIN/UV auth parameter.
    pub pin_uv_auth_param: Option<heapless::Vec<u8, 64>>,
    /// Canonical encoding of the subcommand parameters.
    ///
    /// The platform authenticates `subCommand || subCommandParams`, so the
    /// exact bytes matter; the parameters are re-encoded in the canonical
    /// CBOR form the platform is required to use.
    pub sub_command_params: heapless::Vec<u8, 96>,
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
            rp_id_hash: None,
            pin_uv_auth_protocol: None,
            pin_uv_auth_param: None,
            sub_command_params: heapless::Vec::new(),
        };
        for _ in 0..length {
            match decoder.u8().map_err(|_| Ctap2Status::InvalidCbor)? {
                0x01 => request.sub_command = decoder.u8().map_err(|_| Ctap2Status::InvalidCbor)?,
                0x02 => {
                    // The subcommand parameters are a map; the legacy
                    // layout carried the credential id as a byte string.
                    if decoder.datatype().map_err(|_| Ctap2Status::InvalidCbor)?
                        == minicbor::data::Type::Bytes
                    {
                        let bytes = decoder.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                        request.credential_id = Some(
                            heapless::Vec::from_slice(bytes)
                                .map_err(|_| Ctap2Status::LimitExceeded)?,
                        );
                    } else {
                        request.parse_sub_command_params(params, &mut decoder)?;
                    }
                }
                0x03 => {
                    request.pin_uv_auth_protocol =
                        Some(decoder.u8().map_err(|_| Ctap2Status::InvalidCbor)?)
                }
                0x04 => {
                    let bytes = decoder.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                    request.pin_uv_auth_param = Some(
                        heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?,
                    );
                }
                _ => decoder.skip().map_err(|_| Ctap2Status::InvalidCbor)?,
            }
        }
        Ok(request)
    }

    /// Parse the `subCommandParams` map and keep its raw bytes.
    ///
    /// The platform authenticates `subCommand || subCommandParams`, so the
    /// exact bytes the client sent are kept verbatim.
    fn parse_sub_command_params(
        &mut self,
        params: &[u8],
        decoder: &mut minicbor::Decoder<'_>,
    ) -> Result<(), Ctap2Status> {
        let start = decoder.position();
        let entries = decoder
            .map()
            .map_err(|_| Ctap2Status::InvalidCbor)?
            .ok_or(Ctap2Status::InvalidCbor)?;

        let mut rp_id_hash = None;
        let mut credential_id = None;
        for _ in 0..entries {
            match decoder.u8().map_err(|_| Ctap2Status::InvalidCbor)? {
                0x01 => {
                    let bytes = decoder.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                    if bytes.len() != 32 {
                        return Err(Ctap2Status::InvalidParameter);
                    }
                    let mut hash = [0u8; 32];
                    hash.copy_from_slice(bytes);
                    rp_id_hash = Some(hash);
                }
                0x02 => {
                    // `credentialID` is a PublicKeyCredentialDescriptor map
                    // whose `id` member carries the credential id.
                    credential_id = Some(decode_credential_descriptor(decoder)?);
                }
                _ => decoder.skip().map_err(|_| Ctap2Status::InvalidCbor)?,
            }
        }
        let end = decoder.position();
        self.rp_id_hash = rp_id_hash;
        self.credential_id = credential_id;
        self.sub_command_params = heapless::Vec::from_slice(&params[start..end])
            .map_err(|_| Ctap2Status::LimitExceeded)?;
        Ok(())
    }
}

/// Decode a `PublicKeyCredentialDescriptor` map and return the credential id.
///
/// The descriptor is a WebAuthn structure, so its members use text keys
/// (`id`, `type`); the numeric form (`{2: id}`) is accepted as well.
fn decode_credential_descriptor(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<heapless::Vec<u8, 32>, Ctap2Status> {
    let entries = decoder
        .map()
        .map_err(|_| Ctap2Status::InvalidCbor)?
        .ok_or(Ctap2Status::InvalidCbor)?;
    let mut id = None;
    for _ in 0..entries {
        let text_key = decoder.datatype().map_err(|_| Ctap2Status::InvalidCbor)?
            == minicbor::data::Type::String;
        if text_key {
            let key = decoder.str().map_err(|_| Ctap2Status::InvalidCbor)?;
            if key == "id" {
                let bytes = decoder.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                id =
                    Some(heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?);
            } else {
                decoder.skip().map_err(|_| Ctap2Status::InvalidCbor)?;
            }
        } else {
            let key = decoder.u8().map_err(|_| Ctap2Status::InvalidCbor)?;
            if key == 0x02 {
                let bytes = decoder.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                id =
                    Some(heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?);
            } else {
                decoder.skip().map_err(|_| Ctap2Status::InvalidCbor)?;
            }
        }
    }
    id.ok_or(Ctap2Status::MissingParameter)
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

/// A relying party that owns discoverable credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpEntry {
    /// Relying party identifier.
    pub rp_id: FixedString<64>,
    /// SHA-256 hash of the relying party identifier.
    pub rp_id_hash: [u8; 32],
}

/// `enumerateRPsBegin` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumerateRpsResponse {
    /// Relying party that owns the credentials.
    pub rp: RpEntry,
    /// Total number of relying parties.
    pub total_rps: u32,
}

impl<C> minicbor::Encode<C> for EnumerateRpsResponse {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(3)?;
        e.u8(3)?;
        e.map(1)?;
        e.str("id")?;
        e.str(self.rp.rp_id.as_str())?;
        e.u8(4)?;
        e.bytes(&self.rp.rp_id_hash)?;
        e.u8(5)?;
        e.u32(self.total_rps)?;
        Ok(())
    }
}

/// `enumerateCredentialsBegin` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumerateCredentialsResponse {
    /// User handle of the credential.
    pub user_id: heapless::Vec<u8, 64>,
    /// Credential id.
    pub credential_id: heapless::Vec<u8, 32>,
    /// COSE public key of the credential.
    pub public_key: heapless::Vec<u8, 128>,
    /// Total number of credentials of the relying party.
    pub total_credentials: u32,
}

impl<C> minicbor::Encode<C> for EnumerateCredentialsResponse {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(4)?;
        e.u8(6)?;
        e.map(1)?;
        e.str("id")?;
        e.bytes(&self.user_id)?;
        e.u8(7)?;
        e.map(2)?;
        e.str("type")?;
        e.str("public-key")?;
        e.str("id")?;
        e.bytes(&self.credential_id)?;
        e.u8(8)?;
        e.bytes(&self.public_key)?;
        e.u8(9)?;
        e.u32(self.total_credentials)?;
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

/// SHA-256 hash of a relying party identifier.
#[must_use]
pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(rp_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// List the relying parties that own discoverable credentials.
///
/// The list is deduplicated and keeps the order in which the relying parties
/// were first seen.
#[must_use]
pub fn list_rps<S: CredentialStore>(store: &S) -> heapless::Vec<RpEntry, MAX_CREDENTIALS> {
    let mut rps: heapless::Vec<RpEntry, MAX_CREDENTIALS> = heapless::Vec::new();
    for credential in store.list() {
        if !credential.discoverable {
            continue;
        }
        if rps
            .iter()
            .any(|entry| entry.rp_id.as_str() == credential.rp_id.as_str())
        {
            continue;
        }
        let hash = rp_id_hash(credential.rp_id.as_str());
        let _ = rps.push(RpEntry {
            rp_id: credential.rp_id.clone(),
            rp_id_hash: hash,
        });
    }
    rps
}

/// List the discoverable credentials of a relying party.
#[must_use]
pub fn list_credentials<S: CredentialStore>(
    store: &S,
    hash: &[u8; 32],
) -> heapless::Vec<heapless::Vec<u8, 32>, MAX_CREDENTIALS> {
    let mut ids: heapless::Vec<heapless::Vec<u8, 32>, MAX_CREDENTIALS> = heapless::Vec::new();
    for credential in store.list() {
        if !credential.discoverable {
            continue;
        }
        if &rp_id_hash(credential.rp_id.as_str()) != hash {
            continue;
        }
        let _ = ids.push(credential.id.clone());
    }
    ids
}

/// Rebuild the COSE public key of a stored credential.
#[must_use]
pub fn cose_public_key(credential: &Credential) -> Option<heapless::Vec<u8, 128>> {
    let mut buf = [0u8; 128];
    let length = if credential.algorithm == COSE_ALG_EDDSA {
        let signing_key = EdSigningKey::from_bytes(&credential.private_key);
        let key = OkpPublicKey {
            crv: COSE_CURVE_ED25519,
            x: signing_key.verifying_key().to_bytes(),
        };
        codec::encode_into(&key, &mut buf).ok()?
    } else {
        let signing_key = SigningKey::from_slice(&credential.private_key).ok()?;
        let point = signing_key.verifying_key().to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x()?);
        y.copy_from_slice(point.y()?);
        let key = Ec2PublicKey {
            crv: COSE_CURVE_P256,
            x,
            y,
        };
        codec::encode_into(&key, &mut buf).ok()?
    };
    heapless::Vec::from_slice(&buf[..length]).ok()
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

/// Whether a relying party is within the scope of the active PIN/UV token.
///
/// `bound_rp_id` is the relying party the token is bound to, if any. A token
/// issued without a permissions RP ID serves every relying party.
#[must_use]
pub fn rp_in_scope(rp_id: &str, bound_rp_id: Option<&str>) -> bool {
    match bound_rp_id {
        None => true,
        Some(bound) => bound == rp_id,
    }
}

/// Delete a credential, honouring the relying-party scope of the active
/// PIN/UV token.
///
/// The token is verified against the message the platform authenticates and
/// must carry the `cm` permission. When it is bound to a relying party, the
/// credential must belong to that relying party: a credential of another
/// relying party is refused and preserved.
pub fn delete_credential_scoped<S: CredentialStore + crate::pin::PinState>(
    store: &mut S,
    client_pin: &mut crate::pin::ClientPin,
    param: Option<&[u8]>,
    message: &[u8],
    credential_id: &[u8],
) -> Result<(), Ctap2Status> {
    // The relying party that owns the credential comes from the store, not
    // from the request: it is what the scope of a bound token is checked
    // against.
    let credential = store.get(credential_id);
    let owner = credential
        .as_ref()
        .map(|credential| credential.rp_id.as_str());
    client_pin.authorize(
        store,
        crate::pin::TokenRequest {
            param,
            message,
            uv_requested: false,
            operation: crate::pin::TokenOperation::CredentialManagement {
                scope: crate::pin::ManagementScope::CredentialRelyingParty(owner),
            },
        },
    )?;
    let Some(credential) = credential else {
        return Err(Ctap2Status::NoCredentials);
    };
    store.remove(&credential.id).map_err(|_| Ctap2Status::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::CredentialDescriptor;
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
            algs: heapless::Vec::new(),
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
        let signing_key = SigningKey::from_slice(private_key).unwrap();
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

    /// Create a resident credential and return its id.
    fn resident_credential(
        store: &mut MemoryCredentialStore,
        rng: &mut TestRng,
        rp_id: &str,
        user_id: &[u8],
    ) -> heapless::Vec<u8, 32> {
        let mut request = make_request(rp_id, user_id);
        request.rk = true;
        let response = make_credential(store, rng, &request, true, false).unwrap();
        credential_id_from_auth_data(&response.auth_data)
    }

    /// Build an allow-list descriptor for a credential id.
    fn descriptor(id: &heapless::Vec<u8, 32>) -> CredentialDescriptor {
        CredentialDescriptor {
            id: heapless::Vec::from_slice(id).unwrap(),
        }
    }

    #[test]
    fn assertion_candidates_follow_the_allow_list() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(41);
        let first = resident_credential(&mut store, &mut rng, "example.com", &[1]);
        let second = resident_credential(&mut store, &mut rng, "example.com", &[2]);
        let other = resident_credential(&mut store, &mut rng, "other.test", &[3]);

        // Without an allow list every discoverable credential of the RP
        // matches.
        let request = assertion_request("example.com");
        let candidates = assertion_candidates(&store, &request);
        assert_eq!(candidates.len(), 2);

        // With an allow list the order follows the list.
        let mut request = assertion_request("example.com");
        request.allow_list.push(descriptor(&second)).unwrap();
        request.allow_list.push(descriptor(&first)).unwrap();
        let candidates = assertion_candidates(&store, &request);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], second);
        assert_eq!(candidates[1], first);

        // A credential of another relying party never matches.
        let mut request = assertion_request("example.com");
        request.allow_list.push(descriptor(&second)).unwrap();
        request.allow_list.push(descriptor(&other)).unwrap();
        let candidates = assertion_candidates(&store, &request);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], second);
    }

    #[test]
    fn assertion_reports_the_number_of_matching_credentials() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(42);
        resident_credential(&mut store, &mut rng, "example.com", &[1]);
        resident_credential(&mut store, &mut rng, "example.com", &[2]);

        let request = assertion_request("example.com");
        let response = get_assertion(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(response.number_of_credentials, 2);

        // The remaining credential is served by `authenticatorGetNextAssertion`.
        let candidates = assertion_candidates(&store, &request);
        let next = sign_assertion(
            &mut store,
            &candidates[1],
            request.rp_id.as_str(),
            &request.client_data_hash,
            false,
        )
        .unwrap();
        assert_ne!(next.credential_id, response.credential_id);
        let credential = store.get(&next.credential_id).unwrap();
        assert!(verify(
            &credential.private_key,
            &next.auth_data,
            &request.client_data_hash,
            &next.signature
        ));
    }

    #[test]
    fn assertion_without_matching_credentials_is_rejected() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(43);
        let request = assertion_request("example.com");
        assert_eq!(
            get_assertion(&mut store, &mut rng, &request, true, false),
            Err(Ctap2Status::NoCredentials)
        );
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

    fn make_request_with_algs(rp_id: &str, user_id: &[u8], algs: &[i64]) -> MakeCredentialRequest {
        let mut request = make_request(rp_id, user_id);
        request.algs.extend_from_slice(algs).unwrap();
        request
    }

    /// Build a `authenticatorCredentialManagement` request payload.
    ///
    /// The subcommand parameters are spliced in as raw CBOR, so the test can
    /// use exactly the bytes the platform would send.
    fn cred_mgmt_payload(
        sub_command: u8,
        sub_command_params: Option<&[u8]>,
        pin_uv_auth_param: Option<&[u8]>,
    ) -> heapless::Vec<u8, 128> {
        let mut out = heapless::Vec::new();
        let entries =
            1 + u8::from(sub_command_params.is_some()) + u8::from(pin_uv_auth_param.is_some());
        out.push(0xA0 | entries).unwrap();
        out.push(0x01).unwrap();
        out.push(sub_command).unwrap();
        if let Some(params) = sub_command_params {
            out.push(0x02).unwrap();
            out.extend_from_slice(params).unwrap();
        }
        if let Some(param) = pin_uv_auth_param {
            out.push(0x04).unwrap();
            out.push(0x40 | param.len() as u8).unwrap();
            out.extend_from_slice(param).unwrap();
        }
        out
    }

    #[test]
    fn credential_management_request_parses_subcommand_params() {
        // subCommandParams = { 1: rpIDHash }
        let hash = [0x5Au8; 32];
        let mut params = [0u8; 36];
        params[0] = 0xA1;
        params[1] = 0x01;
        params[2] = 0x58;
        params[3] = 0x20;
        params[4..36].copy_from_slice(&hash);

        let payload = cred_mgmt_payload(CRED_MGMT_ENUMERATE_CREDENTIALS, Some(&params), None);
        let request = CredentialManagementRequest::parse(&payload).unwrap();
        assert_eq!(request.sub_command, CRED_MGMT_ENUMERATE_CREDENTIALS);
        assert_eq!(request.rp_id_hash, Some(hash));
        assert_eq!(request.credential_id, None);
        // The raw parameters are kept: the platform authenticates them.
        assert_eq!(&request.sub_command_params[..], &params[..]);
    }

    #[test]
    fn credential_management_request_parses_the_credential_descriptor() {
        // subCommandParams = { 2: { "id": h'AB', "type": "public-key" } }
        let params: [u8; 24] = [
            0xA1, 0x02, // map(1) { 2: ...
            0xA2, // map(2)
            0x62, b'i', b'd', // "id"
            0x41, 0xAB, // bytes(1) = AB
            0x64, b't', b'y', b'p', b'e', // "type"
            0x6A, b'p', b'u', b'b', b'l', b'i', b'c', b'-', b'k', b'e', b'y', // "public-key"
        ];

        let payload = cred_mgmt_payload(CRED_MGMT_DELETE, Some(&params), None);
        let request = CredentialManagementRequest::parse(&payload).unwrap();
        assert_eq!(request.sub_command, CRED_MGMT_DELETE);
        assert_eq!(
            request.credential_id,
            Some(heapless::Vec::from_slice(&[0xABu8]).unwrap())
        );
    }

    #[test]
    fn enumeration_lists_relying_parties_and_credentials() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(31);
        let request = make_request("example.com", &[1]);
        make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        let other = make_request("other.test", &[2]);
        make_credential(&mut store, &mut rng, &other, true, false).unwrap();

        let rps = list_rps(&store);
        assert_eq!(rps.len(), 2);
        assert_eq!(rps[0].rp_id.as_str(), "example.com");
        assert_eq!(rps[0].rp_id_hash, rp_id_hash("example.com"));

        let hash = rp_id_hash("example.com");
        let credentials = list_credentials(&store, &hash);
        assert_eq!(credentials.len(), 1);
        assert!(store.get(&credentials[0]).is_some());

        // A hash without credentials yields an empty list.
        assert!(list_credentials(&store, &[0u8; 32]).is_empty());
    }

    #[test]
    fn enumeration_responses_use_the_specified_keys() {
        let response = EnumerateRpsResponse {
            rp: RpEntry {
                rp_id: FixedString::new("example.com").unwrap(),
                rp_id_hash: rp_id_hash("example.com"),
            },
            total_rps: 1,
        };
        let mut buf = [0u8; 128];
        let length = codec::encode_into(&response, &mut buf).unwrap();
        let mut decoder = minicbor::Decoder::new(&buf[..length]);
        assert_eq!(decoder.map().unwrap(), Some(3));
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.str().unwrap(), "example.com");
        assert_eq!(decoder.u8().unwrap(), 4);
        assert_eq!(decoder.bytes().unwrap().len(), 32);
        assert_eq!(decoder.u8().unwrap(), 5);
        assert_eq!(decoder.u32().unwrap(), 1);

        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(32);
        let request = make_request("example.com", &[7]);
        make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        let credential = store.list()[0].clone();
        let response = EnumerateCredentialsResponse {
            user_id: credential.user_id.clone(),
            credential_id: credential.id.clone(),
            public_key: cose_public_key(&credential).unwrap(),
            total_credentials: 1,
        };
        let mut buf = [0u8; 256];
        let length = codec::encode_into(&response, &mut buf).unwrap();
        let mut decoder = minicbor::Decoder::new(&buf[..length]);
        assert_eq!(decoder.map().unwrap(), Some(4));
        assert_eq!(decoder.u8().unwrap(), 6);
        assert_eq!(decoder.map().unwrap(), Some(1));
        assert_eq!(decoder.str().unwrap(), "id");
        assert_eq!(decoder.bytes().unwrap(), &[7u8][..]);
        assert_eq!(decoder.u8().unwrap(), 7);
        assert_eq!(decoder.map().unwrap(), Some(2));
        assert_eq!(decoder.str().unwrap(), "type");
        assert_eq!(decoder.str().unwrap(), "public-key");
        assert_eq!(decoder.str().unwrap(), "id");
        assert!(!decoder.bytes().unwrap().is_empty());
        assert_eq!(decoder.u8().unwrap(), 8);
        assert!(!decoder.bytes().unwrap().is_empty());
        assert_eq!(decoder.u8().unwrap(), 9);
        assert_eq!(decoder.u32().unwrap(), 1);
    }

    fn verify_eddsa(
        seed: &[u8; 32],
        auth_data: &[u8],
        client_data_hash: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        use ed25519_dalek::Verifier as _;
        let verifying_key = EdSigningKey::from_bytes(seed).verifying_key();
        let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
            return false;
        };
        let mut message = heapless::Vec::<u8, MAX_SIGNING_INPUT>::new();
        if message.extend_from_slice(auth_data).is_err()
            || message.extend_from_slice(client_data_hash).is_err()
        {
            return false;
        }
        verifying_key.verify(&message, &signature).is_ok()
    }

    #[test]
    fn make_credential_with_eddsa_creates_verifiable_credential() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(11);
        let request = make_request_with_algs("example.com", &[9], &[COSE_ALG_EDDSA]);
        let response = make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(response.alg, COSE_ALG_EDDSA);
        assert_eq!(response.signature.len(), 64);

        let credential = store.find_by_rp("example.com").unwrap();
        assert_eq!(credential.algorithm, COSE_ALG_EDDSA);

        // The attested credential data carries an OKP key; decode and check it.
        let cose_bytes = &response.auth_data[71..];
        let cose: OkpPublicKey = crate::codec::decode_from(cose_bytes).unwrap();
        assert_eq!(cose.crv, COSE_CURVE_ED25519);

        assert!(verify_eddsa(
            &credential.private_key,
            &response.auth_data,
            &request.client_data_hash,
            &response.signature,
        ));
    }

    #[test]
    fn make_credential_with_unsupported_algorithm_is_rejected() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(12);
        // RS256 and RSAES-OAEP are not implemented.
        let request = make_request_with_algs("example.com", &[9], &[-257, -260]);
        assert_eq!(
            make_credential(&mut store, &mut rng, &request, true, false),
            Err(Ctap2Status::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn make_credential_honors_client_algorithm_preference() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(13);
        let request =
            make_request_with_algs("example.com", &[1], &[COSE_ALG_EDDSA, COSE_ALG_ES256]);
        let response = make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(response.alg, COSE_ALG_EDDSA);

        let request =
            make_request_with_algs("example.org", &[2], &[COSE_ALG_ES256, COSE_ALG_EDDSA]);
        let response = make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(response.alg, COSE_ALG_ES256);
    }

    #[test]
    fn get_assertion_signs_with_eddsa() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(14);
        let request = make_request_with_algs("example.com", &[7], &[COSE_ALG_EDDSA]);
        make_credential(&mut store, &mut rng, &request, true, false).unwrap();

        let request = assertion_request("example.com");
        let assertion = get_assertion(&mut store, &mut rng, &request, true, false).unwrap();
        assert_eq!(assertion.signature.len(), 64);
        let credential = store.get(&assertion.credential_id).unwrap();
        assert!(verify_eddsa(
            &credential.private_key,
            &assertion.auth_data,
            &request.client_data_hash,
            &assertion.signature,
        ));
    }

    #[test]
    fn credential_without_algorithm_defaults_to_es256() {
        // Records sealed before EdDSA support carry no algorithm key.
        let mut buf = [0u8; 256];
        let mut writer = crate::codec::SliceWriter::new(&mut buf);
        {
            let mut e = minicbor::Encoder::new(&mut writer);
            e.map(6).unwrap();
            e.u8(0).unwrap();
            e.bytes(&[9u8; 16]).unwrap();
            e.u8(1).unwrap();
            e.str("example.com").unwrap();
            e.u8(2).unwrap();
            e.bytes(&[7u8; 1]).unwrap();
            e.u8(3).unwrap();
            e.bytes(&[8u8; 32]).unwrap();
            e.u8(4).unwrap();
            e.u32(3).unwrap();
            e.u8(5).unwrap();
            e.bool(true).unwrap();
        }
        let len = writer.len();
        let credential: Credential = crate::codec::decode_from(&buf[..len]).unwrap();
        assert_eq!(credential.algorithm, COSE_ALG_ES256);
        assert_eq!(credential.sign_count, 3);
    }

    #[test]
    fn credential_cbor_round_trips_algorithm() {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(15);
        let request = make_request_with_algs("example.com", &[7], &[COSE_ALG_EDDSA]);
        make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        let credential = store.find_by_rp("example.com").unwrap();

        let mut buf = [0u8; 512];
        let len = crate::codec::encode_into(&credential, &mut buf).unwrap();
        let decoded: Credential = crate::codec::decode_from(&buf[..len]).unwrap();
        assert_eq!(decoded, credential);
        assert_eq!(decoded.algorithm, COSE_ALG_EDDSA);
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
            number_of_credentials: 1,
        };
        let mut buf = [0u8; 256];
        let len = crate::codec::encode_into(&response, &mut buf).unwrap();
        let encoded = &buf[..len];
        let has = |needle: &[u8]| encoded.windows(needle.len()).any(|w| w == needle);
        assert!(has(b"id"));
        assert!(has(b"type"));
        assert!(has(b"public-key"));
    }

    #[test]
    fn delete_credential_is_restricted_to_the_bound_rp() {
        use crate::pin::test_support::{auth_param, issue_token};
        use crate::pin::{ManagementScope, PERMISSION_CM, TokenOperation, TokenRequest};

        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(51);
        let bound = credential_id_from_auth_data(
            &make_credential(
                &mut store,
                &mut rng,
                &make_request("a.test", &[1]),
                true,
                false,
            )
            .unwrap()
            .auth_data,
        );
        let other = credential_id_from_auth_data(
            &make_credential(
                &mut store,
                &mut rng,
                &make_request("b.test", &[2]),
                true,
                false,
            )
            .unwrap()
            .auth_data,
        );

        let mut issued = issue_token(Some(PERMISSION_CM), Some("a.test"));
        let message = [CRED_MGMT_DELETE];
        let param = auth_param(&issued.token, &message);

        // A credential of another relying party is refused and preserved.
        assert_eq!(
            delete_credential_scoped(
                &mut store,
                &mut issued.client_pin,
                Some(&param),
                &message,
                &other,
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
        assert!(store.get(&other).is_some());

        // The credential of the bound relying party is removed.
        assert_eq!(
            delete_credential_scoped(
                &mut store,
                &mut issued.client_pin,
                Some(&param),
                &message,
                &bound,
            ),
            Ok(())
        );
        assert!(store.get(&bound).is_none());

        // The scope of the token is the relying party of the credential, not
        // the one of the request.
        let scope = ManagementScope::CredentialRelyingParty(Some("b.test"));
        assert_eq!(
            issued.client_pin.authorize(
                &store,
                TokenRequest {
                    param: Some(&param),
                    message: &message,
                    uv_requested: false,
                    operation: TokenOperation::CredentialManagement { scope },
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }

    #[test]
    fn a_token_without_rp_binding_deletes_any_credential() {
        use crate::pin::PERMISSION_CM;
        use crate::pin::test_support::{auth_param, issue_token};

        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(52);
        let id = credential_id_from_auth_data(
            &make_credential(
                &mut store,
                &mut rng,
                &make_request("b.test", &[1]),
                true,
                false,
            )
            .unwrap()
            .auth_data,
        );

        let mut issued = issue_token(Some(PERMISSION_CM), None);
        let message = [CRED_MGMT_DELETE];
        let param = auth_param(&issued.token, &message);
        assert_eq!(
            delete_credential_scoped(
                &mut store,
                &mut issued.client_pin,
                Some(&param),
                &message,
                &id,
            ),
            Ok(())
        );
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn reset_invalidates_the_pin_uv_auth_token() {
        use crate::pin::test_support::{auth_param, issue_token};
        use crate::pin::{PERMISSION_CM, PERMISSION_MC, TokenOperation, TokenRequest};

        let mut store = MemoryCredentialStore::new();
        let mut issued = issue_token(Some(PERMISSION_MC | PERMISSION_CM), Some("a.test"));
        let message = [0x7Bu8; 32];
        let param = auth_param(&issued.token, &message);
        let request = TokenRequest {
            param: Some(&param),
            message: &message,
            uv_requested: false,
            operation: TokenOperation::MakeCredential { rp_id: "a.test" },
        };
        assert_eq!(issued.client_pin.authorize(&store, request), Ok(true));

        // The reset drops the token: it cannot authorise anything anymore.
        assert_eq!(reset(&mut store, &mut issued.client_pin, true), Ok(()));
        assert_eq!(issued.client_pin.token_permissions(), 0);
        assert_eq!(issued.client_pin.token_rp_id(), None);
        let request = TokenRequest {
            param: Some(&param),
            message: &message,
            uv_requested: false,
            operation: TokenOperation::MakeCredential { rp_id: "a.test" },
        };
        assert_eq!(
            issued.client_pin.authorize(&store, request),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }
}
