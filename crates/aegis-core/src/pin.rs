//! CTAP2 `clientPIN` protocol (PIN/UV auth protocol version 1).
//!
//! Implements ECDH key agreement on P-256, AES-256-CBC payload encryption and
//! HMAC-SHA-256 authentication, plus the PIN hash and retry accounting. PIN
//! state is provided by a [`PinState`] implementation (in-memory or sealed).
//!
//! The issued `pinUvAuthToken` is scoped: [`ClientPin::authorize`] decides an
//! operation from the HMAC of the message, the permission the operation needs
//! (`mc`, `ga` or `cm`) and the relying party the token is bound to. A token
//! used in an operation that tests user presence loses its permissions
//! ([`ClientPin::close_user_presence_operation`]).

use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use minicbor::Decode;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::authenticator::{Rng, rp_id_hash, rp_in_scope};
use crate::configuration::FixedString;
use crate::ctap2::Ctap2Status;
use crate::error::CoreError;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// A COSE EC2 key used for ECDH key agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ec2KeyAgreement {
    /// X coordinate.
    pub x: [u8; 32],
    /// Y coordinate.
    pub y: [u8; 32],
}

impl<C> minicbor::Encode<C> for Ec2KeyAgreement {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(5)?;
        e.i64(1)?;
        e.i64(2)?; // kty: EC2
        e.i64(3)?;
        e.i64(-25)?; // alg: ECDH-ES + HKDF-256
        e.i64(-1)?;
        e.i64(1)?; // crv: P-256
        e.i64(-2)?;
        e.bytes(&self.x)?;
        e.i64(-3)?;
        e.bytes(&self.y)?;
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Ec2KeyAgreement {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let length = d
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite map"))?;
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        for _ in 0..length {
            match d.i64()? {
                -2 => {
                    let bytes = d.bytes()?;
                    if bytes.len() != 32 {
                        return Err(minicbor::decode::Error::message("bad x"));
                    }
                    x.copy_from_slice(bytes);
                }
                -3 => {
                    let bytes = d.bytes()?;
                    if bytes.len() != 32 {
                        return Err(minicbor::decode::Error::message("bad y"));
                    }
                    y.copy_from_slice(bytes);
                }
                _ => d.skip()?,
            }
        }
        Ok(Self { x, y })
    }
}

/// PIN protocol v1 subcommands.
pub const SUB_GET_RETRIES: u8 = 0x01;
/// `getKeyAgreement`.
pub const SUB_GET_KEY_AGREEMENT: u8 = 0x02;
/// `setPIN`.
pub const SUB_SET_PIN: u8 = 0x03;
/// `changePIN`.
pub const SUB_CHANGE_PIN: u8 = 0x04;
/// `getPINToken`.
pub const SUB_GET_PIN_TOKEN: u8 = 0x05;
/// `getPinUvAuthTokenUsingUvWithPermissions` (CTAP2.1, unsupported here).
pub const SUB_GET_UV_TOKEN_WITH_PERMISSIONS: u8 = 0x06;
/// `getPinUvAuthTokenUsingPinWithPermissions` (CTAP2.1).
pub const SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS: u8 = 0x09;

/// Protocol version implemented here.
pub const PIN_PROTOCOL: u8 = 1;

/// `pinUvAuthToken` permission: `authenticatorMakeCredential`.
pub const PERMISSION_MC: u8 = 0x01;
/// `pinUvAuthToken` permission: `authenticatorGetAssertion`.
pub const PERMISSION_GA: u8 = 0x02;
/// `pinUvAuthToken` permission: `authenticatorCredentialManagement`.
pub const PERMISSION_CM: u8 = 0x04;
/// `pinUvAuthToken` permission: `authenticatorBioEnrollment` (unsupported).
pub const PERMISSION_BE: u8 = 0x08;
/// `pinUvAuthToken` permission: `authenticatorLargeBlobs` (unsupported).
pub const PERMISSION_LBW: u8 = 0x10;
/// `pinUvAuthToken` permission: `authenticatorConfig` (unsupported).
pub const PERMISSION_ACFG: u8 = 0x20;

/// Permissions this authenticator can grant.
pub const SUPPORTED_PERMISSIONS: u8 = PERMISSION_MC | PERMISSION_GA | PERMISSION_CM;

/// Default permissions granted by the superseded `getPinToken` subcommand.
pub const DEFAULT_PERMISSIONS: u8 = PERMISSION_MC | PERMISSION_GA;

/// Maximum length of a relying party identifier.
pub const MAX_RP_ID_LEN: usize = 253;

/// Default retry budget.
pub const DEFAULT_RETRIES: u8 = 8;

/// Read-only PIN state and mutation hooks.
pub trait PinState {
    /// Stored PIN hash, if set.
    fn pin_hash(&self) -> Option<[u8; 32]>;
    /// Remaining retries.
    fn pin_retries(&self) -> u8;
    /// Set the PIN hash.
    fn set_pin_hash(&mut self, hash: [u8; 32]) -> Result<(), CoreError>;
    /// Update the retry count.
    fn set_pin_retries(&mut self, retries: u8) -> Result<(), CoreError>;
    /// Remove the PIN.
    fn clear_pin_state(&mut self) -> Result<(), CoreError>;
}

/// A parsed `authenticatorClientPIN` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPinRequest {
    /// PIN protocol version.
    pub protocol: u8,
    /// Subcommand.
    pub sub_command: u8,
    /// Platform key agreement key.
    pub key_agreement: Option<Ec2KeyAgreement>,
    /// Authentication parameter (HMAC).
    pub pin_uv_auth_param: Option<heapless::Vec<u8, 64>>,
    /// Encrypted new PIN.
    pub new_pin_enc: Option<heapless::Vec<u8, 96>>,
    /// Encrypted PIN hash.
    pub pin_hash_enc: Option<heapless::Vec<u8, 32>>,
    /// Requested `pinUvAuthToken` permissions (CTAP2.1).
    pub permissions: Option<u8>,
    /// Permissions RP ID (CTAP2.1).
    pub rp_id: Option<FixedString<MAX_RP_ID_LEN>>,
}

impl ClientPinRequest {
    /// Parse from CTAP2 CBOR parameters.
    pub fn parse(params: &[u8]) -> Result<Self, Ctap2Status> {
        let mut d = minicbor::Decoder::new(params);
        let length = d
            .map()
            .map_err(|_| Ctap2Status::InvalidCbor)?
            .ok_or(Ctap2Status::InvalidCbor)?;

        let mut request = ClientPinRequest {
            protocol: 1,
            sub_command: 0,
            key_agreement: None,
            pin_uv_auth_param: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };

        for _ in 0..length {
            match d.u8().map_err(|_| Ctap2Status::InvalidCbor)? {
                0x01 => request.protocol = d.u8().map_err(|_| Ctap2Status::InvalidCbor)?,
                0x02 => request.sub_command = d.u8().map_err(|_| Ctap2Status::InvalidCbor)?,
                0x03 => {
                    request.key_agreement = Some(
                        Ec2KeyAgreement::decode(&mut d, &mut ())
                            .map_err(|_| Ctap2Status::InvalidCbor)?,
                    )
                }
                0x04 => {
                    let bytes = d.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                    request.pin_uv_auth_param = Some(
                        heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?,
                    )
                }
                0x05 => {
                    let bytes = d.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                    request.new_pin_enc = Some(
                        heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?,
                    )
                }
                0x06 => {
                    let bytes = d.bytes().map_err(|_| Ctap2Status::InvalidCbor)?;
                    request.pin_hash_enc = Some(
                        heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?,
                    )
                }
                0x09 => request.permissions = Some(d.u8().map_err(|_| Ctap2Status::InvalidCbor)?),
                0x0A => {
                    let text = d.str().map_err(|_| Ctap2Status::InvalidCbor)?;
                    request.rp_id =
                        Some(FixedString::new(text).map_err(|_| Ctap2Status::InvalidParameter)?)
                }
                _ => d.skip().map_err(|_| Ctap2Status::InvalidCbor)?,
            }
        }

        if request.protocol != PIN_PROTOCOL {
            return Err(Ctap2Status::InvalidParameter);
        }
        Ok(request)
    }
}

/// `getRetries` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetRetriesResponse {
    /// Remaining retries.
    pub retries: u8,
}

impl<C> minicbor::Encode<C> for GetRetriesResponse {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(1)?;
        e.u8(3)?;
        e.u8(self.retries)?;
        Ok(())
    }
}

/// `getKeyAgreement` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAgreementResponse {
    /// Authenticator key agreement key.
    pub key: Ec2KeyAgreement,
}

impl<C> minicbor::Encode<C> for KeyAgreementResponse {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(1)?;
        e.u8(1)?;
        self.key.encode(e, ctx)?;
        Ok(())
    }
}

/// `getPINToken` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinTokenResponse {
    /// Encrypted PIN token.
    pub token: heapless::Vec<u8, 48>,
}

impl<C> minicbor::Encode<C> for PinTokenResponse {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(1)?;
        e.u8(2)?;
        e.bytes(&self.token)?;
        Ok(())
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Compare the prefix of `expected` with `param`.
///
/// PIN/UV auth protocol 1 truncates the HMAC to 16 bytes; the full 32-byte
/// form is also accepted. Shorter prefixes are rejected: they would reduce
/// the authentication strength to a few bits.
fn ct_eq_prefix(expected: &[u8; 32], param: &[u8]) -> bool {
    if param.len() != 16 && param.len() != 32 {
        return false;
    }
    ct_eq(&expected[..param.len()], param)
}

/// Compute the CTAP PIN hash: SHA-256 of the PIN zero-padded to 64 bytes.
#[must_use]
pub fn pin_hash(pin: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    let length = pin.len().min(64);
    padded[..length].copy_from_slice(&pin[..length]);
    let digest = Sha256::digest(padded);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

fn aes_cbc_encrypt(
    shared: &[u8; 32],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Ctap2Status> {
    if plaintext.is_empty() || plaintext.len() % 16 != 0 || out.len() < plaintext.len() {
        return Err(Ctap2Status::InvalidLength);
    }
    out[..plaintext.len()].copy_from_slice(plaintext);
    let cipher =
        Aes256CbcEnc::new_from_slices(shared, &shared[..16]).map_err(|_| Ctap2Status::Other)?;
    let encrypted = cipher
        .encrypt_padded::<NoPadding>(&mut out[..plaintext.len()], plaintext.len())
        .map_err(|_| Ctap2Status::Other)?;
    Ok(encrypted.len())
}

fn aes_cbc_decrypt(
    shared: &[u8; 32],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, Ctap2Status> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 || out.len() < ciphertext.len() {
        return Err(Ctap2Status::InvalidLength);
    }
    out[..ciphertext.len()].copy_from_slice(ciphertext);
    let cipher =
        Aes256CbcDec::new_from_slices(shared, &shared[..16]).map_err(|_| Ctap2Status::Other)?;
    let decrypted = cipher
        .decrypt_padded::<NoPadding>(&mut out[..ciphertext.len()])
        .map_err(|_| Ctap2Status::Other)?;
    Ok(decrypted.len())
}

fn generate_secret_key<R: Rng>(rng: &mut R) -> Result<SecretKey, Ctap2Status> {
    for _ in 0..16 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            return Ok(key);
        }
    }
    Err(Ctap2Status::Other)
}

fn shared_secret(private: &[u8; 32], platform: &Ec2KeyAgreement) -> Result<[u8; 32], Ctap2Status> {
    let secret = SecretKey::from_slice(private).map_err(|_| Ctap2Status::Other)?;
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&platform.x);
    sec1[33..65].copy_from_slice(&platform.y);
    let public = PublicKey::from_sec1_bytes(&sec1).map_err(|_| Ctap2Status::InvalidParameter)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let out: [u8; 32] = (*shared.raw_secret_bytes()).into();
    Ok(out)
}

/// The relying-party scope of a credential-management subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementScope<'a> {
    /// The device as a whole.
    ///
    /// `getCredsMetadata` and `enumerateRPsBegin` describe every relying
    /// party of the device, so the token must not be bound to one.
    Device,
    /// The credentials of a single relying party.
    ///
    /// `enumerateCredentialsBegin` sends the hash of the relying party
    /// identifier it wants to enumerate.
    RelyingPartyHash(&'a [u8; 32]),
    /// A single credential.
    ///
    /// `deleteCredential` names the credential; the relying party that owns
    /// it comes from the credential store, not from the request.
    CredentialRelyingParty(Option<&'a str>),
}

/// The operation a PIN/UV auth token must authorise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenOperation<'a> {
    /// `authenticatorMakeCredential`: needs the `mc` permission.
    MakeCredential {
        /// The relying party of the request.
        rp_id: &'a str,
    },
    /// `authenticatorGetAssertion`: needs the `ga` permission.
    GetAssertion {
        /// The relying party of the request.
        rp_id: &'a str,
    },
    /// `authenticatorCredentialManagement`: needs the `cm` permission.
    CredentialManagement {
        /// The relying-party scope of the subcommand.
        scope: ManagementScope<'a>,
    },
}

/// A request to authorise an operation with the active PIN/UV auth token.
#[derive(Debug, Clone, Copy)]
pub struct TokenRequest<'a> {
    /// The `pinUvAuthParam` sent by the platform, when present.
    pub param: Option<&'a [u8]>,
    /// The message the platform authenticates.
    pub message: &'a [u8],
    /// Whether the platform asked for user verification.
    pub uv_requested: bool,
    /// The operation to authorise.
    pub operation: TokenOperation<'a>,
}

/// Stateful `clientPIN` handler.
#[derive(Default)]
pub struct ClientPin {
    agreement_private: Option<[u8; 32]>,
    pin_uv_auth_token: Option<[u8; 32]>,
    /// Permissions bound to the active token.
    pin_uv_auth_permissions: u8,
    /// Permissions RP ID bound to the active token.
    pin_uv_auth_rp_id: Option<FixedString<MAX_RP_ID_LEN>>,
}

impl ClientPin {
    /// Create a handler with no key agreement established.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            agreement_private: None,
            pin_uv_auth_token: None,
            pin_uv_auth_permissions: 0,
            pin_uv_auth_rp_id: None,
        }
    }

    /// Verify a `pinUvAuthParam` against the active PIN/UV auth token.
    ///
    /// `message` is the `clientDataHash` for `makeCredential`/`getAssertion`.
    /// Only the spec lengths are accepted: 32 bytes (full HMAC) or 16 bytes
    /// (truncated form used by `makeCredential`/`getAssertion` under protocol
    /// 1). Shorter prefixes would reduce security to a few bits and allow
    /// online brute force, so they are rejected.
    #[must_use]
    pub fn verify_pin_uv_auth_param(&self, param: &[u8], message: &[u8]) -> bool {
        let Some(token) = self.pin_uv_auth_token else {
            return false;
        };
        if param.len() != 16 && param.len() != 32 {
            return false;
        }
        let expected = hmac_sha256(&token, message);
        ct_eq(&expected[..param.len()], param)
    }

    /// Authorise an operation with the active PIN/UV auth token.
    ///
    /// The decision combines the three checks the CTAP2.1 requires: the HMAC
    /// of the message, the permission the operation needs and the
    /// relying-party scope of the token (§6.1.2, §6.2.2, §6.8.2-§6.8.5).
    ///
    /// * `Ok(true)`: the token authorises the operation.
    /// * `Ok(false)`: no token is needed — the operation runs on user
    ///   presence alone (no PIN configured and no user verification asked).
    /// * `Err(Ctap2Status::PinRequired)`: a token is required and the
    ///   platform sent no `pinUvAuthParam`.
    /// * `Err(Ctap2Status::PinAuthInvalid)`: the token is absent, does not
    ///   carry the required permission, is bound to another relying party or
    ///   does not authenticate the message.
    ///
    /// A token issued without a permissions RP ID is bound to the relying
    /// party of its first use for `mc` and `ga` (§6.5.5.7); a `cm` token
    /// without a permissions RP ID stays unbound and drives the whole
    /// device.
    pub fn authorize<S: PinState>(
        &mut self,
        state: &S,
        request: TokenRequest<'_>,
    ) -> Result<bool, Ctap2Status> {
        let permission = match request.operation {
            TokenOperation::MakeCredential { .. } => PERMISSION_MC,
            TokenOperation::GetAssertion { .. } => PERMISSION_GA,
            TokenOperation::CredentialManagement { .. } => PERMISSION_CM,
        };

        let Some(param) = request.param else {
            // Credential management always needs a token.
            if permission == PERMISSION_CM {
                return Err(Ctap2Status::PinRequired);
            }
            // `makeCredential` and `getAssertion` need a token as soon as a
            // PIN is configured or the platform asks for user verification.
            if request.uv_requested || state.pin_hash().is_some() {
                return Err(Ctap2Status::PinRequired);
            }
            return Ok(false);
        };

        if self.pin_uv_auth_token.is_none() {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        if self.pin_uv_auth_permissions & permission == 0 {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        if !self.verify_pin_uv_auth_param(param, request.message) {
            return Err(Ctap2Status::PinAuthInvalid);
        }

        match request.operation {
            TokenOperation::MakeCredential { rp_id } | TokenOperation::GetAssertion { rp_id } => {
                self.bind_rp_id(rp_id)?;
            }
            TokenOperation::CredentialManagement { scope } => {
                self.check_management_scope(scope)?;
            }
        }
        Ok(true)
    }

    /// Bind the token to a relying party, or check the existing binding.
    ///
    /// §6.5.5.7: a token issued without a permissions RP ID gets one on the
    /// first use with a relying party (`mc` and `ga` only).
    fn bind_rp_id(&mut self, rp_id: &str) -> Result<(), Ctap2Status> {
        if let Some(bound) = &self.pin_uv_auth_rp_id {
            if bound.as_str() != rp_id {
                return Err(Ctap2Status::PinAuthInvalid);
            }
            return Ok(());
        }
        let bound = FixedString::new(rp_id).map_err(|_| Ctap2Status::InvalidParameter)?;
        self.pin_uv_auth_rp_id = Some(bound);
        Ok(())
    }

    /// Check the relying-party scope of a credential-management subcommand.
    ///
    /// §6.8.2/§6.8.3: the global subcommands need a token that is not bound
    /// to a relying party. §6.8.4/§6.8.5: the scoped ones accept a token
    /// bound to another relying party only when the request stays inside the
    /// bound relying party.
    fn check_management_scope(&self, scope: ManagementScope<'_>) -> Result<(), Ctap2Status> {
        match scope {
            ManagementScope::Device => {
                if self.pin_uv_auth_rp_id.is_some() {
                    return Err(Ctap2Status::PinAuthInvalid);
                }
            }
            ManagementScope::RelyingPartyHash(hash) => {
                if let Some(bound) = &self.pin_uv_auth_rp_id {
                    if &rp_id_hash(bound.as_str()) != hash {
                        return Err(Ctap2Status::PinAuthInvalid);
                    }
                }
            }
            ManagementScope::CredentialRelyingParty(rp_id) => {
                let Some(rp_id) = rp_id else {
                    // The credential does not exist: a bound token cannot
                    // establish the scope of the deletion.
                    if self.pin_uv_auth_rp_id.is_some() {
                        return Err(Ctap2Status::PinAuthInvalid);
                    }
                    return Ok(());
                };
                if !rp_in_scope(rp_id, self.token_rp_id()) {
                    return Err(Ctap2Status::PinAuthInvalid);
                }
            }
        }
        Ok(())
    }

    /// Close an operation that tested user presence.
    ///
    /// §6.5.5.7: a token used in an operation that tests user presence is
    /// updated to remove every permission but `lbw`, which this
    /// authenticator does not support — the token becomes permission-less.
    ///
    /// The reduction only happens when the token was used and the operation
    /// succeeded. A failed operation (no credential, excluded credential, no
    /// user presence) keeps the permissions, so the platform can retry.
    pub fn close_user_presence_operation(&mut self, token_used: bool, succeeded: bool) {
        if token_used && succeeded {
            self.pin_uv_auth_permissions = 0;
            self.pin_uv_auth_rp_id = None;
        }
    }

    /// Invalidate the active PIN/UV auth token.
    ///
    /// The token, its permissions and its permissions RP ID are dropped: the
    /// platform has to fetch a new one.
    pub fn invalidate_token(&mut self) {
        self.pin_uv_auth_token = None;
        self.pin_uv_auth_permissions = 0;
        self.pin_uv_auth_rp_id = None;
    }

    /// Permissions granted by the active PIN/UV auth token.
    ///
    /// The superseded `getPinToken` subcommand grants `mc` and `ga`.
    #[must_use]
    pub fn token_permissions(&self) -> u8 {
        self.pin_uv_auth_permissions
    }

    /// Relying party bound to the active PIN/UV auth token, if any.
    ///
    /// A token issued without a permissions RP ID is bound to the relying
    /// party of its first use for `mc` and `ga` (§6.5.5.7).
    #[must_use]
    pub fn token_rp_id(&self) -> Option<&str> {
        self.pin_uv_auth_rp_id.as_ref().map(|rp_id| rp_id.as_str())
    }

    /// `getPINRetries`.
    #[must_use]
    pub fn get_retries(&self, state: &impl PinState) -> GetRetriesResponse {
        GetRetriesResponse {
            retries: state.pin_retries(),
        }
    }

    /// `getKeyAgreement`: generate and retain an ephemeral key pair.
    pub fn key_agreement<R: Rng>(
        &mut self,
        rng: &mut R,
    ) -> Result<KeyAgreementResponse, Ctap2Status> {
        let secret = generate_secret_key(rng)?;
        let point = secret.public_key().to_sec1_point(false);
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(point.x().ok_or(Ctap2Status::Other)?);
        y.copy_from_slice(point.y().ok_or(Ctap2Status::Other)?);

        let mut private = [0u8; 32];
        private.copy_from_slice(&secret.to_bytes());
        self.agreement_private = Some(private);

        Ok(KeyAgreementResponse {
            key: Ec2KeyAgreement { x, y },
        })
    }

    fn shared(&self, request: &ClientPinRequest) -> Result<[u8; 32], Ctap2Status> {
        let platform = request
            .key_agreement
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;
        let private = self
            .agreement_private
            .as_ref()
            .ok_or(Ctap2Status::InvalidParameter)?;
        shared_secret(private, platform)
    }

    /// Provision the first PIN from a `setPIN` request and store its hash.
    ///
    /// Returns `Ctap2Status::PinAuthInvalid` if a PIN is already present and
    /// `Ctap2Status::InvalidParameter` unless the authenticated payload decrypts
    /// to exactly 64 bytes. Invalid UTF-8, padding, or fewer than four Unicode
    /// code points returns `Ctap2Status::PinPolicyViolation`.
    pub fn set_pin(
        &mut self,
        request: &ClientPinRequest,
        state: &mut impl PinState,
    ) -> Result<(), Ctap2Status> {
        // `setPIN` provisions the first PIN only. Rotation of an existing PIN
        // must go through `changePIN`, otherwise any host with USB access
        // could overwrite the victim PIN after a bare key agreement.
        if state.pin_hash().is_some() {
            return Err(Ctap2Status::PinAuthInvalid);
        }
        let shared = self.shared(request)?;
        let new_pin_enc = request
            .new_pin_enc
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;
        let auth = request
            .pin_uv_auth_param
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;

        let expected = hmac_sha256(&shared, new_pin_enc);
        if !ct_eq_prefix(&expected, auth) {
            return Err(Ctap2Status::PinAuthInvalid);
        }

        let mut plain = [0u8; 96];
        let length = aes_cbc_decrypt(&shared, new_pin_enc, &mut plain)?;
        if length != 64 {
            return Err(Ctap2Status::InvalidParameter);
        }
        // CTAP2 requires a minimum PIN length of 4 Unicode code points. The
        // UTF-8 PIN must be terminated and zero-padded to exactly 64 bytes.
        let pin_len = plain[..64]
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(Ctap2Status::PinPolicyViolation)?;
        if plain[pin_len..64].iter().any(|&byte| byte != 0) {
            return Err(Ctap2Status::PinPolicyViolation);
        }
        let pin =
            core::str::from_utf8(&plain[..pin_len]).map_err(|_| Ctap2Status::PinPolicyViolation)?;
        if pin.chars().count() < 4 {
            return Err(Ctap2Status::PinPolicyViolation);
        }
        state
            .set_pin_hash(pin_hash(pin.as_bytes()))
            .map_err(|_| Ctap2Status::Other)
    }

    /// `getPINToken` and `getPinUvAuthTokenUsingPinWithPermissions`.
    ///
    /// The superseded `getPinToken` subcommand grants the default `mc`/`ga`
    /// permissions and rejects the `permissions` and `rpId` parameters.
    /// `getPinUvAuthTokenUsingPinWithPermissions` requires the `permissions`
    /// bitfield and binds it (plus the optional permissions RP ID) to the
    /// issued token.
    pub fn get_pin_token<R: Rng>(
        &mut self,
        request: &ClientPinRequest,
        state: &mut impl PinState,
        rng: &mut R,
    ) -> Result<PinTokenResponse, Ctap2Status> {
        let Some(stored_hash) = state.pin_hash() else {
            return Err(Ctap2Status::PinNotSet);
        };
        if state.pin_retries() == 0 {
            return Err(Ctap2Status::PinBlocked);
        }

        let permissions = self.requested_permissions(request)?;

        let shared = self.shared(request)?;
        let pin_hash_enc = request
            .pin_hash_enc
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;
        let auth = request
            .pin_uv_auth_param
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;

        let expected = hmac_sha256(&shared, pin_hash_enc);
        if !ct_eq_prefix(&expected, auth) {
            return Err(Ctap2Status::PinAuthInvalid);
        }

        let mut plain = [0u8; 32];
        let length = aes_cbc_decrypt(&shared, pin_hash_enc, &mut plain)?;
        if length < 16 || !ct_eq(&plain[..16], &stored_hash[..16]) {
            let retries = state.pin_retries().saturating_sub(1);
            state
                .set_pin_retries(retries)
                .map_err(|_| Ctap2Status::Other)?;
            return Err(if retries == 0 {
                Ctap2Status::PinBlocked
            } else {
                Ctap2Status::PinInvalid
            });
        }

        state
            .set_pin_retries(DEFAULT_RETRIES)
            .map_err(|_| Ctap2Status::Other)?;

        let mut token: [u8; 32] = Default::default();
        rng.fill_bytes(&mut token);
        self.pin_uv_auth_token = Some(token);
        self.pin_uv_auth_permissions = permissions;
        self.pin_uv_auth_rp_id = request.rp_id.clone();
        let mut encrypted = [0u8; 48];
        let length = aes_cbc_encrypt(&shared, &token, &mut encrypted)?;
        Ok(PinTokenResponse {
            token: heapless::Vec::from_slice(&encrypted[..length])
                .map_err(|_| Ctap2Status::LimitExceeded)?,
        })
    }

    /// Validate the `permissions`/`rpId` parameters of a token request.
    ///
    /// Returns the permission bitfield to bind to the token.
    fn requested_permissions(&self, request: &ClientPinRequest) -> Result<u8, Ctap2Status> {
        match request.sub_command {
            SUB_GET_PIN_TOKEN => {
                // The superseded subcommand takes neither parameter.
                if request.permissions.is_some() || request.rp_id.is_some() {
                    return Err(Ctap2Status::InvalidParameter);
                }
                Ok(DEFAULT_PERMISSIONS)
            }
            SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS => {
                let permissions = request.permissions.ok_or(Ctap2Status::MissingParameter)?;
                if permissions == 0 {
                    return Err(Ctap2Status::InvalidParameter);
                }
                if permissions & !SUPPORTED_PERMISSIONS != 0 {
                    return Err(Ctap2Status::UnauthorizedPermission);
                }
                Ok(permissions)
            }
            _ => Err(Ctap2Status::InvalidCommand),
        }
    }

    /// `changePIN`: rotate the PIN.
    ///
    /// The platform proves knowledge of the current PIN with `pinHashEnc`
    /// (the encrypted `LEFT(SHA-256(PIN), 16)`) and carries the new PIN in
    /// `newPinEnc` (padded to 64 bytes). The request is authenticated with the
    /// shared secret: `authenticate(sharedSecret, newPinEnc || pinHashEnc)`.
    ///
    /// A wrong current PIN consumes one retry, as the spec requires; a
    /// successful rotation restores the retry budget and invalidates the
    /// active `pinUvAuthToken`.
    pub fn change_pin(
        &mut self,
        request: &ClientPinRequest,
        state: &mut impl PinState,
    ) -> Result<(), Ctap2Status> {
        let Some(stored_hash) = state.pin_hash() else {
            return Err(Ctap2Status::PinNotSet);
        };
        if state.pin_retries() == 0 {
            return Err(Ctap2Status::PinBlocked);
        }

        let shared = self.shared(request)?;
        let new_pin_enc = request
            .new_pin_enc
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;
        let pin_hash_enc = request
            .pin_hash_enc
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;
        let auth = request
            .pin_uv_auth_param
            .as_ref()
            .ok_or(Ctap2Status::MissingParameter)?;

        // The platform authenticates `newPinEnc || pinHashEnc` with the
        // shared secret.
        let mut message = [0u8; 128];
        if new_pin_enc.len() + pin_hash_enc.len() > message.len() {
            return Err(Ctap2Status::InvalidParameter);
        }
        message[..new_pin_enc.len()].copy_from_slice(new_pin_enc);
        message[new_pin_enc.len()..new_pin_enc.len() + pin_hash_enc.len()]
            .copy_from_slice(pin_hash_enc);
        let expected = hmac_sha256(&shared, &message[..new_pin_enc.len() + pin_hash_enc.len()]);
        if !ct_eq_prefix(&expected, auth) {
            return Err(Ctap2Status::PinAuthInvalid);
        }

        // The current PIN is proven by the encrypted hash; a mismatch spends
        // one retry.
        let mut plain = [0u8; 32];
        let length = aes_cbc_decrypt(&shared, pin_hash_enc, &mut plain)?;
        if length < 16 || !ct_eq(&plain[..16], &stored_hash[..16]) {
            let retries = state.pin_retries().saturating_sub(1);
            state
                .set_pin_retries(retries)
                .map_err(|_| Ctap2Status::Other)?;
            // The key agreement is dropped: the platform must renegotiate.
            self.agreement_private = None;
            self.invalidate_token();
            return Err(if retries == 0 {
                Ctap2Status::PinBlocked
            } else {
                Ctap2Status::PinInvalid
            });
        }

        let mut padded = [0u8; 96];
        let length = aes_cbc_decrypt(&shared, new_pin_enc, &mut padded)?;
        if length != 64 {
            return Err(Ctap2Status::InvalidParameter);
        }
        let pin_len = padded[..64]
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(Ctap2Status::PinPolicyViolation)?;
        if padded[pin_len..64].iter().any(|&byte| byte != 0) {
            return Err(Ctap2Status::PinPolicyViolation);
        }
        let pin = core::str::from_utf8(&padded[..pin_len])
            .map_err(|_| Ctap2Status::PinPolicyViolation)?;
        if pin.chars().count() < 4 {
            return Err(Ctap2Status::PinPolicyViolation);
        }

        state
            .set_pin_hash(pin_hash(pin.as_bytes()))
            .map_err(|_| Ctap2Status::Other)?;
        state
            .set_pin_retries(DEFAULT_RETRIES)
            .map_err(|_| Ctap2Status::Other)?;
        // A rotated PIN invalidates every issued token.
        self.invalidate_token();
        Ok(())
    }
}

/// Helpers shared by the unit tests of this crate.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Deterministic randomness for the tests.
    pub(crate) struct TestRng(pub u32);

    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (self.0 >> 24) as u8;
            }
        }
    }

    /// In-memory PIN state.
    #[derive(Default)]
    pub(crate) struct TestPinState {
        /// Stored PIN hash.
        pub(crate) hash: Option<[u8; 32]>,
        /// Remaining retries.
        pub(crate) retries: u8,
    }

    impl PinState for TestPinState {
        fn pin_hash(&self) -> Option<[u8; 32]> {
            self.hash
        }
        fn pin_retries(&self) -> u8 {
            self.retries
        }
        fn set_pin_hash(&mut self, hash: [u8; 32]) -> Result<(), CoreError> {
            self.hash = Some(hash);
            self.retries = DEFAULT_RETRIES;
            Ok(())
        }
        fn set_pin_retries(&mut self, retries: u8) -> Result<(), CoreError> {
            self.retries = retries;
            Ok(())
        }
        fn clear_pin_state(&mut self) -> Result<(), CoreError> {
            self.hash = None;
            Ok(())
        }
    }

    /// The platform side of the PIN protocol.
    pub(crate) struct Platform {
        private: [u8; 32],
        /// The public key of the platform key agreement.
        pub(crate) public: Ec2KeyAgreement,
    }

    impl Platform {
        pub(crate) fn new(rng: &mut TestRng) -> Self {
            let secret = generate_secret_key(rng).unwrap();
            let point = secret.public_key().to_sec1_point(false);
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(point.x().unwrap());
            y.copy_from_slice(point.y().unwrap());
            let mut private = [0u8; 32];
            private.copy_from_slice(&secret.to_bytes());
            Self {
                private,
                public: Ec2KeyAgreement { x, y },
            }
        }

        pub(crate) fn shared(&self, authenticator: &Ec2KeyAgreement) -> [u8; 32] {
            shared_secret(&self.private, authenticator).unwrap()
        }
    }

    /// A PIN/UV auth token issued by the platform.
    pub(crate) struct IssuedToken {
        /// The authenticator handler holding the token.
        pub(crate) client_pin: ClientPin,
        /// The PIN state of the authenticator.
        pub(crate) state: TestPinState,
        /// The raw token, used to build the `pinUvAuthParam` of a request.
        pub(crate) token: [u8; 32],
        /// The platform key agreement key.
        pub(crate) platform: Platform,
        /// The shared secret of the key agreement.
        pub(crate) shared: [u8; 32],
    }

    /// Provision the PIN and issue a PIN/UV auth token.
    ///
    /// The subcommand, the permissions and the permissions RP ID are passed
    /// verbatim, so the tests can exercise the validation of the issuance
    /// path.
    pub(crate) fn try_issue_token(
        sub_command: u8,
        permissions: Option<u8>,
        rp_id: Option<&str>,
    ) -> Result<IssuedToken, Ctap2Status> {
        let mut rng = TestRng(1);
        let mut client_pin = ClientPin::new();
        let mut state = TestPinState::default();
        let key_agreement = client_pin.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let mut padded = [0u8; 64];
        padded[..4].copy_from_slice(b"1234");
        let mut new_pin_enc = [0u8; 64];
        let length = aes_cbc_encrypt(&shared, &padded, &mut new_pin_enc).unwrap();
        let auth = hmac_sha256(&shared, &new_pin_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_SET_PIN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: Some(heapless::Vec::from_slice(&new_pin_enc[..length]).unwrap()),
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        client_pin.set_pin(&request, &mut state)?;

        let hash = pin_hash(b"1234");
        let mut pin_hash_enc = [0u8; 16];
        let length = aes_cbc_encrypt(&shared, &hash[..16], &mut pin_hash_enc).unwrap();
        let auth = hmac_sha256(&shared, &pin_hash_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions,
            rp_id: rp_id.map(|id| FixedString::new(id).expect("rp id fits")),
        };
        let response = client_pin.get_pin_token(&request, &mut state, &mut rng)?;
        let mut token: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        let length = aes_cbc_decrypt(&shared, &response.token, &mut token).unwrap();
        assert_eq!(length, 32);
        Ok(IssuedToken {
            client_pin,
            state,
            token,
            platform,
            shared,
        })
    }

    /// Provision the PIN and issue a PIN/UV auth token.
    ///
    /// `permissions` selects `getPinUvAuthTokenUsingPinWithPermissions`; `None`
    /// issues the legacy `getPinToken` token. `rp_id` binds the token to a
    /// relying party.
    pub(crate) fn issue_token(permissions: Option<u8>, rp_id: Option<&str>) -> IssuedToken {
        let sub_command = match permissions {
            Some(_) => SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
            None => SUB_GET_PIN_TOKEN,
        };
        try_issue_token(sub_command, permissions, rp_id).unwrap()
    }

    /// Build the `pinUvAuthParam` of a request with the issued token.
    pub(crate) fn auth_param(token: &[u8; 32], message: &[u8]) -> [u8; 32] {
        use hmac::Mac;
        let mut mac =
            <HmacSha256 as KeyInit>::new_from_slice(token).expect("HMAC accepts any key length");
        mac.update(message);
        let out = mac.finalize().into_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&out);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        IssuedToken, Platform, TestPinState, TestRng, auth_param, issue_token, try_issue_token,
    };
    use super::*;

    /// Authorise an operation with the active token.
    fn authorize(
        issued: &mut IssuedToken,
        param: Option<&[u8]>,
        message: &[u8],
        operation: TokenOperation<'_>,
    ) -> Result<bool, Ctap2Status> {
        issued.client_pin.authorize(
            &issued.state,
            TokenRequest {
                param,
                message,
                uv_requested: false,
                operation,
            },
        )
    }

    fn set_pin_from_plaintext(
        seed: u32,
        plaintext: &[u8],
    ) -> (Result<(), Ctap2Status>, TestPinState) {
        let mut rng = TestRng(seed);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState::default();
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let mut encrypted = [0u8; 96];
        let encrypted_length = aes_cbc_encrypt(&shared, plaintext, &mut encrypted).unwrap();
        let auth = hmac_sha256(&shared, &encrypted[..encrypted_length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_SET_PIN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: Some(heapless::Vec::from_slice(&encrypted[..encrypted_length]).unwrap()),
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        let result = authenticator.set_pin(&request, &mut state);
        (result, state)
    }

    #[test]
    fn pin_hash_is_sha256_of_padded_pin() {
        let expected = Sha256::digest([b"1234".as_slice(), &[0u8; 60]].concat());
        assert_eq!(pin_hash(b"1234"), expected.as_slice());
    }

    #[test]
    fn set_pin_then_get_token_round_trips() {
        let mut rng = TestRng(1);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState::default();

        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        // setPIN
        let mut padded = [0u8; 64];
        padded[..4].copy_from_slice(b"1234");
        let mut new_pin_enc = [0u8; 64];
        let length = aes_cbc_encrypt(&shared, &padded, &mut new_pin_enc).unwrap();
        let auth = hmac_sha256(&shared, &new_pin_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_SET_PIN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: Some(heapless::Vec::from_slice(&new_pin_enc[..length]).unwrap()),
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        authenticator.set_pin(&request, &mut state).unwrap();
        assert_eq!(state.hash, Some(pin_hash(b"1234")));

        // getPINToken with the correct PIN hash.
        let hash = pin_hash(b"1234");
        let mut pin_hash_enc = [0u8; 16];
        let length = aes_cbc_encrypt(&shared, &hash[..16], &mut pin_hash_enc).unwrap();
        let auth = hmac_sha256(&shared, &pin_hash_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_TOKEN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: None,
            rp_id: None,
        };
        let response = authenticator
            .get_pin_token(&request, &mut state, &mut rng)
            .unwrap();

        // Decrypt the returned token.
        let mut token: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        let length = aes_cbc_decrypt(&shared, &response.token, &mut token).unwrap();
        assert_eq!(length, 32);
        assert_eq!(state.retries, DEFAULT_RETRIES);

        // The issued token authorises makeCredential/getAssertion.
        let message = [0xABu8; 32];
        let param = auth_param(&token, &message);
        assert!(authenticator.verify_pin_uv_auth_param(&param, &message));
        assert!(authenticator.verify_pin_uv_auth_param(&param[..16], &message));
        for invalid_length in [0, 1, 15, 17, 31] {
            assert!(
                !authenticator.verify_pin_uv_auth_param(&param[..invalid_length], &message),
                "accepted a {invalid_length}-byte PIN/UV auth parameter"
            );
        }
        assert!(!authenticator.verify_pin_uv_auth_param(&[0u8; 33], &message));
        assert!(!authenticator.verify_pin_uv_auth_param(&param, b"other"));
        assert!(!ClientPin::new().verify_pin_uv_auth_param(&param, &message));
    }

    #[test]
    fn set_pin_rejected_when_already_set() {
        let mut rng = TestRng(11);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: Some(pin_hash(b"1234")),
            retries: DEFAULT_RETRIES,
        };
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let mut padded = [0u8; 64];
        padded[..4].copy_from_slice(b"5678");
        let mut new_pin_enc = [0u8; 64];
        let length = aes_cbc_encrypt(&shared, &padded, &mut new_pin_enc).unwrap();
        let auth = hmac_sha256(&shared, &new_pin_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_SET_PIN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: Some(heapless::Vec::from_slice(&new_pin_enc[..length]).unwrap()),
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        assert_eq!(
            authenticator.set_pin(&request, &mut state),
            Err(Ctap2Status::PinAuthInvalid)
        );
        assert_eq!(state.hash, Some(pin_hash(b"1234")));
        assert_eq!(state.retries, DEFAULT_RETRIES);
    }

    #[test]
    fn set_pin_rejects_short_pin() {
        let mut rng = TestRng(12);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState::default();
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let mut padded = [0u8; 64];
        padded[..3].copy_from_slice(b"123");
        let mut new_pin_enc = [0u8; 64];
        let length = aes_cbc_encrypt(&shared, &padded, &mut new_pin_enc).unwrap();
        let auth = hmac_sha256(&shared, &new_pin_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_SET_PIN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: Some(heapless::Vec::from_slice(&new_pin_enc[..length]).unwrap()),
            pin_hash_enc: None,
            permissions: None,
            rp_id: None,
        };
        assert_eq!(
            authenticator.set_pin(&request, &mut state),
            Err(Ctap2Status::PinPolicyViolation)
        );
        assert!(state.hash.is_none());
    }

    #[test]
    fn set_pin_validates_unicode_and_zero_padding() {
        let pin = "é猫🙂a";
        let mut padded = [0u8; 64];
        padded[..pin.len()].copy_from_slice(pin.as_bytes());

        let (result, state) = set_pin_from_plaintext(15, &padded);
        assert_eq!(result, Ok(()));
        assert_eq!(state.hash, Some(pin_hash(pin.as_bytes())));
    }

    #[test]
    fn set_pin_rejects_invalid_utf8_or_padding() {
        let mut too_few_code_points = [0u8; 64];
        let three_unicode_chars = "é猫🙂";
        too_few_code_points[..three_unicode_chars.len()]
            .copy_from_slice(three_unicode_chars.as_bytes());

        let mut nonzero_after_terminator = [0u8; 64];
        nonzero_after_terminator[..4].copy_from_slice(b"1234");
        nonzero_after_terminator[5] = b'5';

        let mut invalid_utf8 = [0u8; 64];
        invalid_utf8[..5].copy_from_slice(&[0xFF, b'1', b'2', b'3', b'4']);

        for (seed, plaintext) in [
            (16, too_few_code_points),
            (17, [b'7'; 64]),
            (18, nonzero_after_terminator),
            (19, invalid_utf8),
        ] {
            let (result, state) = set_pin_from_plaintext(seed, &plaintext);
            assert_eq!(result, Err(Ctap2Status::PinPolicyViolation));
            assert!(state.hash.is_none());
        }
    }

    #[test]
    fn set_pin_requires_exactly_64_encrypted_bytes() {
        for (seed, plaintext_length) in [(13, 48), (14, 80)] {
            let mut rng = TestRng(seed);
            let mut authenticator = ClientPin::new();
            let mut state = TestPinState::default();
            let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
            let platform = Platform::new(&mut rng);
            let shared = platform.shared(&key_agreement.key);

            let plaintext = [b'7'; 80];
            let mut encrypted = [0u8; 80];
            let encrypted_length =
                aes_cbc_encrypt(&shared, &plaintext[..plaintext_length], &mut encrypted).unwrap();
            let auth = hmac_sha256(&shared, &encrypted[..encrypted_length]);
            let request = ClientPinRequest {
                protocol: 1,
                sub_command: SUB_SET_PIN,
                key_agreement: Some(platform.public),
                pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
                new_pin_enc: Some(
                    heapless::Vec::from_slice(&encrypted[..encrypted_length]).unwrap(),
                ),
                pin_hash_enc: None,
                permissions: None,
                rp_id: None,
            };

            assert_eq!(
                authenticator.set_pin(&request, &mut state),
                Err(Ctap2Status::InvalidParameter),
                "accepted {plaintext_length} encrypted bytes"
            );
            assert!(state.hash.is_none());
        }
    }

    #[test]
    fn wrong_pin_decrements_retries() {
        let mut rng = TestRng(2);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: Some(pin_hash(b"1234")),
            retries: DEFAULT_RETRIES,
        };

        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let wrong = pin_hash(b"9999");
        let mut pin_hash_enc = [0u8; 16];
        let length = aes_cbc_encrypt(&shared, &wrong[..16], &mut pin_hash_enc).unwrap();
        let auth = hmac_sha256(&shared, &pin_hash_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_TOKEN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: None,
            rp_id: None,
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::PinInvalid)
        );
        assert_eq!(state.retries, DEFAULT_RETRIES - 1);
    }

    #[test]
    fn bad_hmac_is_rejected() {
        let mut rng = TestRng(3);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: Some(pin_hash(b"1234")),
            retries: DEFAULT_RETRIES,
        };
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);

        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_TOKEN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&[0u8; 32]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&[0u8; 16]).unwrap()),
            permissions: None,
            rp_id: None,
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::PinAuthInvalid)
        );
        // Authentication failures do not consume retries.
        assert_eq!(state.retries, DEFAULT_RETRIES);
        let _ = key_agreement;
    }

    #[test]
    fn token_requires_pin_set() {
        let mut rng = TestRng(4);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: None,
            retries: DEFAULT_RETRIES,
        };
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_TOKEN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&[0u8; 32]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&[0u8; 16]).unwrap()),
            permissions: None,
            rp_id: None,
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::PinNotSet)
        );
        let _ = key_agreement;
    }

    /// Build a `changePIN` request from the platform side.
    fn change_pin_request(
        platform: &Platform,
        shared: &[u8; 32],
        current_pin: &[u8],
        new_pin: &[u8],
    ) -> ClientPinRequest {
        let hash = pin_hash(current_pin);
        let mut pin_hash_enc = [0u8; 32];
        let hash_length = aes_cbc_encrypt(shared, &hash[..16], &mut pin_hash_enc).unwrap();

        let mut padded = [0u8; 64];
        padded[..new_pin.len()].copy_from_slice(new_pin);
        let mut new_pin_enc = [0u8; 96];
        let new_length = aes_cbc_encrypt(shared, &padded, &mut new_pin_enc).unwrap();

        let mut message = [0u8; 128];
        message[..new_length].copy_from_slice(&new_pin_enc[..new_length]);
        message[new_length..new_length + hash_length].copy_from_slice(&pin_hash_enc[..hash_length]);
        let auth = hmac_sha256(shared, &message[..new_length + hash_length]);

        ClientPinRequest {
            protocol: 1,
            sub_command: SUB_CHANGE_PIN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: Some(heapless::Vec::from_slice(&new_pin_enc[..new_length]).unwrap()),
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..hash_length]).unwrap()),
            permissions: None,
            rp_id: None,
        }
    }

    #[test]
    fn change_pin_rotates_the_stored_hash() {
        let mut rng = TestRng(21);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: Some(pin_hash(b"1234")),
            retries: 3,
        };
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let request = change_pin_request(&platform, &shared, b"1234", b"567890");
        assert_eq!(authenticator.change_pin(&request, &mut state), Ok(()));
        assert_eq!(state.hash, Some(pin_hash(b"567890")));
        // The retry budget is restored and the token is invalidated.
        assert_eq!(state.retries, DEFAULT_RETRIES);
        assert_eq!(authenticator.token_permissions(), 0);
        assert_eq!(authenticator.token_rp_id(), None);

        // The old PIN no longer opens a token.
        let hash = pin_hash(b"1234");
        let mut pin_hash_enc = [0u8; 32];
        let length = aes_cbc_encrypt(&shared, &hash[..16], &mut pin_hash_enc).unwrap();
        let auth = hmac_sha256(&shared, &pin_hash_enc[..length]);
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_TOKEN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: None,
            rp_id: None,
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::PinInvalid)
        );
    }

    #[test]
    fn change_pin_with_a_wrong_current_pin_spends_a_retry() {
        let mut rng = TestRng(22);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: Some(pin_hash(b"1234")),
            retries: 3,
        };
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let request = change_pin_request(&platform, &shared, b"9999", b"567890");
        assert_eq!(
            authenticator.change_pin(&request, &mut state),
            Err(Ctap2Status::PinInvalid)
        );
        assert_eq!(state.retries, 2);
        assert_eq!(state.hash, Some(pin_hash(b"1234")));
    }

    #[test]
    fn change_pin_requires_a_set_pin_and_rejects_a_short_one() {
        let mut rng = TestRng(23);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState::default();
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let request = change_pin_request(&platform, &shared, b"1234", b"567890");
        assert_eq!(
            authenticator.change_pin(&request, &mut state),
            Err(Ctap2Status::PinNotSet)
        );

        state.hash = Some(pin_hash(b"1234"));
        state.retries = DEFAULT_RETRIES;
        let request = change_pin_request(&platform, &shared, b"1234", b"12");
        assert_eq!(
            authenticator.change_pin(&request, &mut state),
            Err(Ctap2Status::PinPolicyViolation)
        );
        assert_eq!(state.hash, Some(pin_hash(b"1234")));
    }

    #[test]
    fn token_permissions_follow_the_requested_subcommand() {
        let mut rng = TestRng(24);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: Some(pin_hash(b"1234")),
            retries: DEFAULT_RETRIES,
        };
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let hash = pin_hash(b"1234");
        let mut pin_hash_enc = [0u8; 32];
        let length = aes_cbc_encrypt(&shared, &hash[..16], &mut pin_hash_enc).unwrap();
        let auth = hmac_sha256(&shared, &pin_hash_enc[..length]);

        // `getPinToken` grants the default permissions; credential management
        // is not part of them.
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_TOKEN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: None,
            rp_id: None,
        };
        authenticator
            .get_pin_token(&request, &mut state, &mut rng)
            .unwrap();
        assert_eq!(authenticator.token_permissions(), DEFAULT_PERMISSIONS);
        assert_eq!(authenticator.token_permissions() & PERMISSION_CM, 0);

        // A token with the `cm` permission is accepted as well.
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: Some(PERMISSION_CM),
            rp_id: None,
        };
        authenticator
            .get_pin_token(&request, &mut state, &mut rng)
            .unwrap();
        assert_eq!(authenticator.token_permissions(), PERMISSION_CM);

        // A token without the `cm` permission is refused.
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: Some(PERMISSION_MC),
            rp_id: None,
        };
        authenticator
            .get_pin_token(&request, &mut state, &mut rng)
            .unwrap();
        assert_eq!(authenticator.token_permissions(), PERMISSION_MC);
    }

    #[test]
    fn token_requests_validate_the_permissions() {
        let mut rng = TestRng(25);
        let mut authenticator = ClientPin::new();
        let mut state = TestPinState {
            hash: Some(pin_hash(b"1234")),
            retries: DEFAULT_RETRIES,
        };
        let key_agreement = authenticator.key_agreement(&mut rng).unwrap();
        let platform = Platform::new(&mut rng);
        let shared = platform.shared(&key_agreement.key);

        let hash = pin_hash(b"1234");
        let mut pin_hash_enc = [0u8; 32];
        let length = aes_cbc_encrypt(&shared, &hash[..16], &mut pin_hash_enc).unwrap();
        let auth = hmac_sha256(&shared, &pin_hash_enc[..length]);

        // Zero permissions are rejected.
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: Some(0),
            rp_id: None,
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::InvalidParameter)
        );

        // Unsupported permissions are refused.
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: Some(PERMISSION_BE | PERMISSION_LBW),
            rp_id: None,
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::UnauthorizedPermission)
        );

        // The superseded subcommand takes neither parameter.
        let request = ClientPinRequest {
            protocol: 1,
            sub_command: SUB_GET_PIN_TOKEN,
            key_agreement: Some(platform.public),
            pin_uv_auth_param: Some(heapless::Vec::from_slice(&auth[..16]).unwrap()),
            new_pin_enc: None,
            pin_hash_enc: Some(heapless::Vec::from_slice(&pin_hash_enc[..length]).unwrap()),
            permissions: Some(PERMISSION_CM),
            rp_id: None,
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::InvalidParameter)
        );

        // `mc` and `ga` are accepted without a permissions RP ID: the relying
        // party is bound on the first use of the token.
        for permissions in [PERMISSION_MC, PERMISSION_GA] {
            let issued = try_issue_token(
                SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
                Some(permissions),
                None,
            )
            .unwrap();
            assert_eq!(issued.client_pin.token_permissions(), permissions);
            assert_eq!(issued.client_pin.token_rp_id(), None);
        }
    }

    #[test]
    fn make_credential_requires_the_mc_permission() {
        for permissions in [PERMISSION_CM, PERMISSION_GA] {
            let mut issued = issue_token(Some(permissions), None);
            let message = [0x54u8; 32];
            let param = auth_param(&issued.token, &message);
            // The token does not carry the `mc` permission.
            assert_eq!(
                authorize(
                    &mut issued,
                    Some(&param),
                    &message,
                    TokenOperation::MakeCredential { rp_id: "a.test" },
                ),
                Err(Ctap2Status::PinAuthInvalid)
            );
        }

        // The `mc` permission authorises the creation.
        let mut issued = issue_token(Some(PERMISSION_MC), None);
        let message = [0x55u8; 32];
        let param = auth_param(&issued.token, &message);
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Ok(true)
        );
    }

    #[test]
    fn get_assertion_requires_the_ga_permission() {
        for permissions in [PERMISSION_CM, PERMISSION_MC] {
            let mut issued = issue_token(Some(permissions), None);
            let message = [0x56u8; 32];
            let param = auth_param(&issued.token, &message);
            // The token does not carry the `ga` permission.
            assert_eq!(
                authorize(
                    &mut issued,
                    Some(&param),
                    &message,
                    TokenOperation::GetAssertion { rp_id: "a.test" },
                ),
                Err(Ctap2Status::PinAuthInvalid)
            );
        }

        // The `ga` permission authorises the assertion.
        let mut issued = issue_token(Some(PERMISSION_GA), None);
        let message = [0x57u8; 32];
        let param = auth_param(&issued.token, &message);
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::GetAssertion { rp_id: "a.test" },
            ),
            Ok(true)
        );
    }

    #[test]
    fn token_bound_to_another_rp_is_refused() {
        let mut issued = issue_token(Some(PERMISSION_MC | PERMISSION_GA), Some("a.test"));
        let message = [0x58u8; 32];
        let param = auth_param(&issued.token, &message);

        for operation in [
            TokenOperation::MakeCredential { rp_id: "a.test" },
            TokenOperation::GetAssertion { rp_id: "a.test" },
        ] {
            assert_eq!(
                authorize(&mut issued, Some(&param), &message, operation),
                Ok(true)
            );
        }
        for operation in [
            TokenOperation::MakeCredential { rp_id: "b.test" },
            TokenOperation::GetAssertion { rp_id: "b.test" },
            // The comparison is exact and case sensitive.
            TokenOperation::MakeCredential { rp_id: "A.test" },
        ] {
            assert_eq!(
                authorize(&mut issued, Some(&param), &message, operation),
                Err(Ctap2Status::PinAuthInvalid)
            );
        }
    }

    #[test]
    fn first_use_binds_the_token_to_the_relying_party() {
        let mut issued = issue_token(Some(PERMISSION_MC | PERMISSION_GA), None);
        assert_eq!(issued.client_pin.token_rp_id(), None);
        let message = [0x59u8; 32];
        let param = auth_param(&issued.token, &message);

        // The first use binds the token to the relying party of the request.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Ok(true)
        );
        assert_eq!(issued.client_pin.token_rp_id(), Some("a.test"));

        // The same relying party keeps working.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::GetAssertion { rp_id: "a.test" },
            ),
            Ok(true)
        );

        // Another relying party does not.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::GetAssertion { rp_id: "b.test" },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }

    #[test]
    fn legacy_token_is_accepted_by_make_credential_and_get_assertion() {
        let mut issued = issue_token(None, None);
        assert_eq!(issued.client_pin.token_permissions(), DEFAULT_PERMISSIONS);
        assert_eq!(issued.client_pin.token_rp_id(), None);
        let message = [0x5Au8; 32];
        let param = auth_param(&issued.token, &message);

        for operation in [
            TokenOperation::MakeCredential { rp_id: "a.test" },
            TokenOperation::GetAssertion { rp_id: "a.test" },
        ] {
            assert_eq!(
                authorize(&mut issued, Some(&param), &message, operation),
                Ok(true)
            );
        }
        // The legacy token is bound to the relying party of the first use.
        assert_eq!(issued.client_pin.token_rp_id(), Some("a.test"));

        // It never drives credential management.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }

    #[test]
    fn credential_management_requires_the_cm_permission() {
        let message = [0x5Bu8; 32];

        // The legacy token does not carry the `cm` permission.
        let mut legacy = issue_token(None, None);
        let param = auth_param(&legacy.token, &message);
        assert_eq!(
            authorize(
                &mut legacy,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );

        // A token with `mc` only is refused as well.
        let mut mc = issue_token(Some(PERMISSION_MC), None);
        let param = auth_param(&mc.token, &message);
        assert_eq!(
            authorize(
                &mut mc,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );

        // Without a `pinUvAuthParam` the subcommand needs a token.
        let mut cm = issue_token(Some(PERMISSION_CM), None);
        assert_eq!(
            authorize(
                &mut cm,
                None,
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Err(Ctap2Status::PinRequired)
        );
    }

    #[test]
    fn cm_token_without_rp_id_drives_the_whole_device() {
        let mut issued = issue_token(Some(PERMISSION_CM), None);
        assert_eq!(issued.client_pin.token_permissions(), PERMISSION_CM);
        assert_eq!(issued.client_pin.token_rp_id(), None);
        let message = [0x5Cu8; 32];
        let param = auth_param(&issued.token, &message);

        // The global subcommands accept a token without a binding.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Ok(true)
        );
        // And so does the enumeration of the credentials of any relying
        // party.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::RelyingPartyHash(&rp_id_hash("a.test")),
                },
            ),
            Ok(true)
        );
        // The token stays unbound: a `cm` token is never bound to a relying
        // party.
        assert_eq!(issued.client_pin.token_rp_id(), None);
    }

    #[test]
    fn device_scope_requires_a_token_without_rp_binding() {
        // A token bound to a relying party cannot enumerate the device.
        let mut bound = issue_token(Some(PERMISSION_CM), Some("a.test"));
        assert_eq!(bound.client_pin.token_rp_id(), Some("a.test"));
        let message = [0x5Du8; 32];
        let param = auth_param(&bound.token, &message);
        assert_eq!(
            authorize(
                &mut bound,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }

    #[test]
    fn enumerate_credentials_is_restricted_to_the_bound_rp() {
        let mut issued = issue_token(Some(PERMISSION_CM), Some("a.test"));
        let message = [0x5Eu8; 32];
        let param = auth_param(&issued.token, &message);
        let bound = rp_id_hash("a.test");
        let other = rp_id_hash("b.test");

        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::RelyingPartyHash(&bound),
                },
            ),
            Ok(true)
        );
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::RelyingPartyHash(&other),
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }

    #[test]
    fn supported_permissions_are_still_accepted() {
        // Every supported permission is granted.
        for permissions in [
            PERMISSION_MC,
            PERMISSION_GA,
            PERMISSION_CM,
            SUPPORTED_PERMISSIONS,
        ] {
            let issued = try_issue_token(
                SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
                Some(permissions),
                None,
            )
            .unwrap();
            assert_eq!(issued.client_pin.token_permissions(), permissions);
        }

        // Zero permissions are rejected.
        assert_eq!(
            try_issue_token(SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS, Some(0), None).err(),
            Some(Ctap2Status::InvalidParameter)
        );

        // Unsupported permissions are rejected.
        assert_eq!(
            try_issue_token(
                SUB_GET_PIN_UV_AUTH_TOKEN_WITH_PERMISSIONS,
                Some(PERMISSION_BE | PERMISSION_LBW),
                None
            )
            .err(),
            Some(Ctap2Status::UnauthorizedPermission)
        );

        // The superseded subcommand takes neither parameter.
        assert_eq!(
            try_issue_token(SUB_GET_PIN_TOKEN, Some(PERMISSION_CM), None).err(),
            Some(Ctap2Status::InvalidParameter)
        );
        assert_eq!(
            try_issue_token(SUB_GET_PIN_TOKEN, None, Some("a.test")).err(),
            Some(Ctap2Status::InvalidParameter)
        );
    }

    #[test]
    fn change_pin_invalidates_the_token() {
        let mut issued = issue_token(Some(PERMISSION_MC | PERMISSION_CM), Some("a.test"));
        assert_eq!(
            issued.client_pin.token_permissions(),
            PERMISSION_MC | PERMISSION_CM
        );
        assert_eq!(issued.client_pin.token_rp_id(), Some("a.test"));

        let message = [0x5Fu8; 32];
        let param = auth_param(&issued.token, &message);
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Ok(true)
        );

        let request = change_pin_request(&issued.platform, &issued.shared, b"1234", b"567890");
        assert_eq!(
            issued.client_pin.change_pin(&request, &mut issued.state),
            Ok(())
        );
        assert_eq!(issued.client_pin.token_permissions(), 0);
        assert_eq!(issued.client_pin.token_rp_id(), None);

        // The old token is refused, in every operation.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::GetAssertion { rp_id: "a.test" },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }

    #[test]
    fn user_presence_operation_drops_the_token_permissions() {
        let mut issued = issue_token(
            Some(PERMISSION_MC | PERMISSION_GA | PERMISSION_CM),
            Some("a.test"),
        );
        let message = [0x60u8; 32];
        let param = auth_param(&issued.token, &message);
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Ok(true)
        );

        // The operation tested the user presence and succeeded: the token
        // loses every permission and its relying-party binding.
        issued.client_pin.close_user_presence_operation(true, true);
        assert_eq!(issued.client_pin.token_permissions(), 0);
        assert_eq!(issued.client_pin.token_rp_id(), None);

        // Any further use of the token is refused.
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::GetAssertion { rp_id: "a.test" },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::CredentialManagement {
                    scope: ManagementScope::Device,
                },
            ),
            Err(Ctap2Status::PinAuthInvalid)
        );
    }

    #[test]
    fn failed_operation_keeps_the_token_permissions() {
        let mut issued = issue_token(Some(PERMISSION_MC | PERMISSION_GA), Some("a.test"));
        let message = [0x61u8; 32];
        let param = auth_param(&issued.token, &message);
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Ok(true)
        );

        // The operation failed (no credential, excluded credential, no user
        // presence): the permissions are kept.
        issued.client_pin.close_user_presence_operation(true, false);
        assert_eq!(
            issued.client_pin.token_permissions(),
            PERMISSION_MC | PERMISSION_GA
        );
        assert_eq!(issued.client_pin.token_rp_id(), Some("a.test"));
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::MakeCredential { rp_id: "a.test" },
            ),
            Ok(true)
        );

        // An operation that does not use the token keeps them as well.
        issued.client_pin.close_user_presence_operation(false, true);
        assert_eq!(
            issued.client_pin.token_permissions(),
            PERMISSION_MC | PERMISSION_GA
        );
        assert_eq!(issued.client_pin.token_rp_id(), Some("a.test"));
        assert_eq!(
            authorize(
                &mut issued,
                Some(&param),
                &message,
                TokenOperation::GetAssertion { rp_id: "a.test" },
            ),
            Ok(true)
        );
    }
}
