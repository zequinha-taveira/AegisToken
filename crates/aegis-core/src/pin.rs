//! CTAP2 `clientPIN` protocol (PIN/UV auth protocol version 1).
//!
//! Implements ECDH key agreement on P-256, AES-256-CBC payload encryption and
//! HMAC-SHA-256 authentication, plus the PIN hash and retry accounting. PIN
//! state is provided by a [`PinState`] implementation (in-memory or sealed).

use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use minicbor::Decode;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::authenticator::Rng;
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
        .encrypt_padded_mut::<NoPadding>(&mut out[..plaintext.len()], plaintext.len())
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
        .decrypt_padded_mut::<NoPadding>(&mut out[..ciphertext.len()])
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

/// Stateful `clientPIN` handler.
#[derive(Default)]
pub struct ClientPin {
    agreement_private: Option<[u8; 32]>,
    pin_uv_auth_token: Option<[u8; 32]>,
}

impl ClientPin {
    /// Create a handler with no key agreement established.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            agreement_private: None,
            pin_uv_auth_token: None,
        }
    }

    /// Verify a `pinUvAuthParam` against the active PIN/UV auth token.
    ///
    /// `message` is the `clientDataHash` for `makeCredential`/`getAssertion`.
    #[must_use]
    pub fn verify_pin_uv_auth_param(&self, param: &[u8], message: &[u8]) -> bool {
        let Some(token) = self.pin_uv_auth_token else {
            return false;
        };
        if param.is_empty() || param.len() > 32 {
            return false;
        }
        let expected = hmac_sha256(&token, message);
        ct_eq(&expected[..param.len()], param)
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

    /// `setPIN`.
    pub fn set_pin(
        &mut self,
        request: &ClientPinRequest,
        state: &mut impl PinState,
    ) -> Result<(), Ctap2Status> {
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
        if !ct_eq(&expected, auth) {
            return Err(Ctap2Status::PinAuthInvalid);
        }

        let mut plain = [0u8; 96];
        let length = aes_cbc_decrypt(&shared, new_pin_enc, &mut plain)?;
        if length < 64 {
            return Err(Ctap2Status::InvalidLength);
        }
        state
            .set_pin_hash(pin_hash(&plain[..64]))
            .map_err(|_| Ctap2Status::Other)
    }

    /// `getPINToken`.
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
        if !ct_eq(&expected, auth) {
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
        let mut encrypted = [0u8; 48];
        let length = aes_cbc_encrypt(&shared, &token, &mut encrypted)?;
        Ok(PinTokenResponse {
            token: heapless::Vec::from_slice(&encrypted[..length])
                .map_err(|_| Ctap2Status::LimitExceeded)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng(u32);
    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (self.0 >> 24) as u8;
            }
        }
    }

    #[derive(Default)]
    struct TestPinState {
        hash: Option<[u8; 32]>,
        retries: u8,
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

    /// A platform-side helper driving the PIN protocol.
    struct Platform {
        private: [u8; 32],
        public: Ec2KeyAgreement,
    }

    impl Platform {
        fn new(rng: &mut TestRng) -> Self {
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

        fn shared(&self, authenticator: &Ec2KeyAgreement) -> [u8; 32] {
            shared_secret(&self.private, authenticator).unwrap()
        }
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
        };
        let response = authenticator
            .get_pin_token(&request, &mut state, &mut rng)
            .unwrap();

        // Decrypt the returned token.
        let mut token: [u8; 32] = Default::default();
        let length = aes_cbc_decrypt(&shared, &response.token, &mut token).unwrap();
        assert_eq!(length, 32);
        assert_eq!(state.retries, DEFAULT_RETRIES);

        // The issued token authorises makeCredential/getAssertion.
        let message = [0xABu8; 32];
        let param = hmac_sha256(&token, &message);
        assert!(authenticator.verify_pin_uv_auth_param(&param, &message));
        assert!(authenticator.verify_pin_uv_auth_param(&param[..16], &message));
        assert!(!authenticator.verify_pin_uv_auth_param(&param, b"other"));
        assert!(!ClientPin::new().verify_pin_uv_auth_param(&param, &message));
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
        };
        assert_eq!(
            authenticator.get_pin_token(&request, &mut state, &mut rng),
            Err(Ctap2Status::PinNotSet)
        );
        let _ = key_agreement;
    }
}
