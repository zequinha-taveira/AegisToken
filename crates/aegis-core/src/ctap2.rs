//! CTAP2 protocol core (PRD §15).
//!
//! Implements the CTAP2 command dispatch, status codes, `authenticatorGetInfo`
//! response and the COSE key type, plus request parsing for the credential
//! commands. Cryptographic operations, credential storage and attestation are
//! layered on top in later slices.

use minicbor::decode::Decoder;
use minicbor::encode::{Encoder, Write};

use crate::configuration::FixedString;
use crate::error::CoreError;

/// Largest CTAP2 message accepted, advertised in `getInfo`.
pub const MAX_MSG_SIZE: u16 = 1200;

/// Default AegisToken AAGUID.
pub const AAGUID: [u8; 16] = [
    0x41, 0x47, 0x53, 0x54, 0x4F, 0x4B, 0x45, 0x4E, 0xA3, 0x67, 0x69, 0x73, 0x2E, 0x30, 0x30, 0x31,
];

/// CTAP2 command codes.
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion`.
pub const CMD_GET_ASSERTION: u8 = 0x02;
/// `authenticatorGetInfo`.
pub const CMD_GET_INFO: u8 = 0x04;
/// `authenticatorClientPIN`.
pub const CMD_CLIENT_PIN: u8 = 0x06;
/// `authenticatorReset`.
pub const CMD_RESET: u8 = 0x07;
/// `authenticatorGetNextAssertion`.
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;
/// `authenticatorCredentialManagement`.
pub const CMD_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
/// `authenticatorSelection`.
pub const CMD_SELECTION: u8 = 0x0B;
/// `authenticatorLargeBlobs`.
pub const CMD_LARGE_BLOBS: u8 = 0x0C;
/// `authenticatorConfig`.
pub const CMD_CONFIG: u8 = 0x0D;

/// COSE key type for EC2.
pub const COSE_KEY_TYPE_EC2: i64 = 2;
/// COSE algorithm ES256 (ECDSA with SHA-256).
pub const COSE_ALG_ES256: i64 = -7;
/// COSE curve P-256.
pub const COSE_CURVE_P256: i64 = 1;
/// COSE key type for OKP (Octet Key Pair, RFC 8152).
pub const COSE_KEY_TYPE_OKP: i64 = 1;
/// COSE algorithm EdDSA.
pub const COSE_ALG_EDDSA: i64 = -8;
/// COSE curve Ed25519.
pub const COSE_CURVE_ED25519: i64 = 6;

/// CTAP2 status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctap2Status {
    /// Success.
    Ok = 0x00,
    /// Invalid or unsupported command.
    InvalidCommand = 0x01,
    /// Invalid parameter.
    InvalidParameter = 0x02,
    /// Invalid message length.
    InvalidLength = 0x03,
    /// Invalid sequence number.
    InvalidSeq = 0x04,
    /// Timed out.
    Timeout = 0x05,
    /// Channel busy.
    ChannelBusy = 0x06,
    /// Channel requires a lock.
    LockRequired = 0x0A,
    /// Invalid channel.
    InvalidChannel = 0x0B,
    /// Unexpected CBOR type.
    CborUnexpectedType = 0x11,
    /// Invalid CBOR.
    InvalidCbor = 0x12,
    /// Missing required parameter.
    MissingParameter = 0x14,
    /// A limit was exceeded.
    LimitExceeded = 0x15,
    /// Unsupported extension.
    UnsupportedExtension = 0x16,
    /// Credential already excluded.
    CredentialExcluded = 0x19,
    /// Processing.
    Processing = 0x21,
    /// Invalid credential.
    InvalidCredential = 0x22,
    /// User action pending.
    UserActionPending = 0x23,
    /// Operation pending.
    OperationPending = 0x24,
    /// Unsupported algorithm.
    UnsupportedAlgorithm = 0x26,
    /// No credentials found.
    NoCredentials = 0x2E,
    /// User action timed out.
    UserActionTimeout = 0x2F,
    /// Operation not allowed.
    NotAllowed = 0x30,
    /// PIN invalid.
    PinInvalid = 0x31,
    /// PIN blocked.
    PinBlocked = 0x32,
    /// PIN auth invalid.
    PinAuthInvalid = 0x33,
    /// PIN auth blocked.
    PinAuthBlocked = 0x34,
    /// PIN not set.
    PinNotSet = 0x35,
    /// PIN required.
    PinRequired = 0x36,
    /// PIN policy violation.
    PinPolicyViolation = 0x37,
    /// Request too large.
    RequestTooLarge = 0x39,
    /// Action timed out.
    ActionTimeout = 0x3A,
    /// User presence required.
    UpRequired = 0x3B,
    /// UV blocked.
    UvBlocked = 0x3C,
    /// Unspecified error.
    Other = 0x7F,
}

impl Ctap2Status {
    /// Wire status code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

impl From<Ctap2Status> for CoreError {
    fn from(status: Ctap2Status) -> Self {
        match status {
            Ctap2Status::InvalidParameter
            | Ctap2Status::InvalidLength
            | Ctap2Status::MissingParameter => CoreError::InvalidCommand,
            Ctap2Status::InvalidCbor | Ctap2Status::CborUnexpectedType => CoreError::ProtocolError,
            Ctap2Status::NotAllowed | Ctap2Status::PinAuthInvalid => CoreError::Unauthorized,
            _ => CoreError::ProtocolError,
        }
    }
}

/// Map a decode error to a CTAP2 status.
fn invalid(_: minicbor::decode::Error) -> Ctap2Status {
    Ctap2Status::InvalidCbor
}

/// A COSE EC2 P-256 public key (`COSE_Key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ec2PublicKey {
    /// COSE curve (`crv`).
    pub crv: i64,
    /// X coordinate.
    pub x: [u8; 32],
    /// Y coordinate.
    pub y: [u8; 32],
}

impl<C> minicbor::Encode<C> for Ec2PublicKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(5)?;
        e.i64(1)?;
        e.i64(COSE_KEY_TYPE_EC2)?;
        e.i64(3)?;
        e.i64(COSE_ALG_ES256)?;
        e.i64(-1)?;
        e.i64(self.crv)?;
        e.i64(-2)?;
        e.bytes(&self.x)?;
        e.i64(-3)?;
        e.bytes(&self.y)?;
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Ec2PublicKey {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let len = d
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite map"))?;
        let mut key = Ec2PublicKey {
            crv: 0,
            x: [0; 32],
            y: [0; 32],
        };
        for _ in 0..len {
            match d.i64()? {
                -1 => key.crv = d.i64()?,
                -2 => {
                    let bytes = d.bytes()?;
                    if bytes.len() != 32 {
                        return Err(minicbor::decode::Error::message("bad x length"));
                    }
                    key.x.copy_from_slice(bytes);
                }
                -3 => {
                    let bytes = d.bytes()?;
                    if bytes.len() != 32 {
                        return Err(minicbor::decode::Error::message("bad y length"));
                    }
                    key.y.copy_from_slice(bytes);
                }
                _ => d.skip()?,
            }
        }
        Ok(key)
    }
}

/// A COSE OKP Ed25519 public key (`COSE_Key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OkpPublicKey {
    /// COSE curve (`crv`); always [`COSE_CURVE_ED25519`].
    pub crv: i64,
    /// Raw 32-byte public key (`x`).
    pub x: [u8; 32],
}

impl<C> minicbor::Encode<C> for OkpPublicKey {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(4)?;
        e.i64(1)?;
        e.i64(COSE_KEY_TYPE_OKP)?;
        e.i64(3)?;
        e.i64(COSE_ALG_EDDSA)?;
        e.i64(-1)?;
        e.i64(self.crv)?;
        e.i64(-2)?;
        e.bytes(&self.x)?;
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for OkpPublicKey {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let len = d
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("indefinite map"))?;
        let mut key = OkpPublicKey { crv: 0, x: [0; 32] };
        for _ in 0..len {
            match d.i64()? {
                -1 => key.crv = d.i64()?,
                -2 => {
                    let bytes = d.bytes()?;
                    if bytes.len() != 32 {
                        return Err(minicbor::decode::Error::message("bad x length"));
                    }
                    key.x.copy_from_slice(bytes);
                }
                _ => d.skip()?,
            }
        }
        Ok(key)
    }
}

/// `authenticatorGetInfo` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetInfoResponse {
    /// Supported CTAP versions.
    pub versions: &'static [&'static str],
    /// Authenticator AAGUID.
    pub aaguid: [u8; 16],
    /// Resident-key support.
    pub options_rk: bool,
    /// User-presence support.
    pub options_up: bool,
    /// User-verification support.
    pub options_uv: bool,
    /// Whether a PIN can be configured.
    pub options_client_pin: bool,
    /// Maximum message size.
    pub max_msg_size: u16,
    /// Supported PIN/UV auth protocols.
    pub pin_protocols: &'static [u8],
}

impl Default for GetInfoResponse {
    fn default() -> Self {
        Self {
            versions: &["FIDO_2_0", "U2F_V2"],
            aaguid: AAGUID,
            options_rk: true,
            options_up: true,
            options_uv: false,
            // clientPIN (PIN/UV auth protocol v1) is advertised; presence is UP-only.
            options_client_pin: true,
            max_msg_size: MAX_MSG_SIZE,
            pin_protocols: &[1],
        }
    }
}

impl<C> minicbor::Encode<C> for GetInfoResponse {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let with_pin = !self.pin_protocols.is_empty();
        e.map(if with_pin { 5 } else { 4 })?;

        e.u8(1)?;
        e.array(self.versions.len() as u64)?;
        for version in self.versions {
            e.str(version)?;
        }

        e.u8(3)?;
        e.bytes(&self.aaguid)?;

        e.u8(4)?;
        e.map(4)?;
        e.str("rk")?;
        e.bool(self.options_rk)?;
        e.str("up")?;
        e.bool(self.options_up)?;
        e.str("uv")?;
        e.bool(self.options_uv)?;
        e.str("clientPin")?;
        e.bool(self.options_client_pin)?;

        e.u8(5)?;
        e.u16(self.max_msg_size)?;

        if with_pin {
            e.u8(6)?;
            e.array(self.pin_protocols.len() as u64)?;
            for protocol in self.pin_protocols {
                e.u8(*protocol)?;
            }
        }
        Ok(())
    }
}

/// Credential descriptor used by exclude/allow lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialDescriptor {
    /// Credential id.
    pub id: heapless::Vec<u8, 64>,
}

/// `authenticatorMakeCredential` request (fields used by the MVP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeCredentialRequest {
    /// Client data hash (SHA-256), 32 bytes.
    pub client_data_hash: [u8; 32],
    /// Relying party identifier.
    pub rp_id: FixedString<64>,
    /// User handle.
    pub user_id: heapless::Vec<u8, 64>,
    /// Credentials the client wants to avoid re-creating.
    pub exclude_list: heapless::Vec<CredentialDescriptor, 8>,
    /// Acceptable credential algorithms, in client preference order.
    ///
    /// Each entry is a COSE algorithm identifier (`-7` for ES256, `-8` for
    /// EdDSA). Empty when the client sent no `pubKeyCredParams`.
    pub algs: heapless::Vec<i64, 8>,
    /// Resident-key requested.
    pub rk: bool,
    /// User verification requested.
    pub uv: bool,
    /// PIN/UV auth parameter over the client data hash, when provided.
    pub pin_uv_auth_param: Option<heapless::Vec<u8, 64>>,
}

/// `authenticatorGetAssertion` request (fields used by the MVP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetAssertionRequest {
    /// Relying party identifier.
    pub rp_id: FixedString<64>,
    /// Client data hash (SHA-256), 32 bytes.
    pub client_data_hash: [u8; 32],
    /// Credentials the client will accept.
    pub allow_list: heapless::Vec<CredentialDescriptor, 8>,
    /// User presence requested.
    pub up: bool,
    /// User verification requested.
    pub uv: bool,
    /// PIN/UV auth parameter over the client data hash, when provided.
    pub pin_uv_auth_param: Option<heapless::Vec<u8, 64>>,
}

/// A parsed CTAP2 request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ctap2Request {
    /// `authenticatorMakeCredential`.
    MakeCredential(MakeCredentialRequest),
    /// `authenticatorGetAssertion`.
    GetAssertion(GetAssertionRequest),
    /// `authenticatorGetInfo`.
    GetInfo,
    /// `authenticatorClientPIN`.
    ClientPin,
    /// `authenticatorReset`.
    Reset,
    /// `authenticatorGetNextAssertion`.
    GetNextAssertion,
    /// `authenticatorCredentialManagement`.
    CredentialManagement,
    /// `authenticatorSelection`.
    Selection,
    /// `authenticatorLargeBlobs`.
    LargeBlobs,
    /// `authenticatorConfig`.
    Config,
}

/// Parse a CTAP2 request from its command byte and CBOR parameters.
pub fn parse_request(command: u8, params: &[u8]) -> Result<Ctap2Request, Ctap2Status> {
    match command {
        CMD_MAKE_CREDENTIAL => parse_make_credential(params).map(Ctap2Request::MakeCredential),
        CMD_GET_ASSERTION => parse_get_assertion(params).map(Ctap2Request::GetAssertion),
        CMD_GET_INFO => Ok(Ctap2Request::GetInfo),
        CMD_CLIENT_PIN => Ok(Ctap2Request::ClientPin),
        CMD_RESET => Ok(Ctap2Request::Reset),
        CMD_GET_NEXT_ASSERTION => Ok(Ctap2Request::GetNextAssertion),
        CMD_CREDENTIAL_MANAGEMENT => Ok(Ctap2Request::CredentialManagement),
        CMD_SELECTION => Ok(Ctap2Request::Selection),
        CMD_LARGE_BLOBS => Ok(Ctap2Request::LargeBlobs),
        CMD_CONFIG => Ok(Ctap2Request::Config),
        _ => Err(Ctap2Status::InvalidCommand),
    }
}

fn read_map_len(d: &mut Decoder<'_>) -> Result<u64, Ctap2Status> {
    d.map().map_err(invalid)?.ok_or(Ctap2Status::InvalidCbor)
}

fn parse_rp_id(d: &mut Decoder<'_>) -> Result<FixedString<64>, Ctap2Status> {
    // PublicKeyCredentialRpEntity: map with text keys ("id", "name").
    let len = read_map_len(d)?;
    let mut id = None;
    for _ in 0..len {
        let key = d.str().map_err(invalid)?;
        if key == "id" {
            let value = d.str().map_err(invalid)?;
            id = Some(FixedString::new(value).map_err(|_| Ctap2Status::LimitExceeded)?);
        } else {
            d.skip().map_err(invalid)?;
        }
    }
    id.ok_or(Ctap2Status::MissingParameter)
}

fn parse_user_id(d: &mut Decoder<'_>) -> Result<heapless::Vec<u8, 64>, Ctap2Status> {
    // PublicKeyCredentialUserEntity: map with text keys ("id", "name",
    // "displayName"); only "id" is required here.
    let len = read_map_len(d)?;
    let mut id: heapless::Vec<u8, 64> = heapless::Vec::new();
    let mut found = false;
    for _ in 0..len {
        let key = d.str().map_err(invalid)?;
        if key == "id" {
            let value = d.bytes().map_err(invalid)?;
            id.extend_from_slice(value)
                .map_err(|_| Ctap2Status::LimitExceeded)?;
            found = true;
        } else {
            d.skip().map_err(invalid)?;
        }
    }
    if found {
        Ok(id)
    } else {
        Err(Ctap2Status::MissingParameter)
    }
}

fn read_client_data_hash(d: &mut Decoder<'_>) -> Result<[u8; 32], Ctap2Status> {
    let bytes = d.bytes().map_err(invalid)?;
    if bytes.len() != 32 {
        return Err(Ctap2Status::InvalidLength);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(bytes);
    Ok(hash)
}

fn parse_options(d: &mut Decoder<'_>) -> Result<(bool, bool, bool), Ctap2Status> {
    let len = read_map_len(d)?;
    let mut rk = false;
    let mut uv = false;
    let mut up = false;
    for _ in 0..len {
        let key = d.str().map_err(invalid)?;
        match key {
            "rk" => rk = d.bool().map_err(invalid)?,
            "uv" => uv = d.bool().map_err(invalid)?,
            "up" => up = d.bool().map_err(invalid)?,
            _ => d.skip().map_err(invalid)?,
        }
    }
    Ok((rk, uv, up))
}

fn parse_credential_descriptor(d: &mut Decoder<'_>) -> Result<CredentialDescriptor, Ctap2Status> {
    // PublicKeyCredentialDescriptor: map with text keys ("type", "id",
    // "transports"); only "id" is needed here.
    let len = read_map_len(d)?;
    let mut id = None;
    for _ in 0..len {
        let key = d.str().map_err(invalid)?;
        if key == "id" {
            let bytes = d.bytes().map_err(invalid)?;
            id = Some(heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?);
        } else {
            d.skip().map_err(invalid)?;
        }
    }
    Ok(CredentialDescriptor {
        id: id.ok_or(Ctap2Status::MissingParameter)?,
    })
}

fn parse_credential_list(
    d: &mut Decoder<'_>,
    out: &mut heapless::Vec<CredentialDescriptor, 8>,
) -> Result<(), Ctap2Status> {
    let len = d
        .array()
        .map_err(invalid)?
        .ok_or(Ctap2Status::InvalidCbor)?;
    for _ in 0..len {
        out.push(parse_credential_descriptor(d)?)
            .map_err(|_| Ctap2Status::LimitExceeded)?;
    }
    Ok(())
}

fn parse_pub_key_cred_params(
    d: &mut Decoder<'_>,
    out: &mut heapless::Vec<i64, 8>,
) -> Result<(), Ctap2Status> {
    // `pubKeyCredParams`: array of `{"type": "public-key", "alg": <int>}`
    // maps with text keys, in client preference order.
    let len = d
        .array()
        .map_err(invalid)?
        .ok_or(Ctap2Status::InvalidCbor)?;
    for _ in 0..len {
        let entries = read_map_len(d)?;
        let mut alg = None;
        for _ in 0..entries {
            let key = d.str().map_err(invalid)?;
            if key == "alg" {
                alg = Some(d.i64().map_err(invalid)?);
            } else {
                d.skip().map_err(invalid)?;
            }
        }
        if let Some(alg) = alg {
            out.push(alg).map_err(|_| Ctap2Status::LimitExceeded)?;
        }
    }
    Ok(())
}

fn parse_make_credential(params: &[u8]) -> Result<MakeCredentialRequest, Ctap2Status> {
    let mut d = Decoder::new(params);
    let len = read_map_len(&mut d)?;
    let mut client_data_hash = None;
    let mut rp_id = None;
    let mut user_id: heapless::Vec<u8, 64> = heapless::Vec::new();
    let mut exclude_list = heapless::Vec::new();
    let mut algs = heapless::Vec::new();
    let mut rk = false;
    let mut uv = false;
    let mut pin_uv_auth_param = None;

    for _ in 0..len {
        let key = d.i64().map_err(invalid)?;
        match key {
            0x01 => client_data_hash = Some(read_client_data_hash(&mut d)?),
            0x02 => rp_id = Some(parse_rp_id(&mut d)?),
            0x03 => user_id = parse_user_id(&mut d)?,
            0x04 => parse_pub_key_cred_params(&mut d, &mut algs)?,
            0x05 => parse_credential_list(&mut d, &mut exclude_list)?,
            0x07 => {
                let (parsed_rk, parsed_uv, _up) = parse_options(&mut d)?;
                rk = parsed_rk;
                uv = parsed_uv;
            }
            0x08 => {
                let bytes = d.bytes().map_err(invalid)?;
                pin_uv_auth_param =
                    Some(heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?);
            }
            _ => d.skip().map_err(invalid)?,
        }
    }

    Ok(MakeCredentialRequest {
        client_data_hash: client_data_hash.ok_or(Ctap2Status::MissingParameter)?,
        rp_id: rp_id.ok_or(Ctap2Status::MissingParameter)?,
        user_id,
        exclude_list,
        algs,
        rk,
        uv,
        pin_uv_auth_param,
    })
}

fn parse_get_assertion(params: &[u8]) -> Result<GetAssertionRequest, Ctap2Status> {
    let mut d = Decoder::new(params);
    let len = read_map_len(&mut d)?;
    let mut rp_id = None;
    let mut client_data_hash = None;
    let mut allow_list = heapless::Vec::new();
    let mut up = true;
    let mut uv = false;
    let mut pin_uv_auth_param = None;

    for _ in 0..len {
        let key = d.i64().map_err(invalid)?;
        match key {
            0x01 => {
                let value = d.str().map_err(invalid)?;
                rp_id = Some(FixedString::new(value).map_err(|_| Ctap2Status::LimitExceeded)?);
            }
            0x02 => client_data_hash = Some(read_client_data_hash(&mut d)?),
            0x03 => parse_credential_list(&mut d, &mut allow_list)?,
            0x05 => {
                let (_rk, parsed_uv, parsed_up) = parse_options(&mut d)?;
                up = parsed_up;
                uv = parsed_uv;
            }
            0x06 => {
                let bytes = d.bytes().map_err(invalid)?;
                pin_uv_auth_param =
                    Some(heapless::Vec::from_slice(bytes).map_err(|_| Ctap2Status::LimitExceeded)?);
            }
            _ => d.skip().map_err(invalid)?,
        }
    }

    Ok(GetAssertionRequest {
        rp_id: rp_id.ok_or(Ctap2Status::MissingParameter)?,
        client_data_hash: client_data_hash.ok_or(Ctap2Status::MissingParameter)?,
        allow_list,
        up,
        uv,
        pin_uv_auth_param,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode<T: minicbor::Encode<()>>(value: &T, buf: &mut [u8]) -> usize {
        crate::codec::encode_into(value, buf).unwrap()
    }

    struct TestWriter<'a> {
        buf: &'a mut [u8],
        len: usize,
    }

    impl minicbor::encode::Write for TestWriter<'_> {
        type Error = core::convert::Infallible;

        fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.buf[self.len..self.len + data.len()].copy_from_slice(data);
            self.len += data.len();
            Ok(())
        }
    }

    fn with_encoder(buf: &mut [u8], f: impl FnOnce(&mut Encoder<&mut TestWriter<'_>>)) -> usize {
        let mut writer = TestWriter { buf, len: 0 };
        {
            let mut encoder = Encoder::new(&mut writer);
            f(&mut encoder);
        }
        writer.len
    }

    #[test]
    fn status_codes_are_canonical() {
        assert_eq!(Ctap2Status::Ok.code(), 0x00);
        assert_eq!(Ctap2Status::InvalidCommand.code(), 0x01);
        assert_eq!(Ctap2Status::UnsupportedAlgorithm.code(), 0x26);
        assert_eq!(Ctap2Status::NoCredentials.code(), 0x2E);
        assert_eq!(Ctap2Status::UpRequired.code(), 0x3B);
    }

    #[test]
    fn cose_key_round_trips() {
        let key = Ec2PublicKey {
            crv: COSE_CURVE_P256,
            x: [0x11; 32],
            y: [0x22; 32],
        };
        let mut buf = [0u8; 128];
        let len = encode(&key, &mut buf);
        let decoded: Ec2PublicKey = crate::codec::decode_from(&buf[..len]).unwrap();
        assert_eq!(decoded, key);
        // COSE key type is EC2 and algorithm is ES256.
        assert_eq!(buf[0], 0xA5); // map(5)
    }

    #[test]
    fn get_info_encodes_expected_fields() {
        let info = GetInfoResponse::default();
        let mut buf = [0u8; 128];
        let len = encode(&info, &mut buf);

        let mut d = Decoder::new(&buf[..len]);
        let entries = d.map().unwrap().unwrap();
        let mut versions = 0usize;
        let mut aaguid_len = 0usize;
        let mut up = false;
        for _ in 0..entries {
            match d.u8().unwrap() {
                1 => {
                    let n = d.array().unwrap().unwrap();
                    versions = n as usize;
                    for _ in 0..n {
                        d.skip().unwrap();
                    }
                }
                3 => aaguid_len = d.bytes().unwrap().len(),
                4 => {
                    let n = d.map().unwrap().unwrap();
                    for _ in 0..n {
                        let key = d.str().unwrap();
                        let value = d.bool().unwrap();
                        if key == "up" {
                            up = value;
                        }
                    }
                }
                5 => {
                    assert_eq!(d.u16().unwrap(), MAX_MSG_SIZE);
                }
                _ => d.skip().unwrap(),
            }
        }
        assert_eq!(versions, 2);
        assert_eq!(aaguid_len, 16);
        assert!(up);
    }

    #[test]
    fn get_info_request_parses() {
        assert_eq!(parse_request(CMD_GET_INFO, &[]), Ok(Ctap2Request::GetInfo));
    }

    #[test]
    fn reset_request_parses() {
        assert_eq!(parse_request(CMD_RESET, &[]), Ok(Ctap2Request::Reset));
    }

    #[test]
    fn unknown_command_is_invalid() {
        assert_eq!(parse_request(0x7F, &[]), Err(Ctap2Status::InvalidCommand));
    }

    #[test]
    fn make_credential_parses_required_fields() {
        let mut buf = [0u8; 256];
        let len = with_encoder(&mut buf, |e| {
            e.map(4).unwrap();
            e.u8(0x01).unwrap();
            e.bytes(&[0xAB; 32]).unwrap();
            e.u8(0x02).unwrap();
            e.map(1).unwrap();
            e.str("id").unwrap();
            e.str("example.com").unwrap();
            e.u8(0x03).unwrap();
            e.map(1).unwrap();
            e.str("id").unwrap();
            e.bytes(&[1, 2, 3, 4]).unwrap();
            e.u8(0x07).unwrap();
            e.map(1).unwrap();
            e.str("rk").unwrap();
            e.bool(true).unwrap();
        });

        let request = parse_request(CMD_MAKE_CREDENTIAL, &buf[..len]).unwrap();
        let Ctap2Request::MakeCredential(request) = request else {
            panic!("expected makeCredential");
        };
        assert_eq!(request.client_data_hash, [0xAB; 32]);
        assert_eq!(request.rp_id.as_str(), "example.com");
        assert_eq!(&request.user_id[..], &[1, 2, 3, 4]);
        assert!(request.rk);
        assert!(!request.uv);
    }

    #[test]
    fn make_credential_missing_field_is_reported() {
        let mut buf = [0u8; 64];
        let len = with_encoder(&mut buf, |e| {
            e.map(1).unwrap();
            e.u8(0x01).unwrap();
            e.bytes(&[0xAB; 32]).unwrap();
        });
        assert_eq!(
            parse_request(CMD_MAKE_CREDENTIAL, &buf[..len]),
            Err(Ctap2Status::MissingParameter)
        );
    }

    #[test]
    fn make_credential_parses_pub_key_cred_params_in_order() {
        let mut buf = [0u8; 256];
        let len = with_encoder(&mut buf, |e| {
            e.map(5).unwrap();
            e.u8(0x01).unwrap();
            e.bytes(&[0xAB; 32]).unwrap();
            e.u8(0x02).unwrap();
            e.map(1).unwrap();
            e.str("id").unwrap();
            e.str("example.com").unwrap();
            e.u8(0x03).unwrap();
            e.map(1).unwrap();
            e.str("id").unwrap();
            e.bytes(&[1, 2, 3, 4]).unwrap();
            e.u8(0x04).unwrap();
            e.array(2).unwrap();
            e.map(2).unwrap();
            e.str("type").unwrap();
            e.str("public-key").unwrap();
            e.str("alg").unwrap();
            e.i64(COSE_ALG_EDDSA).unwrap();
            e.map(2).unwrap();
            e.str("type").unwrap();
            e.str("public-key").unwrap();
            e.str("alg").unwrap();
            e.i64(COSE_ALG_ES256).unwrap();
            e.u8(0x07).unwrap();
            e.map(0).unwrap();
        });

        let request = parse_request(CMD_MAKE_CREDENTIAL, &buf[..len]).unwrap();
        let Ctap2Request::MakeCredential(request) = request else {
            panic!("expected makeCredential");
        };
        assert_eq!(&request.algs[..], &[COSE_ALG_EDDSA, COSE_ALG_ES256]);
    }

    #[test]
    fn okp_public_key_round_trips() {
        let key = OkpPublicKey {
            crv: COSE_CURVE_ED25519,
            x: [0x42; 32],
        };
        let mut buf = [0u8; 64];
        let len = encode(&key, &mut buf);
        let decoded: OkpPublicKey = crate::codec::decode_from(&buf[..len]).unwrap();
        assert_eq!(decoded, key);
        // COSE key type is OKP and algorithm is EdDSA.
        assert_eq!(buf[0], 0xA4); // map(4)
    }

    #[test]
    fn bad_client_data_hash_length_is_rejected() {
        let mut buf = [0u8; 64];
        let len = with_encoder(&mut buf, |e| {
            e.map(1).unwrap();
            e.u8(0x01).unwrap();
            e.bytes(&[0xAB; 16]).unwrap();
        });
        assert_eq!(
            parse_request(CMD_MAKE_CREDENTIAL, &buf[..len]),
            Err(Ctap2Status::InvalidLength)
        );
    }

    #[test]
    fn non_map_request_is_invalid_cbor() {
        assert_eq!(
            parse_request(CMD_GET_ASSERTION, &[0x01]),
            Err(Ctap2Status::InvalidCbor)
        );
    }

    #[test]
    fn get_assertion_parses() {
        let mut buf = [0u8; 128];
        let len = with_encoder(&mut buf, |e| {
            e.map(2).unwrap();
            e.u8(0x01).unwrap();
            e.str("example.org").unwrap();
            e.u8(0x02).unwrap();
            e.bytes(&[0xCD; 32]).unwrap();
        });
        let request = parse_request(CMD_GET_ASSERTION, &buf[..len]).unwrap();
        let Ctap2Request::GetAssertion(request) = request else {
            panic!("expected getAssertion");
        };
        assert_eq!(request.rp_id.as_str(), "example.org");
        assert_eq!(request.client_data_hash, [0xCD; 32]);
        assert!(request.up);
    }

    #[test]
    fn indefinite_map_is_rejected() {
        // 0xBF = indefinite map, 0xFF = break.
        assert_eq!(
            parse_request(CMD_GET_ASSERTION, &[0xBF, 0xFF]),
            Err(Ctap2Status::InvalidCbor)
        );
    }
}
