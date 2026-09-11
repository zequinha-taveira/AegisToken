//! CTAP1 / U2F mapping (PRD §15).
//!
//! U2F travels over CTAPHID `MSG` as a raw (extended) APDU. This module parses
//! the APDU, dispatches the U2F commands and produces the `data || SW1 SW2`
//! response used by U2F.
//!
//! `U2F_REGISTER` requires an attestation certificate and is not supported yet
//! (`SW_INS_NOT_SUPPORTED`); `U2F_VERSION` and `U2F_AUTHENTICATE` (check-only
//! and sign) are implemented.

use sha2::{Digest, Sha256};

use crate::authenticator::{self, CredentialStore};

/// `U2F_REGISTER` instruction.
pub const INS_REGISTER: u8 = 0x01;
/// `U2F_AUTHENTICATE` instruction.
pub const INS_AUTHENTICATE: u8 = 0x02;
/// `U2F_VERSION` instruction.
pub const INS_VERSION: u8 = 0x03;

/// Success status word.
pub const SW_NO_ERROR: u16 = 0x9000;
/// Wrong length.
pub const SW_WRONG_LENGTH: u16 = 0x6700;
/// Conditions of use not satisfied.
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
/// Wrong data.
pub const SW_WRONG_DATA: u16 = 0x6A80;
/// Instruction not supported.
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
/// Class not supported.
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;

/// Maximum APDU data length.
pub const MAX_APDU_DATA: usize = 256;
/// Maximum U2F response data length.
pub const MAX_RESPONSE: usize = 512;

/// U2F `AUTHENTICATE` P1: check-only.
pub const AUTH_CHECK_ONLY: u8 = 0x07;
/// U2F `AUTHENTICATE` P1: enforce user presence and sign.
pub const AUTH_ENFORCE: u8 = 0x03;

/// A parsed U2F APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Command data.
    pub data: heapless::Vec<u8, MAX_APDU_DATA>,
}

/// Parse a raw U2F (extended) APDU.
pub fn parse_apdu(bytes: &[u8]) -> Result<Apdu, u16> {
    if bytes.len() < 7 {
        return Err(SW_WRONG_LENGTH);
    }
    let length =
        (usize::from(bytes[4]) << 16) | (usize::from(bytes[5]) << 8) | usize::from(bytes[6]);
    if length > MAX_APDU_DATA || bytes.len() < 7 + length {
        return Err(SW_WRONG_LENGTH);
    }
    let mut data: heapless::Vec<u8, MAX_APDU_DATA> = heapless::Vec::new();
    data.extend_from_slice(&bytes[7..7 + length])
        .map_err(|_| SW_WRONG_LENGTH)?;
    Ok(Apdu {
        cla: bytes[0],
        ins: bytes[1],
        p1: bytes[2],
        p2: bytes[3],
        data,
    })
}

/// A U2F response: payload plus status word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct U2fResponse {
    /// Response payload.
    pub data: heapless::Vec<u8, MAX_RESPONSE>,
    /// Status word.
    pub status: u16,
}

impl U2fResponse {
    /// Successful response with `data`.
    pub fn ok(data: &[u8]) -> Self {
        let mut payload: heapless::Vec<u8, MAX_RESPONSE> = heapless::Vec::new();
        payload.extend_from_slice(data).expect("response data fits");
        Self {
            data: payload,
            status: SW_NO_ERROR,
        }
    }

    /// Error response with status word `status`.
    #[must_use]
    pub const fn error(status: u16) -> Self {
        Self {
            data: heapless::Vec::new(),
            status,
        }
    }

    /// Encode as `data || SW1 SW2`.
    pub fn encode_into(&self, out: &mut [u8]) -> usize {
        let length = self.data.len();
        out[..length].copy_from_slice(&self.data);
        out[length..length + 2].copy_from_slice(&self.status.to_be_bytes());
        length + 2
    }
}

/// Whether the request requires User Presence (a signing authenticate).
#[must_use]
pub fn requires_user_presence(request: &[u8]) -> bool {
    matches!(parse_apdu(request), Ok(apdu) if apdu.ins == INS_AUTHENTICATE && apdu.p1 == AUTH_ENFORCE)
}

/// Handle a U2F request.
pub fn handle<C: CredentialStore>(
    request: &[u8],
    store: &mut C,
    up_confirmed: bool,
) -> U2fResponse {
    let apdu = match parse_apdu(request) {
        Ok(apdu) => apdu,
        Err(status) => return U2fResponse::error(status),
    };
    if apdu.cla != 0 {
        return U2fResponse::error(SW_CLA_NOT_SUPPORTED);
    }
    match apdu.ins {
        INS_VERSION => U2fResponse::ok(b"U2F_V2"),
        INS_AUTHENTICATE => authenticate(&apdu, store, up_confirmed),
        INS_REGISTER => U2fResponse::error(SW_INS_NOT_SUPPORTED),
        _ => U2fResponse::error(SW_INS_NOT_SUPPORTED),
    }
}

fn authenticate<C: CredentialStore>(apdu: &Apdu, store: &mut C, up_confirmed: bool) -> U2fResponse {
    // challenge (32) || application (32) || key handle length (1) || key handle.
    if apdu.data.len() < 65 {
        return U2fResponse::error(SW_WRONG_DATA);
    }
    let challenge = &apdu.data[0..32];
    let application = &apdu.data[32..64];
    let key_handle_length = usize::from(apdu.data[64]);
    if key_handle_length == 0 || apdu.data.len() < 65 + key_handle_length {
        return U2fResponse::error(SW_WRONG_DATA);
    }
    let key_handle = &apdu.data[65..65 + key_handle_length];

    let Some(credential) = store.get(key_handle) else {
        return U2fResponse::error(SW_WRONG_DATA);
    };

    match apdu.p1 {
        AUTH_CHECK_ONLY => U2fResponse::ok(&[]),
        AUTH_ENFORCE => {
            if !up_confirmed {
                return U2fResponse::error(SW_CONDITIONS_NOT_SATISFIED);
            }
            let counter = store.next_sign_count(key_handle).unwrap_or(0);
            let counter_bytes = counter.to_be_bytes();

            let mut message: heapless::Vec<u8, 128> = heapless::Vec::new();
            message.push(0x00).expect("fits");
            message.extend_from_slice(application).expect("fits");
            message.push(0x01).expect("fits");
            message.extend_from_slice(&counter_bytes).expect("fits");
            message.extend_from_slice(challenge).expect("fits");

            let signature = match authenticator::sign_message(&credential.private_key, &message) {
                Ok(signature) => signature,
                Err(_) => return U2fResponse::error(SW_CONDITIONS_NOT_SATISFIED),
            };

            let mut data: heapless::Vec<u8, MAX_RESPONSE> = heapless::Vec::new();
            data.push(0x01).expect("fits");
            data.extend_from_slice(&counter_bytes).expect("fits");
            data.extend_from_slice(&signature).expect("fits");
            U2fResponse {
                data,
                status: SW_NO_ERROR,
            }
        }
        _ => U2fResponse::error(SW_WRONG_DATA),
    }
}

/// U2F application-parameter hash (exposed for completeness/tests).
#[must_use]
pub fn application_parameter_hash(app_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(app_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::{self, MemoryCredentialStore, Rng};
    use crate::configuration::FixedString;
    use crate::ctap2::MakeCredentialRequest;

    struct TestRng(u32);
    impl Rng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (self.0 >> 24) as u8;
            }
        }
    }

    fn authenticate_request(
        challenge: &[u8; 32],
        application: &[u8; 32],
        key_handle: &[u8],
        p1: u8,
    ) -> heapless::Vec<u8, 256> {
        let mut data: heapless::Vec<u8, 256> = heapless::Vec::new();
        data.extend_from_slice(challenge).unwrap();
        data.extend_from_slice(application).unwrap();
        data.push(key_handle.len() as u8).unwrap();
        data.extend_from_slice(key_handle).unwrap();

        let mut apdu: heapless::Vec<u8, 256> = heapless::Vec::new();
        apdu.push(0x00).unwrap();
        apdu.push(INS_AUTHENTICATE).unwrap();
        apdu.push(p1).unwrap();
        apdu.push(0x00).unwrap();
        let length = data.len();
        apdu.push(((length >> 16) & 0xFF) as u8).unwrap();
        apdu.push(((length >> 8) & 0xFF) as u8).unwrap();
        apdu.push((length & 0xFF) as u8).unwrap();
        apdu.extend_from_slice(&data).unwrap();
        apdu
    }

    fn version_request() -> heapless::Vec<u8, 16> {
        heapless::Vec::from_slice(&[0x00, INS_VERSION, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap()
    }

    fn store_with_credential() -> (MemoryCredentialStore, heapless::Vec<u8, 32>) {
        let mut store = MemoryCredentialStore::new();
        let mut rng = TestRng(1);
        let request = MakeCredentialRequest {
            client_data_hash: [0x11; 32],
            rp_id: FixedString::new("example.com").unwrap(),
            user_id: heapless::Vec::from_slice(&[1, 2, 3]).unwrap(),
            exclude_list: heapless::Vec::new(),
            rk: true,
            uv: false,
            pin_uv_auth_param: None,
        };
        let response =
            authenticator::make_credential(&mut store, &mut rng, &request, true, false).unwrap();
        let length = u16::from_be_bytes([response.auth_data[53], response.auth_data[54]]) as usize;
        let id = heapless::Vec::from_slice(&response.auth_data[55..55 + length]).unwrap();
        (store, id)
    }

    #[test]
    fn version_is_supported() {
        let mut store = MemoryCredentialStore::new();
        let response = handle(&version_request(), &mut store, false);
        assert_eq!(response.status, SW_NO_ERROR);
        assert_eq!(&response.data[..], b"U2F_V2");
    }

    #[test]
    fn check_only_reports_known_and_unknown() {
        let (mut store, id) = store_with_credential();
        let request = authenticate_request(&[0xAA; 32], &[0xBB; 32], &id, AUTH_CHECK_ONLY);
        assert_eq!(handle(&request, &mut store, false).status, SW_NO_ERROR);

        let unknown = [0u8; 16];
        let request = authenticate_request(&[0xAA; 32], &[0xBB; 32], &unknown, AUTH_CHECK_ONLY);
        assert_eq!(handle(&request, &mut store, false).status, SW_WRONG_DATA);
    }

    #[test]
    fn signing_requires_presence() {
        let (mut store, id) = store_with_credential();
        let request = authenticate_request(&[0xAA; 32], &[0xBB; 32], &id, AUTH_ENFORCE);
        assert_eq!(
            handle(&request, &mut store, false).status,
            SW_CONDITIONS_NOT_SATISFIED
        );
    }

    #[test]
    fn signing_produces_verifiable_assertion() {
        let (mut store, id) = store_with_credential();
        let challenge = [0x11; 32];
        let application = [0x22; 32];
        let request = authenticate_request(&challenge, &application, &id, AUTH_ENFORCE);

        let response = handle(&request, &mut store, true);
        assert_eq!(response.status, SW_NO_ERROR);
        assert_eq!(response.data[0], 0x01);
        let counter = u32::from_be_bytes([
            response.data[1],
            response.data[2],
            response.data[3],
            response.data[4],
        ]);
        assert_eq!(counter, 1);

        // Build the signed message and verify with the credential key.
        let mut message: heapless::Vec<u8, 128> = heapless::Vec::new();
        message.push(0x00).unwrap();
        message.extend_from_slice(&application).unwrap();
        message.push(0x01).unwrap();
        message.extend_from_slice(&response.data[1..5]).unwrap();
        message.extend_from_slice(&challenge).unwrap();

        let credential = store.get(&id).unwrap();
        assert!(verify(
            &credential.private_key,
            &message,
            &response.data[5..]
        ));

        // A second assertion increments the counter.
        let response = handle(&request, &mut store, true);
        assert_eq!(
            u32::from_be_bytes([
                response.data[1],
                response.data[2],
                response.data[3],
                response.data[4]
            ]),
            2
        );
    }

    #[test]
    fn register_is_not_supported() {
        let mut store = MemoryCredentialStore::new();
        let mut apdu: heapless::Vec<u8, 16> = heapless::Vec::new();
        apdu.extend_from_slice(&[0x00, INS_REGISTER, 0x00, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
        assert_eq!(handle(&apdu, &mut store, true).status, SW_INS_NOT_SUPPORTED);
    }

    #[test]
    fn short_apdu_is_rejected() {
        assert_eq!(parse_apdu(&[0x00, 0x03]), Err(SW_WRONG_LENGTH));
    }

    fn verify(private_key: &[u8; 32], message: &[u8], der: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, SigningKey};
        let signing_key =
            SigningKey::from_bytes(p256::FieldBytes::from_slice(private_key)).unwrap();
        let signature = Signature::from_der(der).unwrap();
        signing_key
            .verifying_key()
            .verify(message, &signature)
            .is_ok()
    }
}
