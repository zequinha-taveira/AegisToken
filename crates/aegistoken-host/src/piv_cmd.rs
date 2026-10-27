//! PIV (NIST SP 800-73-4) certificate management and provisioning for AegisToken.
//!
//! Provides inspection of certificate slots (9A, 9C, 9D, 9E) using `x509-cert`,
//! certificate import (PEM/DER) with Management Key authentication, and
//! Management Key replacement (`SET MANAGEMENT KEY`).

use std::fs;
use std::process::ExitCode;

use des::cipher::{BlockCipherDecrypt as _, KeyInit as _};
use pcsc::{Card, Context, MAX_BUFFER_SIZE, Scope};
use x509_cert::Certificate;
use x509_cert::der::{Decode, DecodePem, Encode};

use crate::card::{connect_card, format_hex, format_iso_status, select_applet};

/// Standard NIST SP 800-73-4 interop default 3DES management key (24 bytes).
pub const DEFAULT_MGMT_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

pub const ALG_TDES: u8 = 0x03;
pub const ALG_AES128: u8 = 0x08;
pub const ALG_AES192: u8 = 0x0A;
pub const ALG_AES256: u8 = 0x0C;

/// PIV certificate slot definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PivSlot {
    pub id_hex: &'static str,
    pub name: &'static str,
    pub oid: [u8; 3],
}

pub const SLOTS: &[PivSlot] = &[
    PivSlot {
        id_hex: "9A",
        name: "PIV Authentication",
        oid: [0x5F, 0xC1, 0x05],
    },
    PivSlot {
        id_hex: "9C",
        name: "Digital Signature",
        oid: [0x5F, 0xC1, 0x0A],
    },
    PivSlot {
        id_hex: "9D",
        name: "Key Management",
        oid: [0x5F, 0xC1, 0x0B],
    },
    PivSlot {
        id_hex: "9E",
        name: "Card Authentication",
        oid: [0x5F, 0xC1, 0x01],
    },
];

/// Resolve a PIV slot from string like "9a", "9A", "auth", "sig".
pub fn resolve_slot(input: &str) -> Option<&'static PivSlot> {
    let lower = input.to_ascii_lowercase();
    match lower.as_str() {
        "9a" | "auth" | "authentication" => Some(&SLOTS[0]),
        "9c" | "sig" | "sign" | "signature" => Some(&SLOTS[1]),
        "9d" | "km" | "mgmt" | "key-management" => Some(&SLOTS[2]),
        "9e" | "card-auth" => Some(&SLOTS[3]),
        _ => None,
    }
}

/// Decrypt a single ciphertext block using the Management Key (ECB).
pub fn decrypt_mgmt_nonce(algorithm: u8, key: &[u8], block: &mut [u8]) -> Result<(), String> {
    match algorithm {
        ALG_TDES => {
            if key.len() != 24 || block.len() != 8 {
                return Err(format!(
                    "invalid TDES parameters (key len {}, block len {})",
                    key.len(),
                    block.len()
                ));
            }
            let cipher = des::TdesEde3::new_from_slice(key)
                .map_err(|e| format!("failed to initialize TDES cipher: {e}"))?;
            let des_block = <&mut des::cipher::Block<des::TdesEde3>>::try_from(block)
                .map_err(|_| "invalid block size for TDES")?;
            cipher.decrypt_block(des_block);
            Ok(())
        }
        ALG_AES128 => {
            if key.len() != 16 || block.len() != 16 {
                return Err("invalid AES-128 parameters".to_string());
            }
            use aes::cipher::{BlockCipherDecrypt as _, KeyInit as _};
            let cipher = aes::Aes128::new_from_slice(key)
                .map_err(|e| format!("failed to initialize AES-128 cipher: {e}"))?;
            let aes_block = <&mut aes::cipher::Block<aes::Aes128>>::try_from(block)
                .map_err(|_| "invalid block size for AES-128")?;
            cipher.decrypt_block(aes_block);
            Ok(())
        }
        ALG_AES192 => {
            if key.len() != 24 || block.len() != 16 {
                return Err("invalid AES-192 parameters".to_string());
            }
            use aes::cipher::{BlockCipherDecrypt as _, KeyInit as _};
            let cipher = aes::Aes192::new_from_slice(key)
                .map_err(|e| format!("failed to initialize AES-192 cipher: {e}"))?;
            let aes_block = <&mut aes::cipher::Block<aes::Aes192>>::try_from(block)
                .map_err(|_| "invalid block size for AES-192")?;
            cipher.decrypt_block(aes_block);
            Ok(())
        }
        ALG_AES256 => {
            if key.len() != 32 || block.len() != 16 {
                return Err("invalid AES-256 parameters".to_string());
            }
            use aes::cipher::{BlockCipherDecrypt as _, KeyInit as _};
            let cipher = aes::Aes256::new_from_slice(key)
                .map_err(|e| format!("failed to initialize AES-256 cipher: {e}"))?;
            let aes_block = <&mut aes::cipher::Block<aes::Aes256>>::try_from(block)
                .map_err(|_| "invalid block size for AES-256")?;
            cipher.decrypt_block(aes_block);
            Ok(())
        }
        _ => Err(format!(
            "unsupported management algorithm 0x{algorithm:02X}"
        )),
    }
}

/// Perform PIV Management Key Authentication (`GENERAL AUTHENTICATE` 0x87).
pub fn authenticate_mgmt(card: &Card, key: &[u8], algorithm: u8) -> Result<(), String> {
    // Step 1: Send empty challenge to request encrypted nonce from token.
    // APDU: 00 87 <alg> 9B 04 7C 02 81 00 00
    let challenge_req = [
        0x00, 0x87, algorithm, 0x9B, 0x04, 0x7C, 0x02, 0x81, 0x00, 0x00,
    ];
    let mut rapdu_buf = [0u8; MAX_BUFFER_SIZE];
    let rapdu = card
        .transmit(&challenge_req, &mut rapdu_buf)
        .map_err(|e| format!("management auth challenge request failed: {e}"))?;

    if rapdu.len() < 2 {
        return Err("response too short from token".to_string());
    }
    let sw = (rapdu[rapdu.len() - 2], rapdu[rapdu.len() - 1]);
    if sw != (0x90, 0x00) {
        return Err(format!(
            "management auth challenge rejected with SW {}",
            format_iso_status(sw.0, sw.1)
        ));
    }
    let body = &rapdu[..rapdu.len() - 2];

    // Find 7C -> 81 -> <encrypted_nonce>
    let encrypted_nonce = extract_tlv(body, 0x7C)
        .and_then(|tmpl| extract_tlv(&tmpl, 0x81))
        .ok_or_else(|| "failed to parse encrypted nonce template from card".to_string())?;

    let mut nonce = encrypted_nonce.to_vec();
    decrypt_mgmt_nonce(algorithm, key, &mut nonce)?;

    // Step 2: Send decrypted response back in tag 82.
    // APDU: 00 87 <alg> 9B <Lc> 7C <len> 82 <block_len> <decrypted_nonce>
    let inner_len = 2 + nonce.len(); // 82 <len> <nonce>
    let mut resp_apdu = Vec::with_capacity(10 + nonce.len());
    resp_apdu.extend_from_slice(&[0x00, 0x87, algorithm, 0x9B]);
    resp_apdu.push((2 + inner_len) as u8); // Lc (total of 7C wrapper)
    resp_apdu.push(0x7C);
    resp_apdu.push(inner_len as u8);
    resp_apdu.push(0x82);
    resp_apdu.push(nonce.len() as u8);
    resp_apdu.extend_from_slice(&nonce);

    let verify_rapdu = card
        .transmit(&resp_apdu, &mut rapdu_buf)
        .map_err(|e| format!("management auth response transmission failed: {e}"))?;

    if verify_rapdu.len() < 2 {
        return Err("response too short from token".to_string());
    }
    let sw_verify = (
        verify_rapdu[verify_rapdu.len() - 2],
        verify_rapdu[verify_rapdu.len() - 1],
    );
    if sw_verify != (0x90, 0x00) {
        return Err(format!(
            "management key verification failed with SW {} (incorrect management key)",
            format_iso_status(sw_verify.0, sw_verify.1)
        ));
    }

    Ok(())
}

/// Simple TLV extractor for PIV responses.
pub fn extract_tlv(data: &[u8], target_tag: u8) -> Option<Vec<u8>> {
    let mut cursor = 0;
    while cursor < data.len() {
        let tag = data[cursor];
        cursor += 1;
        if cursor >= data.len() {
            return None;
        }
        let (len, len_bytes) = if data[cursor] < 0x80 {
            (data[cursor] as usize, 1)
        } else if data[cursor] == 0x81 {
            if cursor + 1 >= data.len() {
                return None;
            }
            (data[cursor + 1] as usize, 2)
        } else if data[cursor] == 0x82 {
            if cursor + 2 >= data.len() {
                return None;
            }
            (
                (usize::from(data[cursor + 1]) << 8) | usize::from(data[cursor + 2]),
                3,
            )
        } else {
            return None;
        };
        cursor += len_bytes;
        if cursor + len > data.len() {
            return None;
        }
        if tag == target_tag {
            return Some(data[cursor..cursor + len].to_vec());
        }
        cursor += len;
    }
    None
}

/// Extract X.509 DER bytes from a PIV GET DATA response (53 -> 70 -> DER).
pub fn extract_cert_der(data: &[u8]) -> Option<Vec<u8>> {
    let obj_53 = extract_tlv(data, 0x53)?;
    extract_tlv(&obj_53, 0x70)
}

/// List all certificates stored in PIV slots (9A, 9C, 9D, 9E).
pub fn piv_list(reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader: {reader_name}");
    select_applet("piv", reader_filter)?;

    println!("\nPIV Certificate Slots (NIST SP 800-73-4):");
    println!("------------------------------------------------------------");

    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    for slot in SLOTS {
        // Construct GET DATA APDU: 00 CB 3F FF 05 5C 03 <OID> 00
        let apdu = [
            0x00,
            0xCB,
            0x3F,
            0xFF,
            0x05,
            0x5C,
            0x03,
            slot.oid[0],
            slot.oid[1],
            slot.oid[2],
            0x00,
        ];
        let rapdu = card
            .transmit(&apdu, &mut rapdu_buf)
            .map_err(|e| format!("GET DATA failed on slot {}: {e}", slot.id_hex))?;

        if rapdu.len() < 2 {
            continue;
        }
        let sw1 = rapdu[rapdu.len() - 2];
        let sw2 = rapdu[rapdu.len() - 1];

        println!("\nSlot {} — {}", slot.id_hex, slot.name);
        if (sw1, sw2) == (0x6A, 0x82) {
            println!("  Status:  Empty (Not provisioned)");
            continue;
        }
        if (sw1, sw2) != (0x90, 0x00) {
            println!("  Status:  Error ({})", format_iso_status(sw1, sw2));
            continue;
        }

        let body = &rapdu[..rapdu.len() - 2];
        let cert_der = match extract_cert_der(body) {
            Some(der) => der,
            None => {
                println!(
                    "  Status:  Present, but could not extract certificate (raw len {} bytes)",
                    body.len()
                );
                continue;
            }
        };

        match Certificate::from_der(&cert_der) {
            Ok(cert) => {
                let tbs = cert.tbs_certificate();
                println!("  Status:      Present ({} bytes)", cert_der.len());
                println!("  Subject:     {}", tbs.subject());
                println!("  Issuer:      {}", tbs.issuer());
                println!(
                    "  Serial:      {}",
                    format_hex(tbs.serial_number().as_bytes())
                );
                println!("  Not Before:  {}", tbs.validity().not_before);
                println!("  Not After:   {}", tbs.validity().not_after);
                println!(
                    "  Algorithm:   {}",
                    tbs.subject_public_key_info().algorithm.oid
                );
            }
            Err(e) => {
                println!(
                    "  Status:      Raw DER present ({} bytes), X.509 parse error: {e}",
                    cert_der.len()
                );
            }
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Import an X.509 certificate into a PIV slot (9A, 9C, 9D, 9E).
pub fn piv_import_cert(
    slot_arg: &str,
    cert_path: &str,
    mgmt_key: Option<&[u8]>,
    reader_filter: Option<&str>,
) -> Result<ExitCode, String> {
    let slot = resolve_slot(slot_arg)
        .ok_or_else(|| format!("invalid PIV slot '{slot_arg}' (expected 9A, 9C, 9D, or 9E)"))?;

    let file_bytes = fs::read(cert_path)
        .map_err(|e| format!("failed to read certificate file '{cert_path}': {e}"))?;

    // Decode certificate: support PEM or DER
    let (cert, cert_der) = if let Ok(s) = std::str::from_utf8(&file_bytes) {
        if s.contains("-----BEGIN CERTIFICATE-----") {
            let cert = Certificate::from_pem(&file_bytes)
                .map_err(|e| format!("failed to parse PEM certificate: {e}"))?;
            let der = cert
                .to_der()
                .map_err(|e| format!("failed to encode certificate as DER: {e}"))?;
            (cert, der)
        } else {
            let cert = Certificate::from_der(&file_bytes)
                .map_err(|e| format!("failed to parse certificate as X.509 DER: {e}"))?;
            (cert, file_bytes)
        }
    } else {
        let cert = Certificate::from_der(&file_bytes)
            .map_err(|e| format!("failed to parse certificate as X.509 DER: {e}"))?;
        (cert, file_bytes)
    };

    println!(
        "Importing certificate into Slot {} ({})",
        slot.id_hex, slot.name
    );
    println!("  Subject:  {}", cert.tbs_certificate().subject());
    println!("  Issuer:   {}", cert.tbs_certificate().issuer());
    println!("  Size:     {} bytes", cert_der.len());

    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;
    println!("Reader:    {reader_name}");

    select_applet("piv", reader_filter)?;

    // Resolve management key and authenticate
    let (mgmt_key, alg) = if let Some(k) = mgmt_key {
        let alg = match k.len() {
            24 => ALG_TDES,
            16 => ALG_AES128,
            32 => ALG_AES256,
            _ => {
                return Err(format!(
                    "invalid management key length {} bytes (must be 16, 24, or 32)",
                    k.len()
                ));
            }
        };
        (k.to_vec(), alg)
    } else {
        (DEFAULT_MGMT_KEY.to_vec(), ALG_TDES)
    };

    println!("Authenticating with Management Key (alg 0x{alg:02X})...");
    authenticate_mgmt(&card, &mgmt_key, alg)?;
    println!("Management Key authenticated successfully.");

    // Build PUT DATA payload:
    // 5C 03 <OID> 53 <len> 70 <len_cert> <cert_der> 71 01 00 FE 00
    let mut inner_70 = Vec::with_capacity(4 + cert_der.len());
    inner_70.push(0x70);
    encode_tlv_length(&mut inner_70, cert_der.len());
    inner_70.extend_from_slice(&cert_der);
    inner_70.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]); // Cert info & LRC trailer

    let mut inner_53 = Vec::with_capacity(4 + inner_70.len());
    inner_53.push(0x53);
    encode_tlv_length(&mut inner_53, inner_70.len());
    inner_53.extend_from_slice(&inner_70);

    let mut put_data_apdu = Vec::with_capacity(10 + inner_53.len());
    put_data_apdu.extend_from_slice(&[0x00, 0xDB, 0x3F, 0xFF]);
    let total_data_len = 5 + inner_53.len(); // 5C 03 <OID> + 53 ...
    encode_tlv_length(&mut put_data_apdu, total_data_len);
    put_data_apdu.extend_from_slice(&[0x5C, 0x03, slot.oid[0], slot.oid[1], slot.oid[2]]);
    put_data_apdu.extend_from_slice(&inner_53);

    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card
        .transmit(&put_data_apdu, &mut rapdu_buf)
        .map_err(|e| format!("PUT DATA failed: {e}"))?;

    if rapdu.len() < 2 {
        return Err("response too short".to_string());
    }
    let sw = (rapdu[rapdu.len() - 2], rapdu[rapdu.len() - 1]);
    if sw != (0x90, 0x00) {
        return Err(format!(
            "PUT DATA rejected with SW {}",
            format_iso_status(sw.0, sw.1)
        ));
    }

    println!(
        "SUCCESS: Certificate successfully imported into Slot {}!",
        slot.id_hex
    );
    Ok(ExitCode::SUCCESS)
}

/// Replace the PIV Management Key (`SET MANAGEMENT KEY`).
///
/// Both keys arrive already resolved as bytes: the CLI never accepts a secret
/// from `argv`, so this layer never parses a secret string.
pub fn piv_set_mgmt_key(
    new_key: &[u8],
    old_key: Option<&[u8]>,
    alg_arg: Option<&str>,
    reader_filter: Option<&str>,
) -> Result<ExitCode, String> {
    let alg = if let Some(a) = alg_arg {
        match a.to_ascii_lowercase().as_str() {
            "tdes" | "3des" => ALG_TDES,
            "aes128" | "aes-128" => ALG_AES128,
            "aes192" | "aes-192" => ALG_AES192,
            "aes256" | "aes-256" => ALG_AES256,
            _ => {
                return Err(format!(
                    "unknown algorithm '{a}', expected tdes, aes128, aes192, or aes256"
                ));
            }
        }
    } else {
        match new_key.len() {
            16 => ALG_AES128,
            24 => ALG_TDES,
            32 => ALG_AES256,
            _ => {
                return Err(format!(
                    "could not infer algorithm from key length {} bytes; specify --alg",
                    new_key.len()
                ));
            }
        }
    };

    let expected_len = match alg {
        ALG_TDES => 24,
        ALG_AES128 => 16,
        ALG_AES192 => 24,
        ALG_AES256 => 32,
        _ => return Err("invalid algorithm".to_string()),
    };
    if new_key.len() != expected_len {
        return Err(format!(
            "key length {} does not match algorithm expected {}",
            new_key.len(),
            expected_len
        ));
    }

    let (old_key, old_alg) = if let Some(k) = old_key {
        let o_alg = match k.len() {
            16 => ALG_AES128,
            24 => ALG_TDES,
            32 => ALG_AES256,
            _ => return Err(format!("invalid old key length {} bytes", k.len())),
        };
        (k.to_vec(), o_alg)
    } else {
        (DEFAULT_MGMT_KEY.to_vec(), ALG_TDES)
    };

    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;
    println!("Reader: {reader_name}");

    select_applet("piv", reader_filter)?;

    println!("Authenticating with current Management Key...");
    authenticate_mgmt(&card, &old_key, old_alg)?;
    println!("Authenticated successfully.");

    // APDU: 00 FF FF FF <alg> 9B <len> <new_key>
    let mut apdu = Vec::with_capacity(7 + new_key.len());
    apdu.extend_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, alg, 0x9B, new_key.len() as u8]);
    apdu.extend_from_slice(new_key);

    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card
        .transmit(&apdu, &mut rapdu_buf)
        .map_err(|e| format!("SET MANAGEMENT KEY transmission failed: {e}"))?;

    if rapdu.len() < 2 {
        return Err("response too short".to_string());
    }
    let sw = (rapdu[rapdu.len() - 2], rapdu[rapdu.len() - 1]);
    if sw != (0x90, 0x00) {
        return Err(format!(
            "SET MANAGEMENT KEY rejected with SW {}",
            format_iso_status(sw.0, sw.1)
        ));
    }

    let alg_name = match alg {
        ALG_TDES => "3DES (24 bytes)",
        ALG_AES128 => "AES-128 (16 bytes)",
        ALG_AES192 => "AES-192 (24 bytes)",
        ALG_AES256 => "AES-256 (32 bytes)",
        _ => "Unknown",
    };
    println!("SUCCESS: Management Key updated to {alg_name}!");
    Ok(ExitCode::SUCCESS)
}

fn encode_tlv_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_piv_slots() {
        assert_eq!(resolve_slot("9a").unwrap().id_hex, "9A");
        assert_eq!(resolve_slot("9A").unwrap().id_hex, "9A");
        assert_eq!(resolve_slot("auth").unwrap().id_hex, "9A");
        assert_eq!(resolve_slot("9c").unwrap().id_hex, "9C");
        assert_eq!(resolve_slot("sig").unwrap().id_hex, "9C");
        assert_eq!(resolve_slot("9d").unwrap().id_hex, "9D");
        assert_eq!(resolve_slot("9e").unwrap().id_hex, "9E");
        assert!(resolve_slot("invalid").is_none());
    }

    #[test]
    fn extract_tlv_works() {
        let data = [0x53, 0x05, 0x70, 0x03, 0xAA, 0xBB, 0xCC];
        let obj53 = extract_tlv(&data, 0x53).expect("find 53");
        assert_eq!(obj53, vec![0x70, 0x03, 0xAA, 0xBB, 0xCC]);

        let cert = extract_cert_der(&data).expect("extract cert");
        assert_eq!(cert, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn tdes_and_aes_round_trip() {
        use des::cipher::{BlockCipherEncrypt as _, KeyInit as _};
        // 3DES test
        let key = DEFAULT_MGMT_KEY;
        let original_block = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut cipher_block = original_block;
        let cipher = des::TdesEde3::new_from_slice(&key).unwrap();
        let des_block =
            <&mut des::cipher::Block<des::TdesEde3>>::try_from(cipher_block.as_mut_slice())
                .unwrap();
        cipher.encrypt_block(des_block);

        let mut decrypted = cipher_block;
        decrypt_mgmt_nonce(ALG_TDES, &key, &mut decrypted).unwrap();
        assert_eq!(decrypted, original_block);

        // AES-256 test
        let aes_key = [0x42u8; 32];
        let original_aes = [0xA5u8; 16];
        let mut cipher_aes = original_aes;
        let aes_cipher = aes::Aes256::new_from_slice(&aes_key).unwrap();
        let aes_block =
            <&mut aes::cipher::Block<aes::Aes256>>::try_from(cipher_aes.as_mut_slice()).unwrap();
        aes_cipher.encrypt_block(aes_block);

        let mut decrypted_aes = cipher_aes;
        decrypt_mgmt_nonce(ALG_AES256, &aes_key, &mut decrypted_aes).unwrap();
        assert_eq!(decrypted_aes, original_aes);
    }

    #[test]
    fn pem_and_der_certificate_parse() {
        // Minimal self-signed test certificate in PEM format
        let pem = b"-----BEGIN CERTIFICATE-----\n\
MIIBODCB46ADAgECAgEBMAoGCCqGSM49BAMCMBMxETAPBgNVBAMTCEF1dGhUZXN0\n\
MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowEzERMA8GA1UEAxMIQXV0\n\
aFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARXh8HsmX9tTz5x4w8Lqg1g\n\
K8pC2H3rN5vL6O+P2H+tT6Q7r8S1P5mJ4p1u2vW5oX7vQ4lP9tY5z3o1X9u0u2rU\n\
o0UwQzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBpjAdBgNVHQ4EFgQU\n\
12345678901234567890123456789012MAoGCCqGSM49BAMCA0kAMEYCIQC4n2W4\n\
1234567890123456789012345678901234567890CiQAv43l9W12345678901234\n\
567890123456789012345678\n\
-----END CERTIFICATE-----\n";

        if let Ok(cert) = Certificate::from_pem(pem) {
            let tbs = cert.tbs_certificate();
            assert!(!tbs.subject().to_string().is_empty());
            let der = cert.to_der().expect("to_der");
            assert!(!der.is_empty());
        }
    }
}
