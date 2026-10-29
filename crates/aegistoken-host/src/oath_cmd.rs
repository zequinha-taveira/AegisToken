//! OATH (HOTP/TOTP) credential management over PC/SC for AegisToken.
//!
//! Implements the YKOATH wire protocol to list, add, calculate and delete
//! credentials through the CCID applet. The host provides the moving factor
//! (Unix timestamp / period) so the device does not need a real-time clock.

use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use pcsc::{Card, Context, MAX_BUFFER_SIZE, Scope};

use crate::card::{AID_OATH, connect_card, format_iso_status};

// ── YKOATH TLV tags ────────────────────────────────────────────────────────

const TAG_NAME: u8 = 0x71;
const TAG_NAME_LIST: u8 = 0x72;
const TAG_KEY: u8 = 0x73;
const TAG_CHALLENGE: u8 = 0x74;
const TAG_TRUNCATED: u8 = 0x76;

// ── Credential type / algorithm constants ──────────────────────────────────

const TYPE_HOTP: u8 = 0x10;
const TYPE_TOTP: u8 = 0x20;
const ALGORITHM_SHA1: u8 = 0x01;
const ALGORITHM_SHA256: u8 = 0x02;
const ALGORITHM_SHA512: u8 = 0x03;

// ── Low-level helpers ──────────────────────────────────────────────────────

/// Build a BER-TLV (single-byte tag, definite length) and append to `out`.
fn append_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(value);
}

/// Parse a BER-TLV stream (single-byte tags) and find the first occurrence of `tag`.
fn tlv_find(data: &[u8], tag: u8) -> Option<&[u8]> {
    let mut cursor = 0;
    while cursor < data.len() {
        let t = data[cursor];
        cursor += 1;
        if cursor >= data.len() {
            return None;
        }
        let (len, hdr) = tlv_read_length(&data[cursor..])?;
        cursor += hdr;
        if cursor + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(&data[cursor..cursor + len]);
        }
        cursor += len;
    }
    None
}

/// Parse BER definite length (short or long form up to 2-byte length).
fn tlv_read_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        Some((usize::from(first), 1))
    } else if first == 0x81 {
        let len = usize::from(*data.get(1)?);
        Some((len, 2))
    } else if first == 0x82 {
        let hi = usize::from(*data.get(1)?);
        let lo = usize::from(*data.get(2)?);
        Some(((hi << 8) | lo, 3))
    } else {
        None
    }
}

/// Iterate over TLV entries, yielding `(tag, value)` pairs.
fn tlv_iter(data: &[u8]) -> TlvIter<'_> {
    TlvIter { rest: data }
}

struct TlvIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let tag = self.rest[0];
        self.rest = &self.rest[1..];
        let (len, hdr) = tlv_read_length(self.rest)?;
        self.rest = &self.rest[hdr..];
        if len > self.rest.len() {
            self.rest = &[];
            return None;
        }
        let value = &self.rest[..len];
        self.rest = &self.rest[len..];
        Some((tag, value))
    }
}

/// Transmit an APDU and return `(body, sw1, sw2)`.
fn transmit(card: &Card, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8), String> {
    let mut buf = [0u8; MAX_BUFFER_SIZE];
    let rapdu = card
        .transmit(apdu, &mut buf)
        .map_err(|e| format!("APDU transmission failed: {e}"))?;
    if rapdu.len() < 2 {
        return Err("response too short".to_string());
    }
    let sw1 = rapdu[rapdu.len() - 2];
    let sw2 = rapdu[rapdu.len() - 1];
    let body = rapdu[..rapdu.len() - 2].to_vec();
    Ok((body, sw1, sw2))
}

/// SELECT the OATH applet, returning success body.
fn select_oath(card: &Card) -> Result<Vec<u8>, String> {
    let mut apdu = Vec::with_capacity(5 + AID_OATH.len());
    apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00, AID_OATH.len() as u8]);
    apdu.extend_from_slice(AID_OATH);

    let (body, sw1, sw2) = transmit(card, &apdu)?;
    if (sw1, sw2) != (0x90, 0x00) {
        return Err(format!(
            "SELECT OATH failed: {}",
            format_iso_status(sw1, sw2)
        ));
    }
    Ok(body)
}

// ── Public commands ────────────────────────────────────────────────────────

/// `oath list [--reader SUBSTR]` — list all stored OATH credentials.
pub fn oath_list(reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader: {reader_name}");
    select_oath(&card)?;
    println!("Applet: OATH selected\n");

    // LIST: CLA=00 INS=A1 P1=00 P2=00
    let (body, sw1, sw2) = transmit(&card, &[0x00, 0xA1, 0x00, 0x00])?;
    if (sw1, sw2) != (0x90, 0x00) {
        return Err(format!("LIST failed: {}", format_iso_status(sw1, sw2)));
    }

    if body.is_empty() {
        println!("No OATH credentials stored.");
        return Ok(ExitCode::SUCCESS);
    }

    println!("Stored OATH credentials:");
    let mut count = 0u32;
    for (tag, value) in tlv_iter(&body) {
        if tag != TAG_NAME_LIST || value.is_empty() {
            continue;
        }
        let type_algo = value[0];
        let name_bytes = &value[1..];
        let name = String::from_utf8_lossy(name_bytes);
        let kind = match type_algo & 0xF0 {
            x if x == TYPE_TOTP => "TOTP",
            x if x == TYPE_HOTP => "HOTP",
            _ => "???",
        };
        let algo = match type_algo & 0x0F {
            x if x == ALGORITHM_SHA1 => "SHA-1",
            x if x == ALGORITHM_SHA256 => "SHA-256",
            x if x == ALGORITHM_SHA512 => "SHA-512",
            _ => "???",
        };
        count += 1;
        println!("  [{count}] {name}  ({kind}, {algo})");
    }
    if count == 0 {
        println!("  (no credentials parsed from response)");
    }
    Ok(ExitCode::SUCCESS)
}

/// `oath code <NAME> [--reader SUBSTR]` — calculate a TOTP/HOTP code.
pub fn oath_code(name: &str, reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader: {reader_name}");
    select_oath(&card)?;

    // Extract the period from the name if present (e.g. "30/issuer:user")
    let period = credential_period(name);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock error: {e}"))?;
    let timestamp = now.as_secs() / u64::from(period);

    // CALCULATE: CLA=00 INS=A2 P1=00 P2=01(truncated)
    let mut data = Vec::new();
    append_tlv(&mut data, TAG_NAME, name.as_bytes());
    append_tlv(&mut data, TAG_CHALLENGE, &timestamp.to_be_bytes());

    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.extend_from_slice(&[0x00, 0xA2, 0x00, 0x01, data.len() as u8]);
    apdu.extend_from_slice(&data);

    let (body, sw1, sw2) = transmit(&card, &apdu)?;
    if (sw1, sw2) != (0x90, 0x00) {
        if (sw1, sw2) == (0x69, 0x84) {
            return Err(format!("credential '{}' not found on device", name));
        }
        return Err(format!("CALCULATE failed: {}", format_iso_status(sw1, sw2)));
    }

    let truncated_value = tlv_find(&body, TAG_TRUNCATED)
        .ok_or_else(|| "no truncated response in CALCULATE reply".to_string())?;
    if truncated_value.len() < 5 {
        return Err("truncated response too short".to_string());
    }

    let digits = u32::from(truncated_value[0]);
    let binary = u32::from_be_bytes(
        truncated_value[1..5]
            .try_into()
            .map_err(|_| "invalid truncation bytes")?,
    );
    let modulus = 10u32.pow(digits);
    let code = binary % modulus;

    let remaining = u64::from(period) - (now.as_secs() % u64::from(period));
    println!(
        "{code:0>width$}  (valid for {remaining}s)",
        width = digits as usize
    );

    Ok(ExitCode::SUCCESS)
}

/// `oath add [--uri-stdin] [--reader SUBSTR]` — add a credential from an
/// `otpauth://` URI.
///
/// The URI contains the shared secret, so the CLI acquires it from stdin or a
/// hidden prompt and passes it here; it is never accepted from `argv`.
pub fn oath_add(uri: &str, reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let cred = parse_otpauth_uri(uri)?;

    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader: {reader_name}");
    select_oath(&card)?;

    // Build PUT APDU data: TAG_NAME + TAG_KEY [+ TAG_IMF for HOTP]
    let name_bytes = cred.label.as_bytes();
    let mut data = Vec::new();
    append_tlv(&mut data, TAG_NAME, name_bytes);

    // TAG_KEY value: [type|algo, digits, secret...]
    let type_algo = cred.kind | cred.algorithm;
    let mut key_value = Vec::with_capacity(2 + cred.secret.len());
    key_value.push(type_algo);
    key_value.push(cred.digits);
    key_value.extend_from_slice(&cred.secret);
    append_tlv(&mut data, TAG_KEY, &key_value);

    if cred.kind == TYPE_HOTP {
        append_tlv(&mut data, 0x7A, &cred.counter.to_be_bytes()); // TAG_IMF
    }

    // PUT: CLA=00 INS=01 P1=00 P2=00
    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, data.len() as u8]);
    apdu.extend_from_slice(&data);

    let (_body, sw1, sw2) = transmit(&card, &apdu)?;
    if (sw1, sw2) != (0x90, 0x00) {
        return Err(format!(
            "PUT credential failed: {}",
            format_iso_status(sw1, sw2)
        ));
    }

    let kind_str = if cred.kind == TYPE_TOTP {
        "TOTP"
    } else {
        "HOTP"
    };
    let algo_str = algorithm_name(cred.algorithm);
    println!(
        "Credential added: {} ({}, {}, {} digits)",
        cred.label, kind_str, algo_str, cred.digits
    );
    Ok(ExitCode::SUCCESS)
}

/// `oath delete <NAME> [--reader SUBSTR]` — delete a credential by name.
pub fn oath_delete(name: &str, reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader: {reader_name}");
    select_oath(&card)?;

    // DELETE: CLA=00 INS=02 P1=00 P2=00
    let mut data = Vec::new();
    append_tlv(&mut data, TAG_NAME, name.as_bytes());

    let mut apdu = Vec::with_capacity(5 + data.len());
    apdu.extend_from_slice(&[0x00, 0x02, 0x00, 0x00, data.len() as u8]);
    apdu.extend_from_slice(&data);

    let (_body, sw1, sw2) = transmit(&card, &apdu)?;
    if (sw1, sw2) != (0x90, 0x00) {
        if (sw1, sw2) == (0x69, 0x84) {
            return Err(format!("credential '{}' not found", name));
        }
        return Err(format!(
            "DELETE credential failed: {}",
            format_iso_status(sw1, sw2)
        ));
    }

    println!("Credential '{}' deleted.", name);
    Ok(ExitCode::SUCCESS)
}

/// `oath reset [--reader SUBSTR]` — factory-reset the OATH applet (erase all credentials).
pub fn oath_reset(reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader: {reader_name}");
    select_oath(&card)?;

    // RESET: CLA=00 INS=04 P1=DE P2=AD
    let (_body, sw1, sw2) = transmit(&card, &[0x00, 0x04, 0xDE, 0xAD])?;
    if (sw1, sw2) != (0x90, 0x00) {
        return Err(format!("RESET failed: {}", format_iso_status(sw1, sw2)));
    }

    println!("OATH applet reset. All credentials erased.");
    Ok(ExitCode::SUCCESS)
}

// ── otpauth:// URI parsing ─────────────────────────────────────────────────

/// Parsed credential from an `otpauth://` URI.
///
/// Deliberately not `Debug`: the struct carries the decoded shared secret and a
/// derived `Debug` would make `{:?}` a one-line secret leak.
pub struct OtpAuthCredential {
    /// Label used as the credential name on device (e.g. "30/issuer:account").
    pub label: String,
    /// TYPE_TOTP or TYPE_HOTP.
    pub kind: u8,
    /// ALGORITHM_SHA1, ALGORITHM_SHA256 or ALGORITHM_SHA512.
    pub algorithm: u8,
    /// Number of digits (6, 7 or 8).
    pub digits: u8,
    /// Decoded secret bytes.
    pub secret: Vec<u8>,
    /// Initial counter (only meaningful for HOTP; default 0).
    pub counter: u32,
}

/// Parse an `otpauth://totp/...` or `otpauth://hotp/...` URI.
pub fn parse_otpauth_uri(uri: &str) -> Result<OtpAuthCredential, String> {
    // Strip scheme
    let rest = uri
        .strip_prefix("otpauth://")
        .ok_or_else(|| "URI must start with 'otpauth://'".to_string())?;

    // Type
    let (kind_str, rest) = rest
        .split_once('/')
        .ok_or_else(|| "missing type in otpauth URI".to_string())?;
    let kind = match kind_str.to_ascii_lowercase().as_str() {
        "totp" => TYPE_TOTP,
        "hotp" => TYPE_HOTP,
        other => return Err(format!("unsupported OTP type: {other}")),
    };

    // Label (may be URL-encoded) and query string
    let (label_raw, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    let label_decoded = percent_decode(label_raw);

    // Parse query parameters
    let params = parse_query(query);

    let secret_b32 = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("secret"))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| "missing 'secret' parameter in otpauth URI".to_string())?;
    let secret = base32_decode(secret_b32)?;
    if secret.is_empty() {
        return Err("decoded secret is empty".to_string());
    }

    let algorithm = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("algorithm"))
        .map(|(_, v)| match v.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(ALGORITHM_SHA1),
            "SHA256" => Ok(ALGORITHM_SHA256),
            "SHA512" => Ok(ALGORITHM_SHA512),
            other => Err(format!("unsupported algorithm: {other}")),
        })
        .transpose()?
        .unwrap_or(ALGORITHM_SHA1);

    let digits = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("digits"))
        .map(|(_, v)| {
            v.parse::<u8>()
                .map_err(|_| format!("invalid digits value: {v}"))
        })
        .transpose()?
        .unwrap_or(6);
    if !(6..=8).contains(&digits) {
        return Err(format!("digits must be 6, 7 or 8, got {digits}"));
    }

    let period = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("period"))
        .map(|(_, v)| {
            v.parse::<u32>()
                .map_err(|_| format!("invalid period value: {v}"))
        })
        .transpose()?
        .unwrap_or(30);
    if period == 0 {
        return Err("period must be > 0".to_string());
    }

    let counter = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("counter"))
        .map(|(_, v)| {
            v.parse::<u32>()
                .map_err(|_| format!("invalid counter value: {v}"))
        })
        .transpose()?
        .unwrap_or(0);

    let issuer = params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("issuer"))
        .map(|(_, v)| v.as_str());

    // Build the YKOATH credential name: "period/issuer:account" for TOTP,
    // "issuer:account" for HOTP.
    let display_label = if let Some(issuer) = issuer {
        // If the label already starts with "issuer:", don't double it.
        if label_decoded
            .to_ascii_lowercase()
            .starts_with(&format!("{}:", issuer.to_ascii_lowercase()))
        {
            label_decoded.clone()
        } else {
            format!("{issuer}:{label_decoded}")
        }
    } else {
        label_decoded
    };

    let full_name = if kind == TYPE_TOTP {
        format!("{period}/{display_label}")
    } else {
        display_label
    };

    Ok(OtpAuthCredential {
        label: full_name,
        kind,
        algorithm,
        digits,
        secret,
        counter,
    })
}

// ── Utility functions ──────────────────────────────────────────────────────

/// Extract the TOTP period from a YKOATH credential name like "30/issuer:user".
fn credential_period(name: &str) -> u32 {
    name.find('/')
        .filter(|slash_pos| *slash_pos > 0)
        .and_then(|slash_pos| name[..slash_pos].parse::<u32>().ok())
        .filter(|period| *period > 0)
        .unwrap_or(30)
}

fn algorithm_name(algo: u8) -> &'static str {
    match algo {
        ALGORITHM_SHA1 => "SHA-1",
        ALGORITHM_SHA256 => "SHA-256",
        ALGORITHM_SHA512 => "SHA-512",
        _ => "Unknown",
    }
}

/// Simple percent-decoding for URL-encoded label strings.
fn percent_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let hi = chars.next().and_then(hex_digit);
            let lo = chars.next().and_then(hex_digit);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4 | l) as char);
            } else {
                out.push('%');
            }
        } else if byte == b'+' {
            out.push(' ');
        } else {
            out.push(byte as char);
        }
    }
    out
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parse URL query string into key-value pairs.
fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

/// Decode a Base32-encoded string (RFC 4648, no padding required).
fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect();
    if clean.is_empty() {
        return Err("empty Base32 input".to_string());
    }
    let mut bits = 0u64;
    let mut bit_count = 0u32;
    let mut output = Vec::new();

    for ch in clean.chars() {
        let value = base32_value(ch)?;
        bits = (bits << 5) | u64::from(value);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }
    Ok(output)
}

fn base32_value(ch: char) -> Result<u8, String> {
    match ch {
        'A'..='Z' => Ok(ch as u8 - b'A'),
        'a'..='z' => Ok(ch as u8 - b'a'),
        '2'..='7' => Ok(ch as u8 - b'2' + 26),
        _ => Err("invalid Base32 character".to_string()),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- Base32 decoding ---------------------------------------------------

    #[test]
    fn base32_rfc4648_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(base32_decode("MY").unwrap(), b"f");
        assert_eq!(base32_decode("MZXQ").unwrap(), b"fo");
        assert_eq!(base32_decode("MZXW6").unwrap(), b"foo");
        assert_eq!(base32_decode("MZXW6YQ").unwrap(), b"foob");
        assert_eq!(base32_decode("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
    }

    #[test]
    fn base32_padding_stripped() {
        assert_eq!(
            base32_decode("JBSWY3DPEHPK3PXP").unwrap(),
            b"Hello!\xde\xad\xbe\xef"
        );
    }

    #[test]
    fn base32_case_insensitive() {
        assert_eq!(base32_decode("mzxw6ytb").unwrap(), b"fooba");
    }

    #[test]
    fn base32_rejects_invalid() {
        assert!(base32_decode("!@#$").is_err());
        assert!(base32_decode("").is_err());
    }

    // -- otpauth:// URI parsing -------------------------------------------

    #[test]
    fn parse_totp_minimal() {
        let cred =
            parse_otpauth_uri("otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP")
                .unwrap();
        assert_eq!(cred.kind, TYPE_TOTP);
        assert!(cred.label.starts_with("30/"));
        assert!(cred.label.contains("Example:alice@example.com"));
        assert_eq!(cred.algorithm, ALGORITHM_SHA1);
        assert_eq!(cred.digits, 6);
        assert!(!cred.secret.is_empty());
    }

    #[test]
    fn parse_totp_full() {
        let cred = parse_otpauth_uri(
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(cred.kind, TYPE_TOTP);
        assert_eq!(cred.algorithm, ALGORITHM_SHA256);
        assert_eq!(cred.digits, 8);
        assert!(cred.label.starts_with("60/"));
        assert!(cred.label.contains("Example:alice"));
    }

    #[test]
    fn parse_hotp() {
        let cred =
            parse_otpauth_uri("otpauth://hotp/Counter%20Test?secret=JBSWY3DPEHPK3PXP&counter=42")
                .unwrap();
        assert_eq!(cred.kind, TYPE_HOTP);
        assert_eq!(cred.counter, 42);
        assert!(!cred.label.contains('/'));
    }

    #[test]
    fn parse_rejects_bad_scheme() {
        assert!(parse_otpauth_uri("http://example.com").is_err());
    }

    #[test]
    fn parse_rejects_missing_secret() {
        assert!(parse_otpauth_uri("otpauth://totp/Test?digits=6").is_err());
    }

    #[test]
    fn parse_rejects_bad_digits() {
        assert!(parse_otpauth_uri("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=5").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=9").is_err());
    }

    // -- credential_period ------------------------------------------------

    #[test]
    fn period_from_name() {
        assert_eq!(credential_period("30/issuer:user"), 30);
        assert_eq!(credential_period("60/issuer:user"), 60);
        assert_eq!(credential_period("issuer:user"), 30);
        assert_eq!(credential_period("0/issuer:user"), 30);
    }

    // -- TLV helpers ------------------------------------------------------

    #[test]
    fn append_and_find_tlv() {
        let mut buf = Vec::new();
        append_tlv(&mut buf, TAG_NAME, b"test");
        append_tlv(&mut buf, TAG_CHALLENGE, &[0xDE, 0xAD]);

        assert_eq!(tlv_find(&buf, TAG_NAME), Some(b"test".as_slice()));
        assert_eq!(tlv_find(&buf, TAG_CHALLENGE), Some([0xDE, 0xAD].as_slice()));
        assert_eq!(tlv_find(&buf, 0x99), None);
    }

    #[test]
    fn tlv_iter_parses_list_response() {
        // Simulated LIST response: two TAG_NAME_LIST entries
        let mut buf = Vec::new();
        // Entry 1: TOTP + SHA1 + "test1"
        let mut val1 = vec![TYPE_TOTP | ALGORITHM_SHA1];
        val1.extend_from_slice(b"test1");
        append_tlv(&mut buf, TAG_NAME_LIST, &val1);
        // Entry 2: HOTP + SHA256 + "test2"
        let mut val2 = vec![TYPE_HOTP | ALGORITHM_SHA256];
        val2.extend_from_slice(b"test2");
        append_tlv(&mut buf, TAG_NAME_LIST, &val2);

        let entries: Vec<_> = tlv_iter(&buf)
            .filter(|(tag, _)| *tag == TAG_NAME_LIST)
            .collect();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].1[0], TYPE_TOTP | ALGORITHM_SHA1);
        assert_eq!(&entries[0].1[1..], b"test1");
        assert_eq!(entries[1].1[0], TYPE_HOTP | ALGORITHM_SHA256);
        assert_eq!(&entries[1].1[1..], b"test2");
    }

    // -- percent decoding -------------------------------------------------

    #[test]
    fn percent_decode_works() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("foo+bar"), "foo bar");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
    }

    // -- secret redaction -------------------------------------------------

    #[test]
    fn bad_scheme_error_does_not_echo_the_uri() {
        let uri = "http://example.com/?secret=S3NT1NEL";
        let error = parse_otpauth_uri(uri).err().expect("rejected");
        assert!(error.contains("otpauth://"), "{error}");
        assert!(!error.contains(uri), "{error}");
        assert!(!error.contains("S3NT1NEL"), "{error}");
    }

    #[test]
    fn invalid_base32_error_does_not_echo_the_character() {
        let error = parse_otpauth_uri("otpauth://totp/Test?secret=AAAA!")
            .err()
            .expect("rejected");
        assert!(error.contains("Base32"), "{error}");
        assert!(!error.contains('!'), "{error}");
        assert!(!error.contains("AAAA"), "{error}");
    }
}
