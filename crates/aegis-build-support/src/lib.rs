//! Build policy for the AegisToken firmware images.
//!
//! The firmware embeds the public key that verifies firmware-update packages.
//! The *development* key is the P-256 generator point, so its private key is
//! the number 1: anyone can sign an update that such an image accepts. The
//! only reliable defense is to refuse to build a release image with it.
//!
//! This crate holds that decision so it can be unit-tested on the host: the
//! firmware `build.rs` only wires the environment variables into it.

/// Development P-256 public key: the curve generator point.
///
/// This is public by construction and must never be used in production. It
/// stays as the trap that catches a release built without a real key.
pub const DEV_VENDOR_PUBLIC_KEY: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

/// Length of the hex-encoded vendor key (65 bytes, two characters each).
const HEX_LEN: usize = 130;

/// The firmware-update vendor key an image will embed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorKey {
    /// SEC1 uncompressed P-256 public key (65 bytes).
    pub bytes: [u8; 65],
    /// Whether this is the development key.
    pub is_dev: bool,
}

/// Parse the `AEGIS_RELEASE` flag.
///
/// The release gate is active only for the exact value `1`; `""`, `0` and
/// `false` keep development behaviour. Any other value is an error, so a typo
/// cannot silently disable the gate.
pub fn parse_release_flag(value: Option<&str>) -> Result<bool, String> {
    let Some(value) = value else {
        return Ok(false);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    if trimmed == "1" {
        return Ok(true);
    }
    if trimmed.eq_ignore_ascii_case("false") || trimmed == "0" {
        return Ok(false);
    }
    Err(format!(
        "AEGIS_RELEASE must be '1' to enable the release gate; got '{trimmed}'."
    ))
}

/// Resolve the vendor key an image will embed.
///
/// `env_value` is the raw content of `AEGIS_UPDATE_VENDOR_PUBKEY`; an absent or
/// blank value means "no key given". `release` enables the gate: a release
/// image may not embed the development key, whether it was omitted or passed
/// explicitly.
pub fn resolve_vendor_key(env_value: Option<&str>, release: bool) -> Result<VendorKey, String> {
    let trimmed = env_value.map(str::trim).unwrap_or_default();
    if trimmed.is_empty() {
        return finish(DEV_VENDOR_PUBLIC_KEY, release);
    }
    let bytes = parse_sec1_hex(trimmed)?;
    finish(bytes, release)
}

fn finish(bytes: [u8; 65], release: bool) -> Result<VendorKey, String> {
    let is_dev = bytes == DEV_VENDOR_PUBLIC_KEY;
    if is_dev && release {
        return Err(
            "AEGIS_RELEASE=1 requires a production firmware-update vendor key, but the \
             DEVELOPMENT key would be embedded. Set AEGIS_UPDATE_VENDOR_PUBKEY to exactly \
             130 hex characters (65-byte uncompressed SEC1 P-256 point, 04||X||Y) as printed \
             by scripts/gen-update-key.py, or unset AEGIS_RELEASE for development builds."
                .to_string(),
        );
    }
    Ok(VendorKey { bytes, is_dev })
}

fn parse_sec1_hex(value: &str) -> Result<[u8; 65], String> {
    if value.len() != HEX_LEN {
        return Err(format!(
            "AEGIS_UPDATE_VENDOR_PUBKEY must be exactly {HEX_LEN} hex characters (65-byte \
             uncompressed SEC1 P-256 point, 04||X||Y); got {} characters.",
            value.len()
        ));
    }
    let mut out = [0u8; 65];
    for (index, byte) in out.iter_mut().enumerate() {
        let hex = &value[index * 2..index * 2 + 2];
        // `from_str_radix` accepts a leading sign, so the digits are checked
        // first: only 0-9 and a-f are a hex byte here.
        if !hex.bytes().all(|digit| digit.is_ascii_hexdigit()) {
            return Err(format!(
                "AEGIS_UPDATE_VENDOR_PUBKEY must be hexadecimal ({HEX_LEN} characters); \
                 the character pair at offset {index} is not a hex byte."
            ));
        }
        *byte = u8::from_str_radix(hex, 16).map_err(|_| {
            format!(
                "AEGIS_UPDATE_VENDOR_PUBKEY must be hexadecimal ({HEX_LEN} characters); \
                 the character pair at offset {index} is not a hex byte."
            )
        })?;
    }
    if out[0] != 0x04 {
        return Err(
            "AEGIS_UPDATE_VENDOR_PUBKEY must be an uncompressed SEC1 P-256 point (04||X||Y)."
                .to_string(),
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_HEX: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

    /// A well-formed key that is not the development one (public material,
    /// discarded).
    fn prod_hex() -> String {
        format!("04{}", "a1".repeat(64))
    }

    #[test]
    fn release_flag_only_enables_on_exactly_one() {
        assert!(!parse_release_flag(None).unwrap());
        assert!(!parse_release_flag(Some("")).unwrap());
        assert!(!parse_release_flag(Some("  ")).unwrap());
        assert!(!parse_release_flag(Some("0")).unwrap());
        assert!(!parse_release_flag(Some("false")).unwrap());
        assert!(!parse_release_flag(Some("FALSE")).unwrap());
        assert!(parse_release_flag(Some("1")).unwrap());
        assert!(parse_release_flag(Some(" 1 ")).unwrap());
    }

    #[test]
    fn invalid_release_flag_is_an_error() {
        let error = parse_release_flag(Some("true")).unwrap_err();
        assert!(error.contains("AEGIS_RELEASE must be '1'"));
        assert!(!error.contains("a1a1"));
    }

    #[test]
    fn missing_key_yields_the_development_key() {
        let key = resolve_vendor_key(None, false).unwrap();
        assert!(key.is_dev);
        assert_eq!(key.bytes, DEV_VENDOR_PUBLIC_KEY);
        let key = resolve_vendor_key(Some("   "), false).unwrap();
        assert!(key.is_dev);
    }

    #[test]
    fn release_refuses_the_development_key() {
        let error = resolve_vendor_key(None, true).unwrap_err();
        assert!(error.contains("AEGIS_RELEASE=1 requires a production"));
        assert!(!error.contains(&DEV_HEX[2..]));
    }

    #[test]
    fn explicit_development_key_is_still_the_development_key() {
        let key = resolve_vendor_key(Some(DEV_HEX), false).unwrap();
        assert!(key.is_dev);
        assert_eq!(key.bytes, DEV_VENDOR_PUBLIC_KEY);
        let error = resolve_vendor_key(Some(DEV_HEX), true).unwrap_err();
        assert!(error.contains("AEGIS_RELEASE=1 requires a production"));
    }

    #[test]
    fn release_accepts_a_production_key() {
        let key = resolve_vendor_key(Some(&prod_hex()), true).unwrap();
        assert!(!key.is_dev);
        assert_eq!(key.bytes[0], 0x04);
    }

    #[test]
    fn malformed_keys_are_rejected() {
        let short = resolve_vendor_key(Some("04a1"), false).unwrap_err();
        assert!(short.contains("exactly 130 hex characters"));
        let not_hex = resolve_vendor_key(Some(&"zz".repeat(65)), false).unwrap_err();
        assert!(not_hex.contains("hexadecimal"));
        let compressed =
            resolve_vendor_key(Some(&format!("02{}", "a1".repeat(64))), false).unwrap_err();
        assert!(compressed.contains("uncompressed SEC1"));
    }

    #[test]
    fn signed_or_padded_hex_is_rejected() {
        // `from_str_radix` would read "+a" as 10; the key must be plain hex.
        let signed =
            resolve_vendor_key(Some(&format!("+4{}", "+a".repeat(64))), false).unwrap_err();
        assert!(signed.contains("hexadecimal"));
        let spaced =
            resolve_vendor_key(Some(&format!("0 {}", "a1".repeat(64))), false).unwrap_err();
        assert!(spaced.contains("hexadecimal"));
        let too_long =
            resolve_vendor_key(Some(&format!("04{}", "a1".repeat(65))), false).unwrap_err();
        assert!(too_long.contains("exactly 130 hex characters"));
    }

    #[test]
    fn uppercase_hex_is_accepted_and_matches_the_dev_key() {
        let uppercase = DEV_HEX.to_ascii_uppercase();
        let key = resolve_vendor_key(Some(&uppercase), false).unwrap();
        assert!(key.is_dev);
        assert_eq!(key.bytes, DEV_VENDOR_PUBLIC_KEY);
    }

    #[test]
    fn release_refuses_an_empty_key() {
        let error = resolve_vendor_key(Some(""), true).unwrap_err();
        assert!(error.contains("AEGIS_RELEASE=1 requires a production"));
    }

    #[test]
    fn error_messages_never_print_the_key() {
        let prod = prod_hex();
        for value in [Some(DEV_HEX), Some("zz"), Some("04a1")] {
            let error = resolve_vendor_key(value, true).unwrap_err();
            assert!(!error.contains(&prod[2..]));
            assert!(!error.contains(&DEV_HEX[2..]));
        }
    }

    #[test]
    fn development_key_is_a_valid_curve_point() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let key = p256::PublicKey::from_sec1_bytes(&DEV_VENDOR_PUBLIC_KEY).unwrap();
        assert_eq!(key.to_sec1_point(false).as_bytes(), &DEV_VENDOR_PUBLIC_KEY);
    }
}
