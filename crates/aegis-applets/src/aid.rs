//! Application identifiers (AIDs) of the applets this device exposes.
//!
//! Matching is by prefix: a host may select an OpenPGP card with a
//! version-specific AID that extends [`OPENPGP`], and the router accepts it as
//! long as the requested AID starts with the registered one.

/// PIV (NIST SP 800-73-4), AID `A000000308000010000100`.
pub const PIV: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// OpenPGP card: RID `D27600012401` without the version-specific suffix.
pub const OPENPGP: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// OATH (Yubico) applet, AID `A0000005272101`.
pub const OATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
