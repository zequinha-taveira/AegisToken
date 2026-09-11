//! Build script for the Universal RP2350 Firmware.
//!
//! - Copies `memory.x` onto the linker search path.
//! - Emits the firmware-update vendor public key. Production builds set
//!   `AEGIS_UPDATE_VENDOR_PUBKEY` to 65 hex-encoded bytes (uncompressed SEC1
//!   P-256 public key); otherwise a development key is used (and flagged).

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Development P-256 public key: the curve generator point.
///
/// This is public and must never be used in production. Replace it by setting
/// `AEGIS_UPDATE_VENDOR_PUBKEY` at build time.
const DEV_VENDOR_PUBLIC_KEY: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];

fn parse_sec1_hex(value: &str) -> Option<[u8; 65]> {
    let value = value.trim();
    if value.len() != 130 {
        return None;
    }
    let mut out = [0u8; 65];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // Linker setup: RP235x uses cortex-m-rt's `link.x` plus `memory.x`.
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");

    // Firmware-update vendor key.
    println!("cargo:rerun-if-env-changed=AEGIS_UPDATE_VENDOR_PUBKEY");
    let (key, is_dev) = match env::var("AEGIS_UPDATE_VENDOR_PUBKEY") {
        Ok(hex) => match parse_sec1_hex(&hex) {
            Some(key) => (key, false),
            None => panic!(
                "AEGIS_UPDATE_VENDOR_PUBKEY must be 130 hex characters (65-byte \
                 uncompressed SEC1 P-256 public key)"
            ),
        },
        Err(_) => (DEV_VENDOR_PUBLIC_KEY, true),
    };

    let mut file = File::create(out.join("vendor_key.rs")).unwrap();
    write!(
        file,
        "pub const VENDOR_PUBLIC_KEY: [u8; 65] = {:?};\npub const VENDOR_KEY_IS_DEV: bool = {};\n",
        key, is_dev
    )
    .unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
