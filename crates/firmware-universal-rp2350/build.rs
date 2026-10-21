//! Build script for the Universal RP2350 Firmware.
//!
//! - Copies `memory.x` onto the linker search path.
//! - Emits the firmware-update vendor public key. Production builds set
//!   `AEGIS_UPDATE_VENDOR_PUBKEY` to 65 hex-encoded bytes (uncompressed SEC1
//!   P-256 public key); otherwise a development key is used (and flagged).
//!   Setting `AEGIS_RELEASE=1` turns the development key into a build error.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use aegis_build_support::{parse_release_flag, resolve_vendor_key};

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
    //
    // NOTE: CI runners export `env:` entries even when the backing secret is
    // unset, so an empty value must fall back to the dev key exactly like a
    // missing variable. Only a non-empty malformed value is a hard error.
    println!("cargo:rerun-if-env-changed=AEGIS_UPDATE_VENDOR_PUBKEY");
    println!("cargo:rerun-if-env-changed=AEGIS_RELEASE");
    let release = parse_release_flag(env::var("AEGIS_RELEASE").ok().as_deref())
        .unwrap_or_else(|error| panic!("{error}"));
    let key = resolve_vendor_key(
        env::var("AEGIS_UPDATE_VENDOR_PUBKEY").ok().as_deref(),
        release,
    )
    .unwrap_or_else(|error| panic!("{error}"));
    if key.is_dev {
        println!(
            "cargo:warning=firmware-update vendor key is the DEVELOPMENT key; \
             set AEGIS_UPDATE_VENDOR_PUBKEY for production images"
        );
    }

    let mut file = File::create(out.join("vendor_key.rs")).unwrap();
    write!(
        file,
        "pub const VENDOR_PUBLIC_KEY: [u8; 65] = {:?};\npub const VENDOR_KEY_IS_DEV: bool = {};\n",
        key.bytes, key.is_dev
    )
    .unwrap();

    // Board profile selection: the carrier identity and USB VID/PID presented
    // by the universal firmware. `AEGIS_BOARD` names a profile declared in
    // `board-generic-rp2350`; the build-time MCU family is a separate concern.
    println!("cargo:rerun-if-env-changed=AEGIS_BOARD");
    let board = env::var("AEGIS_BOARD").unwrap_or_default();
    let board = board.as_str();
    let profile = match board {
        "" | "generic" => "GENERIC",
        "yubikey5-lab" => "YUBIKEY5_LAB",
        "waveshare-rp2350-zero" => "WAVESHARE_RP2350_ZERO",
        "waveshare-rp2350-plus" => "WAVESHARE_RP2350_PLUS",
        "waveshare-rp2350-tiny" => "WAVESHARE_RP2350_TINY",
        "waveshare-rp2350-lcd-1.28" => "WAVESHARE_RP2350_LCD_1_28",
        "waveshare-rp2350-touch-lcd-1.28" => "WAVESHARE_RP2350_TOUCH_LCD_1_28",
        "waveshare-rp2350-one" => "WAVESHARE_RP2350_ONE",
        "waveshare-rp2350-geek" => "WAVESHARE_RP2350_GEEK",
        "waveshare-rp2350-lcd-0.96" => "WAVESHARE_RP2350_LCD_096",
        "waveshare-rp2350-eth" => "WAVESHARE_RP2350_ETH",
        "pimoroni-pico-plus-2" => "PIMORONI_PICO_PLUS_2",
        "pimoroni-tiny-2350" => "PIMORONI_TINY_2350",
        "pimoroni-plasma-2350" => "PIMORONI_PLASMA_2350",
        "pimoroni-pga2350" => "PIMORONI_PGA2350",
        "datanoise-picoadk-v2" => "DATANOISE_PICOADK_V2",
        "soldered-nula-max" => "SOLDERED_NULA_MAX",
        "invector-challenger-plus" => "INVECTOR_CHALLENGER_PLUS",
        other => panic!(
            "unknown AEGIS_BOARD '{other}'; expected 'generic', 'yubikey5-lab' or a third-party \
             board profile declared in board-generic-rp2350::capabilities"
        ),
    };
    let mut file = File::create(out.join("board_profile.rs")).unwrap();
    writeln!(
        file,
        "pub const BOARD_PROFILE: BoardProfile = BoardProfile::{profile};"
    )
    .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
