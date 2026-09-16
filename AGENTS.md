# AGENTS.md — AegisToken

Universal RP2350 firmware (Rust): FIDO2/CTAP2 + U2F, Management HID, CCID (PIV/OATH/OpenPGP). One binary for RP2350A/B + RP2354A/B.

## Where code lives

- `crates/aegis-core/` — portable `no_std`/`no_alloc` domain, host-testable. Source of truth during migration.
- `crates/aegis-applets/` — APDU/CCID/AID routing, TLV, PIV/OATH/OpenPGP, `no_std`, host-testable.
- `crates/board-generic-rp2350/` — HAL isolation only (GPIO, BOOTSEL, LED, flash, OTP, TRNG, USB).
- `crates/firmware-universal-rp2350/` — `embassy-rp` binary.
- `crates/aegistoken-host/` — host CLI over libusb `vendored`.
- `crates/security-key-*` — empty scaffolds. Do not move code there.
- Aliases in `.cargo/config.toml`. Toolchain pinned in `rust-toolchain.toml` (1.97.1 + `thumbv8m.main-none-eabihf`). Do not change toolchain or suggest npm/pip installs.

## How to validate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
```

Firmware: `& scripts/build-uf2.ps1` (default rp2350a). Board profiles via `AEGIS_BOARD` or `-BoardProfile`.

## Rules

- Keep `aegis-core`/`aegis-applets` free of HAL/executor deps. Reuse workspace deps. Check `Cargo.toml` first.
- No new `unsafe` without justification. Readable first.
- FIDO path independent of Management/Keyboard/CCID.
- Never commit or log secrets (`*.pem`, `*.key`, PINs, seeds, OTP dumps — gitignored). Without `AEGIS_UPDATE_VENDOR_PUBKEY` build uses DEV update key: warn, never release.
- PIV defaults in `crates/aegis-applets/src/piv.rs` (`DEFAULT_MGMT_KEY`, `DEFAULT_PIN`, `DEFAULT_PUK`, CCC/CHUI) are NIST SP 800-73-4 interop values. Do not flag as leaks, do not randomize.
