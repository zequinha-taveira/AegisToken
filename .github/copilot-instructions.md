# Copilot instructions — AegisToken

Universal RP2350 firmware (Rust): FIDO2/WebAuthn + CTAP1/U2F, Management HID, HID Keyboard (off by default), CCID with PIV / OATH / OpenPGP applets. Single binary for RP2350A/B + RP2354A/B with auto hardware discovery.

## Layout

Workspace (`Cargo.toml`, resolver 3, edition 2024, Rust 1.97.1):
- `crates/aegis-core/` — portable `no_std`/`no_alloc` domain, host-testable.
- `crates/aegis-applets/` — APDU/CCID/AID routing, TLV, PIV/OATH/OpenPGP, `no_std`, host-testable.
- `crates/board-generic-rp2350/` — RP2350 HAL isolation (GPIO, BOOTSEL, LED, flash, OTP, TRNG, USB).
- `crates/firmware-universal-rp2350/` — `embassy-rp` binary, USB tasks.
- `crates/aegistoken-host/` — host CLI over libusb (`vendored`, no Zadig needed).
- `crates/security-key-*` (6 crates) — empty scaffolds, do not move code there.
- `scripts/build-uf2.ps1`, `scripts/validate_*.py`, `docs/`, `.cargo/config.toml` aliases (`build-fw`, `test-core`, etc.).

## Build / test / lint — always run in this order

```powershell
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
cargo clippy -p aegistoken-host --all-targets -- -D warnings
cargo test -p aegistoken-host
```

Firmware (needs `thumbv8m.main-none-eabihf`):
```powershell
& scripts/build-uf2.ps1
& scripts/build-uf2.ps1 -Board rp2350b
cargo clippy -p firmware-universal-rp2350 --no-default-features --features rp2350a --target thumbv8m.main-none-eabihf --release -- -D warnings
```

Third-party board profile: `AEGIS_BOARD` env or `-BoardProfile` (e.g. `waveshare-rp2350-zero`). Default `generic` = VID:PID `1209:0001`.

Do not suggest `npm`, `pip install`, or changing toolchain. Toolchain is pinned in `rust-toolchain.toml`.

## Code conventions

- `aegis-core` / `aegis-applets`: keep `no_std` + `no_alloc`, no HAL/executor deps, reuse workspace deps (`heapless`, `zeroize`, `sha2`, `p256`, `aes-gcm`, etc.). Check `Cargo.toml` before adding a dependency.
- Readable first, no premature optimization. No new `unsafe` without recorded justification.
- FIDO path must stay independent of Management/Keyboard/CCID. Presence only accepted in `FidoWaitPresence`.
- Config: versioned CBOR + CRC-32, two-slot atomic commit. Secrets: AES-256-GCM sealed with OTP master key, never exported or logged.

## Security — CodeQL / secret scanning false positives

- `crates/aegis-applets/src/piv.rs`: `DEFAULT_MGMT_KEY` (`0102030405060708` x3), `DEFAULT_PIN=b"123456"`, `DEFAULT_PUK=b"12345678"` are NIST SP 800-73-4 interop defaults. They must exist. Do NOT report as leaked secrets, do NOT propose random generation as a fix, do NOT emit autofix for `rust/hard-coded-cryptographic-value` here. Correct action is dismiss as `Won't fix` with spec reference.
- Same for default CCC/CHUI/KEY_HISTORY constants in that file.
- Real secrets (`*.pem`, `*.key`, OTP dumps, PINs, seeds) are gitignored. Never commit or log them. Never include them in suggestions.
- Without `AEGIS_UPDATE_VENDOR_PUBKEY` the build embeds a DEV update key with a warning — not releasable. Do not suppress that warning.
