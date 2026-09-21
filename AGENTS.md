# AGENTS.md — AegisToken

Universal RP2350 firmware (Rust): FIDO2/CTAP2 + U2F, Management HID, CCID (PIV/OATH/OpenPGP). One binary for RP2350A/B + RP2354A/B.

## Stack

- Toolchain pinned in `rust-toolchain.toml` (1.97.1 + `thumbv8m.main-none-eabihf`). Do not change it. Do not suggest npm/pip installs.
- Workspace in `Cargo.toml`. `default-members = ["crates/aegis-core", "crates/aegis-applets"]` so host `cargo test`/`cargo build` works without the embedded target.
- Embedded: `embassy-rp` + `embassy-usb` + `embassy-executor`, async. Host CLI: `rusb` with `vendored` libusb (no WinUSB/Zadig).
- Aliases in `.cargo/config.toml`: `cargo build-fw`, `cargo build-fw-release`, `cargo clippy-fw`, `cargo test-core`, `cargo clippy-core`, `cargo test-applets`, `cargo clippy-applets`.

## Where code lives

- `crates/aegis-core/` — portable `no_std`/`no_alloc` domain (state, lifecycle, CTAP2/U2F, PIN, storage, update, recovery), host-testable. Source of truth during migration.
- `crates/aegis-applets/` — APDU/CCID/AID routing, TLV, PIV/OATH/OpenPGP + RSA, `no_std`, host-testable.
- `crates/board-generic-rp2350/` — HAL isolation only (GPIO, BOOTSEL, LED, flash, OTP, TRNG, USB HID/CCID classes).
- `crates/firmware-universal-rp2350/` — `embassy-rp` binary (USB tasks, selftest).
- `crates/aegistoken-host/` — host CLI over libusb `vendored` (Management HID).
- `crates/security-key-*` — empty scaffolds. Do not move code there.
- `scripts/` — `build-uf2.ps1`, `validate_*.py`, `set_pin.py`, `gen-update-key.py`. `docs/` — architecture, security-model, development, production, ssh-git.

## How to validate

```powershell
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
cargo clippy -p aegistoken-host --all-targets -- -D warnings
cargo test -p aegistoken-host
```

Firmware (default rp2350a, board profiles via `AEGIS_BOARD` or `-BoardProfile`):

```powershell
& scripts/build-uf2.ps1
& scripts/build-uf2.ps1 -Board rp2350b
& scripts/build-uf2.ps1 -BoardProfile waveshare-rp2350-zero
```

Python validators: `validate_management.py` (AC-003..009), `validate_fido.py` (AC-002/011/013/020), `validate_ccid.py` (AC-016), `validate_piv.py` (AC-017/021), `validate_oath.py` (AC-018), `validate_openpgp.py` (AC-019/021).

Workflows (on demand): `/gates` runs the gates, `/spec <slice>` implements a roadmap slice spec-first; skills `aegis-gates` and `aegis-spec`, subagents `gates` and `review`.

## Rules

- Keep `aegis-core`/`aegis-applets` free of HAL/executor deps. Reuse workspace deps. Check `Cargo.toml` before adding a dependency.
- FIDO path independent of Management/Keyboard/CCID. CCID never reachable from FIDO. Recovery denies FIDO/CCID/credentials (diagnostics + update only).
- No new `unsafe` without justification. Readable first, no premature optimization.
- `AnyPin::steal` for runtime LED GPIO is the single justified exception (one owner per pin); GPIO 0-5 (QSPI) never a candidate (compile-time enforced).
- Never commit or log secrets (`*.pem`, `*.key`, PINs, seeds, OTP dumps — gitignored). Without `AEGIS_UPDATE_VENDOR_PUBKEY` build uses DEV update key: warn, never release.
- PIV defaults in `crates/aegis-applets/src/piv.rs` (`DEFAULT_MGMT_KEY`, `DEFAULT_PIN`, `DEFAULT_PUK`, CCC/CHUI) are NIST SP 800-73-4 interop values. Do not flag as leaks, do not randomize.
- No private-key import in applets (on-device generation only); only public material (certs) importable.
- Tests mandatory for new/changed logic. Check existing test layout first (`cargo test -p aegis-core`, `-p aegis-applets`).
- Always validate after any code change: run `cargo fmt --all --check`, the `clippy -D warnings` and `cargo test` gates for every touched crate, plus `cargo build-fw` when firmware/HAL is affected. Never consider a task done with red or skipped validation.
- Verify your own work: exercise the changed behavior yourself (test, CLI, or script) and report the evidence; never claim done without executing the check.
- One logical change per commit/PR. Do not commit without explicit request; inspect `git status`/`git diff` first.
- Public API/protocol changes require doc updates (`README.md`, `docs/`, `roadmap.md`, `validation.md` as applicable). Prefer editing existing docs over creating new ones. Repo user docs are pt-BR.
- When a roadmap item is completed, mark it done in `roadmap.md` in the same change.
