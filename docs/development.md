# Development

The migration scaffold (`security-key-*`) is intentionally dependency-free.
Until those crates take over a responsibility, `aegis-core` and `aegis-applets`
are the active host-testable crates and both are default workspace members.

## Host gates

Every change must pass:

```bash
cargo fmt --all --check
cargo clippy -p aegis-core --all-targets -- -D warnings
cargo test -p aegis-core
cargo clippy -p aegis-applets --all-targets -- -D warnings
cargo test -p aegis-applets
cargo clippy -p aegistoken-host --all-targets -- -D warnings
cargo test -p aegistoken-host
```

Embedded changes additionally require the firmware gates from `roadmap.md`
(`clippy` and `build` for `thumbv8m.main-none-eabihf`).

## Applet validators (need hardware)

Host-side suites run without a device; the PC/SC validators need one:

```powershell
python scripts/validate_ccid.py       # CCID routing (AC-016)
python scripts/validate_piv.py        # PIV incl. RSA-2048 (AC-017, AC-021)
python scripts/validate_oath.py       # OATH (AC-018)
python scripts/validate_openpgp.py    # OpenPGP incl. RSA-2048 (AC-019, AC-021)
```

All scripts print `[PASS]/[FAIL]` per check and exit non-zero on failure;
see `validation.md` for the AC matrix, the hardware procedures that cannot
run in CI, and the recorded interop assumptions.
