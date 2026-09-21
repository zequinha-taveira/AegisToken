# CONTEXT.md — AegisToken

## What it is

Universal firmware for the RP2350 family (RP2350A/B + RP2354A/B, one binary with automatic hardware discovery). Implements a FIDO2/WebAuthn + U2F authenticator, a proprietary Management HID interface, and CCID smartcard applets (PIV / OATH / OpenPGP), as a single USB composite device.

- USB product: `AegisToken FIDO2 USB Authenticator`, VID `0x1209` PID `0x0001` (generic profile). Third-party boards use VID `0x2E8A` + allocated PID (see `README.md` table).
- Release artifact: `rp2350-universal.uf2` via `scripts/build-uf2.ps1`.
- Status: phases 0–15 done; 16 (RSA-2048) and 17 (applet conformance) in firmware, hardware validation pending. See `roadmap.md` and `validation.md` (AC-001..AC-021).

## USB interfaces (strictly separated)

| Interface | Class | Purpose |
|-----------|-------|---------|
| FIDO HID | usage page `0xF1D0` | CTAP2/FIDO2 (incl. Ed25519 `ed25519-sk`) + CTAP1/U2F |
| Management HID | vendor `0xFF00` | Config, lifecycle, diagnostics, firmware update |
| HID Keyboard | standard | Optional, disabled by default, lifecycle + presence gated, never reachable from FIDO |
| CCID | `0x0B` | ISO 7816 applets: PIV, OpenPGP, OATH (ECC + RSA-2048) |

Invariants: FIDO never depends on Keyboard/Management/CCID. CCID never reachable from FIDO. Recovery mode denies FIDO/CCID/credentials.

## Crate map

- `aegis-core` — portable domain: `state`, `lifecycle`, `recovery`, `capabilities`, `discovery`, `configuration` (CBOR + CRC-32, two-slot atomic commit), `presence` (debounce, consume-once, contextual), `ctaphid`, `ctap2`, `u2f`, `authenticator`, `pin` (clientPIN v1), `credential_store` (sealed), `storage`/`secret` (AES-256-GCM via OTP root key), `update` (signed ES256 package + anti-rollback), `management_protocol`.
- `aegis-applets` — `apdu` (short/extended, `61xx`/`6Cxx`), `ccid` framing, `router` (AID select), `tlv`, `pin` framework (`63Cx`), `piv` (NIST SP 800-73-4), `oath` (YKOATH, RFC 4226/6238), `openpgp` (v3.4 slice), `rsa` (RSA-2048 on `crypto-bigint`, no alloc, CRT + blinding), `sealed` (`SealedPivStore`/`SealedOathStore`/`SealedOpenPgpStore`).
- `board-generic-rp2350` — HAL only: GPIO/BOOTSEL (RAM-resident QSPI reader), LED, flash/QSPI, OTP root key, TRNG, USB HID/CCID classes, `PresenceAdapter::wait`.
- `firmware-universal-rp2350` — `embassy-rp` binary: USB tasks, boot selftest (`selftest.rs`, `applet-select`), `DeviceManager` (BoardIdentity / BoardHardwareProfile / McuIdentity).
- `aegistoken-host` — Rust CLI over libusb `vendored`: `list`, `info`, `capabilities`, `config`, `validate` (AC-003..009). `--vid`/`--pid` needed for third-party profiles.
- `security-key-*` — empty scaffolds, ignore.

## Key facts for edits

- Config: versioned CBOR, `DeviceConfig::for_board` derives factory defaults from board profile; USB identity in config must mirror `ValidationContext.identity`; LED off by default on LED-less boards.
- Presence: only valid in `FidoWaitPresence` (`bootsel_allowed_as_presence`); BOOTSEL or external GPIO per `PresenceProfile`.
- Crypto: P-256/P-384/Ed25519/X25519 + RSA-2048 (PKCS#1 v1.5 only; no RSA-3072/PSS, no OpenPGP KDF). Private keys generated on-device, never exported/imported. OATH has no RTC — host supplies timestamp/counter.
- Flash: 2 MiB minimum; applet region 19× 8 KiB two-slot stores (PIV meta + 10 objects, OATH 2+commit, OpenPGP 4+commit); `const assert` against `FlashLayout`.
- PIV defaults (PIN `123456`, PUK `12345678`, 3DES mgmt key `0102..08`, CCC/CHUI) are spec interop vectors, not leaks.
- DEV update key is embedded unless `AEGIS_UPDATE_VENDOR_PUBKEY` is set — never release such builds. Real secure boot/rollback enforced by RP2350 bootrom + OTP (production step, see `production.md`).

## Validation pointers

- Host gates: `cargo fmt --check`, `clippy -D warnings`, `cargo test` for `aegis-core` (~193 tests), `aegis-applets` (~147), `aegistoken-host` (5).
- Hardware scripts in `scripts/`: `validate_management.py`, `validate_fido.py` (needs FIDO interface free — Windows `fidohid` holds it; see `validation.md` options A/B/C), `validate_ccid/piv/oath/openpgp.py` (need `pcscd`/`usbccid`), `set_pin.py`.
- Windows Management HID works driverless via libusb HID backend (no Zadig). Linux needs `scripts/99-aegistoken.rules`.
- Known gaps: on-device credential store still in-memory pending storage-sharing refactor; CCID/RSA/SSH flows validated on host only, hardware runs pending (AC-016..021); no CTAPHID keepalive during presence wait.
