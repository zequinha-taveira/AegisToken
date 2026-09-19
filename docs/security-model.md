# Security Model

The migration must preserve the existing security boundaries: FIDO operations
remain independent from management and keyboard paths, user presence remains
contextual, and secrets are never exported or logged.

## Hardware trust boundary

- **No secure element.** The RP2350 is a general-purpose MCU without a
  discrete secure element or tamper-responsive package.
- **Real hardening in scope:** OTP-derived sealing key, AES-256-GCM at rest,
  RP2350 secure boot (ECDSA secp256k1 + OTP bootkey hash) with anti-rollback,
  and signed firmware updates.
- **Physical attacks are out of scope:** invasive probing, fault injection,
  power/side-channel analysis and flash decapsulation are not mitigated
  beyond the OTP/secure-boot hardening above.

## Backup scope

- **Seed backup covers the deterministic identity only.** Restoring a seed
  on a new board does not restore resident passkeys, OpenPGP keys or PIV
  keys: those keys are generated on-device, sealed under the board's
  OTP root key, and do not survive a board swap.

## Applet security invariants (phases 11-17)

The PIV, OpenPGP and OATH applets must preserve the following invariants:

- **Private keys never leave the device.** Key generation happens on-device
  from the hardware TRNG; no import path for private keys exists. Only public
  material (certificates, data objects) may be imported.
- **PIN state is persistent and fail-closed.** Retry counters, blocked states
  and unblock flows are sealed with the OTP-derived key and survive power
  cycles; every failed attempt decrements before any other work.
- **Secrets are sealed at rest.** Credential keys, OATH secrets, PIN-derived
  values and data objects are stored in sealed records (AES-256-GCM under the
  OTP root key); no applet response can export them.
- **Each signing operation honours its touch policy.** When a slot or
  credential requires touch, the applet arms the contextual presence machine
  and fails with the applet's standard error on absence or timeout.
- **Transport paths stay isolated.** CCID is never reachable from the FIDO
  input path, the management HID remains separate, and Recovery denies CCID
  the same way it denies FIDO (diagnostics and firmware update remain
  available).
- **No secrets in logs or diagnostics.** Applet diagnostics report state,
  counters and capabilities, never key material, PINs or OATH secrets.
- **Constant-time discipline.** ECDSA/ECDH/EdDSA use the existing RustCrypto
  primitives. RSA-2048 (phase 16) uses fixed-size Montgomery modexp
  (`crypto-bigint`, no `alloc`) with mandatory multiplicative blinding on
  every private operation, plus a public-op re-verification of signatures
  (fault-injection guard). Residual side channels are documented in
  `crates/aegis-applets/src/rsa.rs`: Montgomery setup over secret moduli,
  the single-pass unpad scan index, and probabilistic (non-FIPS) prime
  generation. RSA-3072/PSS stay out of scope. No brainpoolP512r1 / X448 /
  Ed448 (no mature `no_std` Rust arithmetic yet); brainpoolP256r1 and
  P384r1 remain supported.
- **USB identity.** The default is the project's own pid.codes id
  `0x1209:0x0001`. The YubiKey USB identity that `ykman` / Yubico
  Authenticator auto-recognize is an opt-in `VIDPID=Yubikey5` build for
  local testing only — not for distribution.
