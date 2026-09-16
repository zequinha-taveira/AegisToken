# Security Model

The migration must preserve the existing security boundaries: FIDO operations
remain independent from management and keyboard paths, user presence remains
contextual, and secrets are never exported or logged.

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
  generation. RSA-3072/PSS stay out of scope.
