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

## FIDO PIN/UV invariants (phase 7)

The `pinUvAuthToken` is a live proof of user verification and is scoped:

- **The token is scoped by operation and by relying party.** A token only
  authorises the operation its permission covers (`mc` for
  `authenticatorMakeCredential`, `ga` for `authenticatorGetAssertion`) and the
  relying party it is bound to. A token issued without a permissions RP ID
  serves every relying party; a token bound to `R` serves only the requests
  whose `rp.id` is exactly `R` (exact, case-sensitive comparison).
- **Credential management is scoped too.** `enumerateRPsBegin` requires a
  token that is not bound to a relying party, because the enumeration of
  relying parties is global. `enumerateCredentialsBegin` and
  `deleteCredential` require the `cm` capability and, for a bound token, only
  the credentials of the bound relying party; a credential of another relying
  party is refused and preserved in the store.
- **A missing permission or a diverging relying party is an authentication
  failure, not an absent proof.** The request is answered with
  `CTAP2_ERR_PIN_AUTH_INVALID` (`0x33`), the operation is aborted before any
  effect — no credential is created, no assertion is signed, no credential is
  removed — and the `UV` flag is not written to the `authenticatorData`.
  `0x40` (`UnauthorizedPermission`) stays reserved for the token issuance
  path.
- **The scope check is pure core logic.** It lives in `aegis-core` (`pin` and
  `authenticator`), with no HAL, executor or storage dependency; the firmware
  only hands over the relying party, the credential id and the `rpIdHash` of
  the request. The FIDO path stays independent from Management, keyboard and
  CCID. The relying-party comparison is a plain string comparison (the relying
  party is not a secret); the HMAC comparison stays constant time.
- **Documented deviations.** The token of the superseded `getPinToken`
  subcommand keeps its CTAP2.0 semantics: it grants `mc|ga`, it is not bound to
  a relying party and it still drives credential management. A strict CTAP2.1
  authenticator would require an explicit `cm` permission there; changing it is
  a separate slice with a compatibility impact.

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
  `0x1209:0x0001`. Compatibility with Yubico Authenticator and `ykman` is
  protocol-based (FIDO HID, OATH/YKOATH and PIV over CCID), not a claim that
  the device is a YubiKey. Any VID/PID profile used to exercise tools that
  filter by Yubico identity is laboratory-only, requires authorization, and
  must never be distributed.
