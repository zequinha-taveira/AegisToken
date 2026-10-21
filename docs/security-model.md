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

## Firmware update key

- **The development update key is public by construction.** It is the P-256
  generator point, so its private key is the number 1: anyone can sign a
  package that such an image accepts. It exists only as a trap for images
  built without a real key.
- **A distributable image may not embed it.** The build refuses to produce a
  release image with the development key: `-Release` (or `AEGIS_RELEASE=1`)
  turns the "development key in use" warning into a build error, whether the
  key was omitted or passed explicitly. The policy lives in
  `crates/aegis-build-support` and is covered by host tests; the boot warning
  remains the last defense for images that were already flashed.
- **The key is public material.** It is derived from the environment at build
  time and never committed; the message that rejects a bad key never prints
  it.

## Backup scope

- **Seed backup covers the deterministic identity only.** Restoring a seed
  on a new board does not restore resident passkeys, OpenPGP keys or PIV
  keys: those keys are generated on-device, sealed under the board's
  OTP root key, and do not survive a board swap.

## FIDO PIN/UV invariants (phase 7)

The `pinUvAuthToken` is a live proof of user verification and is scoped:

- **The token is scoped by operation and by relying party.** A token only
  authorises the operation its permission covers (`mc` for
  `authenticatorMakeCredential`, `ga` for `authenticatorGetAssertion`, `cm`
  for `authenticatorCredentialManagement`) and the relying party it is bound
  to. A token issued without a permissions RP ID is bound to the relying party
  of its **first use** for `mc` and `ga` (§6.5.5.7); from then on, a token
  bound to `R` serves only the requests whose `rp.id` is exactly `R` (exact,
  case-sensitive comparison).
- **Credential management is scoped too.** Every credential-management
  subcommand requires the `cm` permission, including `getCredsMetadata`.
  `enumerateRPsBegin` and `getCredsMetadata` require a token that is not
  bound to a relying party, because the enumeration of the device is global.
  `enumerateCredentialsBegin` and `deleteCredential` require the `cm`
  capability and, for a bound token, only the credentials of the bound relying
  party; a credential of another relying party is refused and preserved in the
  store.
- **A missing permission or a diverging relying party is an authentication
  failure, not an absent proof.** The request is answered with
  `CTAP2_ERR_PIN_AUTH_INVALID` (`0x33`), the operation is aborted before any
  effect — no credential is created, no assertion is signed, no credential is
  removed — and the `UV` flag is not written to the `authenticatorData`.
  `0x40` (`UnauthorizedPermission`) stays reserved for the token issuance
  path.
- **The token is spent by an operation that tests user presence.** After a
  successful `authenticatorMakeCredential` or `authenticatorGetAssertion` that
  used the token, the token loses every permission (§6.5.5.7 — `lbw` is not
  supported here) and its relying-party binding: any further use is refused
  with `0x33` and the platform has to fetch a fresh token. A failed operation
  or an operation that did not use the token keeps the permissions.
- **The token does not outlive the PIN.** `changePIN` and
  `authenticatorReset` invalidate the active token: its secret, its
  permissions and its relying-party binding are dropped.
- **A pending assertion belongs to the channel that started it.** The
  `authenticatorGetNextAssertion` continuation state is keyed by the CTAPHID
  channel: another application on the same host cannot continue an assertion it
  never asked for, and receives no credential id or user handle. The state is
  only created for a request that produced a signature
  (`aegis-core::assertion`, host-tested).
- **The scope check is pure core logic.** It lives in `aegis-core` (`pin` and
  `authenticator`), with no HAL, executor or storage dependency; the firmware
  only hands over the relying party, the credential id and the `rpIdHash` of
  the request. The FIDO path stays independent from Management, keyboard and
  CCID. The relying-party comparison is a plain string comparison (the relying
  party is not a secret); the HMAC comparison stays constant time.
- **Documented deviations.** The token of the superseded `getPinToken`
  subcommand keeps its CTAP2.0 shape — it grants `mc|ga` and is not bound to a
  relying party — but it never authorises credential management: the `cm`
  permission has to be requested explicitly. The *usage timer* of §6.5.2.1 is
  not implemented, so a token lives as long as the CTAPHID session unless it
  is spent by an operation that tests user presence.

## Recovery and lockout path isolation

- **The deny-list is applied at boot, before any sealed store is opened.**
  The boot destination (`Active`, `Recovery` or `Locked`, derived from the
  BOOTSEL pin) is turned into a boot plan in `aegis-core`
  (`state::BootPlan`). The plan states, per path, what the firmware may serve
  (FIDO, CCID, Management HID, laboratory OTP HID) and which sealed stores it
  may open (the FIDO credential store and the applet stores). The firmware
  reads the plan and obeys it; it makes no security decision of its own.
- **Recovery and locked deny the authentication paths.** In those
  destinations the FIDO and CCID tasks are not started, and the sealed-store
  open points are additionally conditioned on the plan, so a path denied by
  policy neither serves requests nor touches sealed material.
- **Management stays available.** Diagnostics (`GET_STATUS`,
  `GET_DIAGNOSTICS`) and the signed firmware-update path remain enabled in
  every destination — they are what recovery is for. The laboratory OTP HID
  also stays enabled: it is read-only diagnostics and exposes no secret.
- **Fail-closed by construction.** The plan is a total function over the
  execution state: any state that is not a boot destination yields a plan
  without FIDO and without CCID, keeping Management. The plan never enables
  FIDO where `state::fido_allowed` denies it.
- **Known limits.** The FIDO and CCID interfaces still enumerate in recovery
  (suppressing enumeration would require changing the USB descriptors); the
  observable effect is "enumerated and mute". The recovery *session*
  (`aegis-core::recovery::RecoverySession`) is not yet executed on device, and
  the sealed stores remain closed but present in flash.

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
