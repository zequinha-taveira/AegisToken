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
- **The credential count follows the CTAP 2.1 rules and is never truncated.**
  `numberOfCredentials` is present only when more than one credential matched
  and the request carried no allow list; it is absent with an allow list, with
  a single match and in the continuation responses. A store holding more
  matching credentials than the limit is reported as `LimitExceeded` instead
  of silently dropping a credential, so the count can never understate the
  number of candidates (`aegis-core::authenticator`, host-tested).
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
- **The BOOTSEL sample must be electrically meaningful.** BOOTSEL is read from
  the QSPI chip-select pad with the XIP driver released. Before sampling, the
  firmware enables that pad's input buffer and pull-up and clears its
  isolation bit: a released pad without them floats and reads low, which is
  indistinguishable from a pressed button and would silently select Recovery,
  muting FIDO and CCID. The pad configuration is reapplied on every sample and
  an unstable multi-sample reading counts as "released".
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
  cycles; every failed attempt decrements before any other work. Unblock is
  fail-closed at each applet's command handler: the OpenPGP `RESET RETRY
  COUNTER` (`P1=0x02, P2=0x81`) requires the admin PIN already verified in
  the session (`pw3_verified`) and answers `6982` without touching any state
  otherwise; the resetting-code path (`P1=0x00`) answers `6A81` while the
  code is not provisioned; unknown parameters answer `6A86`; a successful
  unblock restores the PW1 counter, never touches the admin PIN and does not
  consume the PW3 session (it survives until `select()`). The PIN slot itself
  writes the new hash without knowing about sessions — the authorization is
  the caller's obligation (PIV verifies the PUK, OpenPGP requires the PW3).
  Admin mutations are session-gated: in OpenPGP, `CHANGE REFERENCE DATA` of
  the **PW3** (`P2=0x83`) also requires the admin session (`pw3_verified`)
  and answers `6982` before touching the slot, the counter, the session
  flags or the store (a session refusal neither consumes a retry nor
  persists); the current PIN in the command body remains a second factor
  (`slot.change` still verifies it) and the session survives the swap (only
  `select()` clears it). The **PW1** change (`P2=0x81`/`0x82`) keeps the
  current-PIN-in-data authority — card-spec/ecosystem behavior. The body is
  the card-spec one, the exact concatenation `current‖new` with no delimiter
  (`Lnew = Lc − Lold`): a body outside the format window `12 ≤ Lc ≤ 254` is
  refused with `6A80` before touching the slot (no attempt consumed, no
  save), and inside it the length known in the card is resolved by scanning
  the slot's stored hash — a read that consumes no attempt; a body no
  candidate delimits costs exactly one attempt (`63Cx` persisted), the same
  price a fixed-width change already charged for a wrong current PIN.
  A failed save in a PIN-mutating OpenPGP handler is **observable**: `VERIFY`
  (when it consumes an attempt), `CHANGE REFERENCE DATA`, `RESET RETRY
  COUNTER` and an accepted `PUT DATA` answer `6A84` instead of confirming a
  mutation that the store refused (a successful `VERIFY` moves nothing
  persistable and emits no save). The in-session RAM state stays
  restrictive and each reload is clamped to a per-slot sticky floor — the
  lowest retry counter known to be persisted or consumed in the session.
  **Trade-offs:** the floor is intra-session (it survives `select()`, is
  zeroed on a power cycle), and writing ahead of every attempt is
  deliberately rejected for flash wear. Until a good save re-anchors the
  floor, a power cycle can therefore restore the persisted counter when the
  save of the consumed attempt failed — this is the documented degradation
  model for a failing flash, not an unintended gap.
  The PIV applet follows the same rule on its own per-slot records: a `VERIFY`
  that consumes an attempt, `CHANGE REFERENCE DATA` and `RESET RETRY COUNTER`
  answer `6A84` when the save of the mutated record fails, and only the record
  of the slot that changed is written (`RECORD_PIN`/`RECORD_PUK`), so a
  refused save is attributable to one slot and is never confirmed as
  `63Cx`/`9000`. A successful `VERIFY`, an empty `VERIFY` and the parameter,
  length, format and blocked refusals (`6A86`, `6A88`, `6A80`, `6985`, `6700`,
  `6983`) save nothing. Its reloads are clamped to the same sticky per-slot
  floor (`pin_floor`/`puk_floor`, independent per slot): a failed save lowers
  the floor to the RAM counter — an unblock that did not persist can never
  raise it, so the next `SELECT` stays blocked — and a later good save
  re-anchors it. This matters more in PIV because a CCID stack reselects the
  AID per operation, so the floor is what closes the re-select window; between
  power cycles the persisted state governs, under the same trade-offs
  (intra-session floor, write-ahead rejected for flash wear).
  The OATH applet applies the same fail-closed rule to `RESET`
  (`P1=0xDE, P2=0xAD`), with the order inverted: the store erase (`clear`) is
  committed **before** any volatile cleanup, and a store refusal answers
  `6A84` instead of `9000` — credentials, access code and the authentication
  flags stay exactly as they were, and only an armed touch request (`pending`)
  is dropped. The order is what closes the hole here, because the empty OATH
  volatile state is the **permissive** side (`require_auth` releases when
  `auth_key` is empty), unlike the restrictive PIV/OpenPGP floor: clearing RAM
  first and failing the erase would silently disable the access code for the
  session and let the next save persist a state without it. There is no floor
  and no rollback: either the erase persisted and the RAM is cleared, or
  nothing changes. The happy path is a **single** write (the redundant
  `save_state()` of the empty blob was removed: it duplicated the erase and
  its failure had no correct answer), the removed persisted state is the whole
  blob (credentials, access code, HMAC algorithm/challenge; the in-session
  `auth_algorithm` lingers in RAM untouched, since it never leaves the blob
  on its own), and `P1`/`P2` outside the canonical pair answer `6D00` without
  touching the store. `INS_RESET`
  stays unauthenticated (YKOATH: it erases, it never reveals) and the erase is
  **logical** — the `SealedBlob` slot rotation may keep older sealed
  generations until they are overwritten.
  The OATH **read** path is fail-closed as well: `OathStore::load` distinguishes
  `Some(0)` (blank store — a virgin region or an erased record, a legitimate
  empty state) from `None` (IO, corruption or an undecryptable record), so the
  sealed adapter maps `Err` to `None` instead of collapsing it into "no state".
  Any `None`, or a blob the decoder refuses, closes the applet for the session:
  it answers `6F00` to every state command (`LIST`, `CALCULATE`,
  `CALCULATE ALL`, `PUT`, `DELETE`, `SET CODE`, `VALIDATE`, `confirm_presence`)
  and normalizes the volatile state to the boot state, so a failed read cannot
  disable the access code or let a `PUT` overwrite the blob that was not read.
  The direction is forced by the asymmetry with the other applets: the empty
  OATH state is the **permissive** side, whereas the OpenPGP default is
  restrictive and PIV answers `6F00` in its own `SELECT`. Accepted decisions,
  not gaps: (a) `SELECT` keeps answering the FCI (`9000`) so the recovery path
  stays reachable from the standard tooling, but the access-code block
  (`TAG_CHALLENGE`/`0x7B`) is omitted and `authenticated` stays false while
  closed; (b) `RESET` (`DE AD`) is the **necessary exception** — it erases and
  reveals nothing, its own result stays fail-closed (`6A84` keeps the applet
  closed) and, once the erase persists, the applet is open only over the empty
  state that erase proved, with the next `SELECT` reading the store again;
  (c) every `SELECT` is a fresh attempt and the refusal is volatile (never
  persisted), so a recovered read reopens the applet with its credentials and
  access code; (d) an unknown instruction while closed answers `6F00`, because
  state availability precedes instruction refusal. The trigger (a sick flash)
  sits outside the live threat model; this is robustness in the restrictive
  direction. The operational cost is documented in `validation.md`: a `RESET`
  during a transient failure erases credentials a later `SELECT` could have
  recovered, so reselect before resetting.
  The OATH **pending touch request** is bounded and dropped by mutation.
  `pending` holds an index into the credential vector plus the moving-factor
  parameters, so `confirm_presence` re-checks the index against the current
  length before indexing and answers `6985` when it no longer fits: indexing
  outside the vector would panic in `no_std` and halt the whole firmware
  (FIDO2, Management, PIV and OATH share one binary), and a shifted index would
  return another credential's code under a touch granted for the first. Every
  handler that changes the credential set drops the request first - `put`,
  `delete` (unconditionally, before authentication, name resolution and the
  store write, so a refused `DELETE` (`6982`/`6984`/`6A80`) or a failed save
  (`6A84`) disarms too) - and so do the pre-existing paths that reset the
  volatile state (`RESET`, RAM normalization) or restart the session
  (`SELECT`), because the authorization belongs to the credential that asked
  for it, not to whatever a later write stores. `CALCULATE ALL` is
  read-only over the set (HOTP entries are reported without computing, so no
  counter moves) and does not disarm, and neither does the HOTP counter bump in
  `calculate_index`, which runs after the request was consumed. An invalid
  index **collapses** into the same `6985` as "no pending request" (no oracle:
  the card never says whether the credential was deleted or never requested)
  and no new status word is introduced. **Trade-off:** a host that interleaves
  a `PUT`/`DELETE` between the armed `CALCULATE` and the confirmation receives
  `6985` and reissues the `CALCULATE`, the same handling as a cancelled touch.
  This is defensive robustness, not a reachable exposure: `Card::poll`
  serializes presence today (no frame is processed between the `6FF0` and the
  confirmation), so the applet keeps the invariant locally instead of
  inheriting it from the transport.
- **Secrets are sealed at rest.** Credential keys, OATH secrets, PIN-derived
  values and data objects are stored in sealed records (AES-256-GCM under the
  OTP root key); no applet response can export them.
- **The state an accepted command writes survives the session.** The decoder
  accepts the geometry its writer produces above the 48-octet slab, so the blob
  a sealed store holds is the state the next boot and every `select()` read
  back (OpenPGP: the decryption slot with `len = 104` — 32-octet ECDH scalar
  plus 72 octets of RFC 6637 material — under `UNSET` or ECDH P-256); every
  other width, slot or algorithm stays fail-closed. No `STATE_VERSION` bump and
  no migration: a blob written before the decoder learned that geometry decodes
  unchanged. The provisioned RFC 6637 material is card state, not a new secret:
  the sender's ciphertext plus public parameters, with the private key staying
  in the slot.
- **The card's private key never leaves it, and the ECDH model is the one the
  specification defines.** The OpenPGP Card 3.4.1 §4.4.3.8 defines the ECDH
  `PSO:DECIPHER` as a *partial decrypt*: the card calculates the shared secret
  with its own private key and returns it, because the ephemeral key of the
  message was chosen by the **sender** — the host cannot compute it by
  itself. The release of that derived value is gated by the verification of PW1
  in mode 82 (and by the touch policy, when enabled). The card can also
  decrypt on its own, following RFC 6637 §8 (KDF of §7, AES key wrap of
  RFC 3394, the OpenPGP symmetric layer of RFC 4880 §13.9 with the continuous
  CFB chain, the quick check and the modification detection code); in that mode
  the shared secret never leaves the card. Only ciphertext (the wrapped session
  key) and public material (the recipient fingerprint) are importable; the
  private key of the slot is generated on the device and never imported.
  Provisioning only accepts material the decipher can actually consume
  (`PUT DATA D2`: P-256 with the KDF of SHA-256, AES-128/192/256 as the KEK
  and a wrapped key in the RFC 3394 block domain); anything outside the
  domain is refused with `0x6A80` at the border, so nothing accepted can
  fail only at the first real decipher. The
  primitives live in `aegis-applets::ecdh` and `aegis-applets::pgp_sym`, covered
  by the RFC 3394 test vectors, by an independent reference implementation of
  the symmetric layer (`tests/openpgp_sym_reference.py`) and by an end-to-end
  interoperability test with a real GnuPG (`openpgp::tests::gnupg_interop`).
  The symmetric layer of RFC 4880 §13.9 compares its key-derived material —
  the quick-check octets, the MDC packet structure and the SHA-1 of the
  modification detection code — in constant time, through the same
  `constant_time_eq` accumulator discipline as the PIN comparison; the failure
  categories stay distinguishable by status word (`0x6F00` vs `0x6A80`) on
  purpose, for protocol interoperability, and only the timing *inside* each
  category is uniform — a documented behavior, not a gap. The adversarial
  contract of the data-heavy commands is pinned by the host suite
  (`openpgp::tests::adversarial_apdu`): every structurally malformed
  `PSO:DECIPHER` frame and every `PUT DATA D2` body out of the domain answers
  a single closed status word (`0x6A80` at the border, `0x6F00` when the size
  or the wrap can only fail later) with an empty body, no panic, no save and
  no state change, and no refusal ever echoes the private scalar, the wrapped
  session key or a shared secret off its documented route (window-checked per
  refusal). The deterministic `0x9000` + `Z` of the partial decrypt remains
  the only route where derived secret material leaves the card, gated by PW1
  in mode 82; an all-zero X25519 point agrees to the all-zero shared secret —
  the card accepts it as curve behavior, and refusing non-contributory points
  is a documented non-goal; ciphertext the card cannot decrypt answers
  `0x6F00` without ever being decoded upstream; the 2048-octet response
  window of the full-RFC 6637 decipher is a recorded interop decision — it is
  kept, not widened (`specs/openpgp-decipher-response-window.md`): at the
  applet boundary a 2048-octet message answers `0x9000` byte for byte and
  2049 answers `0x6A84` with an empty body. Over the real CCID transport that
  window is unreachable because the command input closes first: the largest
  scdaemon-shaped command (`86‖80`, extended frame) that fits one 2100-octet
  CCID message answers `0x9000` byte for byte, and one octet of frame more
  dies in the assembler with `CcidError::Overflow` before any applet code
  runs — the firmware then resets the card silently and answers nothing
  (documented, not negotiated). Messages over the window are the documented
  partial decrypt (card spec `0x9000` + `Z`) or a host-side job.
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

## Host tooling

The host side is part of the trust boundary: a secret that leaks on the host
defeats the on-device protections. The host tools follow these rules:

- **A secret is never accepted in `argv`.** The OS exposes a process command
  line to other local processes (`ps`, `/proc/<pid>/cmdline`, Task Manager,
  WMI) and keeps it in shell history. `aegistoken-host` rejects `--key` and
  `--old-key` (and a positional key for `piv-set-mgmt-key`), and
  `scripts/set_pin.py` and `scripts/validate_fido.py` reject `--pin` and
  `--old-pin`, with exit code 2. The refusal names the option but never echoes
  the value or a fragment of it.
- **The channels are a hidden prompt or stdin.** With a terminal, the secret
  is read through a hidden prompt (`rpassword`/`getpass`, host-only,
  Apache-2.0). For automation it arrives on stdin
  (`--key-stdin`/`--old-key-stdin`, `--pin-stdin`/`--old-pin-stdin`,
  `validate_fido.py --pin-stdin`); the mode is all-or-nothing, and `--change`
  reads the current secret first and the new one second. `validate_fido.py`
  without a PIN flag still runs the presence-only checks. Without a terminal
  and without the flags the tool fails instead of prompting or echoing. Stdin
  keys are parsed by a shape-only parser that reports length and encoding
  class, never the bytes.
- **Errors and logs stay redacted.** `set_pin.py` and `validate_fido.py` remove
  every acquired secret from the error text before printing it. No secret is
  written to a temporary file, a config file or a log. In `set_pin.py`,
  `--help` is processed before any secret is touched, so `--help --pin <value>`
  prints the usage without reading or echoing the value; the Rust CLI and
  `validate_fido.py` reject a secret option at parse time even when `--help` is
  also present (it never reaches a prompt). `validate_fido.py` also never prints
  the temporary PIN used by its `changePIN` round trip.
- **The OATH URI is a secret carrier too.** An `otpauth://` URI contains the
  shared `secret=`, so `aegistoken-host oath add` accepts it only from
  `--uri-stdin` (pipe) or the hidden prompt, refuses a positional URI without
  echoing it, and the parser reports the shape of an invalid URI or Base32
  input without echoing the value or a character of it. `OtpAuthCredential` has
  no `Debug` implementation, so the decoded secret cannot be printed by `{:?}`.
- **A leaked secret is rotated, not deprecated.** There is no compatibility
  opt-in for argv secrets: the only remediation is to rotate the exposed key
  or PIN and clear the shell history. The `rpassword` dependency is
  host-only and never enters the firmware workspace members.

