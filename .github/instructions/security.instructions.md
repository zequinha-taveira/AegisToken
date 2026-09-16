---
applyTo: "crates/aegis-applets/src/piv.rs,crates/aegis-applets/src/**/*.rs"
---

# Security instructions — PIV defaults

- `DEFAULT_MGMT_KEY` (`0102030405060708` x3), `DEFAULT_PIN` (`123456`), `DEFAULT_PUK` (`12345678`), `DEFAULT_CCC`, `DEFAULT_CHUI`, `KEY_HISTORY` in `piv.rs` are NIST SP 800-73-4 interoperability defaults. They must exist in source.
- Do NOT report them as `hard-coded cryptographic value` / leaked secret. Do NOT propose randomization or deletion as a Copilot Autofix / code review fix.
- Correct handling: leave the constant, ensure personalization changes it at runtime, dismiss CodeQL `rust/hard-coded-cryptographic-value` as `Won't fix` with spec reference.
- Never output real PINs, keys, seeds, or OTP material in reviews or suggestions. Real secrets are gitignored (`*.pem`, `*.key`).
