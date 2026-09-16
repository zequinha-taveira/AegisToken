# SSH and Git signing with AegisToken

AegisToken works as a FIDO2 security key for SSH (`ed25519-sk`,
`ecdsa-sk`) and as an OpenPGP card for `gpg-agent` SSH. This guide covers
Linux, macOS and Windows.

## Requirements

- Firmware with Phase 15 (Ed25519 in CTAP2 and OpenPGP).
- OpenSSH 8.2+ with FIDO support (`ssh -V`; needs libfido2).
- A resident-capable flow: the token supports discoverable credentials
  (`rk` option). User verification (`verify-required`) is **not** supported:
  the device is presence-only (BOOTSEL), so skip that option.

When OpenSSH asks for confirmation, press **BOOTSEL** on the token.

## FIDO2 SSH keys (`ed25519-sk`)

Generate a resident key (recommended: the private handle stays usable via
`ssh-keygen -K` on any host):

```sh
ssh-keygen -t ed25519-sk -O resident -C "user@host"
```

For a non-resident key, omit `-O resident` and keep the generated
`~/.ssh/id_ed25519_sk` file (it stores the key handle; the private key
never leaves the token).

List resident keys and load one into the agent:

```sh
ssh-keygen -K
ssh-add -K  # or: ssh-add ~/.ssh/id_ed25519_sk
```

Use it normally afterwards:

```sh
ssh -i ~/.ssh/id_ed25519_sk user@server
```

On the server, append the `.pub` contents to `~/.ssh/authorized_keys` as
with any SSH key. `ecdsa-sk` works the same way (`-t ecdsa-sk`).

### Windows notes

- The OpenSSH that ships with Windows supports `-sk` keys; prefer
  Windows OpenSSH over PuTTY for FIDO flows.
- The FIDO HID interface may be claimed by the OS; SSH needs raw access
  like a browser does. If key generation fails to find the token, run the
  flow once in a browser (e.g. register at a test site) to confirm the
  device enumerates, then retry.

## Git commit and tag signing over SSH

Configure Git to sign with your SSH key (no GPG needed):

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk.pub
git commit -S -m "message"
git log --show-signature
```

Each signature prompts for BOOTSEL presence through `ssh-agent`. Verifiers
need OpenSSH 8.2+ and your public key (e.g. in the `allowed signers` file
for `git verify-commit` / hosting providers that accept SSH signatures).

## OpenPGP alternative (`gpg-agent` SSH)

If you prefer the OpenPGP applet, generate an authentication key on-card
(`gpg --card-edit` → `generate`), enable SSH in the agent and fetch the
key:

```sh
# ~/.gnupg/gpg-agent.conf
enable-ssh-support
```

```sh
gpg-connect-agent "keyinfo --list" /bye
SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)" ssh-add -L
```

This uses the AUT slot (ECDSA P-256 or Ed25519 after setting the slot
algorithm). PIN handling follows the OpenPGP card rules (PW1).

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `ssh-keygen` reports no security key | Token not enumerated; check USB connection and OS access (see above) |
| `unsupported algorithm` from the token | Client offered only RSA/ECDH algs; use `-t ed25519-sk` or `-t ecdsa-sk` |
| Signature prompt never completes | BOOTSEL not pressed within the presence timeout; retry |
| `verify-required` fails | Expected: the token has no user verification, only presence |
| `gpg --card-status` shows no keys | Generate keys on-card first; check PW1/PW3 verification |
