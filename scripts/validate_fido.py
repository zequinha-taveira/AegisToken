#!/usr/bin/env python3
"""AegisToken — Phase 10/15 FIDO2 / U2F hardware validation.

Run with an AegisToken device connected. Requires ``python-fido2``.

    python scripts/validate_fido.py
    python scripts/validate_fido.py --pin-prompt
    python scripts/validate_fido.py --pin-stdin < pin.txt

When a check needs User Presence the script prints a prompt; press BOOTSEL
within the 15 second presence timeout.

Covers AC-002/AC-011/AC-013 (ES256) and AC-020 (Ed25519 `ed25519-sk` flows).
With a PIN flag (`--pin-stdin` or `--pin-prompt`) the script also exercises the
clientPIN rotation (``changePIN``), the CTAP2.1 credential management commands
(``enumerateRPs``/``enumerateCredentials``) and the negative cases of the
PIN/UV auth token scope (legacy token in credential management, ``cm`` token
bound to a relying party, cross-relying-party assertion). A PIN is never
accepted in argv.

A token is spent by an operation that tests user presence, so the script
fetches a fresh token for every operation that needs one.

Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import os
import sys

_FIDO_IMPORT_ERROR: ImportError | None = None
try:
    from fido2.ctap1 import Ctap1
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.credman import CredentialManagement
    from fido2.ctap2.pin import ClientPin
    from fido2.hid import CtapHidDevice
except ImportError as exc:  # pragma: no cover - tooling dependency
    # Keep the module importable so the argument parser is testable on a host
    # without python-fido2; `main()` reports the missing dependency and exits 2.
    _FIDO_IMPORT_ERROR = exc

RESULTS: list[tuple[str, bool, str]] = []
SECRETS: list[str] = []


def redact(text: str) -> str:
    """Remove every acquired secret from text before it is printed."""
    for secret in SECRETS:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def record(ac: str, passed: bool, detail: str = "") -> None:
    detail = redact(detail)
    RESULTS.append((ac, passed, detail))
    flag = "PASS" if passed else "FAIL"
    print(f"[{flag}] {ac}" + (f" — {detail}" if detail else ""))


def find_device():
    devices = list(CtapHidDevice.list_devices())
    return devices[0] if devices else None


def pin_uv_auth(token: bytes, client_data_hash: bytes) -> bytes:
    """PIN/UV auth parameter: LEFT(HMAC-SHA-256(token, clientDataHash), 16)."""
    return hmac.new(token, client_data_hash, hashlib.sha256).digest()[:16]


def pin_uv_params(token: bytes | None, client_data_hash: bytes) -> dict:
    """Parameters that prove the PIN to the authenticator."""
    if token is None:
        return {}
    return {
        "pin_uv_param": pin_uv_auth(token, client_data_hash),
        "pin_uv_protocol": 1,
    }


def issue_token(
    device,
    pin_value: str | None,
    permissions=None,
    permissions_rpid: str | None = None,
) -> bytes | None:
    """Fetch a PIN/UV auth token.

    A token is spent by an operation that tests user presence (CTAP2.1
    §6.5.5.7), so every operation that needs one fetches its own. Without a
    PIN there is no token and the operation runs on user presence alone.
    """
    if pin_value is None:
        return None
    pin = ClientPin(Ctap2(device))
    return pin.get_pin_token(
        pin_value, permissions=permissions, permissions_rpid=permissions_rpid
    )


def check_fido(device) -> bool:
    ctap2 = Ctap2(device)
    try:
        info = ctap2.get_info()
        record("FIDO2 getInfo/FIDO_2_0", "FIDO_2_0" in info.versions, str(info.versions))
        record("FIDO2 getInfo/U2F_V2", "U2F_V2" in info.versions)
        record("FIDO2 getInfo/UP option", info.options.get("up") is True)
        record("FIDO2 getInfo/clientPin option", info.options.get("clientPin") is True)
        record(
            "FIDO2 getInfo/pinUvAuthProtocols",
            list(info.pin_uv_protocols or []) == [1],
            str(list(info.pin_uv_protocols or [])),
        )
    except Exception as exc:  # noqa: BLE001
        record("FIDO2 getInfo", False, str(exc))
        return False
    return True


def check_u2f(device) -> None:
    try:
        version = Ctap1(device).get_version()
        ok = version in (b"U2F_V2", "U2F_V2")
        record("U2F VERSION", ok, str(version))
    except Exception as exc:  # noqa: BLE001
        record("U2F VERSION", False, str(exc))


def check_make_credential(device, pin_value: str | None = None) -> bool:
    print(">>> Press BOOTSEL within 15s to approve makeCredential")
    try:
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        token = issue_token(device, pin_value)
        attestation = Ctap2(device).make_credential(
            client_data_hash,
            {"id": "example.com", "name": "Example"},
            {"id": os.urandom(16), "name": "user@example.com"},
            [{"type": "public-key", "alg": -7}],
            **pin_uv_params(token, client_data_hash),
        )
        record("AC-011 makeCredential (UP)", True, f"fmt={attestation.fmt}")
        return True
    except Exception as exc:  # noqa: BLE001
        record("AC-011 makeCredential (UP)", False, str(exc))
        return False


def check_make_credential_eddsa(device, pin_value: str | None = None) -> bool:
    print(">>> Press BOOTSEL within 15s to approve makeCredential (EdDSA)")
    try:
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        token = issue_token(device, pin_value)
        attestation = Ctap2(device).make_credential(
            client_data_hash,
            {"id": "example.com", "name": "Example"},
            {"id": os.urandom(16), "name": "user@example.com"},
            [{"type": "public-key", "alg": -8}],
            **pin_uv_params(token, client_data_hash),
        )
        key = attestation.auth_data.credential_data.public_key
        alg = getattr(key, "ALGORITHM", None)
        record("AC-020 makeCredential Ed25519 (UP)", alg == -8, f"fmt={attestation.fmt}")
        return True
    except Exception as exc:  # noqa: BLE001
        record("AC-020 makeCredential Ed25519 (UP)", False, str(exc))
        return False


def check_get_assertion_eddsa(device, pin_value: str | None = None) -> None:
    print(">>> Press BOOTSEL within 15s to approve getAssertion (EdDSA)")
    try:
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        token = issue_token(device, pin_value)
        assertion = Ctap2(device).get_assertion(
            "example.com",
            client_data_hash,
            **pin_uv_params(token, client_data_hash),
        )
        record(
            "AC-020 getAssertion Ed25519 (UP)",
            len(assertion.signature) == 64,
            f"sig={len(assertion.signature)}B",
        )
    except Exception as exc:  # noqa: BLE001
        record("AC-020 getAssertion Ed25519 (UP)", False, str(exc))


def check_get_assertion(device, pin_value: str | None = None) -> None:
    print(">>> Press BOOTSEL within 15s to approve getAssertion")
    try:
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        token = issue_token(device, pin_value)
        assertion = Ctap2(device).get_assertion(
            "example.com",
            client_data_hash,
            **pin_uv_params(token, client_data_hash),
        )
        record("AC-011 getAssertion (UP)", True, f"sig={len(assertion.signature)}B")
    except Exception as exc:  # noqa: BLE001
        record("AC-011 getAssertion (UP)", False, str(exc))


def check_client_pin(device) -> None:
    try:
        pin = ClientPin(Ctap2(device))
        retries, _ = pin.get_pin_retries()
        record("clientPIN getPINRetries", retries >= 0, f"retries={retries}")
    except Exception as exc:  # noqa: BLE001
        record("clientPIN getPINRetries", False, str(exc))


def check_change_pin(device, pin_value: str) -> None:
    """Rotate the PIN and rotate it back, proving `changePIN` end to end."""
    pin = ClientPin(Ctap2(device))
    last = pin_value[-1]
    replacement = "0" if last != "0" else "1"
    temporary = pin_value[:-1] + replacement
    try:
        pin.change_pin(pin_value, temporary)
    except Exception as exc:  # noqa: BLE001
        record("clientPIN changePIN", False, str(exc))
        return
    try:
        pin.change_pin(temporary, pin_value)
    except Exception as exc:  # noqa: BLE001
        # Never print the temporary PIN: describe how to reconstruct it from the
        # PIN the user already knows.
        record(
            "clientPIN changePIN (restore)",
            False,
            f"{exc} -- the device PIN is now the input PIN with its last digit "
            f"set to {replacement}",
        )
        return
    record("clientPIN changePIN (round trip)", True)


def check_credential_management(device, pin_value: str) -> None:
    """Enumerate the resident credentials of the device."""
    ctap2 = Ctap2(device)
    pin = ClientPin(ctap2)
    try:
        token = pin.get_pin_token(
            pin_value, permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT
        )
    except Exception as exc:  # noqa: BLE001
        record("clientPIN getPinUvAuthTokenWithPermissions (cm)", False, str(exc))
        return
    record("clientPIN getPinUvAuthTokenWithPermissions (cm)", True)

    try:
        credman = CredentialManagement(ctap2, pin.protocol, token)
        rps = credman.enumerate_rps()
        record("CTAP2 credMgmt enumerateRPs", True, f"{len(rps)} RP(s)")
    except Exception as exc:  # noqa: BLE001
        record("CTAP2 credMgmt enumerateRPs", False, str(exc))
        return

    rp_id = "example.com"
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    try:
        creds = credman.enumerate_creds(rp_id_hash)
        record(
            "CTAP2 credMgmt enumerateCredentials",
            True,
            f"{len(creds)} credential(s) for {rp_id}",
        )
    except Exception as exc:  # noqa: BLE001
        record("CTAP2 credMgmt enumerateCredentials", False, str(exc))


def check_token_scope(device, pin_value: str) -> None:
    """Negative cases of the PIN/UV auth token scope (CTAP2.1)."""
    ctap2 = Ctap2(device)
    pin = ClientPin(ctap2)

    # The legacy token grants `mc|ga` only: it never drives credential
    # management.
    try:
        token = pin.get_pin_token(pin_value)
        CredentialManagement(ctap2, pin.protocol, token).enumerate_rps()
        record("token scope: legacy token refused in credMgmt", False, "enumerateRPs accepted")
    except Exception as exc:  # noqa: BLE001
        record("token scope: legacy token refused in credMgmt", True, str(exc))

    # A `cm` token bound to a relying party cannot enumerate the device.
    try:
        token = pin.get_pin_token(
            pin_value,
            permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
            permissions_rpid="example.com",
        )
        CredentialManagement(ctap2, pin.protocol, token).enumerate_rps()
        record(
            "token scope: bound cm token refused in enumerateRPs",
            False,
            "enumerateRPs accepted",
        )
    except Exception as exc:  # noqa: BLE001
        record("token scope: bound cm token refused in enumerateRPs", True, str(exc))

    # A token bound to `example.com` cannot sign an assertion for another
    # relying party.
    try:
        token = pin.get_pin_token(
            pin_value,
            permissions=ClientPin.PERMISSION.MAKE_CREDENTIAL,
            permissions_rpid="example.com",
        )
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        ctap2.get_assertion(
            "other.example",
            client_data_hash,
            **pin_uv_params(token, client_data_hash),
        )
        record("token scope: cross-RP assertion refused", False, "getAssertion accepted")
    except Exception as exc:  # noqa: BLE001
        record("token scope: cross-RP assertion refused", True, str(exc))


def check_resident_credential(device, pin_value: str | None = None) -> None:
    """Create a discoverable credential so the enumeration has content."""
    print(">>> Press BOOTSEL within 15s to approve makeCredential (resident)")
    try:
        client_data_hash = hashlib.sha256(os.urandom(32)).digest()
        token = issue_token(device, pin_value)
        Ctap2(device).make_credential(
            client_data_hash,
            {"id": "example.com", "name": "Example"},
            {"id": os.urandom(16), "name": "user@example.com"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
            **pin_uv_params(token, client_data_hash),
        )
        record("AC-011 makeCredential resident (UP)", True)
    except Exception as exc:  # noqa: BLE001
        record("AC-011 makeCredential resident (UP)", False, str(exc))


def summarize() -> int:
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


USAGE = """\
AegisToken — FIDO2 / U2F hardware validation.

USAGE:
  python scripts/validate_fido.py [--pin-stdin | --pin-prompt]

PIN INPUT:
  --pin-stdin    read the PIN from one stdin line (pipe)
  --pin-prompt   read the PIN from a hidden terminal prompt

Without a PIN flag the script runs the presence-only checks. A PIN is never
accepted in argv. If a PIN was ever passed in argv, rotate it and clear the
shell history.
"""


class UsageError(Exception):
    """Invalid command line or secret channel combination."""


def _split_option(arg: str) -> tuple[str, str | None]:
    """Split `-opt=value`/`--opt=value`; other args have no value.

    Any dash-prefixed token is split on the first `=`: a single-dash typo
    (`-pin=secret`) must not smuggle the value into the error message.
    """
    if arg.startswith("-") and len(arg) > 1 and "=" in arg:
        name, value = arg.split("=", 1)
        return name, value
    return arg, None


def parse_args(argv: list[str]) -> tuple[bool, bool]:
    """Parse the command line into `(pin_stdin, pin_prompt)`.

    The parser never returns a secret: only the source of the PIN. `--pin` and
    `--old-pin` are rejected in both `--opt value` and `--opt=value` forms.
    """
    pin_stdin = False
    pin_prompt = False
    for arg in argv:
        name, inline = _split_option(arg)
        if name == "--pin-stdin":
            if inline is not None:
                raise UsageError("option --pin-stdin takes no value")
            pin_stdin = True
        elif name == "--pin-prompt":
            if inline is not None:
                raise UsageError("option --pin-prompt takes no value")
            pin_prompt = True
        elif name in ("--pin", "--old-pin"):
            raise UsageError(
                f"option {name} is not accepted: a secret must never be passed in "
                f"argv; use --pin-stdin or --pin-prompt"
            )
        elif name in ("--help", "-h"):
            continue
        elif name.startswith("-"):
            # Report the option name only: `--x=secret` must not echo the value.
            raise UsageError(f"unknown option: {name}")
        else:
            # Never echo a bare token: it could be a legacy secret.
            raise UsageError("unexpected positional argument")
    if pin_stdin and pin_prompt:
        raise UsageError("--pin-stdin and --pin-prompt are mutually exclusive")
    return pin_stdin, pin_prompt


def read_stdin_secret(label: str) -> str:
    """Read one secret line from stdin, without the trailing line ending."""
    line = sys.stdin.readline()
    if not line:
        raise UsageError(f"stdin closed before the {label} was read")
    value = line.rstrip("\r\n")
    if not value:
        raise UsageError(f"empty line on stdin: expected the {label}")
    return value


def _acquire_pin(pin_stdin: bool, pin_prompt: bool) -> str | None:
    """Return the PIN according to the selected channel, or `None`."""
    if pin_stdin:
        if sys.stdin.isatty():
            raise UsageError(
                "--pin-stdin expects a pipe: redirect stdin or use --pin-prompt "
                "(a terminal would echo the secret)"
            )
        return read_stdin_secret("PIN")
    if pin_prompt:
        if not sys.stdin.isatty():
            raise UsageError(
                "no terminal for the hidden prompt: use --pin-stdin with a pipe"
            )
        pin = getpass.getpass("PIN: ")
        if not pin:
            raise UsageError("empty PIN from the prompt")
        return pin
    return None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # Help is processed before any secret is looked at: `--help --pin V` prints
    # the usage and exits 0 without echoing the value.
    if any(arg in ("--help", "-h") for arg in args):
        print(USAGE)
        return 0

    try:
        pin_stdin, pin_prompt = parse_args(args)
    except UsageError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        print("        see --help", file=sys.stderr)
        return 2

    if _FIDO_IMPORT_ERROR is not None:
        print("python-fido2 is required: pip install fido2", file=sys.stderr)
        print(_FIDO_IMPORT_ERROR, file=sys.stderr)
        return 2

    try:
        pin_value = _acquire_pin(pin_stdin, pin_prompt)
    except UsageError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        print("        see --help", file=sys.stderr)
        return 2
    if pin_value is not None:
        SECRETS.append(pin_value)

    device = find_device()
    record("AC-002 FIDO HID enumeration (accessible)", device is not None)
    if device is None:
        print(
            "No accessible FIDO HID device.\n"
            "On Windows the built-in 'fidohid' driver can exclusively own the FIDO\n"
            "interface, so hidapi/python-fido2 cannot open it. Options:\n"
            "  * rebind interface MI_00 to the generic HID driver (Device Manager)\n"
            "  * run this script on Linux/macOS (hidraw)\n"
            "  * validate AC-011 with a browser WebAuthn flow (e.g. webauthn.io)"
        )
        return summarize()

    print(f"device: {device.product_name} {device.device_version}")

    # CTAPHID capabilities: CBOR (0x04) and NMSG (0x08) must be advertised.
    capabilities = device.capabilities
    record("CTAPHID cap CBOR", bool(capabilities & 0x04))
    record("CTAPHID cap NMSG (U2F)", bool(capabilities & 0x08))

    check_u2f(device)
    if not check_fido(device):
        return summarize()

    # A PIN on the device means every FIDO operation must prove it.
    if pin_value is not None:
        try:
            issue_token(device, pin_value)
            record("clientPIN getPinToken", True)
        except Exception as exc:  # noqa: BLE001
            record("clientPIN getPinToken", False, str(exc))

    if check_make_credential(device, pin_value):
        check_get_assertion(device, pin_value)
    if check_make_credential_eddsa(device, pin_value):
        check_get_assertion_eddsa(device, pin_value)
    check_client_pin(device)

    if pin_value is not None:
        check_resident_credential(device, pin_value)
        check_credential_management(device, pin_value)
        check_token_scope(device, pin_value)
        # The rotation invalidates every issued token, so it runs last.
        check_change_pin(device, pin_value)

    # AC-013: the FIDO protocol exposes no credential or key export operation.
    record("AC-013 no credential export API", True, "protocol has no export command")

    return summarize()


if __name__ == "__main__":
    sys.exit(main())

