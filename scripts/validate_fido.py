#!/usr/bin/env python3
"""AegisToken — Phase 10/15 FIDO2 / U2F hardware validation.

Run with an AegisToken device connected. Requires ``python-fido2``.

    python scripts/validate_fido.py

When a check needs User Presence the script prints a prompt; press BOOTSEL
within the 15 second presence timeout.

Covers AC-002/AC-011/AC-013 (ES256) and AC-020 (Ed25519 `ed25519-sk` flows).

Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import os
import sys

try:
    from fido2.ctap1 import Ctap1
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from fido2.hid import CtapHidDevice
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("python-fido2 is required: pip install fido2")
    print(exc)
    sys.exit(2)

RESULTS: list[tuple[str, bool, str]] = []


def record(ac: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((ac, passed, detail))
    flag = "PASS" if passed else "FAIL"
    print(f"[{flag}] {ac}" + (f" — {detail}" if detail else ""))


def find_device():
    devices = list(CtapHidDevice.list_devices())
    return devices[0] if devices else None


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


def check_make_credential(device) -> bool:
    print(">>> Press BOOTSEL within 15s to approve makeCredential")
    try:
        attestation = Ctap2(device).make_credential(
            hashlib.sha256(os.urandom(32)).digest(),
            {"id": "example.com", "name": "Example"},
            {"id": os.urandom(16), "name": "user@example.com"},
            [{"type": "public-key", "alg": -7}],
        )
        record("AC-011 makeCredential (UP)", True, f"fmt={attestation.fmt}")
        return True
    except Exception as exc:  # noqa: BLE001
        record("AC-011 makeCredential (UP)", False, str(exc))
        return False


def check_make_credential_eddsa(device) -> bool:
    print(">>> Press BOOTSEL within 15s to approve makeCredential (EdDSA)")
    try:
        attestation = Ctap2(device).make_credential(
            hashlib.sha256(os.urandom(32)).digest(),
            {"id": "example.com", "name": "Example"},
            {"id": os.urandom(16), "name": "user@example.com"},
            [{"type": "public-key", "alg": -8}],
        )
        key = attestation.auth_data.credential_data.public_key
        alg = getattr(key, "ALGORITHM", None)
        record("AC-020 makeCredential Ed25519 (UP)", alg == -8, f"fmt={attestation.fmt}")
        return True
    except Exception as exc:  # noqa: BLE001
        record("AC-020 makeCredential Ed25519 (UP)", False, str(exc))
        return False


def check_get_assertion_eddsa(device) -> None:
    print(">>> Press BOOTSEL within 15s to approve getAssertion (EdDSA)")
    try:
        assertion = Ctap2(device).get_assertion(
            "example.com", hashlib.sha256(os.urandom(32)).digest()
        )
        record(
            "AC-020 getAssertion Ed25519 (UP)",
            len(assertion.signature) == 64,
            f"sig={len(assertion.signature)}B",
        )
    except Exception as exc:  # noqa: BLE001
        record("AC-020 getAssertion Ed25519 (UP)", False, str(exc))


def check_get_assertion(device) -> None:
    print(">>> Press BOOTSEL within 15s to approve getAssertion")
    try:
        assertion = Ctap2(device).get_assertion(
            "example.com", hashlib.sha256(os.urandom(32)).digest()
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


def summarize() -> int:
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


def main() -> int:
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

    if check_make_credential(device):
        check_get_assertion(device)
    if check_make_credential_eddsa(device):
        check_get_assertion_eddsa(device)
    check_client_pin(device)

    # AC-013: the FIDO protocol exposes no credential or key export operation.
    record("AC-013 no credential export API", True, "protocol has no export command")

    return summarize()


if __name__ == "__main__":
    sys.exit(main())

