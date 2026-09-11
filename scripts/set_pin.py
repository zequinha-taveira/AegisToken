#!/usr/bin/env python3
"""AegisToken — set or change the FIDO2 client PIN.

    python scripts/set_pin.py             # set a new PIN (prompts)
    python scripts/set_pin.py --change    # change the PIN (prompts old/new)
    python scripts/set_pin.py --retries   # show remaining PIN retries

Non-interactive:
    python scripts/set_pin.py --set --pin 123456
    python scripts/set_pin.py --change --old-pin 123456 --pin 654321

Requires python-fido2 and access to the FIDO HID interface. On Windows the
built-in `fidohid` driver claims the interface, so remap MI_00 to the generic
HID driver first (see validation.md).
"""

from __future__ import annotations

import getpass
import sys

try:
    from fido2.ctap2 import Ctap2
    from fido2.ctap2.pin import ClientPin
    from fido2.hid import CtapHidDevice
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("python-fido2 is required: pip install fido2")
    print(exc)
    sys.exit(2)


def parse_args(argv: list[str]) -> tuple[str, str | None, str | None]:
    mode = "--set"
    pin = None
    old_pin = None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg in ("--set", "--change", "--retries"):
            mode = arg
        elif arg == "--pin" and index + 1 < len(argv):
            index += 1
            pin = argv[index]
        elif arg == "--old-pin" and index + 1 < len(argv):
            index += 1
            old_pin = argv[index]
        index += 1
    return mode, pin, old_pin


def main() -> int:
    mode, pin_value, old_value = parse_args(sys.argv[1:])

    device = next(iter(CtapHidDevice.list_devices()), None)
    if device is None:
        print("[FAIL] no accessible FIDO HID device.")
        print("        On Windows, remap interface MI_00 to the generic HID driver.")
        return 1

    client_pin = ClientPin(Ctap2(device))

    try:
        if mode == "--retries":
            retries, _ = client_pin.get_pin_retries()
            print(f"[PASS] remaining PIN retries: {retries}")
        elif mode == "--change":
            old = old_value if old_value is not None else getpass.getpass("Current PIN: ")
            new = pin_value if pin_value is not None else getpass.getpass("New PIN: ")
            client_pin.change_pin(old, new)
            print("[PASS] PIN changed")
        else:
            new = pin_value if pin_value is not None else getpass.getpass("New PIN: ")
            client_pin.set_pin(new)
            print("[PASS] PIN set")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
