#!/usr/bin/env python3
"""AegisToken — set or change the FIDO2 client PIN.

    python scripts/set_pin.py             # set a new PIN (hidden prompt)
    python scripts/set_pin.py --change    # change the PIN (hidden prompt, old/new)
    python scripts/set_pin.py --retries   # show remaining PIN retries

Non-interactive (stdin, never argv):
    python scripts/set_pin.py --set --pin-stdin < pin.txt
    python scripts/set_pin.py --change --old-pin-stdin --pin-stdin < pins.txt

A secret is never accepted in argv: the OS exposes a process command line to
other local processes and keeps it in shell history. Use the hidden prompt when
stdin is a terminal, or pipe the secret(s) through stdin. If a secret was ever
passed in argv, rotate it and clear the shell history.

Requires python-fido2 and access to the FIDO HID interface. On Windows the
built-in `fidohid` driver claims the interface, so remap MI_00 to the generic
HID driver first (see validation.md).
"""

from __future__ import annotations

import getpass
import sys

USAGE = """\
AegisToken — set or change the FIDO2 client PIN.

USAGE:
  python scripts/set_pin.py [--set | --change | --retries] [--pin-stdin]
                            [--old-pin-stdin]

MODES:
  --set         set a new PIN (default)
  --change      change the PIN (current PIN, then new PIN)
  --retries     show the remaining PIN retries

SECRET INPUT:
  --pin-stdin       read the new PIN from one stdin line
  --old-pin-stdin   read the current PIN from one stdin line (needs --pin-stdin)

Without the stdin flags the PIN is read from a hidden terminal prompt. Secrets
are never accepted in argv. If a secret was ever passed in argv, rotate it and
clear the shell history.
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


def parse_args(argv: list[str]) -> tuple[str, bool, bool]:
    """Parse the command line into `(mode, pin_stdin, old_pin_stdin)`.

    The parser never returns a secret: only the source of each secret. `--pin`
    and `--old-pin` are rejected in both `--opt value` and `--opt=value` forms.
    """
    mode = "--set"
    pin_stdin = False
    old_pin_stdin = False
    for arg in argv:
        name, inline = _split_option(arg)
        if name in ("--set", "--change", "--retries"):
            if inline is not None:
                raise UsageError(f"option {name} takes no value")
            mode = name
        elif name in ("--pin", "--old-pin"):
            raise UsageError(
                f"option {name} is not accepted: a secret must never be passed in "
                f"argv; use {name}-stdin or the hidden prompt"
            )
        elif name == "--pin-stdin":
            if inline is not None:
                raise UsageError("option --pin-stdin takes no value")
            pin_stdin = True
        elif name == "--old-pin-stdin":
            if inline is not None:
                raise UsageError("option --old-pin-stdin takes no value")
            old_pin_stdin = True
        elif name in ("--help", "-h"):
            continue
        elif name.startswith("-"):
            # Report the option name only: `--x=secret` must not echo the value.
            raise UsageError(f"unknown option: {name}")
        else:
            # Never echo a bare token: it could be a legacy secret.
            raise UsageError("unexpected positional argument")
    return mode, pin_stdin, old_pin_stdin


def read_stdin_secret(label: str) -> str:
    """Read one secret line from stdin, without the trailing line ending."""
    line = sys.stdin.readline()
    if not line:
        raise UsageError(f"stdin closed before the {label} was read")
    value = line.rstrip("\r\n")
    if not value:
        raise UsageError(f"empty line on stdin: expected the {label}")
    return value


def redact(text: str, secrets: list[str | None]) -> str:
    """Remove any acquired secret from text before it reaches stderr."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _require_tty() -> None:
    if not sys.stdin.isatty():
        raise UsageError(
            "no terminal for the hidden prompt: use --pin-stdin (and "
            "--old-pin-stdin) with a pipe"
        )


def _acquire(mode: str, pin_stdin: bool, old_pin_stdin: bool) -> tuple[str | None, str]:
    """Return `(old_pin, new_pin)` according to the selected channel."""
    if mode == "--retries":
        if pin_stdin or old_pin_stdin:
            raise UsageError("--retries does not take a secret input flag")
        return None, ""

    if pin_stdin or old_pin_stdin:
        if sys.stdin.isatty():
            raise UsageError(
                "--pin-stdin/--old-pin-stdin expect a pipe: redirect stdin or "
                "use the hidden prompt (a terminal would echo the secret)"
            )
        if mode == "--set":
            if old_pin_stdin:
                raise UsageError("--old-pin-stdin is only valid with --change")
            return None, read_stdin_secret("new PIN")
        if not (pin_stdin and old_pin_stdin):
            raise UsageError(
                "--change with stdin needs both --old-pin-stdin and --pin-stdin "
                "(current PIN first, then the new PIN)"
            )
        old = read_stdin_secret("current PIN")
        new = read_stdin_secret("new PIN")
        return old, new

    _require_tty()
    if mode == "--set":
        return None, getpass.getpass("New PIN: ")
    old = getpass.getpass("Current PIN: ")
    new = getpass.getpass("New PIN: ")
    return old, new


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    # Help is processed before any secret is looked at: `--help --pin V` prints
    # the usage and exits 0 without echoing the value.
    if any(arg in ("--help", "-h") for arg in args):
        print(USAGE)
        return 0

    try:
        mode, pin_stdin, old_pin_stdin = parse_args(args)
        old_pin, new_pin = _acquire(mode, pin_stdin, old_pin_stdin)
    except UsageError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        print("        see --help", file=sys.stderr)
        return 2

    try:
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.pin import ClientPin
        from fido2.hid import CtapHidDevice
    except ImportError as exc:  # pragma: no cover - tooling dependency
        print("python-fido2 is required: pip install fido2", file=sys.stderr)
        print(exc, file=sys.stderr)
        return 2

    device = next(iter(CtapHidDevice.list_devices()), None)
    if device is None:
        print("[FAIL] no accessible FIDO HID device.")
        print("        On Windows, remap interface MI_00 to the generic HID driver.")
        return 1

    client_pin = ClientPin(Ctap2(device))
    secrets = [old_pin, new_pin]

    try:
        if mode == "--retries":
            retries, _ = client_pin.get_pin_retries()
            print(f"[PASS] remaining PIN retries: {retries}")
        elif mode == "--change":
            client_pin.change_pin(old_pin, new_pin)
            print("[PASS] PIN changed")
        else:
            client_pin.set_pin(new_pin)
            print("[PASS] PIN set")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] {redact(str(exc), secrets)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
