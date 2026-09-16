#!/usr/bin/env python3
"""AegisToken — Phase 11 CCID / applet routing hardware validation (AC-016).

Run with an AegisToken device connected. Requires ``pyscard`` (``pip install
pyscard``) and a working PC/SC stack (``pcscd`` on Linux, the Smart Card service
on Windows).

    python scripts/validate_ccid.py
    python scripts/validate_ccid.py --reader Aegis

The script powers the card, checks the ATR, selects the PIV, OpenPGP and OATH
applications by AID, and verifies the router's error status words. Phases
12-16 replaced the early placeholders with real applets: unknown AIDs still
answer ``6A82`` and unsupported instructions ``6D00``/``6E00``, while each
applet answers its own command set (see ``validate_piv.py``,
``validate_oath.py`` and ``validate_openpgp.py``).

Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import sys

try:
    from smartcard.System import readers
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("pyscard is required: pip install pyscard")
    print(exc)
    sys.exit(2)

RESULTS: list[tuple[str, bool, str]] = []

AID_PIV = "A000000308000010000100"
AID_OPENPGP = "D2760001240103040000000000000000"
AID_OATH = "A0000005272101"
AID_UNKNOWN = "A000000308000010000200"

EXPECTED_ATR = [0x3B, 0x00]


def record(ac: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((ac, passed, detail))
    flag = "PASS" if passed else "FAIL"
    print(f"[{flag}] {ac}" + (f" — {detail}" if detail else ""))


def select(connection, aid_hex: str):
    aid = list(bytes.fromhex(aid_hex))
    return connection.transmit([0x00, 0xA4, 0x04, 0x00, len(aid), *aid])


def transmit(connection, apdu: list[int]):
    return connection.transmit(apdu)


def find_reader(substring: str | None):
    available = list(readers())
    if not available:
        return None, []
    if substring is not None:
        needle = substring.lower()
        for reader in available:
            if needle in str(reader).lower():
                return reader, available
        return None, available
    for reader in available:
        if "aegis" in str(reader).lower():
            return reader, available
    return available[0], available


def main() -> int:
    substring = None
    if "--reader" in sys.argv:
        index = sys.argv.index("--reader")
        if index + 1 < len(sys.argv):
            substring = sys.argv[index + 1]

    reader, available = find_reader(substring)
    record(
        "AC-016 CCID reader enumeration",
        reader is not None,
        f"readers={[str(r) for r in available]}" if reader is None else str(reader),
    )
    if reader is None:
        print(
            "No PC/SC reader found.\n"
            "  * Windows: the CCID interface (class 0x0B) binds to the inbox\n"
            "    'usbccid' driver; check Device Manager > Smart card readers.\n"
            "  * Linux: install pcscd/ccid and confirm with 'opensc-tool -l'."
        )
        return summarize()

    connection = reader.createConnection()
    try:
        connection.connect()
    except Exception as exc:  # noqa: BLE001
        record("AC-016 card activation", False, str(exc))
        return summarize()
    record("AC-016 card activation", True, f"ATR={bytes(connection.getATR()).hex().upper()}")

    atr = list(connection.getATR())
    record("AC-016 ATR is 3B 00", atr == EXPECTED_ATR, f"atr={bytes(atr).hex().upper()}")

    try:
        _, sw1, sw2 = transmit(connection, [0x00, 0xCB, 0x3F, 0xFF])
        record(
            "AC-016 command without selection",
            (sw1, sw2) == (0x69, 0x85),
            f"sw={sw1:02X}{sw2:02X}",
        )
    except Exception as exc:  # noqa: BLE001
        record("AC-016 command without selection", False, str(exc))

    for name, aid_hex in [
        ("PIV", AID_PIV),
        ("OpenPGP", AID_OPENPGP),
        ("OATH", AID_OATH),
    ]:
        try:
            _, sw1, sw2 = select(connection, aid_hex)
            record(
                f"AC-016 SELECT {name}",
                (sw1, sw2) == (0x90, 0x00),
                f"sw={sw1:02X}{sw2:02X}",
            )
        except Exception as exc:  # noqa: BLE001
            record(f"AC-016 SELECT {name}", False, str(exc))

    try:
        _, sw1, sw2 = select(connection, AID_UNKNOWN)
        record(
            "AC-016 unknown AID rejected",
            (sw1, sw2) == (0x6A, 0x82),
            f"sw={sw1:02X}{sw2:02X}",
        )
    except Exception as exc:  # noqa: BLE001
        record("AC-016 unknown AID rejected", False, str(exc))

    try:
        select(connection, AID_PIV)
        _, sw1, sw2 = transmit(connection, [0x00, 0x01, 0x00, 0x00])
        record(
            "AC-016 unsupported INS on selected applet",
            (sw1, sw2) == (0x6D, 0x00),
            f"sw={sw1:02X}{sw2:02X}",
        )
    except Exception as exc:  # noqa: BLE001
        record("AC-016 unsupported INS on selected applet", False, str(exc))

    try:
        _, sw1, sw2 = transmit(connection, [0x80, 0x01, 0x00, 0x00])
        record(
            "AC-016 proprietary CLA rejected",
            (sw1, sw2) == (0x6E, 0x00),
            f"sw={sw1:02X}{sw2:02X}",
        )
    except Exception as exc:  # noqa: BLE001
        record("AC-016 proprietary CLA rejected", False, str(exc))

    try:
        _, sw1, sw2 = transmit(connection, [0x00, 0xC0, 0x00, 0x00, 0x00])
        record(
            "AC-016 GET RESPONSE without pending",
            (sw1, sw2) == (0x69, 0x85),
            f"sw={sw1:02X}{sw2:02X}",
        )
    except Exception as exc:  # noqa: BLE001
        record("AC-016 GET RESPONSE without pending", False, str(exc))

    return summarize()


def summarize() -> int:
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
