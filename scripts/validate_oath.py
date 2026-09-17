#!/usr/bin/env python3
"""AegisToken — Phase 13 OATH/TOTP hardware validation (AC-018).

Requires ``pyscard`` and a working PC/SC stack. The validator selects OATH,
stores a temporary RFC 6238 TOTP credential, calculates the code for moving
factor 1, verifies LIST, and deletes the credential again.

    python scripts/validate_oath.py
    python scripts/validate_oath.py --reader Aegis

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

AID_OATH = bytes.fromhex("A0000005272101")
NAME = b"30/AegisToken:validate"
SECRET_SHA1 = b"12345678901234567890"

INS_PUT = 0x01
INS_DELETE = 0x02
INS_LIST = 0xA1
INS_CALCULATE = 0xA2

TAG_NAME = 0x71
TAG_NAME_LIST = 0x72
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_TRUNCATED = 0x76


def record(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    flag = "PASS" if passed else "FAIL"
    print(f"[{flag}] {name}" + (f" — {detail}" if detail else ""))


def tlv(tag: int, value: bytes) -> bytes:
    if len(value) >= 0x80:
        raise ValueError("validator only emits short TLVs")
    return bytes([tag, len(value)]) + value


def find_tlv(data: bytes, wanted: int) -> bytes | None:
    index = 0
    while index + 2 <= len(data):
        tag = data[index]
        length = data[index + 1]
        index += 2
        value = data[index : index + length]
        if len(value) != length:
            return None
        index += length
        if tag == wanted:
            return value
    return None


def transmit(connection, apdu: list[int]) -> tuple[bytes, int]:
    data, sw1, sw2 = connection.transmit(apdu)
    return bytes(data), (sw1 << 8) | sw2


def select(connection) -> tuple[bytes, int]:
    return transmit(connection, [0x00, 0xA4, 0x04, 0x00, len(AID_OATH), *AID_OATH])


def find_reader(substring: str | None):
    available = list(readers())
    if not available:
        return None, []
    if substring:
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
    reader_filter = None
    if "--reader" in sys.argv:
        index = sys.argv.index("--reader")
        if index + 1 < len(sys.argv):
            reader_filter = sys.argv[index + 1]

    reader, available = find_reader(reader_filter)
    record(
        "AC-018 OATH reader enumeration",
        reader is not None,
        f"readers={[str(item) for item in available]}" if reader is None else str(reader),
    )
    if reader is None:
        print("No PC/SC reader found; verify the CCID driver and pcscd/Smart Card service.")
        return summarize()

    connection = reader.createConnection()
    try:
        connection.connect()
    except Exception as exc:  # noqa: BLE001
        record("AC-018 card activation", False, str(exc))
        return summarize()

    data, sw = select(connection)
    record("AC-018 SELECT OATH", sw == 0x9000, f"sw={sw:04X}")
    if sw != 0x9000:
        return summarize()

    # Key descriptor: TOTP (0x20) + HMAC-SHA1 (0x01), eight digits.
    key = bytes([0x21, 8]) + SECRET_SHA1
    put_data = tlv(TAG_NAME, NAME) + tlv(TAG_KEY, key)
    _, sw = transmit(connection, [0x00, INS_PUT, 0x00, 0x00, len(put_data), *put_data])
    record("AC-018 PUT TOTP credential", sw == 0x9000, f"sw={sw:04X}")

    try:
        data, sw = transmit(connection, [0x00, INS_LIST, 0x00, 0x00])
        listed = find_tlv(data, TAG_NAME_LIST)
        record("AC-018 LIST credential", sw == 0x9000 and listed is not None, f"sw={sw:04X}")

        # RFC 6238 timestamp 59 with a 30-second period => moving factor 1.
        challenge = (1).to_bytes(8, "big")
        calculate_data = tlv(TAG_NAME, NAME) + tlv(TAG_CHALLENGE, challenge)
        data, sw = transmit(
            connection,
            [0x00, INS_CALCULATE, 0x00, 0x01, len(calculate_data), *calculate_data],
        )
        response = find_tlv(data, TAG_TRUNCATED)
        code = int.from_bytes(response[1:], "big") if response and len(response) == 5 else None
        record("AC-018 CALCULATE TOTP", sw == 0x9000 and code == 94_287_082, f"sw={sw:04X} code={code}")
    finally:
        delete_data = tlv(TAG_NAME, NAME)
        _, sw = transmit(connection, [0x00, INS_DELETE, 0x00, 0x00, len(delete_data), *delete_data])
        record("AC-018 DELETE credential", sw == 0x9000, f"sw={sw:04X}")

    return summarize()


def summarize() -> int:
    failed = [result for result in RESULTS if not result[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
