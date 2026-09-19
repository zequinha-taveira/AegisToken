#!/usr/bin/env python3
"""AegisToken — Phase 12 PIV hardware validation (AC-017) + Phase 16 RSA.

Run with an AegisToken device connected. Requires ``pyscard`` and
``cryptography`` (both available where ``python-fido2`` is installed).

    python scripts/validate_piv.py
    python scripts/validate_piv.py --reader Aegis

The script selects the PIV application, reads the CCC and CHUID, exercises the
default PIN and the 3DES management key (mutual authentication), generates a
P-256 key in slot 9C, signs a digest and verifies the signature off-card with
``cryptography``. The RSA section (AC-021, Phase 16d) then covers both RSA
slots (9A + 9C): explicit PIN re-verification, RSA-2048 key generation,
raw-block sign with ``s^e mod n`` check, and a DigestInfo/EMSA-PKCS1-v1_5
round-trip verified with the ``cryptography`` padding library.

Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import os
import sys

try:
    from smartcard.System import readers
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("pyscard is required: pip install pyscard")
    print(exc)
    sys.exit(2)

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa as rsa_mod
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

    try:
        # cryptography >= 43 moves 3DES to the decrepit module.
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # pragma: no cover - older cryptography
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("cryptography is required: pip install cryptography")
    print(exc)
    sys.exit(2)

RESULTS: list[tuple[str, bool, str]] = []

AID_PIV = "A000000308000010000100"
OBJECT_CHUID = "5FC102"
OBJECT_CCC = "5FC107"
OBJECT_SIGNATURE_CERT = "5FC10A"
OBJECT_UNKNOWN = "5FC17F"

DEFAULT_PIN = b"123456"
DEFAULT_MGMT_KEY = bytes.fromhex("0102030405060708" * 3)

ALG_TDES = 0x03
ALG_RSA2048 = 0x07
ALG_ECCP256 = 0x11
REF_PIN = 0x80
REF_MANAGEMENT = 0x9B
REF_PIV_AUTH = 0x9A
REF_SIGNATURE = 0x9C


def record(ac: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((ac, passed, detail))
    flag = "PASS" if passed else "FAIL"
    print(f"[{flag}] {ac}" + (f" — {detail}" if detail else ""))


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


def transmit(connection, apdu: list[int]):
    data, sw1, sw2 = connection.transmit(apdu)
    return bytes(data), (sw1 << 8) | sw2


def xapdu(cla: int, ins: int, p1: int, p2: int, data: bytes) -> list[int]:
    """Build a command APDU, using extended Lc for payloads >= 256 bytes."""
    header = [cla, ins, p1, p2]
    if not data:
        return header
    if len(data) < 256:
        return header + [len(data), *data]
    return header + [0x00, (len(data) >> 8) & 0xFF, len(data) & 0xFF, *data]


def select(connection, aid_hex: str):
    aid = list(bytes.fromhex(aid_hex))
    return transmit(connection, [0x00, 0xA4, 0x04, 0x00, len(aid), *aid])


def get_data(connection, object_hex: str):
    oid = bytes.fromhex(object_hex)
    return transmit(connection, [0x00, 0xCB, 0x3F, 0xFF, 2 + len(oid), 0x5C, len(oid), *oid])


def padded_pin(pin: bytes) -> bytes:
    return pin + b"\xFF" * (8 - len(pin))


def tdes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(TripleDES(key), modes.ECB())
    return cipher.decryptor().update(block)


def tdes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(TripleDES(key), modes.ECB())
    return cipher.encryptor().update(block)


def tlv_find(data: bytes, tag: int) -> bytes | None:
    """Minimal single-level BER-TLV search."""
    index = 0
    while index < len(data):
        parsed = tlv_at(data, index)
        if parsed is None:
            return None
        parsed_tag, value, index = parsed
        if parsed_tag == tag:
            return value
    return None


def tlv_at(data: bytes, index: int):
    if index >= len(data):
        return None
    tag = data[index]
    index += 1
    if tag & 0x1F == 0x1F:
        while index < len(data) and data[index] & 0x80:
            tag = (tag << 8) | data[index]
            index += 1
        if index >= len(data):
            return None
        tag = (tag << 8) | data[index]
        index += 1
    if index >= len(data):
        return None
    length = data[index]
    index += 1
    if length & 0x80:
        count = length & 0x7F
        length = 0
        for _ in range(count):
            length = (length << 8) | data[index]
            index += 1
    if index + length > len(data):
        return None
    return tag, data[index : index + length], index + length


def main() -> int:
    substring = None
    if "--reader" in sys.argv:
        index = sys.argv.index("--reader")
        if index + 1 < len(sys.argv):
            substring = sys.argv[index + 1]

    reader, available = find_reader(substring)
    record(
        "AC-017 PIV reader enumeration",
        reader is not None,
        f"readers={[str(r) for r in available]}" if reader is None else str(reader),
    )
    if reader is None:
        print(
            "No PC/SC reader found.\n"
            "  * Windows: the CCID interface binds to the inbox 'usbccid' driver.\n"
            "  * Linux: install pcscd/ccid and confirm with 'opensc-tool -l'."
        )
        return summarize()

    connection = reader.createConnection()
    try:
        connection.connect()
    except Exception as exc:  # noqa: BLE001
        record("AC-017 card activation", False, str(exc))
        return summarize()

    data, sw = select(connection, AID_PIV)
    record("AC-017 SELECT PIV", sw == 0x9000, f"sw={sw:04X}")

    data, sw = get_data(connection, OBJECT_CCC)
    ccc = tlv_find(data, 0x53) if sw == 0x9000 else None
    record("AC-017 GET DATA CCC", ccc is not None and ccc[:2] == b"\xF0\x15", f"sw={sw:04X}")

    data, sw = get_data(connection, OBJECT_CHUID)
    chuid = tlv_find(data, 0x53) if sw == 0x9000 else None
    record("AC-017 GET DATA CHUID", chuid is not None and chuid[:2] == b"\x30\x19", f"sw={sw:04X}")

    _, sw = get_data(connection, OBJECT_UNKNOWN)
    record("AC-017 unknown object rejected", sw == 0x6A82, f"sw={sw:04X}")

    # PUT DATA requires administrator authentication.
    cert = bytes.fromhex("70 03 01 02 03")
    oid = bytes.fromhex(OBJECT_SIGNATURE_CERT)
    body = bytes([0x5C, len(oid)]) + oid + cert
    _, sw = transmit(connection, [0x00, 0xDB, 0x3F, 0xFF, len(body), *body])
    record("AC-017 PUT DATA requires admin", sw == 0x6982, f"sw={sw:04X}")

    # VERIFY: one wrong attempt, then the default PIN.
    wrong = padded_pin(b"000000")
    _, sw = transmit(connection, [0x00, 0x20, 0x00, REF_PIN, 8, *wrong])
    record("AC-017 VERIFY tracks retries", sw & 0xFFF0 == 0x63C0, f"sw={sw:04X}")
    _, sw = transmit(connection, [0x00, 0x20, 0x00, REF_PIN, 8, *padded_pin(DEFAULT_PIN)])
    record("AC-017 VERIFY default PIN", sw == 0x9000, f"sw={sw:04X}")

    # Management key: mutual authentication with the default 3DES key.
    data, sw = transmit(
        connection,
        [0x00, 0x87, ALG_TDES, REF_MANAGEMENT, 0x04, 0x7C, 0x02, 0x80, 0x00],
    )
    template = tlv_find(data, 0x7C) if sw == 0x9000 else None
    witness = tlv_find(template, 0x80) if template is not None else None
    record("AC-017 management witness", witness is not None, f"sw={sw:04X}")

    authenticated = False
    if witness is not None:
        nonce = tdes_ecb_decrypt(DEFAULT_MGMT_KEY, witness)
        challenge = os.urandom(8)
        inner = (
            bytes([0x80, 0x08])
            + nonce
            + bytes([0x81, 0x08])
            + challenge
            + bytes([0x82, 0x00])
        )
        body = bytes([0x7C, len(inner)]) + inner
        data, sw = transmit(
            connection,
            [0x00, 0x87, ALG_TDES, REF_MANAGEMENT, len(body), *body],
        )
        response = tlv_find(data, 0x7C)
        encrypted = tlv_find(response, 0x82) if response is not None else None
        authenticated = (
            sw == 0x9000
            and encrypted is not None
            and tdes_ecb_decrypt(DEFAULT_MGMT_KEY, encrypted) == challenge
        )
    record("AC-017 management key mutual auth", authenticated)

    if not authenticated:
        return summarize()

    # GENERATE ASYMMETRIC KEY PAIR: P-256 in slot 9C, PIN once, no touch.
    ac = bytes([0xAC, 0x06, 0x80, 0x01, ALG_ECCP256, 0xAA, 0x01, 0x02])
    data, sw = transmit(
        connection,
        [0x00, 0x47, 0x00, REF_SIGNATURE, len(ac), *ac],
    )
    template = tlv_find(data, 0x7F49) if sw == 0x9000 else None
    point = tlv_find(template, 0x86) if template is not None else None
    record(
        "AC-017 GENERATE P-256 key",
        point is not None and point[0] == 0x04 and len(point) == 65,
        f"sw={sw:04X}",
    )
    if point is None:
        return summarize()

    digest = hashlib.sha256(os.urandom(32)).digest()
    inner = bytes([0x82, 0x00, 0x81, 0x20]) + digest
    body = bytes([0x7C, len(inner)]) + inner
    data, sw = transmit(
        connection,
        [0x00, 0x87, ALG_ECCP256, REF_SIGNATURE, len(body), *body],
    )
    template = tlv_find(data, 0x7C) if sw == 0x9000 else None
    der = tlv_find(template, 0x82) if template is not None else None

    verified = False
    error = ""
    if der is not None:
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), point
            )
            public_key.verify(
                der,
                digest,
                ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())),
            )
            verified = True
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
    record(
        "AC-017 GENERAL AUTHENTICATE sign",
        der is not None,
        f"sw={sw:04X} sig={len(der) if der else 0}B",
    )
    record("AC-017 signature verifies (P-256)", verified, error)

    # --- Phase 16d: RSA-2048 (AC-021), both slots -------------------------
    # On-device key generation takes seconds; the PC/SC timeout covers it.
    # Explicit re-VERIFY: do not rely on the PIN-`once` state cached from the
    # P-256 flow above.
    _, sw = transmit(connection, [0x00, 0x20, 0x00, REF_PIN, 8, *padded_pin(DEFAULT_PIN)])
    record("AC-021 VERIFY PIN before RSA", sw == 0x9000, f"sw={sw:04X}")
    if sw != 0x9000:
        return summarize()

    for slot, label in ((REF_PIV_AUTH, "9A"), (REF_SIGNATURE, "9C")):
        ac = bytes([0xAC, 0x06, 0x80, 0x01, ALG_RSA2048, 0xAA, 0x01, 0x02])
        data, sw = transmit(
            connection,
            [0x00, 0x47, 0x00, slot, len(ac), *ac],
        )
        template = tlv_find(data, 0x7F49) if sw == 0x9000 else None
        modulus = tlv_find(template, 0x81) if template is not None else None
        exponent = tlv_find(template, 0x82) if template is not None else None
        record(
            f"AC-021 GENERATE RSA-2048 key ({label})",
            modulus is not None
            and len(modulus) == 256
            and exponent == bytes([0x01, 0x00, 0x01]),
            f"sw={sw:04X}",
        )
        if modulus is None:
            return summarize()

        block = os.urandom(256)
        inner = bytes([0x82, 0x00, 0x81, 0x82, 0x01, 0x00]) + block
        body = bytes([0x7C, 0x82, (len(inner) >> 8) & 0xFF, len(inner) & 0xFF]) + inner
        data, sw = transmit(
            connection,
            xapdu(0x00, 0x87, ALG_RSA2048, slot, body),
        )
        template = tlv_find(data, 0x7C) if sw == 0x9000 else None
        raw = tlv_find(template, 0x82) if template is not None else None
        record(
            f"AC-021 GENERAL AUTHENTICATE RSA sign ({label})",
            raw is not None and len(raw) == 256,
            f"sw={sw:04X}",
        )

        # Raw RSA check without a padding library: s^e mod n must equal the block.
        n = int.from_bytes(modulus, "big")
        e = int.from_bytes(exponent, "big")
        verified = (
            raw is not None
            and pow(int.from_bytes(raw, "big"), e, n) == int.from_bytes(block, "big")
        )
        record(f"AC-021 RSA signature inverts with the public key ({label})", verified)

        # DigestInfo/EMSA-PKCS1-v1_5 round-trip: host frames the EM, card
        # applies the raw private operation, host verifies with the padding
        # library (same pattern as validate_openpgp.py AC-021).
        digest = hashlib.sha256(b"abc").digest()
        digest_info = bytes.fromhex("3031300D060960864801650304020105000420") + digest
        em = b"\x00\x01" + b"\xff" * (256 - len(digest_info) - 3) + b"\x00" + digest_info
        inner = bytes([0x82, 0x00, 0x81, 0x82, 0x01, 0x00]) + em
        body = bytes([0x7C, 0x82, (len(inner) >> 8) & 0xFF, len(inner) & 0xFF]) + inner
        data, sw = transmit(
            connection,
            xapdu(0x00, 0x87, ALG_RSA2048, slot, body),
        )
        template = tlv_find(data, 0x7C) if sw == 0x9000 else None
        sig = tlv_find(template, 0x82) if template is not None else None
        em_ok = False
        try:
            numbers = rsa_mod.RSAPublicNumbers(n, e)
            numbers.public_key().verify(
                sig,
                digest,
                padding.PKCS1v15(),
                asym_utils.Prehashed(hashes.SHA256()),
            )
            em_ok = sw == 0x9000 and sig is not None and len(sig) == 256
        except Exception:
            em_ok = False
        record(f"AC-021 RSA DigestInfo signature verifies ({label})", em_ok, f"sw={sw:04X}")

    return summarize()


def summarize() -> int:
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
