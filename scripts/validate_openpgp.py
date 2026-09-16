#!/usr/bin/env python3
"""AegisToken — Phase 14/15 OpenPGP Card validation (AC-019) + Phase 16 RSA.

Requires ``pyscard`` and ``cryptography``. The validator exercises the P-256
and Ed25519/X25519 OpenPGP Card slices plus RSA-2048: application data,
PW1/PW3, key generation, signatures/decryption and external verification.

    python scripts/validate_openpgp.py
    python scripts/validate_openpgp.py --reader Aegis

Secure messaging and private-key import are intentionally not tested.
"""

from __future__ import annotations

import sys

try:
    from smartcard.System import readers
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("pyscard is required: pip install pyscard")
    print(exc)
    sys.exit(2)

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("cryptography is required: pip install cryptography")
    print(exc)
    sys.exit(2)

RESULTS: list[tuple[str, bool, str]] = []

AID_OPENPGP = bytes.fromhex("D2760001240103040000000000000000")
PW1 = b"123456"
PW3 = b"12345678"

ATTRS_ECDSA_P256 = bytes.fromhex("132A8648CE3D030107")
ATTRS_ED25519 = bytes.fromhex("162B06010401DA470F01")
ATTRS_X25519 = bytes.fromhex("122B060104019755010501")
ATTRS_RSA2048 = bytes.fromhex("0108000020")
ATTRS_RSA2048_STORED = bytes.fromhex("010800002000")


def record(name: str, passed: bool, detail: str = "") -> None:
    RESULTS.append((name, passed, detail))
    flag = "PASS" if passed else "FAIL"
    print(f"[{flag}] {name}" + (f" — {detail}" if detail else ""))


def transmit(connection, apdu: list[int]) -> tuple[bytes, int]:
    data, sw1, sw2 = connection.transmit(apdu)
    return bytes(data), (sw1 << 8) | sw2


def tlv(tag: int, value: bytes) -> bytes:
    if len(value) >= 0x80:
        raise ValueError("validator only emits short TLVs")
    return bytes([tag, len(value)]) + value


def find_tlv(data: bytes, wanted: int) -> bytes | None:
    """Find a TLV value by tag (one- or two-byte tags, short/long lengths)."""
    index = 0
    while index < len(data):
        first = data[index]
        if first & 0x1F == 0x1F:
            if index + 2 > len(data):
                return None
            tag = (first << 8) | data[index + 1]
            index += 2
        else:
            tag = first
            index += 1
        if index >= len(data):
            return None
        length_byte = data[index]
        index += 1
        if length_byte < 0x80:
            length = length_byte
        elif length_byte == 0x81:
            if index >= len(data):
                return None
            length = data[index]
            index += 1
        elif length_byte == 0x82:
            if index + 2 > len(data):
                return None
            length = (data[index] << 8) | data[index + 1]
            index += 2
        else:
            return None
        value = data[index : index + length]
        if len(value) != length:
            return None
        index += length
        if tag == wanted:
            return value
    return None


def xapdu(cla: int, ins: int, p1: int, p2: int, data: bytes) -> list[int]:
    """Build a command APDU, using extended Lc for payloads >= 256 bytes."""
    header = [cla, ins, p1, p2]
    if not data:
        return header
    if len(data) < 256:
        return header + [len(data), *data]
    return header + [0x00, (len(data) >> 8) & 0xFF, len(data) & 0xFF, *data]


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
        "AC-019 OpenPGP reader enumeration",
        reader is not None,
        f"readers={[str(item) for item in available]}" if reader is None else str(reader),
    )
    if reader is None:
        return summarize()

    connection = reader.createConnection()
    try:
        connection.connect()
    except Exception as exc:  # noqa: BLE001
        record("AC-019 card activation", False, str(exc))
        return summarize()

    data, sw = transmit(connection, [0x00, 0xA4, 0x04, 0x00, len(AID_OPENPGP), *AID_OPENPGP])
    record("AC-019 SELECT OpenPGP", sw == 0x9000, f"sw={sw:04X}")
    if sw != 0x9000:
        return summarize()

    data, sw = transmit(connection, [0x00, 0xCA, 0x00, 0xC4, 0x00])
    record("AC-019 GET DATA PW status", sw == 0x9000 and len(data) == 7, f"sw={sw:04X}")

    _, sw = transmit(connection, [0x00, 0x20, 0x00, 0x83, len(PW3), *PW3])
    record("AC-019 VERIFY PW3", sw == 0x9000, f"sw={sw:04X}")

    # OpenPGP Card v3.4: P-256 ECDSA attributes are 13 + the truncated OID.
    data, sw = transmit(connection, [0x00, 0xCA, 0x00, 0xC1, 0x00])
    record(
        "AC-019 GET DATA signature attributes",
        sw == 0x9000 and data == bytes.fromhex("132A8648CE3D030107"),
        f"sw={sw:04X}",
    )

    # Generate the signature key (CRT B6 = signature key).
    data, sw = transmit(connection, [0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00])
    public_template = find_tlv(data, 0x7F49) if sw == 0x9000 else None
    point = find_tlv(public_template, 0x81) if public_template is not None else None
    record(
        "AC-019 GENERATE P-256 signature key",
        point is not None and len(point) == 65 and point[0] == 0x04,
        f"sw={sw:04X}",
    )
    if point is None:
        return summarize()

    _, sw = transmit(connection, [0x00, 0x20, 0x00, 0x81, len(PW1), *PW1])
    record("AC-019 VERIFY PW1", sw == 0x9000, f"sw={sw:04X}")

    digest = bytes.fromhex("A5" * 32)
    data, sw = transmit(connection, [0x00, 0x2A, 0x9E, 0x9A, len(digest), *digest])
    verified = False
    try:
        # OpenPGP card ECDSA signatures are raw r||s; convert to DER.
        r = int.from_bytes(data[:32], "big")
        s = int.from_bytes(data[32:64], "big")
        der = asym_utils.encode_dss_signature(r, s)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        public_key.verify(
            der,
            digest,
            ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())),
        )
        verified = sw == 0x9000
    except Exception:
        verified = False
    record("AC-019 PSO: COMPUTE DIGITAL SIGNATURE", sw == 0x9000, f"sw={sw:04X}")
    record("AC-019 OpenPGP signature verifies", verified)

    # --- Phase 15: Ed25519 signing slot -----------------------------------
    _, sw = transmit(connection, [0x00, 0xDA, 0x00, 0xC1, len(ATTRS_ED25519), *ATTRS_ED25519])
    record("AC-019 PUT DATA C1 Ed25519 attrs", sw == 0x9000, f"sw={sw:04X}")

    data, sw = transmit(connection, [0x00, 0xCA, 0x00, 0xC1, 0x00])
    record(
        "AC-019 GET DATA C1 reflects PUT",
        sw == 0x9000 and data == ATTRS_ED25519,
        f"sw={sw:04X}",
    )

    data, sw = transmit(connection, [0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00])
    public_template = find_tlv(data, 0x7F49) if sw == 0x9000 else None
    ed_point = find_tlv(public_template, 0x81) if public_template is not None else None
    record(
        "AC-019 GENERATE Ed25519 signature key",
        ed_point is not None and len(ed_point) == 32,
        f"sw={sw:04X}",
    )
    if ed_point is None:
        return summarize()

    _, sw = transmit(connection, [0x00, 0x20, 0x00, 0x81, len(PW1), *PW1])
    record("AC-019 VERIFY PW1 (Ed25519)", sw == 0x9000, f"sw={sw:04X}")

    message = bytes.fromhex("5A" * 48)
    data, sw = transmit(connection, [0x00, 0x2A, 0x9E, 0x9A, len(message), *message])
    ed_verified = False
    try:
        Ed25519PublicKey.from_public_bytes(ed_point).verify(data, message)
        ed_verified = sw == 0x9000 and len(data) == 64
    except Exception:
        ed_verified = False
    record("AC-019 PSO Ed25519 raw signature", sw == 0x9000, f"sw={sw:04X}")
    record("AC-019 Ed25519 signature verifies", ed_verified)

    # --- Phase 15: X25519 decryption slot ----------------------------------
    _, sw = transmit(connection, [0x00, 0xDA, 0x00, 0xC2, len(ATTRS_X25519), *ATTRS_X25519])
    record("AC-019 PUT DATA C2 X25519 attrs", sw == 0x9000, f"sw={sw:04X}")

    data, sw = transmit(connection, [0x00, 0x47, 0x80, 0x00, 0x02, 0xB8, 0x00])
    public_template = find_tlv(data, 0x7F49) if sw == 0x9000 else None
    x_point = find_tlv(public_template, 0x81) if public_template is not None else None
    record(
        "AC-019 GENERATE X25519 decryption key",
        x_point is not None and len(x_point) == 32,
        f"sw={sw:04X}",
    )
    if x_point is None:
        return summarize()

    _, sw = transmit(connection, [0x00, 0x20, 0x00, 0x82, len(PW1), *PW1])
    record("AC-019 VERIFY PW1 (decipher)", sw == 0x9000, f"sw={sw:04X}")

    peer_private = X25519PrivateKey.generate()
    peer_point = peer_private.public_key().public_bytes_raw()
    cipher = tlv(0xA6, tlv(0x7F49, tlv(0x86, peer_point)))
    data, sw = transmit(connection, [0x00, 0x2A, 0x80, 0x86, len(cipher), *cipher])
    x_ok = False
    try:
        expected = peer_private.exchange(X25519PublicKey.from_public_bytes(x_point))
        x_ok = sw == 0x9000 and data == expected
    except Exception:
        x_ok = False
    record("AC-019 PSO X25519 shared secret agrees", x_ok, f"sw={sw:04X}")

    # --- Phase 16: RSA-2048 (AC-021, application data path) -----------------
    _, sw = transmit(connection, [0x00, 0xDA, 0x00, 0xC1, len(ATTRS_RSA2048), *ATTRS_RSA2048])
    record("AC-021 PUT DATA C1 RSA-2048 attrs", sw == 0x9000, f"sw={sw:04X}")

    data, sw = transmit(connection, [0x00, 0xCA, 0x00, 0xC1, 0x00])
    record(
        "AC-021 GET DATA C1 canonical RSA attrs",
        sw == 0x9000 and data == ATTRS_RSA2048_STORED,
        f"sw={sw:04X}",
    )

    data, sw = transmit(connection, [0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00])
    public_template = find_tlv(data, 0x7F49) if sw == 0x9000 else None
    rsa_n = find_tlv(public_template, 0x81) if public_template is not None else None
    rsa_e = find_tlv(public_template, 0x82) if public_template is not None else None
    record(
        "AC-021 GENERATE RSA-2048 signature key",
        rsa_n is not None and len(rsa_n) == 256 and rsa_e == bytes([0x01, 0x00, 0x01]),
        f"sw={sw:04X}",
    )
    if rsa_n is None:
        return summarize()

    _, sw = transmit(connection, [0x00, 0x20, 0x00, 0x81, len(PW1), *PW1])
    record("AC-021 VERIFY PW1 (RSA)", sw == 0x9000, f"sw={sw:04X}")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"abc")
    fingerprint = digest.finalize()
    digest_info = bytes.fromhex("3031300D060960864801650304020105000420") + fingerprint
    data, sw = transmit(connection, [0x00, 0x2A, 0x9E, 0x9A, len(digest_info), *digest_info])
    rsa_verified = False
    try:
        public_numbers = rsa_mod.RSAPublicNumbers(
            int.from_bytes(rsa_n, "big"), int.from_bytes(rsa_e, "big")
        )
        public_key = public_numbers.public_key()
        public_key.verify(
            bytes(data),
            fingerprint,
            asym_padding.PKCS1v15(),
            asym_utils.Prehashed(hashes.SHA256()),
        )
        rsa_verified = sw == 0x9000 and len(data) == 256
    except Exception:
        rsa_verified = False
    record("AC-021 PSO RSA DigestInfo signature", sw == 0x9000, f"sw={sw:04X}")
    record("AC-021 RSA signature verifies (OpenSSL)", rsa_verified)

    # Decryption slot: fresh RSA key, encrypt host-side, decipher on-card.
    _, sw = transmit(connection, [0x00, 0xDA, 0x00, 0xC2, len(ATTRS_RSA2048), *ATTRS_RSA2048])
    record("AC-021 PUT DATA C2 RSA-2048 attrs", sw == 0x9000, f"sw={sw:04X}")

    data, sw = transmit(connection, [0x00, 0x47, 0x80, 0x00, 0x02, 0xB8, 0x00])
    public_template = find_tlv(data, 0x7F49) if sw == 0x9000 else None
    dec_n = find_tlv(public_template, 0x81) if public_template is not None else None
    dec_e = find_tlv(public_template, 0x82) if public_template is not None else None
    record(
        "AC-021 GENERATE RSA-2048 decryption key",
        dec_n is not None and len(dec_n) == 256,
        f"sw={sw:04X}",
    )
    if dec_n is None:
        return summarize()

    _, sw = transmit(connection, [0x00, 0x20, 0x00, 0x82, len(PW1), *PW1])
    record("AC-021 VERIFY PW1 (RSA decipher)", sw == 0x9000, f"sw={sw:04X}")

    message = b"rsa-decrypt-ok"
    dec_numbers = rsa_mod.RSAPublicNumbers(int.from_bytes(dec_n, "big"), int.from_bytes(dec_e, "big"))
    cipher = dec_numbers.public_key().encrypt(message, asym_padding.PKCS1v15())
    payload = bytes([0x02]) + cipher
    data, sw = transmit(connection, xapdu(0x00, 0x2A, 0x80, 0x86, payload))
    dec_ok = sw == 0x9000 and len(data) == 256 and data.endswith(message) and data[:2] == bytes([0x00, 0x02])
    record("AC-021 PSO RSA decipher returns raw block", dec_ok, f"sw={sw:04X}")

    data, sw = transmit(connection, [0x00, 0xCA, 0x00, 0xC7, 0x00])
    record(
        "AC-021 fingerprint C7 present",
        sw == 0x9000 and len(data) == 20 and data != bytes(20),
        f"sw={sw:04X}",
    )

    return summarize()


def summarize() -> int:
    failed = [result for result in RESULTS if not result[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
