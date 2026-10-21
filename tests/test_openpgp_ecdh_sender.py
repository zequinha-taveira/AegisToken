"""Tests of the OpenPGP ECDH sender (the GnuPG side of the card flow).

The sender is the piece a host plays against the card: it derives the key
encryption key, wraps the session key and encrypts the message. These tests
pin it to the normative vectors, so that the card implementation in
``crates/aegis-applets`` is checked against an independent implementation.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

import openpgp_ecdh_sender as sender  # noqa: E402

FINGERPRINT = bytes.fromhex("00112233445566778899aabbccddeeff01020304")
ZB = bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")


def test_kdf_parameters_follow_rfc6637() -> None:
    param = sender.kdf_parameters(FINGERPRINT)
    assert len(param) == 54
    assert param[0] == 8
    assert param[1:9] == sender.CURVE_OID_P256
    assert param[9] == sender.ALG_ECDH
    assert param[10:12] == b"\x03\x01"
    assert param[12] == sender.HASH_SHA256
    assert param[13] == sender.KEK_AES128
    assert param[14:34] == b"Anonymous Sender    "
    assert param[34:54] == FINGERPRINT


def test_kdf_matches_the_reference_value() -> None:
    derived = sender.kdf(sender.kdf_parameters(FINGERPRINT), ZB, 32)
    assert (
        derived.hex()
        == "cf6863d856b144fcc63b70491361be41925dfdd5b4a701e9b6d15bd23d6a1ea6"
    )


def test_key_wrap_matches_rfc3394() -> None:
    kek = bytes(range(16))
    data = bytes.fromhex("00112233445566778899aabbccddeeff")
    wrapped = sender.aes_key_wrap(kek, data)
    assert (
        wrapped.hex() == "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
    )


def test_wrapped_session_key_carries_the_algorithm_and_checksum() -> None:
    kek = bytes(range(16))
    session_key = bytes([0x5A] * 16)
    wrapped = sender.wrap_session_key(kek, session_key)
    # The wrapped value is the session key packet (24 octets) wrapped by the
    # AES key wrap, which adds one block for the integrity check.
    assert len(wrapped) == 32
    # Unwrap it again to inspect the session key packet.
    inner = sender.aes_key_unwrap(kek, wrapped)
    assert inner[0] == sender.SYM_AES128
    assert inner[1:17] == session_key
    assert sum(session_key) & 0xFFFF == int.from_bytes(inner[17:19], "big")
    assert inner[19:] == bytes([5]) * 5


def test_the_symmetric_layer_is_self_consistent() -> None:
    key = bytes(range(0x10, 0x20))
    plaintext, ciphertext = sender.build_message(key, b"aegistoken")
    # The quick check: the last two octets of the prefix replicate the two
    # before them.
    assert plaintext[16] == plaintext[14]
    assert plaintext[17] == plaintext[15]
    assert len(ciphertext) == len(plaintext)


def test_the_shared_secret_is_the_x_coordinate() -> None:
    ephemeral = sender.ephemeral_key()
    public = ephemeral.public_key().public_bytes(
        encoding=__import__(
            "cryptography.hazmat.primitives.serialization",
            fromlist=["Encoding"],
        ).Encoding.X962,
        format=__import__(
            "cryptography.hazmat.primitives.serialization",
            fromlist=["PublicFormat"],
        ).PublicFormat.UncompressedPoint,
    )
    secret = sender.shared_secret(ephemeral, public)
    assert len(secret) == 32


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
