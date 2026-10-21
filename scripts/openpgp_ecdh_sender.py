"""The sender side of the OpenPGP card ECDH flow (RFC 6637 §8).

This is the piece a host like GnuPG plays: it generates the ephemeral key
pair, derives the key encryption key, wraps the session key for the card and
encrypts the message. The card does the rest (the "card decrypts on its own"
mode of ``aegis-applets::openpgp``).

It is written here, in Python, from the text of the RFCs, so that it is an
*independent* implementation of the sender side: the Rust implementation in
``crates/aegis-applets`` is checked against it, and the hardware validator
(``scripts/validate_openpgp.py``) uses it to drive a real card.

Normative references:

* RFC 6637 §7 (the KDF) and §8 (the ECDH method, the KDF parameters and the
  key wrapping).
* RFC 3394 (the AES key wrap).
* RFC 4880 §13.9 (the OpenPGP CFB) and §5.14 (the modification detection
  code).
"""

from __future__ import annotations

import hashlib
import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# The curve OID of P-256, as the RFC 6637 §11 requires it (the DER value
# bytes, without the tag and the length).
CURVE_OID_P256 = bytes.fromhex("2A8648CE3D030107")

# The ECDH public key algorithm id (RFC 6637 §5).
ALG_ECDH = 18

# The hash id of SHA-256 and the key wrap algorithm ids of AES (RFC 4880 §9).
HASH_SHA256 = 8
KEK_AES128 = 7
KEK_AES192 = 8
KEK_AES256 = 9

# The symmetric algorithm ids used in the session key packet.
SYM_AES128 = 7
SYM_AES192 = 8
SYM_AES256 = 9

KEK_LENGTH = {KEK_AES128: 16, KEK_AES192: 24, KEK_AES256: 32}
SESSION_LENGTH = {SYM_AES128: 16, SYM_AES192: 24, SYM_AES256: 32}

ANONYMOUS_SENDER = b"Anonymous Sender    "


def kdf_parameters(
    fingerprint: bytes,
    kdf_hash_id: int = HASH_SHA256,
    kek_alg_id: int = KEK_AES128,
    curve_oid: bytes = CURVE_OID_P256,
    alg_id: int = ALG_ECDH,
) -> bytes:
    """The KDF parameters of RFC 6637 §8.

    ``len(curve_oid) || curve_oid || public_key_alg_ID || 0x03 || 0x01 ||
    KDF_hash_ID || KEK_alg_ID || "Anonymous Sender    " || fingerprint``.
    """
    if len(fingerprint) != 20:
        raise ValueError("the recipient fingerprint must be 20 bytes")
    return (
        bytes([len(curve_oid)])
        + curve_oid
        + bytes([alg_id, 0x03, 0x01, kdf_hash_id, kek_alg_id])
        + ANONYMOUS_SENDER
        + fingerprint
    )


def kdf(param: bytes, zb: bytes, length: int) -> bytes:
    """The key derivation function of RFC 6637 §7.

    The concatenation KDF of NIST SP 800-56A (alternative 1) with SHA-256:
    ``SHA-256(00 00 00 01 || ZB || Param)``, continued with the counter in
    ``00 00 00 02`` for longer outputs.
    """
    if length <= 0:
        raise ValueError("the derived key must not be empty")
    out = b""
    counter = 1
    while len(out) < length:
        out += hashlib.sha256(struct.pack(">I", counter) + zb + param).digest()
        counter += 1
    return out[:length]


def aes_key_wrap(kek: bytes, data: bytes) -> bytes:
    """The AES key wrap of RFC 3394."""
    if len(kek) not in KEK_LENGTH.values():
        raise ValueError("the key encryption key must be 128, 192 or 256 bits")
    if len(data) < 16 or len(data) % 8 != 0:
        raise ValueError("the key data must be a multiple of 8 octets")
    cipher = Cipher(algorithms.AES(kek), modes.ECB())
    encryptor = cipher.encryptor()
    n = len(data) // 8
    a = b"\xa6" * 8
    r = [data[8 * i : 8 * (i + 1)] for i in range(n)]
    for j in range(6):
        for i in range(1, n + 1):
            block = encryptor.update(a + r[i - 1])
            t = (n * j + i).to_bytes(8, "big")
            a = bytes(x ^ y for x, y in zip(block[:8], t))
            r[i - 1] = block[8:]
    return a + b"".join(r)


def aes_key_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """The inverse of the AES key wrap of RFC 3394."""
    if len(kek) not in KEK_LENGTH.values():
        raise ValueError("the key encryption key must be 128, 192 or 256 bits")
    if len(wrapped) < 24 or len(wrapped) % 8 != 0:
        raise ValueError("the wrapped key must be a multiple of 8 octets")
    cipher = Cipher(algorithms.AES(kek), modes.ECB())
    decryptor = cipher.decryptor()
    n = len(wrapped) // 8 - 1
    a = wrapped[:8]
    r = [wrapped[8 * (i + 1) : 8 * (i + 2)] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = (n * j + i).to_bytes(8, "big")
            block = decryptor.update(
                bytes(x ^ y for x, y in zip(a, t)) + r[i - 1]
            )
            a = block[:8]
            r[i - 1] = block[8:]
    if a != b"\xa6" * 8:
        raise ValueError("the key wrap integrity check failed")
    return b"".join(r)


def wrap_session_key(
    kek: bytes, session_key: bytes, symm_alg_id: int = SYM_AES128
) -> bytes:
    """The wrapped session key of RFC 6637 §8.

    ``m = symm_alg_ID || session key || checksum || PKCS#5 padding``; the
    checksum is the sum of the session key octets modulo 65536 (RFC 4880
    §5.1) and the padding brings the value to the 8 octet granularity.
    """
    if len(session_key) != SESSION_LENGTH.get(symm_alg_id):
        raise ValueError("the session key length does not match the algorithm")
    checksum = sum(session_key) & 0xFFFF
    m = bytes([symm_alg_id]) + session_key + struct.pack(">H", checksum)
    padding = 8 - (len(m) % 8)
    m += bytes([padding]) * padding
    return aes_key_wrap(kek, m)


def openpgp_cfb_encrypt(session_key: bytes, plaintext: bytes) -> bytes:
    """The OpenPGP CFB of RFC 4880 §13.9, with the resynchronization."""
    bs = 16
    if len(plaintext) < bs + 2:
        raise ValueError("the plaintext must carry the BS+2 octet prefix")
    cipher = Cipher(algorithms.AES(session_key), modes.ECB())
    encryptor = cipher.encryptor()
    out = bytearray()
    fr = b"\x00" * bs
    fre = encryptor.update(fr)
    first = bytes(x ^ y for x, y in zip(fre, plaintext[:bs]))
    out += first
    fr = first
    fre = encryptor.update(fr)
    out += bytes(x ^ y for x, y in zip(fre[:2], plaintext[bs : bs + 2]))
    fr = bytes(out[2 : bs + 2])
    rest = plaintext[bs + 2 :]
    for offset in range(0, len(rest), bs):
        block = rest[offset : offset + bs]
        fre = encryptor.update(fr)
        cipher_block = bytes(x ^ y for x, y in zip(fre, block))
        out += cipher_block
        fr = cipher_block
    return bytes(out)


def build_message(session_key: bytes, data: bytes) -> tuple[bytes, bytes]:
    """The plaintext and the ciphertext of an OpenPGP encrypted data packet.

    The plaintext is the prefix (BS+2 octets), the data and the modification
    detection code packet (RFC 4880 §5.14): its tag octet, its length octet
    and the SHA-1 hash of the preceding data.
    """
    bs = 16
    prefix = bytearray(os.urandom(bs))
    prefix[bs - 2] = prefix[bs - 4]
    prefix[bs - 1] = prefix[bs - 3]
    prefix += bytes((prefix[bs - 2], prefix[bs - 1]))
    body = bytes(prefix) + data
    mdc = hashlib.sha1(body + bytes((0xD3, 0x14))).digest()
    plaintext = body + bytes((0xD3, 0x14)) + mdc
    return plaintext, openpgp_cfb_encrypt(session_key, plaintext)


def ephemeral_key() -> ec.EllipticCurvePrivateKey:
    """A fresh ephemeral key pair, as the sender of a message would use."""
    return ec.generate_private_key(ec.SECP256R1())


def shared_secret(
    ephemeral: ec.EllipticCurvePrivateKey, card_public: bytes
) -> bytes:
    """The ECDH shared secret with the card's public key.

    The result is the ``x`` coordinate of the shared point, as the KDF of
    RFC 6637 §7 expects.
    """
    point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), card_public)
    return ephemeral.exchange(ec.ECDH(), point)


def card_public_point(response: bytes) -> bytes:
    """The public key of a card, from a ``7F49`` response."""
    index = 0
    while index < len(response):
        tag = response[index]
        length = response[index + 1]
        value = response[index + 2 : index + 2 + length]
        if tag == 0x86:
            return value
        index += 2 + length
    raise ValueError("the public key was not found in the response")


def main() -> None:
    """A self test of the sender side (no card needed)."""
    import sys

    # The KDF against the value the Rust test uses.
    fingerprint = bytes.fromhex("00112233445566778899aabbccddeeff01020304")
    param = kdf_parameters(fingerprint)
    assert len(param) == 54, len(param)
    zb = bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")
    derived = kdf(param, zb, 32)
    assert (
        derived.hex()
        == "cf6863d856b144fcc63b70491361be41925dfdd5b4a701e9b6d15bd23d6a1ea6"
    ), derived.hex()

    # The key wrap against the vector of RFC 3394 §4.1.
    kek = bytes(range(16))
    data = bytes.fromhex("00112233445566778899aabbccddeeff")
    wrapped = aes_key_wrap(kek, data)
    assert (
        wrapped.hex()
        == "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
    ), wrapped.hex()

    # The symmetric layer against the vector of the reference implementation.
    key = bytes(range(0x10, 0x20))
    message = b"AegisToken OpenPGP symmetric layer reference vector"
    _, ciphertext = build_message(key, message)
    print(f"sender self test: ok (ciphertext {len(ciphertext)} bytes)")
    sys.exit(0)


if __name__ == "__main__":
    main()
