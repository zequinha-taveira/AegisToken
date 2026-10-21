"""Reference implementation of the OpenPGP symmetric layer (RFC 4880 §13.9).

This script is **not** part of the firmware. It exists to generate the test
vectors embedded in `crates/aegis-applets/src/pgp_sym.rs`: it was written
directly from the text of RFC 4880 §13.9 ("OpenPGP CFB Mode") and §5.13 (the
Sym. Encrypted Integrity Protected Data Packet), independently of the Rust
implementation, so that both agree on the byte layout of the CFB stream, the
resynchronization step and the modification detection code.

Run it to print the vectors:

    python tests/openpgp_sym_reference.py

The output is pasted into the Rust test module as fixed vectors.
"""

from __future__ import annotations

import hashlib
import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - the reference needs the cryptography package
    print("the reference implementation needs the 'cryptography' package", file=sys.stderr)
    raise

BS = 16  # AES block size


def _keystream_block(key: bytes, fr: bytes) -> bytes:
    """E(FR): the AES encryption of the feedback register."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(fr)


def encrypt(session_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt `plaintext` with the OpenPGP CFB of RFC 4880 §13.9.

    The plaintext must already carry the BS+2 octet prefix and the
    modification detection code; this function only performs the CFB with the
    resynchronization step.
    """
    if len(plaintext) < BS + 2:
        raise ValueError("the plaintext must carry the BS+2 octet prefix")
    out = bytearray()
    fr = b"\x00" * BS
    # Steps 1 to 5: the first BS octets of the prefix.
    fre = _keystream_block(session_key, fr)
    first = bytes(a ^ b for a, b in zip(fre, plaintext[:BS]))
    out += first
    fr = first
    # Step 6: the two quick-check octets.
    fre = _keystream_block(session_key, fr)
    out += bytes(a ^ b for a, b in zip(fre[:2], plaintext[BS : BS + 2]))
    # Step 7: the resynchronization loads C[3]..C[BS+2] into FR.
    fr = bytes(out[2 : BS + 2])
    rest = plaintext[BS + 2 :]
    for offset in range(0, len(rest), BS):
        block = rest[offset : offset + BS]
        fre = _keystream_block(session_key, fr)
        cipher_block = bytes(a ^ b for a, b in zip(fre, block))
        out += cipher_block
        fr = cipher_block
    return bytes(out)


def decrypt(session_key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt the OpenPGP CFB stream of RFC 4880 §13.9 (the inverse)."""
    if len(ciphertext) < BS + 2:
        raise ValueError("the ciphertext is shorter than the prefix")
    out = bytearray()
    fr = b"\x00" * BS
    fre = _keystream_block(session_key, fr)
    first = bytes(a ^ b for a, b in zip(fre, ciphertext[:BS]))
    out += first
    fr = ciphertext[:BS]
    fre = _keystream_block(session_key, fr)
    out += bytes(a ^ b for a, b in zip(fre[:2], ciphertext[BS : BS + 2]))
    fr = ciphertext[2 : BS + 2]
    rest = ciphertext[BS + 2 :]
    for offset in range(0, len(rest), BS):
        block = rest[offset : offset + BS]
        fre = _keystream_block(session_key, fr)
        plain_block = bytes(a ^ b for a, b in zip(fre, block))
        out += plain_block
        fr = block
    return bytes(out)


def build_message(session_key: bytes, data: bytes) -> tuple[bytes, bytes]:
    """Build the OpenPGP "Sym. Encrypted Integrity Protected Data" body.

    Returns the CFB ciphertext and the plaintext (prefix || data || MDC
    packet). The prefix carries the quick-check octets: the last two octets
    replicate the two before them, as required by RFC 4880 §13.9.

    The modification detection code packet (RFC 4880 §5.14) is the last packet
    of the plaintext: its tag octet (0xD3), its length octet (0x14) and the
    20 octet SHA-1 hash of the preceding data (prefix included) are encrypted
    along with the data.
    """
    prefix = bytearray(os.urandom(BS))
    prefix[BS - 2] = prefix[BS - 4]
    prefix[BS - 1] = prefix[BS - 3]
    prefix += bytes((prefix[BS - 2], prefix[BS - 1]))
    body = bytes(prefix) + data
    mdc = hashlib.sha1(body + bytes((0xD3, 0x14))).digest()
    plaintext = body + bytes((0xD3, 0x14)) + mdc
    return encrypt(session_key, plaintext), plaintext


def main() -> None:
    key = bytes(range(0x10, 0x20))
    data = b"AegisToken OpenPGP symmetric layer reference vector"
    ciphertext, plaintext = build_message(key, data)

    print("session key :", key.hex())
    print("data        :", data.hex())
    print("plaintext   :", plaintext.hex())
    print("ciphertext  :", ciphertext.hex())
    # The quick check: the last two octets of the prefix replicate the two
    # before them.
    print("quick check :", plaintext[BS - 2 : BS + 2].hex())
    # The round trip of the reference itself.
    assert decrypt(key, ciphertext) == plaintext
    print("round trip  : ok")


if __name__ == "__main__":
    main()
