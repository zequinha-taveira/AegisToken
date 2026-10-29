"""Tests of the OpenPGP symmetric layer against a real GnuPG message.

The vector comes from a message that GnuPG encrypted for an ECDH P-256 key (the
RFC 6637 flow of ``crates/aegis-applets/src/openpgp.rs``): the session key is
the one ``gpg --show-session-key --decrypt`` reported and the ciphertext is the
body of the Sym. Encrypted Integrity Protected Data packet. It pins the CFB
chain of RFC 4880 section 13.9 to an implementation other than our own.
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import openpgp_sym_reference as reference  # noqa: E402

# gpg: session key: '9:0D5A98ADCDFCFB0B8A69AB354440849E828B4CDB592BE01CB30D910BE4F8FCF5'
SESSION_KEY = bytes.fromhex(
    "0d5a98adcdfcfb0b8a69ab354440849e828b4cdb592be01cb30d910be4f8fcf5"
)
CIPHERTEXT = bytes.fromhex(
    "0b7e36999fa641148c8d24af02d207861c966153c5b4de7a14ed2c8f0f2f4c39"
    "b1f793abb5596fa46ac49cbebd843913c98d54dfa2d6b7dcfeb8d7b576093561"
    "b80198ca8094c48547fde74057ba3b4d70222204dfc79e81a018c481"
)
PLAINTEXT = bytes.fromhex(
    "5de0eb52d472c54b9ce31196204f1e991e99ac32620b6d6573736167652e747874"
    "6ad9707d4165676973546f6b656e20476e75504720696e7465726f706572616269"
    "6c697479d314c570a224b0624efd3cadf390dc84425c91771e56"
)

MESSAGE = b"AegisToken GnuPG interoperability"


def test_decrypts_a_message_encrypted_by_gnupg() -> None:
    plaintext = reference.decrypt(SESSION_KEY, CIPHERTEXT)
    assert plaintext == PLAINTEXT

    # The quick check of the prefix and the modification detection code of
    # GnuPG both hold.
    assert plaintext[16] == plaintext[14]
    assert plaintext[17] == plaintext[15]
    assert plaintext[-22:-20] == b"\xd3\x14"
    assert hashlib.sha1(plaintext[:-20]).digest() == plaintext[-20:]

    # The data is the literal data packet that GnuPG wrote in the old packet
    # format (tag 11): the format, the file name, the date and the message.
    assert plaintext[18] == 0xAC
    name_length = plaintext[21]
    assert plaintext[22 : 22 + name_length] == b"message.txt"
    assert plaintext[22 + name_length + 4 : -22] == MESSAGE


def test_encrypts_to_the_gnupg_ciphertext() -> None:
    assert reference.encrypt(SESSION_KEY, PLAINTEXT) == CIPHERTEXT
