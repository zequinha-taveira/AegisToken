#!/usr/bin/env python3
"""Generate the AegisToken firmware-update vendor key (P-256 / ES256).

    python scripts/gen-update-key.py [update-vendor-key.pem]

Writes the PKCS#8 private key (PEM) and prints the uncompressed SEC1 public key
(65 bytes, hex) to inject at build time via ``AEGIS_UPDATE_VENDOR_PUBKEY``.

The private key signs firmware update packages; keep it offline and secret.
"""

from __future__ import annotations

import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError as exc:  # pragma: no cover - tooling dependency
    print("cryptography is required: pip install cryptography")
    print(exc)
    sys.exit(2)


def main() -> int:
    output = sys.argv[1] if len(sys.argv) > 1 else "update-vendor-key.pem"

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(output, "wb") as handle:
        handle.write(pem)

    public = key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    hex_key = public.hex()

    print(f"wrote {output}  (KEEP SECRET — do not commit)")
    print(f"public key ({len(public)} bytes, uncompressed SEC1):")
    print(hex_key)
    print("\nBuild the firmware with:")
    print(f'  $env:AEGIS_UPDATE_VENDOR_PUBKEY="{hex_key}"')
    print("  cargo build -p firmware-universal-rp2350 --target thumbv8m.main-none-eabihf --release")
    return 0


if __name__ == "__main__":
    sys.exit(main())
