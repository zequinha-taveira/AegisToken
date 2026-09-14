# Architecture

The repository is being prepared for a staged crate migration. The existing
`aegis-core`, board, firmware, and host crates remain the active implementation
while the new `security-key-*` crates provide stable boundaries for future moves.

## Planned boundaries

| Crate | Responsibility |
| --- | --- |
| `security-key-core` | Portable authentication domain and state |
| `security-key-crypto` | Cryptographic primitives and traits |
| `security-key-storage` | Storage traits and implementations |
| `security-key-ctap` | CTAP2, CTAPHID, CBOR, and U2F |
| `security-key-usb` | HID, FIDO, and management USB transport |
| `security-key-hal` | Portable hardware abstraction boundaries |

No implementation is moved by the initial scaffold. Each responsibility can be
migrated and verified independently before the old `aegis-core` modules are
removed.
