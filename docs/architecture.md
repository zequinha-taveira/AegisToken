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

## Applet stack (phases 11-17)

Beyond FIDO, the device exposes PIV, OpenPGP and OATH applets over a USB CCID
interface (class `0x0B`, ISO 7816-4), composed alongside the FIDO HID and
management HID functions. The layering keeps the MCU-independent core free of
USB and hardware details:

| Layer | Crate | Responsibility |
| --- | --- | --- |
| Firmware | `firmware-universal-rp2350` | USB composition (FIDO HID, management HID, CCID), embassy tasks, async presence |
| Board HAL | `board-generic-rp2350` | CCID USB class, bulk endpoint I/O, flash, OTP, TRNG |
| Applets | `aegis-applets` | APDU codec, CCID framing, AID routing, TLV, shared PIN framework, PIV/OATH/OpenPGP applets, RSA-2048 primitives (Montgomery + blinding), sealed record cells and generational multi-shard blobs |
| Core | `aegis-core` | Traits, sealed secret storage, atomic records, presence state machine, error taxonomy |

`aegis-applets` is `no_std` and `no_alloc` and is unit-tested on the host,
mirroring the `aegis-core` pattern: protocol logic never depends on a HAL or an
executor, and the firmware layer only moves bytes between USB endpoints and the
applet router. Private keys are generated on-device and never leave the applet;
only public material (certificates, DOs) can be imported. Applet state persists
in AES-256-GCM sealed cells (one per PIV record, sharded whole-blobs with a
commit cell for OATH/OpenPGP) over flash regions shared behind a blocking
mutex; without a provisioned root key the firmware runs the same applets on
volatile stores.
