#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! Hardware-agnostic smart-card applets for the AegisToken Universal RP2350
//! Firmware (roadmap Phase 11).
//!
//! This crate owns everything that speaks ISO 7816 and CCID to a host, without
//! ever touching a HAL, an executor or a USB driver:
//!
//! - [`apdu`]: ISO 7816-4 command/response APDUs, status words and response
//!   chaining (`61xx`/`GET RESPONSE`).
//! - [`ccid`]: USB CCID message framing (`PC_to_RDR_*` / `RDR_to_PC_*`) and a
//!   reassembler that turns bulk packets into complete messages.
//! - [`router`]: AID-based applet selection and command dispatch.
//! - [`rsa`]: RSA-2048 primitives (PKCS#1 v1.5, CRT with blinding) backing
//!   the PIV and OpenPGP applets.
//! - [`pin`]: the shared PIN/retry framework (persistent counters, blocking,
//!   unblock) reused by the PIV, OpenPGP and OATH applets.
//! - [`card`]: the stateful card front end combining a [`ccid::Assembler`]
//!   with a [`router::Router`].
//! - [`sealed`]: sealed applet persistence: AES-256-GCM record cells and
//!   generational multi-shard blobs backing the applet store traits.
//!
//! The crate must never depend on `aegis-core` hardware traits or on a concrete
//! board; the firmware layer only moves bytes between USB endpoints and
//! [`card::Card`].

pub mod aid;
pub mod apdu;
pub mod card;
pub mod ccid;
pub mod oath;
pub mod openpgp;
pub mod pin;
pub mod piv;
pub mod placeholder;
pub mod router;
pub mod rsa;
pub mod sealed;
pub mod tlv;
