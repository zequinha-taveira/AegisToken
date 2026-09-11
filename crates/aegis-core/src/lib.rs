#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! Hardware-agnostic core logic for the AegisToken Universal RP2350 Firmware.
//!
//! This crate must never depend on a concrete HAL, executor or board. It owns
//! the deterministic, host-testable domain: execution and lifecycle state
//! machines, device capabilities, the configuration model with validation and
//! integrity-protected records, contextual User Presence with replay
//! protection, hardware-abstraction traits and the error taxonomy.

pub mod authenticator;
pub mod capabilities;
pub mod codec;
pub mod configuration;
pub mod credential_store;
pub mod ctap2;
pub mod ctaphid;
pub mod discovery;
pub mod error;
pub mod lifecycle;
pub mod management;
pub mod management_protocol;
pub mod pin;
pub mod presence;
pub mod recovery;
pub mod secret;
pub mod state;
pub mod storage;
pub mod traits;
pub mod u2f;
pub mod update;

pub use capabilities::DeviceCapabilities;
pub use configuration::DeviceConfig;
pub use error::{CoreError, CoreResult};
pub use lifecycle::LifecycleState;
pub use state::ExecutionState;

/// Firmware semantic version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Official USB product string.
///
/// Note: the PRD §2 fixes this as `AegisToken FIDO2 Authenticator`; it now
/// carries the `USB` qualifier per product direction.
pub const PRODUCT_USB_STRING: &str = "AegisToken FIDO2 USB Authenticator";

/// Official firmware family name (PRD §2).
pub const FIRMWARE_FAMILY: &str = "Universal RP2350 Firmware";

/// Release artifact name (PRD §2, §36).
pub const RELEASE_ARTIFACT: &str = "rp2350-universal.uf2";
