#![no_std]
//! Board-agnostic hardware abstraction for the RP2350 family.
//!
//! This crate owns every hardware-specific detail (GPIO, BOOTSEL, LED, flash,
//! watchdog). The firmware layer must not reference a concrete board or vendor:
//! it only consumes the traits from [`aegis_core::traits`] and the capability
//! set produced by [`capabilities`].
//!
//! See PRD §7.1 (hardware layer), §8 (automatic discovery) and §28 (board
//! abstraction).

pub use embassy_rp;

pub mod capabilities;
pub mod flash;
pub mod hid;
pub mod led;
pub mod otp;
pub mod presence;
pub mod rng;
pub mod usb;
pub mod watchdog;

mod hardware;

pub use capabilities::BoardProfile;
pub use hardware::{Board, Platform};
