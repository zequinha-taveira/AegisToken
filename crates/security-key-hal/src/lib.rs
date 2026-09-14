#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! Hardware abstraction boundaries for security-key implementations.
//!
//! This crate is a migration scaffold. Board-specific implementations remain
//! in the existing board crates until the HAL boundary is introduced.

pub mod crypto;
pub mod flash;
pub mod gpio;
pub mod rng;
pub mod usb;
