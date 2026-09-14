#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! USB transport boundaries for security-key implementations.
//!
//! This crate is a migration scaffold. The implementation remains in
//! `aegis-core` until each responsibility is moved deliberately.

pub mod fido;
pub mod hid;
pub mod management;
