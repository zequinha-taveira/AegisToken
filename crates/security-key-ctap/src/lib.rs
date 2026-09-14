#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! CTAP protocol boundaries for security-key implementations.
//!
//! This crate is a migration scaffold. The implementation remains in
//! `aegis-core` until each responsibility is moved deliberately.

pub mod cbor;
pub mod ctap2;
pub mod ctaphid;
pub mod u2f;
