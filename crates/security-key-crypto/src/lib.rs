#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! Cryptographic boundaries for security-key implementations.
//!
//! This crate is a migration scaffold. The implementation remains in
//! `aegis-core` until each responsibility is moved deliberately.

pub mod aes;
pub mod hash;
pub mod hmac;
pub mod p256;
pub mod traits;
