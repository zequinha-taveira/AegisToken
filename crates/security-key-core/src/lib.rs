#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
//! Portable security-key domain boundaries.
//!
//! This crate is a migration scaffold. The implementation remains in
//! `aegis-core` until each responsibility is moved deliberately.

pub mod authenticator;
pub mod credential;
pub mod error;
pub mod key;
pub mod presence;
pub mod state;
