//! Structured error taxonomy (PRD §30).
//!
//! Every failure surfaced by the core maps to exactly one of these categories.
//! The Management HID layer later translates these into wire status codes
//! without leaking internal detail.

use core::fmt;

/// Error categories exposed by the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CoreError {
    /// The command itself is malformed or not well formed.
    InvalidCommand,
    /// The command is well formed but not known to this firmware.
    UnsupportedCommand,
    /// A requested feature is not present in the declared capabilities.
    InvalidCapability,
    /// A configuration value failed validation.
    InvalidConfiguration,
    /// The requested transition is not legal from the current state.
    InvalidState,
    /// The caller is not permitted to perform the operation.
    Unauthorized,
    /// Persistent storage failed.
    StorageError,
    /// Cryptographic verification failed.
    CryptoError,
    /// Firmware image or update package failed verification.
    FirmwareError,
    /// The wire protocol was violated.
    ProtocolError,
}

impl CoreError {
    /// Stable wire code for the Management HID status field.
    ///
    /// These values are part of the protocol contract and must not be
    /// renumbered once released.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            CoreError::InvalidCommand => 0x01,
            CoreError::UnsupportedCommand => 0x02,
            CoreError::InvalidCapability => 0x03,
            CoreError::InvalidConfiguration => 0x04,
            CoreError::InvalidState => 0x05,
            CoreError::Unauthorized => 0x06,
            CoreError::StorageError => 0x07,
            CoreError::CryptoError => 0x08,
            CoreError::FirmwareError => 0x09,
            CoreError::ProtocolError => 0x0A,
        }
    }

    /// Short, non-sensitive human-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            CoreError::InvalidCommand => "invalid command",
            CoreError::UnsupportedCommand => "unsupported command",
            CoreError::InvalidCapability => "invalid capability",
            CoreError::InvalidConfiguration => "invalid configuration",
            CoreError::InvalidState => "invalid state",
            CoreError::Unauthorized => "unauthorized",
            CoreError::StorageError => "storage error",
            CoreError::CryptoError => "crypto error",
            CoreError::FirmwareError => "firmware error",
            CoreError::ProtocolError => "protocol error",
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for CoreError {}

/// Convenience alias for fallible core operations.
pub type CoreResult<T> = Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique() {
        let all = [
            CoreError::InvalidCommand,
            CoreError::UnsupportedCommand,
            CoreError::InvalidCapability,
            CoreError::InvalidConfiguration,
            CoreError::InvalidState,
            CoreError::Unauthorized,
            CoreError::StorageError,
            CoreError::CryptoError,
            CoreError::FirmwareError,
            CoreError::ProtocolError,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.code(), b.code(), "{a:?} and {b:?} share a code");
            }
        }
    }

    #[test]
    fn display_matches_as_str() {
        assert_eq!(CoreError::CryptoError.to_string(), "crypto error");
    }
}
