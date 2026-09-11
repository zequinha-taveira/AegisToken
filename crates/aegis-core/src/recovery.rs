//! Recovery mode and diagnostics (PRD §21, §22).
//!
//! Recovery exposes firmware update, diagnostics and device recovery, but it
//! never grants FIDO approval, never arms User Presence and never exposes
//! credential or key material. [`RecoverySession`] makes those denials
//! explicit and testable.

use crate::capabilities::DeviceCapabilities;
use crate::error::CoreError;
use crate::lifecycle::LifecycleState;
use crate::state::{ExecutionState, fido_allowed};

/// Operations permitted in recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOperation {
    /// Read-only diagnostics.
    Diagnostics,
    /// Apply a signed firmware update.
    FirmwareUpdate,
    /// Factory-reset / device recovery.
    DeviceRecovery,
}

/// Whether `operation` is allowed by recovery policy.
#[must_use]
pub const fn operation_allowed(operation: RecoveryOperation) -> bool {
    matches!(
        operation,
        RecoveryOperation::Diagnostics
            | RecoveryOperation::FirmwareUpdate
            | RecoveryOperation::DeviceRecovery
    )
}

/// Diagnostics report (PRD §12, "Diagnostics").
#[derive(Debug, Clone, Copy, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct DiagnosticsReport {
    /// Firmware major version.
    #[n(0)]
    pub version_major: u8,
    /// Firmware minor version.
    #[n(1)]
    pub version_minor: u8,
    /// Firmware patch version.
    #[n(2)]
    pub version_patch: u8,
    /// Lifecycle state code.
    #[n(3)]
    pub lifecycle: u8,
    /// Active configuration schema version.
    #[n(4)]
    pub config_version: u16,
    /// Whether a configuration is staged.
    #[n(5)]
    pub staged: bool,
    /// Addressable GPIO count.
    #[n(6)]
    pub gpio_count: u8,
    /// Flash capacity in bytes.
    #[n(7)]
    pub flash_size_bytes: u32,
}

impl DiagnosticsReport {
    /// Build a report from the current device state.
    #[must_use]
    pub fn current(
        lifecycle: LifecycleState,
        config_version: u16,
        staged: bool,
        capabilities: &DeviceCapabilities,
    ) -> Self {
        let mut parts = crate::VERSION.split('.');
        let mut next = || parts.next().and_then(|p| p.parse::<u8>().ok()).unwrap_or(0);
        Self {
            version_major: next(),
            version_minor: next(),
            version_patch: next(),
            lifecycle: lifecycle as u8,
            config_version,
            staged,
            gpio_count: capabilities.gpio_count,
            flash_size_bytes: capabilities.flash.size_bytes,
        }
    }
}

/// A recovery-mode session.
///
/// The session tracks the recovery execution state and enforces the recovery
/// isolation rules. It is created when the device enters recovery (firmware
/// validation failure or explicit request).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySession {
    state: ExecutionState,
}

impl Default for RecoverySession {
    fn default() -> Self {
        Self::enter()
    }
}

impl RecoverySession {
    /// Enter recovery.
    #[must_use]
    pub const fn enter() -> Self {
        Self {
            state: ExecutionState::Recovery,
        }
    }

    /// Current execution state.
    #[must_use]
    pub const fn state(&self) -> ExecutionState {
        self.state
    }

    /// Authorize a recovery operation.
    pub fn authorize(&self, operation: RecoveryOperation) -> Result<(), CoreError> {
        if operation_allowed(operation) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized)
        }
    }

    /// Enter firmware update from recovery.
    pub fn begin_firmware_update(&mut self) -> Result<(), CoreError> {
        self.state = self.state.transition(ExecutionState::FirmwareUpdate)?;
        Ok(())
    }

    /// Return to recovery after a firmware update.
    pub fn finish_firmware_update(&mut self) -> Result<(), CoreError> {
        self.state = self.state.transition(ExecutionState::Recovery)?;
        Ok(())
    }

    /// FIDO operations are never served in recovery (PRD §22).
    pub const fn fido_operation(&self) -> Result<(), CoreError> {
        if fido_allowed(self.state) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized)
        }
    }

    /// User Presence is never armed in recovery (PRD §17, §22).
    pub const fn user_presence(&self) -> Result<(), CoreError> {
        Err(CoreError::Unauthorized)
    }

    /// Credential access is never granted in recovery (PRD §22, §25).
    pub const fn credential_access(&self) -> Result<(), CoreError> {
        Err(CoreError::Unauthorized)
    }

    /// Secret export is never granted in recovery (PRD §25).
    pub const fn export_secret(&self) -> Result<(), CoreError> {
        Err(CoreError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_allows_diagnostics_and_update() {
        let mut session = RecoverySession::enter();
        assert_eq!(session.state(), ExecutionState::Recovery);
        assert_eq!(session.authorize(RecoveryOperation::Diagnostics), Ok(()));
        assert_eq!(session.authorize(RecoveryOperation::FirmwareUpdate), Ok(()));
        assert_eq!(session.authorize(RecoveryOperation::DeviceRecovery), Ok(()));

        session.begin_firmware_update().unwrap();
        assert_eq!(session.state(), ExecutionState::FirmwareUpdate);
        session.finish_firmware_update().unwrap();
        assert_eq!(session.state(), ExecutionState::Recovery);
    }

    #[test]
    fn recovery_never_grants_fido_or_presence() {
        let session = RecoverySession::enter();
        assert_eq!(session.fido_operation(), Err(CoreError::Unauthorized));
        assert_eq!(session.user_presence(), Err(CoreError::Unauthorized));
        assert_eq!(session.credential_access(), Err(CoreError::Unauthorized));
        assert_eq!(session.export_secret(), Err(CoreError::Unauthorized));
    }

    #[test]
    fn fido_still_denied_during_firmware_update() {
        let mut session = RecoverySession::enter();
        session.begin_firmware_update().unwrap();
        assert_eq!(session.fido_operation(), Err(CoreError::Unauthorized));
    }

    #[test]
    fn diagnostics_report_encodes() {
        let report = DiagnosticsReport::current(
            LifecycleState::Factory,
            1,
            false,
            &DeviceCapabilities::rp2350a(),
        );
        let mut buf = [0u8; 128];
        let length = crate::codec::encode_into(&report, &mut buf).unwrap();
        assert!(length > 0);
        assert_eq!(report.gpio_count, 30);
        assert_eq!(report.flash_size_bytes, 2 * 1024 * 1024);
    }
}
