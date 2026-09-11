//! Execution state machine (PRD §19).
//!
//! The execution state is deliberately independent from the lifecycle state
//! (PRD §20). It describes *what the firmware is doing right now*, not the
//! provisioning status of the device.

use crate::error::CoreError;

/// Runtime execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionState {
    /// Power-on initialization in progress.
    Boot,
    /// Idle and ready to serve either FIDO or management traffic.
    Active,
    /// A FIDO operation is waiting for User Presence.
    FidoWaitPresence,
    /// A FIDO operation is executing.
    FidoOperation,
    /// The management interface is handling a request.
    Management,
    /// Firmware update in progress.
    FirmwareUpdate,
    /// Running the recovery service.
    Recovery,
    /// Locked out: only an authorized recovery path can leave this state.
    Locked,
}

impl ExecutionState {
    /// Whether `next` is a legal successor of `self`.
    ///
    /// A state is always allowed to transition to itself so callers can apply
    /// transitions idempotently.
    #[must_use]
    pub const fn can_transition(self, next: ExecutionState) -> bool {
        use ExecutionState::*;
        if self as u8 == next as u8 {
            return true;
        }
        match self {
            Boot => matches!(next, Active | Recovery | Locked),
            Active => matches!(
                next,
                FidoWaitPresence | FidoOperation | Management | FirmwareUpdate | Recovery | Locked
            ),
            FidoWaitPresence => matches!(next, FidoOperation | Active | Locked),
            FidoOperation => matches!(next, Active | Locked),
            Management => matches!(next, Active | FirmwareUpdate | Locked),
            FirmwareUpdate => matches!(next, Active | Recovery | Locked),
            Recovery => matches!(next, Active | FirmwareUpdate | Locked),
            Locked => matches!(next, Recovery),
        }
    }

    /// Apply a transition, rejecting illegal edges.
    pub const fn transition(self, next: ExecutionState) -> Result<ExecutionState, CoreError> {
        if self.can_transition(next) {
            Ok(next)
        } else {
            Err(CoreError::InvalidState)
        }
    }
}

/// Destination chosen immediately after power-on (PRD §17, §21).
///
/// Holding BOOTSEL during reset requests recovery; otherwise the firmware
/// proceeds to normal operation.
#[must_use]
pub const fn boot_destination(bootsel_held: bool) -> ExecutionState {
    if bootsel_held {
        ExecutionState::Recovery
    } else {
        ExecutionState::Active
    }
}

/// Whether a BOOTSEL event may be interpreted as FIDO User Presence.
///
/// This is the mandatory contextual rule from PRD §17: BOOTSEL is *only*
/// User Presence while the execution state is [`ExecutionState::FidoWaitPresence`].
#[must_use]
pub const fn bootsel_allowed_as_presence(state: ExecutionState) -> bool {
    matches!(state, ExecutionState::FidoWaitPresence)
}

/// Whether FIDO operations may be served in `state`.
///
/// Recovery and locked states never serve FIDO (PRD §22).
#[must_use]
pub const fn fido_allowed(state: ExecutionState) -> bool {
    matches!(
        state,
        ExecutionState::Active | ExecutionState::FidoWaitPresence | ExecutionState::FidoOperation
    )
}

#[cfg(test)]
mod tests {
    use super::ExecutionState::*;
    use super::*;

    const ALL: [ExecutionState; 8] = [
        Boot,
        Active,
        FidoWaitPresence,
        FidoOperation,
        Management,
        FirmwareUpdate,
        Recovery,
        Locked,
    ];

    #[test]
    fn self_transition_is_always_allowed() {
        for s in ALL {
            assert!(s.can_transition(s), "{s:?} -> {s:?}");
            assert_eq!(s.transition(s), Ok(s));
        }
    }

    #[test]
    fn known_edges_are_allowed() {
        assert!(Boot.can_transition(Active));
        assert!(Boot.can_transition(Recovery));
        assert!(Active.can_transition(FidoWaitPresence));
        assert!(Active.can_transition(Management));
        assert!(FidoWaitPresence.can_transition(FidoOperation));
        assert!(FidoOperation.can_transition(Active));
        assert!(Management.can_transition(FirmwareUpdate));
        assert!(FirmwareUpdate.can_transition(Recovery));
        assert!(Recovery.can_transition(Active));
        assert!(Locked.can_transition(Recovery));
    }

    #[test]
    fn illegal_edges_are_rejected() {
        assert_eq!(Boot.transition(FidoOperation), Err(CoreError::InvalidState));
        assert_eq!(
            FidoOperation.transition(FidoWaitPresence),
            Err(CoreError::InvalidState)
        );
        assert_eq!(Locked.transition(Active), Err(CoreError::InvalidState));
        assert_eq!(Recovery.transition(Boot), Err(CoreError::InvalidState));
    }

    #[test]
    fn bootsel_only_approved_waiting_for_presence() {
        for s in ALL {
            assert_eq!(
                bootsel_allowed_as_presence(s),
                s == FidoWaitPresence,
                "state {s:?}"
            );
        }
    }

    #[test]
    fn boot_destination_follows_bootsel() {
        assert_eq!(boot_destination(true), Recovery);
        assert_eq!(boot_destination(false), Active);
    }

    #[test]
    fn fido_denied_outside_active_and_fido_states() {
        assert!(fido_allowed(Active));
        assert!(fido_allowed(FidoWaitPresence));
        assert!(fido_allowed(FidoOperation));
        for state in [Boot, Management, FirmwareUpdate, Recovery, Locked] {
            assert!(!fido_allowed(state), "{state:?}");
        }
    }
}
