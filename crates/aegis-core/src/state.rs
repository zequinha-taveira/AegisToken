//! Execution state machine (PRD §19).
//!
//! The execution state is deliberately independent from the lifecycle state
//! (PRD §20). It describes *what the firmware is doing right now*, not the
//! provisioning status of the device.
//!
//! The boot destination ([`boot_destination`]) leads to the boot plan
//! ([`BootPlan`]), which states per path what the firmware may serve and
//! which sealed stores it may open.

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

/// Whether `state` is a destination a boot can land on.
#[must_use]
pub const fn is_boot_destination(state: ExecutionState) -> bool {
    matches!(
        state,
        ExecutionState::Active | ExecutionState::Recovery | ExecutionState::Locked
    )
}

/// Boot plan: the transport paths the firmware may serve after a boot.
///
/// The plan is the single policy decision for the boot. It is derived from
/// the boot destination and states, per path, what may be served and which
/// sealed stores may be opened. The firmware reads the plan and obeys it; it
/// never decides on its own which paths to open.
///
/// The plan is fail-closed: only [`ExecutionState::Active`] enables the FIDO
/// and CCID paths, and the sealed stores follow their path. Management
/// (diagnostics and firmware update) stays enabled in every destination, and
/// so does the read-only laboratory OTP HID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootPlan {
    destination: ExecutionState,
    fido: bool,
    ccid: bool,
    management: bool,
    otp_lab: bool,
    sealed_credential_store: bool,
    sealed_applet_stores: bool,
}

impl BootPlan {
    /// Derive the plan for a boot destination.
    ///
    /// Any state that is not a boot destination yields the same fail-closed
    /// plan as the denied destinations: no FIDO, no CCID, no sealed store.
    #[must_use]
    pub const fn for_destination(destination: ExecutionState) -> Self {
        let fido =
            is_boot_destination(destination) && matches!(destination, ExecutionState::Active);
        Self {
            destination,
            fido,
            ccid: fido,
            management: true,
            otp_lab: true,
            sealed_credential_store: fido,
            sealed_applet_stores: fido,
        }
    }

    /// The destination the plan was derived from.
    #[must_use]
    pub const fn destination(&self) -> ExecutionState {
        self.destination
    }

    /// Whether the FIDO path may be served.
    #[must_use]
    pub const fn fido(&self) -> bool {
        self.fido
    }

    /// Whether the CCID path may be served.
    #[must_use]
    pub const fn ccid(&self) -> bool {
        self.ccid
    }

    /// Whether the Management HID path may be served.
    #[must_use]
    pub const fn management(&self) -> bool {
        self.management
    }

    /// Whether the laboratory OTP HID path may be served.
    #[must_use]
    pub const fn otp_lab(&self) -> bool {
        self.otp_lab
    }

    /// Whether the sealed FIDO credential store may be opened.
    #[must_use]
    pub const fn sealed_credential_store(&self) -> bool {
        self.sealed_credential_store
    }

    /// Whether the sealed applet stores may be opened.
    #[must_use]
    pub const fn sealed_applet_stores(&self) -> bool {
        self.sealed_applet_stores
    }
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

    #[test]
    fn boot_plan_active_enables_fido_ccid_management() {
        let plan = BootPlan::for_destination(Active);
        assert_eq!(plan.destination(), Active);
        assert!(plan.fido());
        assert!(plan.ccid());
        assert!(plan.management());
        assert!(plan.otp_lab());
        assert!(plan.sealed_credential_store());
        assert!(plan.sealed_applet_stores());
    }

    #[test]
    fn boot_plan_recovery_denies_fido_ccid_keeps_management() {
        let plan = BootPlan::for_destination(Recovery);
        assert_eq!(plan.destination(), Recovery);
        assert!(!plan.fido());
        assert!(!plan.ccid());
        assert!(plan.management());
        assert!(plan.otp_lab());
        assert!(!plan.sealed_credential_store());
        assert!(!plan.sealed_applet_stores());
    }

    #[test]
    fn boot_plan_locked_denies_fido_ccid_keeps_management() {
        let plan = BootPlan::for_destination(Locked);
        assert_eq!(plan.destination(), Locked);
        assert!(!plan.fido());
        assert!(!plan.ccid());
        assert!(plan.management());
        assert!(plan.otp_lab());
        assert!(!plan.sealed_credential_store());
        assert!(!plan.sealed_applet_stores());
    }

    #[test]
    fn boot_plan_fido_and_ccid_never_diverge() {
        for state in ALL {
            let plan = BootPlan::for_destination(state);
            assert_eq!(plan.fido(), plan.ccid(), "{state:?}");
        }
    }

    #[test]
    fn boot_plan_never_enables_fido_where_fido_allowed_denies() {
        for state in ALL {
            let plan = BootPlan::for_destination(state);
            if !fido_allowed(state) {
                assert!(!plan.fido(), "{state:?}");
            }
        }
    }

    #[test]
    fn boot_plan_is_fail_closed_for_non_destination_states() {
        for state in ALL {
            if is_boot_destination(state) {
                continue;
            }
            let plan = BootPlan::for_destination(state);
            assert!(!plan.fido(), "{state:?}");
            assert!(!plan.ccid(), "{state:?}");
            assert!(plan.management(), "{state:?}");
        }
    }

    #[test]
    fn boot_destination_is_always_a_legal_successor_of_boot() {
        for held in [true, false] {
            let destination = boot_destination(held);
            assert!(Boot.can_transition(destination), "{held}");
            assert_eq!(Boot.transition(destination), Ok(destination), "{held}");
        }
    }

    #[test]
    fn boot_plan_denies_sealed_stores_outside_active() {
        for state in ALL {
            let plan = BootPlan::for_destination(state);
            assert_eq!(plan.sealed_credential_store(), plan.fido(), "{state:?}");
            assert_eq!(plan.sealed_applet_stores(), plan.ccid(), "{state:?}");
        }
    }
}
