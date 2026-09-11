//! Device lifecycle state machine (PRD §20).
//!
//! Lifecycle is independent from the execution state. It tracks the
//! provisioning status of the device across factory, commissioning,
//! provisioning, active operation and decommissioning.

use crate::error::CoreError;

/// Provisioning lifecycle of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleState {
    /// Fresh from the factory, no ownership established.
    Factory,
    /// Ownership is being established through Management HID.
    Commissioning,
    /// Ownership established, device not yet provisioned with keys.
    Commissioned,
    /// Cryptographic material is being provisioned.
    Provisioning,
    /// Provisioned and ready to be activated.
    Provisioned,
    /// Normal operating state.
    Active,
    /// Temporarily disabled but not decommissioned.
    Suspended,
    /// Permanently retired; only a factory reset may re-enter Factory.
    Decommissioned,
}

impl LifecycleState {
    /// Whether `next` is a legal successor of `self`.
    ///
    /// A state may always transition to itself.
    #[must_use]
    pub const fn can_transition(self, next: LifecycleState) -> bool {
        if self as u8 == next as u8 {
            return true;
        }
        use LifecycleState::*;
        match self {
            Factory => matches!(next, Commissioning),
            Commissioning => matches!(next, Commissioned | Factory),
            Commissioned => matches!(next, Provisioning),
            Provisioning => matches!(next, Provisioned | Commissioned),
            Provisioned => matches!(next, Active),
            Active => matches!(next, Suspended | Decommissioned),
            Suspended => matches!(next, Active | Decommissioned),
            Decommissioned => matches!(next, Factory),
        }
    }

    /// Apply a transition, rejecting illegal edges.
    pub const fn transition(self, next: LifecycleState) -> Result<LifecycleState, CoreError> {
        if self.can_transition(next) {
            Ok(next)
        } else {
            Err(CoreError::InvalidState)
        }
    }

    /// Whether persistent configuration may be modified in this state.
    ///
    /// Configuration is a commissioning-time concern; operational states
    /// reject changes (PRD §11 lifecycle check).
    #[must_use]
    pub const fn allows_config_change(self) -> bool {
        matches!(
            self,
            LifecycleState::Factory | LifecycleState::Commissioning | LifecycleState::Commissioned
        )
    }

    /// Whether the device is retired.
    #[must_use]
    pub const fn is_decommissioned(self) -> bool {
        matches!(self, LifecycleState::Decommissioned)
    }

    /// Whether the device can serve FIDO operations.
    #[must_use]
    pub const fn is_operational(self) -> bool {
        matches!(self, LifecycleState::Provisioned | LifecycleState::Active)
    }
}

/// Guarded lifecycle orchestration (PRD §20).
///
/// Wraps [`LifecycleState`] with named operations so callers never apply raw
/// transitions. Every operation fails with [`CoreError::InvalidState`] when the
/// current state does not permit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleManager {
    state: LifecycleState,
}

impl LifecycleManager {
    /// Create a manager in `state`.
    #[must_use]
    pub const fn new(state: LifecycleState) -> Self {
        Self { state }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    fn advance(&mut self, next: LifecycleState) -> Result<(), CoreError> {
        self.state = self.state.transition(next)?;
        Ok(())
    }

    /// Begin commissioning. Idempotent while already commissioning.
    pub fn commission(&mut self) -> Result<(), CoreError> {
        match self.state {
            LifecycleState::Factory => self.advance(LifecycleState::Commissioning),
            LifecycleState::Commissioning => Ok(()),
            _ => Err(CoreError::InvalidState),
        }
    }

    /// Complete commissioning.
    pub fn finish_commissioning(&mut self) -> Result<(), CoreError> {
        self.advance(LifecycleState::Commissioned)
    }

    /// Begin provisioning.
    pub fn begin_provisioning(&mut self) -> Result<(), CoreError> {
        self.advance(LifecycleState::Provisioning)
    }

    /// Complete provisioning.
    pub fn finish_provisioning(&mut self) -> Result<(), CoreError> {
        self.advance(LifecycleState::Provisioned)
    }

    /// Activate the device.
    pub fn activate(&mut self) -> Result<(), CoreError> {
        self.advance(LifecycleState::Active)
    }

    /// Suspend the device.
    pub fn suspend(&mut self) -> Result<(), CoreError> {
        self.advance(LifecycleState::Suspended)
    }

    /// Resume a suspended device.
    pub fn resume(&mut self) -> Result<(), CoreError> {
        self.advance(LifecycleState::Active)
    }

    /// Decommission the device.
    pub fn decommission(&mut self) -> Result<(), CoreError> {
        self.advance(LifecycleState::Decommissioned)
    }

    /// Return a decommissioned device to the factory state.
    pub fn factory_reset(&mut self) -> Result<(), CoreError> {
        match self.state {
            LifecycleState::Decommissioned => self.advance(LifecycleState::Factory),
            LifecycleState::Factory => Ok(()),
            _ => Err(CoreError::InvalidState),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LifecycleState::*;
    use super::*;

    const ALL: [LifecycleState; 8] = [
        Factory,
        Commissioning,
        Commissioned,
        Provisioning,
        Provisioned,
        Active,
        Suspended,
        Decommissioned,
    ];

    #[test]
    fn self_transition_is_always_allowed() {
        for s in ALL {
            assert!(s.can_transition(s));
            assert_eq!(s.transition(s), Ok(s));
        }
    }

    #[test]
    fn happy_path() {
        let mut s = Factory;
        for next in [
            Commissioning,
            Commissioned,
            Provisioning,
            Provisioned,
            Active,
        ] {
            s = s.transition(next).unwrap();
        }
        assert_eq!(s, Active);
    }

    #[test]
    fn illegal_edges_are_rejected() {
        assert_eq!(Factory.transition(Active), Err(CoreError::InvalidState));
        assert_eq!(
            Factory.transition(Provisioned),
            Err(CoreError::InvalidState)
        );
        assert_eq!(Active.transition(Factory), Err(CoreError::InvalidState));
        assert_eq!(
            Decommissioned.transition(Active),
            Err(CoreError::InvalidState)
        );
    }

    #[test]
    fn abort_paths() {
        assert_eq!(Commissioning.transition(Factory), Ok(Factory));
        assert_eq!(Provisioning.transition(Commissioned), Ok(Commissioned));
    }

    #[test]
    fn config_change_only_during_commissioning_states() {
        for s in ALL {
            let expected = matches!(s, Factory | Commissioning | Commissioned);
            assert_eq!(s.allows_config_change(), expected, "state {s:?}");
        }
    }

    #[test]
    fn operational_states() {
        assert!(Provisioned.is_operational());
        assert!(Active.is_operational());
        assert!(!Suspended.is_operational());
        assert!(!Decommissioned.is_operational());
        assert!(Decommissioned.is_decommissioned());
    }
}

#[cfg(test)]
mod manager_tests {
    use super::*;

    #[test]
    fn full_lifecycle_flow() {
        let mut manager = LifecycleManager::new(LifecycleState::Factory);
        manager.commission().unwrap();
        manager.finish_commissioning().unwrap();
        manager.begin_provisioning().unwrap();
        manager.finish_provisioning().unwrap();
        manager.activate().unwrap();
        assert_eq!(manager.state(), LifecycleState::Active);

        manager.suspend().unwrap();
        assert_eq!(manager.state(), LifecycleState::Suspended);
        manager.resume().unwrap();
        assert_eq!(manager.state(), LifecycleState::Active);

        manager.decommission().unwrap();
        assert_eq!(manager.state(), LifecycleState::Decommissioned);
        manager.factory_reset().unwrap();
        assert_eq!(manager.state(), LifecycleState::Factory);
    }

    #[test]
    fn out_of_order_operations_are_rejected() {
        let mut manager = LifecycleManager::new(LifecycleState::Factory);
        assert_eq!(manager.activate(), Err(CoreError::InvalidState));
        assert_eq!(manager.decommission(), Err(CoreError::InvalidState));
        assert_eq!(manager.factory_reset(), Ok(()));

        manager.commission().unwrap();
        assert_eq!(manager.finish_provisioning(), Err(CoreError::InvalidState));
    }

    #[test]
    fn re_commissioning_is_idempotent() {
        let mut manager = LifecycleManager::new(LifecycleState::Factory);
        manager.commission().unwrap();
        assert_eq!(manager.commission(), Ok(()));
        assert_eq!(manager.state(), LifecycleState::Commissioning);
    }
}
