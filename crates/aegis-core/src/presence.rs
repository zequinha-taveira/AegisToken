//! Contextual User Presence with replay protection (PRD §16, §18).
//!
//! The controller is a pure state machine driven by sampled button levels and
//! a monotonic millisecond clock, so its behaviour is fully host-testable.
//! Presence is bound to a specific FIDO operation and consumed at most once.

use core::fmt;

use crate::configuration::PresenceConfig;
use crate::error::CoreError;
use crate::state::{ExecutionState, bootsel_allowed_as_presence};

/// Error returned while waiting for or arming presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PresenceError {
    /// No presence was provided before the timeout elapsed.
    Timeout,
    /// The waiting operation was cancelled.
    Cancelled,
    /// Presence was already armed for another operation.
    AlreadyArmed,
    /// Presence was requested without being armed.
    NotArmed,
}

impl fmt::Display for PresenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PresenceError::Timeout => "presence timeout",
            PresenceError::Cancelled => "presence cancelled",
            PresenceError::AlreadyArmed => "presence already armed",
            PresenceError::NotArmed => "presence not armed",
        })
    }
}

impl core::error::Error for PresenceError {}

impl From<PresenceError> for CoreError {
    fn from(value: PresenceError) -> Self {
        match value {
            PresenceError::Cancelled => CoreError::Unauthorized,
            PresenceError::Timeout | PresenceError::AlreadyArmed | PresenceError::NotArmed => {
                CoreError::InvalidState
            }
        }
    }
}

/// Blocking hardware abstraction for a presence source (PRD §16).
pub trait UserPresence {
    /// Block until presence is confirmed for the current operation.
    fn wait_for_presence(&mut self) -> Result<(), PresenceError>;
}

/// Debounce and timeout parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceTiming {
    /// Debounce interval, in milliseconds.
    pub debounce_ms: u16,
    /// Timeout, in milliseconds.
    pub timeout_ms: u16,
}

impl From<&PresenceConfig> for PresenceTiming {
    fn from(config: &PresenceConfig) -> Self {
        Self {
            debounce_ms: config.debounce_ms,
            timeout_ms: config.timeout_ms,
        }
    }
}

/// Result of advancing the presence controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceOutcome {
    /// Presence was confirmed for `operation_id`.
    Confirmed {
        /// The FIDO operation that requested presence.
        operation_id: u32,
    },
    /// The operation timed out without presence.
    Timeout {
        /// The FIDO operation that requested presence.
        operation_id: u32,
    },
}

#[derive(Debug, Clone, Copy)]
struct Armed {
    operation_id: u32,
    deadline_ms: u64,
}

/// Pure presence state machine.
#[derive(Debug, Clone)]
pub struct PresenceController {
    timing: PresenceTiming,
    armed: Option<Armed>,
    raw_pressed: bool,
    debounced_pressed: bool,
    raw_change_ms: u64,
    /// Set when arming while the button is already down. A fresh release is
    /// then required before a press can count, preventing a press captured
    /// before the operation from being replayed into it.
    awaiting_release: bool,
}

impl PresenceController {
    /// Create a controller with the given timing.
    #[must_use]
    pub const fn new(timing: PresenceTiming) -> Self {
        Self {
            timing,
            armed: None,
            raw_pressed: false,
            debounced_pressed: false,
            raw_change_ms: 0,
            awaiting_release: false,
        }
    }

    /// Arm presence for `operation_id`. Fails if already armed.
    pub fn arm(&mut self, operation_id: u32, now_ms: u64) -> Result<(), PresenceError> {
        if self.armed.is_some() {
            return Err(PresenceError::AlreadyArmed);
        }
        self.armed = Some(Armed {
            operation_id,
            deadline_ms: now_ms + u64::from(self.timing.timeout_ms),
        });
        self.awaiting_release = self.raw_pressed || self.debounced_pressed;
        Ok(())
    }

    /// Disarm any pending presence.
    pub fn disarm(&mut self) {
        self.armed = None;
        self.awaiting_release = false;
    }

    /// Whether presence is currently armed.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.armed.is_some()
    }

    /// The operation currently awaiting presence, if any.
    #[must_use]
    pub const fn armed_operation(&self) -> Option<u32> {
        match self.armed {
            Some(armed) => Some(armed.operation_id),
            None => None,
        }
    }

    /// Feed an instantaneous raw button level and advance time.
    pub fn update(&mut self, pressed: bool, now_ms: u64) -> Option<PresenceOutcome> {
        if pressed != self.raw_pressed {
            self.raw_pressed = pressed;
            self.raw_change_ms = now_ms;
        }
        self.settle(now_ms)
    }

    /// Advance time without a new sample (used for debounce settling/timeout).
    pub fn poll(&mut self, now_ms: u64) -> Option<PresenceOutcome> {
        self.settle(now_ms)
    }

    fn settle(&mut self, now_ms: u64) -> Option<PresenceOutcome> {
        // Promote the raw level once it has been stable for the debounce window.
        if self.raw_pressed != self.debounced_pressed
            && now_ms.saturating_sub(self.raw_change_ms) >= u64::from(self.timing.debounce_ms)
        {
            self.debounced_pressed = self.raw_pressed;
            if self.debounced_pressed {
                if self.awaiting_release {
                    // Ignore: the button was already down when we armed.
                } else if let Some(armed) = self.armed.take() {
                    return Some(PresenceOutcome::Confirmed {
                        operation_id: armed.operation_id,
                    });
                }
            } else {
                self.awaiting_release = false;
            }
        }

        if let Some(armed) = self.armed {
            if now_ms >= armed.deadline_ms {
                self.armed = None;
                self.awaiting_release = false;
                return Some(PresenceOutcome::Timeout {
                    operation_id: armed.operation_id,
                });
            }
        }

        None
    }
}

/// Enforces the contextual BOOTSEL rule (PRD §17).
///
/// Presence is only armed and only accepts samples while the execution state is
/// [`ExecutionState::FidoWaitPresence`]. Leaving that state disarms any pending
/// operation, so a press captured elsewhere can never approve a FIDO operation.
pub struct ContextualPresence {
    controller: PresenceController,
}

impl ContextualPresence {
    /// Create a contextual presence gate.
    #[must_use]
    pub const fn new(timing: PresenceTiming) -> Self {
        Self {
            controller: PresenceController::new(timing),
        }
    }

    /// Arm presence for `operation_id`, only if `state` allows it.
    pub fn arm(
        &mut self,
        state: ExecutionState,
        operation_id: u32,
        now_ms: u64,
    ) -> Result<(), PresenceError> {
        if !bootsel_allowed_as_presence(state) {
            return Err(PresenceError::NotArmed);
        }
        self.controller.arm(operation_id, now_ms)
    }

    /// Disarm any pending presence.
    pub fn disarm(&mut self) {
        self.controller.disarm();
    }

    /// Whether presence is armed.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.controller.is_armed()
    }

    /// Feed a raw button level, gated on the execution state.
    pub fn update(
        &mut self,
        state: ExecutionState,
        pressed: bool,
        now_ms: u64,
    ) -> Option<PresenceOutcome> {
        if !bootsel_allowed_as_presence(state) {
            self.controller.disarm();
            return None;
        }
        self.controller.update(pressed, now_ms)
    }

    /// Advance time, gated on the execution state.
    pub fn poll(&mut self, state: ExecutionState, now_ms: u64) -> Option<PresenceOutcome> {
        if !bootsel_allowed_as_presence(state) {
            self.controller.disarm();
            return None;
        }
        self.controller.poll(now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller() -> PresenceController {
        PresenceController::new(PresenceTiming {
            debounce_ms: 20,
            timeout_ms: 1_000,
        })
    }

    #[test]
    fn fresh_press_after_arm_confirms() {
        let mut c = controller();
        c.arm(7, 0).unwrap();
        assert_eq!(c.update(true, 10), None); // contact bounce, not settled
        assert_eq!(
            c.update(true, 30),
            Some(PresenceOutcome::Confirmed { operation_id: 7 })
        );
        assert!(!c.is_armed());
    }

    #[test]
    fn press_before_arm_is_not_replayed() {
        let mut c = controller();
        c.update(true, 0); // user already holding the button
        c.update(true, 30);
        c.arm(1, 40).unwrap();
        // Still held: must not confirm.
        assert_eq!(c.update(true, 80), None);
        // Release must settle past the debounce window...
        assert_eq!(c.update(false, 100), None);
        assert_eq!(c.poll(125), None);
        // ...then a fresh press confirms.
        assert_eq!(c.update(true, 130), None);
        assert_eq!(
            c.poll(155),
            Some(PresenceOutcome::Confirmed { operation_id: 1 })
        );
    }

    #[test]
    fn presence_is_consumed_once() {
        let mut c = controller();
        c.arm(5, 0).unwrap();
        c.update(true, 0);
        assert_eq!(
            c.poll(20),
            Some(PresenceOutcome::Confirmed { operation_id: 5 })
        );
        // Further presses are ignored: not armed any more.
        assert_eq!(c.update(false, 40), None);
        assert_eq!(c.update(true, 60), None);
        assert_eq!(c.poll(80), None);
    }

    #[test]
    fn presence_cannot_cross_operations() {
        let mut c = controller();
        c.arm(1, 0).unwrap();
        c.update(true, 0);
        assert_eq!(
            c.poll(20),
            Some(PresenceOutcome::Confirmed { operation_id: 1 })
        );

        // Arm a second operation while the button is still held: the stale
        // press must not satisfy it.
        c.arm(2, 30).unwrap();
        assert_eq!(c.update(true, 60), None);
        assert_eq!(c.update(false, 80), None);
        assert_eq!(c.poll(105), None);
        assert_eq!(c.update(true, 110), None);
        assert_eq!(
            c.poll(135),
            Some(PresenceOutcome::Confirmed { operation_id: 2 })
        );
    }

    #[test]
    fn short_bounce_does_not_confirm() {
        let mut c = controller();
        c.arm(9, 0).unwrap();
        assert_eq!(c.update(true, 0), None);
        // Released again after 5 ms (< debounce of 20 ms).
        assert_eq!(c.update(false, 5), None);
        // Settle at 30 ms: the raw level has been stable at false for 25 ms.
        assert_eq!(c.poll(30), None);
        assert!(c.is_armed());
    }

    #[test]
    fn timeout_is_reported_and_disarms() {
        let mut c = controller();
        c.arm(3, 0).unwrap();
        assert_eq!(c.poll(999), None);
        assert_eq!(
            c.poll(1_000),
            Some(PresenceOutcome::Timeout { operation_id: 3 })
        );
        assert!(!c.is_armed());
    }

    #[test]
    fn arming_twice_is_rejected() {
        let mut c = controller();
        c.arm(1, 0).unwrap();
        assert_eq!(c.arm(2, 0), Err(PresenceError::AlreadyArmed));
    }

    #[test]
    fn disarm_stops_confirmation() {
        let mut c = controller();
        c.arm(1, 0).unwrap();
        c.disarm();
        assert_eq!(c.update(true, 0), None);
        assert_eq!(c.poll(20), None);
        assert!(!c.is_armed());
    }

    fn gate() -> ContextualPresence {
        ContextualPresence::new(PresenceTiming {
            debounce_ms: 20,
            timeout_ms: 1_000,
        })
    }

    #[test]
    fn arming_outside_wait_presence_is_rejected() {
        use ExecutionState::*;
        let mut g = gate();
        for state in [
            Boot,
            Active,
            FidoOperation,
            Management,
            FirmwareUpdate,
            Recovery,
            Locked,
        ] {
            assert_eq!(
                g.arm(state, 1, 0),
                Err(PresenceError::NotArmed),
                "{state:?}"
            );
        }
    }

    #[test]
    fn presence_confirmed_only_in_wait_presence() {
        let mut g = gate();
        g.arm(ExecutionState::FidoWaitPresence, 7, 0).unwrap();
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, true, 0), None);
        assert_eq!(
            g.update(ExecutionState::FidoWaitPresence, true, 20),
            Some(PresenceOutcome::Confirmed { operation_id: 7 })
        );
    }

    #[test]
    fn bootsel_in_other_states_never_confirms() {
        // A press while in Active is dropped, and must not leak into a later
        // wait-presence operation.
        let mut g = gate();
        assert_eq!(g.update(ExecutionState::Active, true, 0), None);
        assert_eq!(g.update(ExecutionState::Active, true, 20), None);

        g.arm(ExecutionState::FidoWaitPresence, 1, 30).unwrap();
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, false, 80), None);
        assert_eq!(g.poll(ExecutionState::FidoWaitPresence, 105), None);
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, true, 110), None);
        assert_eq!(
            g.poll(ExecutionState::FidoWaitPresence, 135),
            Some(PresenceOutcome::Confirmed { operation_id: 1 })
        );
    }

    #[test]
    fn press_before_arm_in_wait_presence_requires_fresh_edge() {
        let mut g = gate();
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, true, 0), None);
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, true, 30), None);
        g.arm(ExecutionState::FidoWaitPresence, 2, 40).unwrap();
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, true, 80), None);
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, false, 100), None);
        assert_eq!(g.poll(ExecutionState::FidoWaitPresence, 125), None);
        assert_eq!(g.update(ExecutionState::FidoWaitPresence, true, 130), None);
        assert_eq!(
            g.poll(ExecutionState::FidoWaitPresence, 155),
            Some(PresenceOutcome::Confirmed { operation_id: 2 })
        );
    }

    #[test]
    fn leaving_wait_presence_disarms() {
        let mut g = gate();
        g.arm(ExecutionState::FidoWaitPresence, 1, 0).unwrap();
        assert!(g.is_armed());
        assert_eq!(g.update(ExecutionState::FidoOperation, true, 10), None);
        assert!(!g.is_armed());
    }
}
