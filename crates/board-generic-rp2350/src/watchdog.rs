//! Watchdog wrapper (PRD §7.1).
//!
//! Exposes a small, hardware-agnostic surface so the firmware can arm the
//! watchdog and feed it from its main loop without depending on the HAL.

use embassy_rp::watchdog::Watchdog;
use embassy_time::Duration;

/// On-chip watchdog.
pub struct WatchdogHandle {
    inner: Watchdog,
}

impl WatchdogHandle {
    /// Wrap the watchdog peripheral.
    #[must_use]
    pub fn new(inner: Watchdog) -> Self {
        Self { inner }
    }

    /// Arm the watchdog with an initial timeout.
    pub fn start(&mut self, timeout: Duration) {
        self.inner.start(timeout);
    }

    /// Feed the watchdog, extending the deadline.
    pub fn feed(&mut self, timeout: Duration) {
        self.inner.feed(timeout);
    }

    /// Force an immediate reset.
    pub fn trigger_reset(&mut self) {
        self.inner.trigger_reset();
    }
}
