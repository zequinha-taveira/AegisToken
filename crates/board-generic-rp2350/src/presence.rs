//! Presence button abstraction (PRD §16, §18).
//!
//! A [`Button`] produces an instantaneous pressed/released level. A
//! [`ButtonPresence`] wraps one with the core presence state machine to provide
//! debounced, consume-once, operation-bound User Presence.
//!
//! The contextual rule (BOOTSEL only counts while the execution state is
//! `FidoWaitPresence`) is enforced by [`aegis_core::presence::ContextualPresence`]
//! in the firmware state machine.

use aegis_core::presence::{PresenceError, PresenceTiming, PresenceWaiter, UserPresence};
use embassy_rp::Peri;
use embassy_rp::gpio::Input;
use embassy_rp::peripherals::BOOTSEL;
use embassy_time::{Duration, Timer, block_for};

/// Polling period for the button, in milliseconds.
const POLL_MS: u64 = 1;

/// INFROM_PAD bit in `IO_QSPI` `GPIO_STATUS`.
const INFROM_PAD_BIT: u32 = 1 << 17;

/// An instantaneous, active-low presence button.
pub trait Button {
    /// Whether the button is currently pressed.
    fn is_pressed(&mut self) -> bool;
}

/// A plain GPIO button.
pub struct GpioButton {
    pin: Input<'static>,
    active_low: bool,
}

impl GpioButton {
    /// Wrap a configured input pin, honouring the board's button polarity.
    #[must_use]
    pub fn new(pin: Input<'static>, active_low: bool) -> Self {
        Self { pin, active_low }
    }
}

impl Button for GpioButton {
    fn is_pressed(&mut self) -> bool {
        if self.active_low {
            self.pin.is_low()
        } else {
            self.pin.is_high()
        }
    }
}

/// Reads the BOOTSEL pad state from RAM with XIP momentarily disabled.
///
/// BOOTSEL is multiplexed onto the QSPI chip-select pad. To observe it the
/// output driver is temporarily released so the BOOTSEL resistor can pull the
/// pad low, then `INFROM_PAD` is sampled and the control register restored.
///
/// # Safety
///
/// Must run from RAM (see the link section): flash XIP is disabled for the
/// duration. The caller must not be interrupted while it runs.
#[cfg(target_arch = "arm")]
#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
unsafe fn read_bootsel_pad() -> u32 {
    let cs_ptr = embassy_rp::pac::IO_QSPI.gpio(1).as_ptr() as *mut u32;
    let result: u32;
    // SAFETY: see the function contract; the caller ensures RAM residency and
    // that interrupts are masked.
    unsafe {
        core::arch::asm!(
            ".equiv GPIO_STATUS, 0x0",
            ".equiv GPIO_CTRL, 0x4",
            "ldr {orig}, [{cs}, $GPIO_CTRL]",
            // OEOVER = DISABLE (0b10 << 14) releases the chip-select output; the
            // same value doubles as the settle-loop counter.
            "str {magic}, [{cs}, $GPIO_CTRL]",
            "2:",
            "subs {magic}, #8",
            "bne 2b",
            "ldr {magic}, [{cs}, $GPIO_STATUS]",
            "str {orig}, [{cs}, $GPIO_CTRL]",
            cs = in(reg) cs_ptr,
            orig = out(reg) _,
            magic = inout(reg) 0x8000u32 => result,
            options(nostack),
        );
    }
    result
}

/// Sample the BOOTSEL button; `true` means pressed.
#[must_use]
pub fn bootsel_pressed() -> bool {
    #[cfg(target_arch = "arm")]
    let status = critical_section::with(|_| {
        // SAFETY: the routine is RAM-resident and interrupts are disabled by
        // the critical section, so no flash fetch occurs while XIP is off.
        unsafe { read_bootsel_pad() }
    });

    #[cfg(not(target_arch = "arm"))]
    let status = 0u32;

    // BOOTSEL is active low.
    (status & INFROM_PAD_BIT) == 0
}

/// The BOOTSEL button.
pub struct BootselButton {
    bootsel: Peri<'static, BOOTSEL>,
}

impl BootselButton {
    /// Wrap the BOOTSEL peripheral.
    #[must_use]
    pub fn new(bootsel: Peri<'static, BOOTSEL>) -> Self {
        Self { bootsel }
    }
}

impl Button for BootselButton {
    fn is_pressed(&mut self) -> bool {
        // Retain ownership of the BOOTSEL peripheral token.
        let _ = self.bootsel.reborrow();
        bootsel_pressed()
    }
}

/// Maps a [`Button`] onto the core presence state machine.
pub struct ButtonPresence<B: Button> {
    button: B,
    waiter: PresenceWaiter,
}

impl<B: Button> ButtonPresence<B> {
    /// Create a presence source over `button`.
    #[must_use]
    pub fn new(button: B, timing: PresenceTiming) -> Self {
        Self {
            button,
            waiter: PresenceWaiter::new(timing),
        }
    }

    /// Sample the underlying button.
    pub fn is_pressed(&mut self) -> bool {
        self.button.is_pressed()
    }

    /// Advance the presence state machine by one sample.
    ///
    /// Returns `true` once the presence is confirmed. The operation stays armed
    /// between calls, so a caller can interleave other work (sending CTAPHID
    /// keepalive notifications) without restarting the debounce window.
    pub fn poll_presence(&mut self) -> Result<bool, PresenceError> {
        self.waiter.poll(self.button.is_pressed())
    }

    /// Await User Presence, yielding to the executor between samples.
    ///
    /// Unlike the [`UserPresence`] implementation (which busy-waits with
    /// `block_for` and is meant for a dedicated context), this keeps the USB
    /// and Management tasks responsive while the button is being held.
    pub async fn wait(&mut self) -> Result<(), PresenceError> {
        loop {
            if self.poll_presence()? {
                return Ok(());
            }
            Timer::after(Duration::from_millis(POLL_MS)).await;
        }
    }
}

impl<B: Button> UserPresence for ButtonPresence<B> {
    fn wait_for_presence(&mut self) -> Result<(), PresenceError> {
        loop {
            if self.poll_presence()? {
                return Ok(());
            }
            block_for(Duration::from_millis(POLL_MS));
        }
    }
}

/// The User Presence source selected by the board hardware profile.
///
/// Wrapping the two concrete [`ButtonPresence`] instantiations in one enum lets
/// [`crate::hardware::Board`] honour whatever the profile declares without
/// exposing the button type to the firmware.
pub enum PresenceAdapter {
    /// BOOTSEL is the presence source.
    Bootsel(ButtonPresence<BootselButton>),
    /// A dedicated external button is the presence source.
    Gpio(ButtonPresence<GpioButton>),
}

// The synchronous `UserPresence` surface is for callers outside the async
// executor. The firmware awaits [`PresenceAdapter::wait`] instead, since the
// single cooperative executor must keep servicing USB and the watchdog.
impl UserPresence for PresenceAdapter {
    fn wait_for_presence(&mut self) -> Result<(), PresenceError> {
        match self {
            PresenceAdapter::Bootsel(presence) => presence.wait_for_presence(),
            PresenceAdapter::Gpio(presence) => presence.wait_for_presence(),
        }
    }
}

impl PresenceAdapter {
    /// Await User Presence on the profile-selected source, without blocking the
    /// executor between samples.
    pub async fn wait(&mut self) -> Result<(), PresenceError> {
        match self {
            PresenceAdapter::Bootsel(presence) => presence.wait().await,
            PresenceAdapter::Gpio(presence) => presence.wait().await,
        }
    }

    /// Advance the presence state machine by one sample; `true` when confirmed.
    ///
    /// Lets the firmware interleave CTAPHID keepalive notifications while the
    /// user is asked for presence, without restarting the debounce window.
    pub fn poll_presence(&mut self) -> Result<bool, PresenceError> {
        match self {
            PresenceAdapter::Bootsel(presence) => presence.poll_presence(),
            PresenceAdapter::Gpio(presence) => presence.poll_presence(),
        }
    }
}
