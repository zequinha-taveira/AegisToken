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

/// QSPI chip-select input bit in `SIO` `GPIO_HI_IN` (RP2350 datasheet §12.1.2).
///
/// The RP2350 does not route the QSPI pads to the `IO_QSPI` status register in
/// a way software can observe: `INFROMPAD` stays zero even while the pad is
/// driven high. The pad input is only exposed through the single-cycle IO
/// block's high bank, which observes GPIO32-47, the QSPI pins and the USB pins.
/// Reading `INFROMPAD` made every boot look like a held BOOTSEL.
const QSPI_CSN_BIT: u32 = 1 << 27;

/// Input enable bit in the RP2350 `PADS_QSPI` pad control register.
#[cfg(target_arch = "arm")]
const PAD_IE: u32 = 1 << 6;
/// Pull-up enable bit in the RP2350 `PADS_QSPI` pad control register.
#[cfg(target_arch = "arm")]
const PAD_PUE: u32 = 1 << 3;
/// Pull-down enable bit in the RP2350 `PADS_QSPI` pad control register.
#[cfg(target_arch = "arm")]
const PAD_PDE: u32 = 1 << 2;
/// Pad isolation bit in the RP2350 `PADS_QSPI` pad control register.
#[cfg(target_arch = "arm")]
const PAD_ISO: u32 = 1 << 8;

/// Pad control value that makes the QSPI chip-select pad readable.
///
/// The sampler releases the XIP driver, so the pad floats. Without an input
/// buffer and a pull-up the released pad reads low, which is indistinguishable
/// from a pressed BOOTSEL. The isolation bit gates the input path as well.
#[cfg(target_arch = "arm")]
#[must_use]
pub const fn bootsel_pad_ctrl(original: u32) -> u32 {
    (original | PAD_IE | PAD_PUE) & !(PAD_PDE | PAD_ISO)
}

/// Configure the QSPI chip-select pad for sampling.
///
/// Runs with XIP enabled, before [`read_bootsel_pad`] disables it. The pull-up
/// is left enabled afterwards: it only matters while the XIP driver is
/// released, and a defined level on chip select is preferable to a floating
/// one. BOOTSEL pulls the pad low through a series resistor, so it wins over
/// the internal pull-up when pressed.
#[cfg(target_arch = "arm")]
fn configure_bootsel_pad() {
    let ctrl = bootsel_pad_ctrl(embassy_rp::pac::PADS_QSPI.gpio(1).read().0);
    embassy_rp::pac::PADS_QSPI
        .gpio(1)
        .write_value(embassy_rp::pac::pads::regs::GpioCtrl(ctrl));
}

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
/// The caller must first run [`configure_bootsel_pad`]: a released pad without
/// input enable and pull-up floats low and always reads as pressed.
///
/// Sample the QSPI chip-select pad with the output driver released.
///
/// Returns the `SIO` `GPIO_HI_IN` word in the low half and the `IO_QSPI`
/// status word in the high half, so the diagnostics can compare both paths.
///
/// # Safety
///
/// Must run from RAM (see the link section): flash XIP is disabled for the
/// duration. The caller must not be interrupted while it runs.
#[cfg(target_arch = "arm")]
#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
unsafe fn read_bootsel_pad(ctrl: u32) -> u64 {
    let cs_ptr = embassy_rp::pac::IO_QSPI.gpio(1).as_ptr() as *mut u32;
    let sio_ptr = embassy_rp::pac::SIO.as_ptr() as *mut u32;
    let hi: u32;
    let io: u32;
    // SAFETY: see the function contract; the caller ensures RAM residency and
    // that interrupts are masked.
    unsafe {
        core::arch::asm!(
            ".equiv GPIO_STATUS, 0x0",
            ".equiv GPIO_CTRL,   0x4",
            ".equiv GPIO_HI_IN,  0x8",
            "ldr {orig}, [{cs}, $GPIO_CTRL]",
            // Release the output driver for the duration of the sample; the
            // delay loop lets the pad settle before it is read.
            "str {ctrl}, [{cs}, $GPIO_CTRL]",
            "2:",
            "subs {count}, #8",
            "bne 2b",
            "ldr {hi}, [{sio}, $GPIO_HI_IN]",
            "ldr {io}, [{cs}, $GPIO_STATUS]",
            "str {orig}, [{cs}, $GPIO_CTRL]",
            cs = in(reg) cs_ptr,
            sio = in(reg) sio_ptr,
            ctrl = in(reg) ctrl,
            orig = out(reg) _,
            count = inout(reg) 4096u32 => _,
            hi = out(reg) hi,
            io = out(reg) io,
            options(nostack),
        );
    }
    ((io as u64) << 32) | u64::from(hi)
}

/// `IO_QSPI` control value that releases the chip-select output driver.
#[cfg(target_arch = "arm")]
const OE_RELEASED: u32 = 0b10 << 14;

/// Sample the BOOTSEL button; `true` means pressed.
#[must_use]
pub fn bootsel_pressed() -> bool {
    #[cfg(target_arch = "arm")]
    let sample = critical_section::with(|_| {
        // The pad is configured with XIP still enabled; the sample below runs
        // from RAM with XIP off.
        configure_bootsel_pad();
        // SAFETY: the routine is RAM-resident and interrupts are disabled by
        // the critical section, so no flash fetch occurs while XIP is off.
        unsafe { read_bootsel_pad(OE_RELEASED) }
    });

    #[cfg(not(target_arch = "arm"))]
    let sample = 0u64;

    // BOOTSEL is active low: it pulls the chip select low.
    (sample as u32 & QSPI_CSN_BIT) == 0
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
