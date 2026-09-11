//! Concrete board composition (PRD §28).
//!
//! [`Platform`] builds the board adapters and the USB device from the HAL
//! peripherals. [`Board`] exposes the hardware-agnostic [`Rp2350Hardware`]
//! trait; the USB device is kept separate so its endpoints can be driven by
//! their own tasks.

use aegis_core::capabilities::DeviceCapabilities;
use aegis_core::presence::{PresenceTiming, UserPresence};
use aegis_core::traits::{Led, Rp2350Hardware, Storage};
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::FLASH;
use embassy_rp::watchdog::Watchdog;
use embassy_time::Duration;

use crate::capabilities::{self, BoardProfile};
use crate::flash::FlashStorage;
use crate::led::GpioLed;
use crate::presence::{BootselButton, ButtonPresence};
use crate::rng::HardwareRng;
use crate::usb::Usb;
use crate::watchdog::WatchdogHandle;

/// A fully initialized RP2350 board.
///
/// `FLASH_SIZE` is the flash capacity in bytes known at build time, used to
/// size the `embassy-rp` flash driver and reported as the flash capability.
pub struct Board<const FLASH_SIZE: usize> {
    capabilities: DeviceCapabilities,
    presence: ButtonPresence<BootselButton>,
    led: Option<GpioLed>,
    storage: FlashStorage<FLASH_SIZE>,
    watchdog: WatchdogHandle,
}

impl<const FLASH_SIZE: usize> Board<FLASH_SIZE> {
    /// Sample the BOOTSEL button (active low).
    #[must_use]
    pub fn bootsel_pressed(&mut self) -> bool {
        crate::presence::bootsel_pressed()
    }

    /// Arm the watchdog.
    pub fn start_watchdog(&mut self, timeout: Duration) {
        self.watchdog.start(timeout);
    }

    /// Feed the watchdog.
    pub fn feed_watchdog(&mut self, timeout: Duration) {
        self.watchdog.feed(timeout);
    }

    /// Force a reset.
    pub fn trigger_reset(&mut self) {
        self.watchdog.trigger_reset();
    }
}

impl<const FLASH_SIZE: usize> Rp2350Hardware for Board<FLASH_SIZE> {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    fn user_presence(&mut self) -> &mut dyn UserPresence {
        &mut self.presence
    }

    fn led(&mut self) -> Option<&mut dyn Led> {
        self.led.as_mut().map(|led| led as &mut dyn Led)
    }

    fn storage(&mut self) -> &mut dyn Storage {
        &mut self.storage
    }
}

/// Board plus USB device, ready to be driven by the firmware.
pub struct Platform<const FLASH_SIZE: usize> {
    /// Hardware adapters and discovered capabilities.
    pub board: Board<FLASH_SIZE>,
    /// The USB device exposing FIDO HID and Management HID.
    pub usb: Usb,
    /// True random number generator for credential key generation.
    pub rng: HardwareRng,
}

impl<const FLASH_SIZE: usize> Platform<FLASH_SIZE> {
    /// Initialize the board and USB from the HAL peripherals and a board
    /// profile. Capabilities are derived automatically, so no manual board
    /// selection is required.
    pub fn new(p: embassy_rp::Peripherals, profile: &BoardProfile) -> Self {
        let usb = Usb::new(p.USB);
        let rng = HardwareRng::new(p.TRNG);

        let flash = Flash::<FLASH, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
        let capabilities = capabilities::discover(profile, Some(FLASH_SIZE as u32));

        let led = capabilities
            .led
            .available
            .then(|| GpioLed::new(Output::new(p.PIN_25, Level::Low)));

        let timing = PresenceTiming {
            debounce_ms: profile.presence_debounce_ms,
            timeout_ms: profile.presence_timeout_ms,
        };
        let presence = ButtonPresence::new(BootselButton::new(p.BOOTSEL), timing);
        let storage = FlashStorage::new(flash);
        let watchdog = WatchdogHandle::new(Watchdog::new(p.WATCHDOG));

        Self {
            board: Board {
                capabilities,
                presence,
                led,
                storage,
                watchdog,
            },
            usb,
            rng,
        }
    }
}
