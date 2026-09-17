//! Concrete board composition (PRD §28).
//!
//! [`DeviceManager`] builds the board adapters and the USB device from the HAL
//! peripherals and a [`BoardProfile`], and carries the discovered Board and MCU
//! identities. [`Board`] exposes the hardware-agnostic
//! [`Rp2350Hardware`] trait; the USB device is kept separate so its endpoints
//! can be driven by their own tasks.

use aegis_core::capabilities::{DeviceCapabilities, Rp2350Family};
use aegis_core::configuration::PresenceSource;
use aegis_core::hardware_profile::BoardHardwareProfile;
use aegis_core::identity::{BoardIdentity, McuIdentity};
use aegis_core::presence::{PresenceTiming, UserPresence};
use aegis_core::traits::{Led, Rp2350Hardware, Storage};
use core::cell::RefCell;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{AnyPin, Input, Pull};
use embassy_rp::peripherals::FLASH;
use embassy_rp::watchdog::Watchdog;
use embassy_sync::blocking_mutex::CriticalSectionMutex;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::Duration;

use crate::capabilities::{self, BoardProfile};
use crate::flash::FlashStorage;
use crate::led::GpioLed;
use crate::presence::{BootselButton, ButtonPresence, GpioButton, PresenceAdapter};
use crate::rng::HardwareRng;
use crate::usb::Usb;
use crate::watchdog::WatchdogHandle;

/// A fully initialized RP2350 board.
///
/// `FLASH_SIZE` is the flash capacity in bytes known at build time, used to
/// size the `embassy-rp` flash driver and reported as the flash capability.
pub struct Board<const FLASH_SIZE: usize> {
    capabilities: DeviceCapabilities,
    presence: Mutex<CriticalSectionRawMutex, PresenceAdapter>,
    led: Option<GpioLed>,
    storage: CriticalSectionMutex<RefCell<FlashStorage<FLASH_SIZE>>>,
    watchdog: WatchdogHandle,
}

/// Disjoint borrows of a [`Board`]'s resources.
///
/// The firmware runs the User Presence waiter and the housekeeping loop
/// concurrently; splitting the borrows lets each task take only what it owns
/// without contending for the whole board. User Presence is a single physical
/// resource shared by the FIDO and CCID front-ends, so it is handed out behind
/// an async mutex. Flash is likewise one peripheral shared by housekeeping
/// (config, staging) and the CCID task (applet stores); both take the same
/// blocking mutex and touch disjoint regions, locking only around each
/// [`Storage`] call.
pub struct BoardParts<'a, const FLASH_SIZE: usize> {
    /// User Presence source selected by the board hardware profile.
    pub presence: &'a Mutex<CriticalSectionRawMutex, PresenceAdapter>,
    /// Status LED, when the board declares one.
    pub led: Option<&'a mut GpioLed>,
    /// Persistent storage.
    pub storage: &'a CriticalSectionMutex<RefCell<FlashStorage<FLASH_SIZE>>>,
    /// Watchdog handle.
    pub watchdog: &'a mut WatchdogHandle,
}

impl<const FLASH_SIZE: usize> Board<FLASH_SIZE> {
    /// Borrow the board's resources disjointly.
    pub fn split(&mut self) -> BoardParts<'_, FLASH_SIZE> {
        BoardParts {
            presence: &self.presence,
            led: self.led.as_mut(),
            storage: &self.storage,
            watchdog: &mut self.watchdog,
        }
    }

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
        self.presence.get_mut()
    }

    fn led(&mut self) -> Option<&mut dyn Led> {
        self.led.as_mut().map(|led| led as &mut dyn Led)
    }

    fn storage(&mut self) -> &mut dyn Storage {
        self.storage.get_mut().get_mut()
    }
}

/// The composed device: hardware, USB transport and RNG, plus the identities the
/// firmware presents.
///
/// This is the Device Manager of the firmware: it is the single place that
/// answers "which board am I on" ([`BoardIdentity`]), "which chip am I running
/// on" ([`McuIdentity`]) and "how is this board wired"
/// ([`BoardHardwareProfile`]), so the protocol layers never see a GPIO number.
pub struct DeviceManager<const FLASH_SIZE: usize> {
    /// Hardware adapters and discovered capabilities.
    pub board: Board<FLASH_SIZE>,
    /// The USB device exposing FIDO HID, Management HID and CCID.
    pub usb: Usb,
    /// True random number generator for credential key generation.
    ///
    /// Shared between the FIDO and CCID front-ends, so it is serialized behind
    /// an async mutex.
    pub rng: Mutex<CriticalSectionRawMutex, HardwareRng>,
    identity: BoardIdentity,
    mcu: McuIdentity,
    hardware: BoardHardwareProfile,
}

impl<const FLASH_SIZE: usize> DeviceManager<FLASH_SIZE> {
    /// Initialize the board and USB from the HAL peripherals, a board profile
    /// and the build-time MCU family. Capabilities are derived automatically, so
    /// no manual board selection is required.
    pub fn new(p: embassy_rp::Peripherals, profile: &BoardProfile, family: Rp2350Family) -> Self {
        let usb = Usb::new(p.USB, profile);
        let rng = Mutex::new(HardwareRng::new(p.TRNG));

        let flash = Flash::<FLASH, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
        let capabilities = capabilities::discover(profile, family);

        // The LED pin comes from the board profile; when the profile declares
        // the GPIO configurable, the runtime configuration may move it among
        // the profile's candidate pins.
        let led = profile
            .hardware
            .led
            .gpio
            .filter(|_| capabilities.led.available)
            .map(|gpio| {
                GpioLed::new(
                    gpio,
                    profile.hardware.led.active_low,
                    profile.hardware.led.candidate_gpios,
                )
            });

        let presence_profile = profile.hardware.presence;
        let timing = PresenceTiming {
            debounce_ms: presence_profile.debounce_ms,
            timeout_ms: presence_profile.timeout_ms,
        };
        // The presence source comes from the board profile: BOOTSEL or a
        // dedicated external button. The external button is claimed by number
        // because the profile decides at runtime which pad it is; see the
        // safety note on [`GpioLed::build`] for the same reasoning.
        let presence = Mutex::new(match presence_profile.source {
            PresenceSource::Bootsel => {
                PresenceAdapter::Bootsel(ButtonPresence::new(BootselButton::new(p.BOOTSEL), timing))
            }
            PresenceSource::ExternalButton => match presence_profile.gpio {
                Some(gpio) => {
                    let pin = unsafe { AnyPin::steal(gpio) };
                    let pull = if presence_profile.active_low {
                        Pull::Up
                    } else {
                        Pull::Down
                    };
                    let input = Input::new(pin, pull);
                    PresenceAdapter::Gpio(ButtonPresence::new(
                        GpioButton::new(input, presence_profile.active_low),
                        timing,
                    ))
                }
                // A profile that names the external button but declares no pin
                // cannot be honoured; fail safe to BOOTSEL rather than panic at
                // boot. The board catalog const-asserts a pin for its profiles.
                None => PresenceAdapter::Bootsel(ButtonPresence::new(
                    BootselButton::new(p.BOOTSEL),
                    timing,
                )),
            },
        });
        let storage = CriticalSectionMutex::new(RefCell::new(FlashStorage::new(flash)));
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
            identity: profile.identity(),
            mcu: capabilities::discover_mcu_identity(family),
            hardware: profile.hardware(),
        }
    }

    /// Board identity presented by this device.
    #[must_use]
    pub const fn identity(&self) -> BoardIdentity {
        self.identity
    }

    /// MCU identity discovered from the installed chip.
    #[must_use]
    pub const fn mcu_identity(&self) -> McuIdentity {
        self.mcu
    }

    /// Hardware parameters of the installed board.
    #[must_use]
    pub const fn hardware_profile(&self) -> BoardHardwareProfile {
        self.hardware
    }
}
