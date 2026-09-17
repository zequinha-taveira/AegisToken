//! Status LED driver (PRD §26).
//!
//! The generic board drives a plain digital GPIO. The pin is rebuilt from the
//! runtime configuration, so the Device Manager may move the status LED to
//! another board-declared candidate GPIO without reflashing. Brightness is
//! tracked even where the hardware cannot dim, so the same configuration is
//! honoured by richer drivers (PWM, addressable) that implement the trait.

use aegis_core::configuration::{LedBehavior, LedConfig};
use aegis_core::error::CoreError;
use aegis_core::traits::Led;
use embassy_rp::gpio::{AnyPin, Level, Output};

/// A digital-GPIO status LED.
pub struct GpioLed {
    pin: Output<'static>,
    gpio: u8,
    active_low: bool,
    candidates: &'static [u8],
    brightness: u8,
    behavior: LedBehavior,
}

impl GpioLed {
    /// Create the LED driver on `gpio`.
    ///
    /// `candidates` are the board-declared GPIOs the runtime configuration may
    /// select; an empty list means the pin is fixed.
    #[must_use]
    pub fn new(gpio: u8, active_low: bool, candidates: &'static [u8]) -> Self {
        Self {
            pin: Self::build(gpio, active_low, false),
            gpio,
            active_low,
            candidates,
            brightness: 255,
            behavior: LedBehavior::Off,
        }
    }

    /// Build a type-erased output on `gpio`.
    ///
    /// # Safety
    ///
    /// Claiming a pad solely by number bypasses the peripheral singleton
    /// ownership. The caller passes either the board's fixed LED pin or a pin
    /// declared in [`GpioLed::candidates`]; the board declares no other owner
    /// for those pads (the QSPI flash pins are excluded from every candidate
    /// list) and the firmware holds exactly one LED driver.
    fn build(gpio: u8, active_low: bool, on: bool) -> Output<'static> {
        let pin = unsafe { AnyPin::steal(gpio) };
        Output::new(pin, Self::level(active_low, on))
    }

    /// Output level for the requested on/off state, honouring active-low wiring.
    const fn level(active_low: bool, on: bool) -> Level {
        if on ^ active_low {
            Level::High
        } else {
            Level::Low
        }
    }

    /// Drive the LED on or off, honouring active-low wiring.
    fn set_active(&mut self, active: bool) {
        if Self::level(self.active_low, active) == Level::High {
            self.pin.set_high();
        } else {
            self.pin.set_low();
        }
    }

    /// Whether the configured behaviour requests light, ignoring blink phase.
    const fn wants_light(&self) -> bool {
        !matches!(self.behavior, LedBehavior::Off) && self.brightness > 0
    }

    /// Last configured brightness.
    #[must_use]
    pub const fn brightness(&self) -> u8 {
        self.brightness
    }

    /// Last configured behaviour.
    #[must_use]
    pub const fn behavior(&self) -> LedBehavior {
        self.behavior
    }
}

impl Led for GpioLed {
    fn set_brightness(&mut self, brightness: u8) -> Result<(), CoreError> {
        // A digital GPIO cannot dim; the value is retained so a capable driver
        // (PWM) can apply it. The capability model hides this field when the
        // hardware cannot dim, so this path is only reached when configured.
        self.brightness = brightness;
        let light = self.wants_light();
        self.set_active(light);
        Ok(())
    }

    fn set_behavior(&mut self, behavior: LedBehavior) -> Result<(), CoreError> {
        self.behavior = behavior;
        let light = self.wants_light();
        self.set_active(light);
        Ok(())
    }

    fn configure(&mut self, config: &LedConfig) -> Result<(), CoreError> {
        if config.gpio != self.gpio {
            if !self.candidates.contains(&config.gpio) {
                return Err(CoreError::InvalidCapability);
            }
            // Dropping the old `Output` resets the previous pad; build on the
            // newly selected candidate.
            self.pin = Self::build(config.gpio, self.active_low, false);
            self.gpio = config.gpio;
        }
        self.brightness = config.brightness;
        self.behavior = if config.enabled {
            config.behavior
        } else {
            LedBehavior::Off
        };
        let light = self.wants_light();
        self.set_active(light);
        Ok(())
    }
}
