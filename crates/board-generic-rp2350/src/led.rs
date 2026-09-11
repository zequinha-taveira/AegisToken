//! Status LED driver (PRD §26).
//!
//! The generic board drives a plain digital GPIO. Brightness and behaviour are
//! tracked so the core configuration is honoured even where the hardware cannot
//! dim, and richer drivers (PWM, addressable) can implement the same trait.

use aegis_core::configuration::LedBehavior;
use aegis_core::error::CoreError;
use aegis_core::traits::Led;
use embassy_rp::gpio::Output;

/// A digital-GPIO status LED.
pub struct GpioLed {
    pin: Output<'static>,
    brightness: u8,
    behavior: LedBehavior,
}

impl GpioLed {
    /// Wrap a configured output pin.
    #[must_use]
    pub fn new(pin: Output<'static>) -> Self {
        Self {
            pin,
            brightness: 255,
            behavior: LedBehavior::Off,
        }
    }

    /// Force the LED on or off, bypassing the behaviour policy.
    pub fn set_active(&mut self, active: bool) {
        if active {
            self.pin.set_high();
        } else {
            self.pin.set_low();
        }
    }

    /// Toggle the LED, bypassing the behaviour policy.
    pub fn toggle(&mut self) {
        self.pin.toggle();
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
        Ok(())
    }

    fn set_behavior(&mut self, behavior: LedBehavior) -> Result<(), CoreError> {
        self.behavior = behavior;
        match behavior {
            LedBehavior::Off => self.pin.set_low(),
            LedBehavior::Solid | LedBehavior::Activity | LedBehavior::Blink => self.pin.set_high(),
        }
        Ok(())
    }
}
