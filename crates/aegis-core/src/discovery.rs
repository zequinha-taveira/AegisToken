//! Capability derivation from raw hardware facts (PRD §8, §9).
//!
//! The board layer gathers [`HardwareFacts`] from the chip and board. This
//! module turns those facts into the [`DeviceCapabilities`] the firmware is the
//! authority on. Keeping the derivation here makes it host-testable and free of
//! any hardware dependency.

use crate::capabilities::{
    DeviceCapabilities, FlashCapabilities, LedCapabilities, LedDriverCapabilities,
    PresenceCapabilities, Rp2350Family, Rp2350Package, UsbCapabilities,
};

/// Default flash capacity assumed when no device could be interrogated.
pub const DEFAULT_FLASH_SIZE_BYTES: u32 = 2 * 1024 * 1024;

/// Default maximum USB product string length.
pub const DEFAULT_PRODUCT_STRING_LEN: u8 = 64;

/// Facts discovered about the chip and the board it is mounted on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareFacts {
    /// Die family (RP2350 vs RP2354).
    pub family: Rp2350Family,
    /// Physical package, from `SYSINFO.PACKAGE_SEL`.
    pub package: Rp2350Package,
    /// Chip revision, from `SYSINFO.CHIP_ID.REVISION`.
    pub revision: u8,
    /// Flash capacity read from the device JEDEC id, when available.
    pub flash_size_bytes: Option<u32>,
    /// GPIO driving the status LED, when the board has one.
    pub led_gpio: Option<u8>,
    /// Whether the LED GPIO may be chosen by configuration.
    pub led_configurable_gpio: bool,
    /// Whether brightness is actually controllable.
    pub led_brightness: bool,
    /// Brightness used when `led_brightness` is false.
    pub led_default_brightness: u8,
    /// LED driver technologies present.
    pub led_drivers: LedDriverCapabilities,
    /// GPIO of a dedicated external presence button, when present.
    pub external_button_gpio: Option<u8>,
}

impl HardwareFacts {
    /// Minimal facts for a generic RP2350A board with an LED on GPIO25.
    #[must_use]
    pub const fn generic_rp2350a() -> Self {
        Self {
            family: Rp2350Family::Rp2350,
            package: Rp2350Package::Qfn60,
            revision: 0,
            flash_size_bytes: None,
            led_gpio: Some(25),
            led_configurable_gpio: false,
            led_brightness: false,
            led_default_brightness: 255,
            led_drivers: LedDriverCapabilities {
                gpio: true,
                pwm: false,
                ws2812: false,
            },
            external_button_gpio: None,
        }
    }
}

/// Derive the advertised capability set from discovered facts.
#[must_use]
pub fn derive_capabilities(facts: &HardwareFacts) -> DeviceCapabilities {
    let internal_flash = matches!(facts.family, Rp2350Family::Rp2354);
    DeviceCapabilities {
        family: facts.family,
        package: facts.package,
        gpio_count: facts.package.gpio_count(),
        flash: FlashCapabilities {
            external: !internal_flash,
            internal: internal_flash,
            size_bytes: facts.flash_size_bytes.unwrap_or(DEFAULT_FLASH_SIZE_BYTES),
        },
        usb: UsbCapabilities {
            device: true,
            fido_hid: true,
            management_hid: true,
            max_product_string_len: DEFAULT_PRODUCT_STRING_LEN,
        },
        led: LedCapabilities {
            available: facts.led_gpio.is_some(),
            configurable_gpio: facts.led_configurable_gpio,
            brightness: facts.led_brightness,
            drivers: facts.led_drivers,
            default_gpio: facts.led_gpio,
            default_brightness: facts.led_default_brightness,
        },
        presence: PresenceCapabilities {
            bootsel: true,
            external_button: facts.external_button_gpio.is_some(),
            external_button_gpio: facts.external_button_gpio,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_sel_mapping_is_inverted_as_documented() {
        // PACKAGE_SEL = 1 => QFN60.
        assert_eq!(Rp2350Package::from_package_sel(true), Rp2350Package::Qfn60);
        assert_eq!(Rp2350Package::from_package_sel(false), Rp2350Package::Qfn80);
    }

    #[test]
    fn qfn80_yields_48_gpio() {
        let mut facts = HardwareFacts::generic_rp2350a();
        facts.package = Rp2350Package::Qfn80;
        facts.family = Rp2350Family::Rp2350;
        let caps = derive_capabilities(&facts);
        assert_eq!(caps.gpio_count, 48);
        assert_eq!(caps.package, Rp2350Package::Qfn80);
    }

    #[test]
    fn rp2354_uses_internal_flash() {
        let mut facts = HardwareFacts::generic_rp2350a();
        facts.family = Rp2350Family::Rp2354;
        let caps = derive_capabilities(&facts);
        assert!(caps.flash.internal && !caps.flash.external);
    }

    #[test]
    fn flash_size_falls_back_to_default() {
        let facts = HardwareFacts::generic_rp2350a();
        assert_eq!(
            derive_capabilities(&facts).flash.size_bytes,
            DEFAULT_FLASH_SIZE_BYTES
        );

        let mut facts = facts;
        facts.flash_size_bytes = Some(4 * 1024 * 1024);
        assert_eq!(
            derive_capabilities(&facts).flash.size_bytes,
            4 * 1024 * 1024
        );
    }

    #[test]
    fn no_led_gpio_means_led_unavailable() {
        let mut facts = HardwareFacts::generic_rp2350a();
        facts.led_gpio = None;
        assert!(!derive_capabilities(&facts).led.available);
    }

    #[test]
    fn external_button_is_reflected() {
        let mut facts = HardwareFacts::generic_rp2350a();
        facts.external_button_gpio = Some(6);
        let caps = derive_capabilities(&facts);
        assert!(caps.presence.external_button);
        assert_eq!(caps.presence.external_button_gpio, Some(6));
    }
}
