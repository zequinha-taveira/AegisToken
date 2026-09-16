//! Capability derivation from the board hardware profile and the discovered MCU
//! variant (PRD §8, §9).
//!
//! The board layer gathers the MCU facts (`family`, `package`, `revision`) and
//! selects a [`BoardHardwareProfile`]. This module turns those into the
//! [`DeviceCapabilities`] the firmware is the authority on. Keeping the
//! derivation here makes it host-testable and free of any hardware dependency.

use crate::capabilities::{
    DeviceCapabilities, FlashCapabilities, LedCapabilities, LedDriverCapabilities,
    PresenceCapabilities, Rp2350Family, Rp2350Package, UsbCapabilities,
};
use crate::configuration::{LedDriver, PresenceSource};
use crate::hardware_profile::BoardHardwareProfile;

/// Default maximum USB product string length.
pub const DEFAULT_PRODUCT_STRING_LEN: u8 = 64;

/// Map an LED driver selection to the capability flags.
#[must_use]
const fn driver_caps(driver: Option<LedDriver>) -> LedDriverCapabilities {
    match driver {
        Some(LedDriver::Gpio) => LedDriverCapabilities {
            gpio: true,
            pwm: false,
            ws2812: false,
        },
        Some(LedDriver::Pwm) => LedDriverCapabilities {
            gpio: false,
            pwm: true,
            ws2812: false,
        },
        Some(LedDriver::Ws2812) => LedDriverCapabilities {
            gpio: false,
            pwm: false,
            ws2812: true,
        },
        None => LedDriverCapabilities {
            gpio: false,
            pwm: false,
            ws2812: false,
        },
    }
}

/// Derive the advertised capability set from a board hardware profile and the
/// discovered MCU variant.
#[must_use]
pub fn derive_capabilities(
    profile: &BoardHardwareProfile,
    family: Rp2350Family,
    package: Rp2350Package,
) -> DeviceCapabilities {
    let internal_flash = matches!(family, Rp2350Family::Rp2354);
    let bootsel = matches!(profile.presence.source, PresenceSource::Bootsel);
    let external_button = matches!(profile.presence.source, PresenceSource::ExternalButton)
        && profile.presence.gpio.is_some();
    DeviceCapabilities {
        family,
        package,
        gpio_count: package.gpio_count(),
        flash: FlashCapabilities {
            external: !internal_flash,
            internal: internal_flash,
            size_bytes: profile.flash.size_bytes,
        },
        usb: UsbCapabilities {
            device: true,
            fido_hid: true,
            management_hid: true,
            max_product_string_len: DEFAULT_PRODUCT_STRING_LEN,
        },
        led: LedCapabilities {
            available: profile.led.available(),
            configurable_gpio: profile.led.configurable_gpio,
            candidate_gpio_mask: profile.led.candidate_mask(),
            brightness: profile.led.brightness,
            drivers: driver_caps(profile.led.driver),
            default_gpio: profile.led.gpio,
            default_brightness: profile.led.default_brightness,
        },
        presence: PresenceCapabilities {
            bootsel,
            external_button,
            external_button_gpio: if external_button {
                profile.presence.gpio
            } else {
                None
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::LedDriver;
    use crate::hardware_profile::{FlashProfile, LedProfile, PresenceProfile};

    fn profile() -> BoardHardwareProfile {
        BoardHardwareProfile::new(
            LedProfile::gpio(25, false),
            PresenceProfile::bootsel(20, 15_000),
            FlashProfile::new(2 * 1024 * 1024),
        )
    }

    #[test]
    fn qfn80_yields_48_gpio() {
        let caps = derive_capabilities(&profile(), Rp2350Family::Rp2350, Rp2350Package::Qfn80);
        assert_eq!(caps.gpio_count, 48);
        assert_eq!(caps.package, Rp2350Package::Qfn80);
    }

    #[test]
    fn rp2354_uses_internal_flash() {
        let caps = derive_capabilities(&profile(), Rp2350Family::Rp2354, Rp2350Package::Qfn60);
        assert!(caps.flash.internal && !caps.flash.external);
    }

    #[test]
    fn flash_size_comes_from_the_profile() {
        let mut profile = profile();
        profile.flash = FlashProfile::new(8 * 1024 * 1024);
        let caps = derive_capabilities(&profile, Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert_eq!(caps.flash.size_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn no_led_profile_means_led_unavailable() {
        let mut profile = profile();
        profile.led = LedProfile::NONE;
        let caps = derive_capabilities(&profile, Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert!(!caps.led.available);
        assert_eq!(caps.led.drivers, LedDriverCapabilities::default());
    }

    #[test]
    fn led_driver_is_reflected_in_capabilities() {
        let mut profile = profile();
        profile.led.driver = Some(LedDriver::Pwm);
        let caps = derive_capabilities(&profile, Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert!(caps.led.available && caps.led.drivers.pwm && !caps.led.drivers.gpio);
    }

    #[test]
    fn configurable_led_gpio_is_reflected_as_a_mask() {
        let mut profile = profile();
        profile.led = LedProfile::configurable_gpio(16, false, &[6, 16, 22]);
        let caps = derive_capabilities(&profile, Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert!(caps.led.configurable_gpio);
        assert_eq!(caps.led.candidate_gpio_mask & (1 << 16), 1 << 16);
        assert_eq!(caps.led.candidate_gpio_mask & (1 << 7), 0);
    }

    #[test]
    fn external_button_is_reflected() {
        let mut profile = profile();
        profile.presence = PresenceProfile::external_button(6, true, 20, 15_000);
        let caps = derive_capabilities(&profile, Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert!(caps.presence.external_button);
        assert_eq!(caps.presence.external_button_gpio, Some(6));
    }

    #[test]
    fn presence_source_is_mutually_exclusive() {
        let mut profile = profile();
        profile.presence = PresenceProfile::bootsel(20, 15_000);
        let caps = derive_capabilities(&profile, Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert!(caps.presence.bootsel);
        assert!(!caps.presence.external_button);

        profile.presence = PresenceProfile::external_button(6, true, 20, 15_000);
        let caps = derive_capabilities(&profile, Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert!(!caps.presence.bootsel);
        assert!(caps.presence.external_button);
        assert_eq!(caps.presence.external_button_gpio, Some(6));
    }

    #[test]
    fn usb_always_declares_both_hid_interfaces() {
        let caps = derive_capabilities(&profile(), Rp2350Family::Rp2350, Rp2350Package::Qfn60);
        assert!(caps.usb.device && caps.usb.fido_hid && caps.usb.management_hid);
    }
}
