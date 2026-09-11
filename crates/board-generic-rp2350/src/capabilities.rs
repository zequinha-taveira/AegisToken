//! Automatic hardware discovery (PRD §8).
//!
//! The firmware is the authority on capabilities. This module reads the chip's
//! own identification registers and combines them with a minimal board profile
//! to produce the [`DeviceCapabilities`] advertised over Management HID.

use aegis_core::capabilities::{
    DeviceCapabilities, LedDriverCapabilities, Rp2350Family, Rp2350Package,
};
use aegis_core::discovery::{HardwareFacts, derive_capabilities};
use embassy_rp::pac;

/// Board-specific wiring that the chip itself cannot report.
///
/// The universal firmware adapts to the profile instead of hard-coding a
/// vendor: a future board only needs a new [`BoardProfile`], never a change to
/// the FIDO, lifecycle or management layers.
#[derive(Debug, Clone, Copy)]
pub struct BoardProfile {
    /// Die family (RP2350 or RP2354).
    pub family: Rp2350Family,
    /// GPIO driving the status LED, if any.
    pub led_gpio: Option<u8>,
    /// Whether the LED GPIO may be changed by configuration.
    pub led_configurable_gpio: bool,
    /// Whether brightness is actually controllable.
    pub led_brightness: bool,
    /// Brightness used when `led_brightness` is false.
    pub led_default_brightness: u8,
    /// LED driver technologies present on the board.
    pub led_drivers: LedDriverCapabilities,
    /// GPIO of a dedicated external presence button, if any.
    pub external_button_gpio: Option<u8>,
    /// Presence debounce interval, in milliseconds.
    pub presence_debounce_ms: u16,
    /// Presence timeout, in milliseconds.
    pub presence_timeout_ms: u16,
}

impl BoardProfile {
    /// Build the generic carrier profile for a given die family.
    const fn generic(family: Rp2350Family) -> Self {
        Self {
            family,
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
            presence_debounce_ms: 20,
            presence_timeout_ms: 15_000,
        }
    }

    /// Generic RP2350A carrier: status LED on GPIO25, BOOTSEL as presence.
    pub const GENERIC: Self = Self::generic(Rp2350Family::Rp2350);

    /// Generic RP2354A/B carrier: identical wiring to [`Self::GENERIC`] but with
    /// the 2 MiB in-package flash advertised (`Rp2350Family::Rp2354`).
    pub const GENERIC_RP2354: Self = Self::generic(Rp2350Family::Rp2354);
}

/// Read the JEDEC JEP-106 chip identifier.
#[must_use]
pub fn read_chip_id() -> u32 {
    pac::SYSINFO.chip_id().read().0
}

/// Read the chip revision from `SYSINFO.CHIP_ID`.
#[must_use]
pub fn read_chip_revision() -> u8 {
    pac::SYSINFO.chip_id().read().revision()
}

/// Read the JEDEC part number from `SYSINFO.CHIP_ID`.
#[must_use]
pub fn read_chip_part() -> u16 {
    pac::SYSINFO.chip_id().read().part()
}

/// Read `SYSINFO.PACKAGE_SEL`: `true` means the QFN-60 package.
#[must_use]
pub fn read_package_sel() -> bool {
    pac::SYSINFO.package_sel().read().package_sel()
}

/// Extract the chip revision from a raw chip identifier.
#[must_use]
pub const fn chip_revision(chip_id: u32) -> u8 {
    (chip_id >> 28) as u8
}

/// Extract the JEDEC part number from a raw chip identifier.
#[must_use]
pub const fn chip_part(chip_id: u32) -> u16 {
    ((chip_id >> 12) & 0xFFFF) as u16
}

/// Derive the capability set from the chip and board profile.
#[must_use]
pub fn discover(profile: &BoardProfile, flash_size_bytes: Option<u32>) -> DeviceCapabilities {
    let chip_id = read_chip_id();
    let facts = HardwareFacts {
        family: profile.family,
        package: Rp2350Package::from_package_sel(read_package_sel()),
        revision: chip_revision(chip_id),
        flash_size_bytes,
        led_gpio: profile.led_gpio,
        led_configurable_gpio: profile.led_configurable_gpio,
        led_brightness: profile.led_brightness,
        led_default_brightness: profile.led_default_brightness,
        led_drivers: profile.led_drivers,
        external_button_gpio: profile.external_button_gpio,
    };
    derive_capabilities(&facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chip_id_fields_are_extracted() {
        // REVISION=0x3, PART=0x0004, MANUFACTURER=0x493, STOP=1.
        let chip_id = 0x3_004_927;
        assert_eq!(chip_revision(chip_id), 0x3);
        assert_eq!(chip_part(chip_id), 0x0004);
    }
}
