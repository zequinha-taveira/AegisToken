//! Board hardware profile (PRD §7.1, §8, §26).
//!
//! A [`BoardHardwareProfile`] collects everything that varies from one carrier
//! board to the next — the status LED, the User Presence input and the flash
//! capacity/layout — as declarative data. The firmware core and the protocol
//! layers never see a GPIO number: they ask a [`crate::traits::UserPresence`]
//! or a [`crate::traits::Led`], and this profile decides what that means on the
//! installed board.
//!
//! Keeping the profile here (hardware-free data, const-constructible) makes it
//! host-testable and keeps the concrete HAL in `board-generic-rp2350`.

use crate::configuration::{LedDriver, PresenceSource};

/// Status LED wiring on a board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedProfile {
    /// LED driver, or `None` when the board has no status LED.
    pub driver: Option<LedDriver>,
    /// GPIO driving the LED data / on-off signal.
    pub gpio: Option<u8>,
    /// Whether the LED is active-low.
    pub active_low: bool,
    /// Whether the GPIO may be chosen by configuration.
    pub configurable_gpio: bool,
    /// GPIOs configuration may select for the LED.
    ///
    /// Empty when the LED GPIO is fixed to [`LedProfile::gpio`]. Bits in
    /// [`LedProfile::candidate_mask`] are derived from this list.
    pub candidate_gpios: &'static [u8],
    /// Whether brightness is actually controllable.
    pub brightness: bool,
    /// Brightness used when `brightness` is false.
    pub default_brightness: u8,
}

impl LedProfile {
    /// A board with no status LED.
    pub const NONE: Self = Self {
        driver: None,
        gpio: None,
        active_low: false,
        configurable_gpio: false,
        candidate_gpios: &[],
        brightness: false,
        default_brightness: 255,
    };

    /// A plain digital-GPIO LED on a fixed `gpio`.
    #[must_use]
    pub const fn gpio(gpio: u8, active_low: bool) -> Self {
        Self {
            driver: Some(LedDriver::Gpio),
            gpio: Some(gpio),
            active_low,
            configurable_gpio: false,
            candidate_gpios: &[],
            brightness: false,
            default_brightness: 255,
        }
    }

    /// A plain digital-GPIO LED whose GPIO may be chosen from `candidate_gpios`.
    ///
    /// `gpio` is the initial/default pin and must be one of the candidates; the
    /// board catalog const-asserts this.
    #[must_use]
    pub const fn configurable_gpio(
        gpio: u8,
        active_low: bool,
        candidate_gpios: &'static [u8],
    ) -> Self {
        Self {
            driver: Some(LedDriver::Gpio),
            gpio: Some(gpio),
            active_low,
            configurable_gpio: true,
            candidate_gpios,
            brightness: false,
            default_brightness: 255,
        }
    }

    /// Whether the board declares a usable status LED.
    ///
    /// A driver with no GPIO to drive is not usable, so a profile that declares
    /// a driver but no pin is reported as unavailable.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.driver.is_some() && self.gpio.is_some()
    }

    /// GPIOs configuration may select, as a bitmask (`bit n` = GPIO `n`).
    ///
    /// GPIOs at or above 64 cannot be represented and are ignored; the RP2350
    /// family tops out well below that.
    #[must_use]
    pub const fn candidate_mask(&self) -> u64 {
        let mut mask = 0u64;
        let mut index = 0;
        while index < self.candidate_gpios.len() {
            let gpio = self.candidate_gpios[index];
            if gpio < 64 {
                mask |= 1u64 << gpio;
            }
            index += 1;
        }
        mask
    }
}

/// User Presence input wiring on a board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceProfile {
    /// Input used for User Presence.
    pub source: PresenceSource,
    /// GPIO of the dedicated button, when not BOOTSEL.
    pub gpio: Option<u8>,
    /// Whether the button is active-low.
    pub active_low: bool,
    /// Debounce interval, in milliseconds.
    pub debounce_ms: u16,
    /// Presence timeout, in milliseconds.
    pub timeout_ms: u16,
}

impl PresenceProfile {
    /// Use the BOOTSEL button.
    #[must_use]
    pub const fn bootsel(debounce_ms: u16, timeout_ms: u16) -> Self {
        Self {
            source: PresenceSource::Bootsel,
            gpio: None,
            active_low: true,
            debounce_ms,
            timeout_ms,
        }
    }

    /// Use a dedicated external button on `gpio`.
    #[must_use]
    pub const fn external_button(
        gpio: u8,
        active_low: bool,
        debounce_ms: u16,
        timeout_ms: u16,
    ) -> Self {
        Self {
            source: PresenceSource::ExternalButton,
            gpio: Some(gpio),
            active_low,
            debounce_ms,
            timeout_ms,
        }
    }
}

/// Physical layout of the regions the firmware stores to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashLayout {
    /// Base offset of the two configuration slots.
    pub config_offset: u32,
    /// Size of one storage slot; must match the flash erase granularity.
    pub slot_size: u32,
    /// Base offset of the applet storage region.
    pub applet_offset: u32,
    /// Total size of the applet storage region.
    pub applet_size: u32,
    /// Base offset of the firmware staging region.
    pub staging_offset: u32,
}

impl FlashLayout {
    /// Layout used across the supported boards: config at 1 MiB, applet
    /// storage at 1.0625 MiB, staging at 1.25 MiB, well inside the smallest
    /// supported 2 MiB flash.
    pub const STANDARD: Self = Self {
        config_offset: 0x10_0000,
        slot_size: 4096,
        applet_offset: 0x11_0000,
        applet_size: 0x3_0000,
        staging_offset: 0x14_0000,
    };

    /// Number of two-slot applet stores the region provides.
    ///
    /// Every store owns two [`FlashLayout::slot_size`] slots, matching the
    /// power-fail-safe record format used by the firmware.
    #[must_use]
    pub const fn applet_store_count(&self) -> u32 {
        self.applet_size / (self.slot_size * 2)
    }

    /// Base offset of applet store `index`.
    ///
    /// The caller must keep `index` below [`FlashLayout::applet_store_count`].
    #[must_use]
    pub const fn applet_store_offset(&self, index: u32) -> u32 {
        self.applet_offset + index * self.slot_size * 2
    }
}

/// Flash capacity and layout on a board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashProfile {
    /// Nominal flash capacity in bytes.
    pub size_bytes: u32,
    /// Region layout used by the firmware stores.
    pub layout: FlashLayout,
}

impl FlashProfile {
    /// A flash of `size_bytes` using the standard region layout.
    #[must_use]
    pub const fn new(size_bytes: u32) -> Self {
        Self {
            size_bytes,
            layout: FlashLayout::STANDARD,
        }
    }
}

/// Everything hardware-related that varies per carrier board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoardHardwareProfile {
    /// Status LED wiring.
    pub led: LedProfile,
    /// User Presence input wiring.
    pub presence: PresenceProfile,
    /// Flash capacity and layout.
    pub flash: FlashProfile,
}

impl BoardHardwareProfile {
    /// Build a board hardware profile from its parts.
    #[must_use]
    pub const fn new(led: LedProfile, presence: PresenceProfile, flash: FlashProfile) -> Self {
        Self {
            led,
            presence,
            flash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_led_profile_is_unavailable() {
        assert!(!LedProfile::NONE.available());
        assert_eq!(LedProfile::NONE.driver, None);
    }

    #[test]
    fn gpio_led_profile_is_available_and_active_low_aware() {
        let led = LedProfile::gpio(16, true);
        assert!(led.available());
        assert_eq!(led.driver, Some(LedDriver::Gpio));
        assert_eq!(led.gpio, Some(16));
        assert!(led.active_low);
    }

    #[test]
    fn fixed_gpio_profile_has_no_candidates() {
        let led = LedProfile::gpio(25, false);
        assert!(!led.configurable_gpio);
        assert!(led.available());
        assert!(led.candidate_gpios.is_empty());
        assert_eq!(led.candidate_mask(), 0);
    }

    #[test]
    fn a_driver_without_a_pin_is_not_available() {
        let led = LedProfile {
            driver: Some(LedDriver::Gpio),
            gpio: None,
            ..LedProfile::NONE
        };
        assert!(!led.available());
    }

    #[test]
    fn configurable_gpio_profile_masks_candidates() {
        let led = LedProfile::configurable_gpio(16, false, &[6, 16, 22]);
        assert!(led.configurable_gpio);
        assert_eq!(led.candidate_gpios, &[6, 16, 22]);
        let mask = led.candidate_mask();
        assert_eq!(mask & (1 << 6), 1 << 6);
        assert_eq!(mask & (1 << 16), 1 << 16);
        assert_eq!(mask & (1 << 22), 1 << 22);
        assert_eq!(mask & (1 << 7), 0);
    }

    #[test]
    fn presence_profiles_capture_source_and_polarity() {
        let bootsel = PresenceProfile::bootsel(20, 15_000);
        assert_eq!(bootsel.source, PresenceSource::Bootsel);
        assert_eq!(bootsel.gpio, None);

        let button = PresenceProfile::external_button(6, false, 30, 10_000);
        assert_eq!(button.source, PresenceSource::ExternalButton);
        assert_eq!(button.gpio, Some(6));
        assert!(!button.active_low);
    }

    #[test]
    fn flash_profile_uses_standard_layout() {
        let flash = FlashProfile::new(4 * 1024 * 1024);
        assert_eq!(flash.size_bytes, 4 * 1024 * 1024);
        assert_eq!(flash.layout, FlashLayout::STANDARD);
        // The standard layout must fit the smallest supported flash.
        assert!(flash.layout.staging_offset < 2 * 1024 * 1024);
    }

    #[test]
    fn standard_layout_regions_do_not_overlap() {
        let layout = FlashLayout::STANDARD;
        let config_end = layout.config_offset + layout.slot_size * 2;
        assert!(config_end <= layout.applet_offset);
        assert!(layout.applet_offset + layout.applet_size <= layout.staging_offset);
        // The smallest supported flash must hold every region.
        assert!(layout.applet_offset + layout.applet_size < 2 * 1024 * 1024);
    }

    #[test]
    fn applet_stores_are_two_slots_wide_and_in_range() {
        let layout = FlashLayout::STANDARD;
        assert_eq!(layout.applet_store_count(), 24);
        assert_eq!(layout.applet_store_offset(0), layout.applet_offset);
        assert_eq!(
            layout.applet_store_offset(1),
            layout.applet_offset + layout.slot_size * 2
        );
        let last = layout.applet_store_offset(layout.applet_store_count() - 1);
        assert_eq!(
            last + layout.slot_size * 2,
            layout.applet_offset + layout.applet_size
        );
    }

    #[test]
    fn board_hardware_profile_composes_parts() {
        let profile = BoardHardwareProfile::new(
            LedProfile::gpio(25, false),
            PresenceProfile::bootsel(20, 15_000),
            FlashProfile::new(2 * 1024 * 1024),
        );
        assert!(profile.led.available());
        assert_eq!(profile.presence.source, PresenceSource::Bootsel);
        assert_eq!(profile.flash.size_bytes, 2 * 1024 * 1024);
    }
}
