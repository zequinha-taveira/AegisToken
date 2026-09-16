//! Automatic hardware discovery and the board catalog (PRD §8).
//!
//! A [`BoardProfile`] pairs the declarative **Board Identity** (vendor, product,
//! board model, revision and USB IDs) with the **Board Hardware Profile** (LED,
//! presence and flash wiring). The firmware is the authority on capabilities:
//! this module reads the chip's own identification registers and combines them
//! with the hardware profile to produce the [`DeviceCapabilities`] advertised
//! over Management HID.

use aegis_core::PRODUCT_USB_STRING;
use aegis_core::capabilities::{DeviceCapabilities, Rp2350Family, Rp2350Package};
use aegis_core::configuration::{DEFAULT_PRODUCT_ID, DEFAULT_VENDOR_ID, PresenceSource};
use aegis_core::discovery::derive_capabilities;
use aegis_core::hardware_profile::{
    BoardHardwareProfile, FlashProfile, LedProfile, PresenceProfile,
};
use aegis_core::identity::{BoardIdentity, MAX_BOARD_IDENTITY_LEN, McuIdentity};
use embassy_rp::pac;

/// USB vendor identifier under which Raspberry Pi sub-licenses RP2350 product
/// identifiers to board vendors
/// (<https://github.com/raspberrypi/usb-pid>).
pub const RASPBERRY_PI_VENDOR_ID: u16 = 0x2E8A;

/// Conservative flash capacity used when the exact size is not declared.
///
/// The standard storage layout only uses the first ~1.3 MiB, so declaring the
/// smallest supported flash never claims space the board may not have.
pub const CONSERVATIVE_FLASH_BYTES: u32 = 2 * 1024 * 1024;

/// Default User Presence debounce interval, in milliseconds.
pub const DEFAULT_DEBOUNCE_MS: u16 = 20;

/// Default User Presence timeout, in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u16 = 15_000;

/// GPIOs the generic AegisToken carrier may drive as a status LED.
///
/// GPIO 0-5 are reserved for the QSPI flash on every supported carrier, so only
/// 6..=29 (the QFN-60 range) are offered as runtime-selectable LED pins.
pub const GENERIC_LED_CANDIDATES: &[u8] = &[
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
];

/// Board Identity plus its Hardware Profile.
///
/// The universal firmware adapts to the profile instead of hard-coding a
/// vendor: a future board only needs a new [`BoardProfile`], never a change to
/// the FIDO, lifecycle or management layers.
#[derive(Debug, Clone, Copy)]
pub struct BoardProfile {
    /// Who made the board and the product it carries (USB identity).
    pub identity: BoardIdentity,
    /// The LED, presence and flash parameters that vary per board.
    pub hardware: BoardHardwareProfile,
}

impl BoardProfile {
    /// Board identity this profile declares to the host.
    #[must_use]
    pub const fn identity(&self) -> BoardIdentity {
        self.identity
    }

    /// Hardware parameters this profile declares.
    #[must_use]
    pub const fn hardware(&self) -> BoardHardwareProfile {
        self.hardware
    }

    /// Build a third-party carrier profile around the AegisToken product.
    ///
    /// Third-party RP2350 boards draw their USB product identifier from the
    /// sub-license Raspberry Pi grants board vendors under `2E8A`; the product
    /// string stays the AegisToken product built for that carrier, and the
    /// board vendor becomes the manufacturer.
    ///
    /// The LED is left unspecified: these boards typically expose addressable
    /// RGB LEDs the firmware does not drive yet, so no plain-GPIO status LED is
    /// claimed. The flash size is the conservative minimum until the board's
    /// exact capacity is declared.
    const fn third_party(manufacturer: &'static str, board: &'static str, product_id: u16) -> Self {
        Self {
            identity: BoardIdentity::new(
                manufacturer,
                PRODUCT_USB_STRING,
                board,
                0,
                RASPBERRY_PI_VENDOR_ID,
                product_id,
            ),
            hardware: BoardHardwareProfile::new(
                LedProfile::NONE,
                PresenceProfile::bootsel(DEFAULT_DEBOUNCE_MS, DEFAULT_TIMEOUT_MS),
                FlashProfile::new(CONSERVATIVE_FLASH_BYTES),
            ),
        }
    }

    /// Generic AegisToken RP2350 carrier: status LED on GPIO25, BOOTSEL as
    /// presence, conservative 2 MiB flash. The MCU family is selected at build
    /// time, not by the board profile.
    pub const GENERIC: Self = Self {
        identity: BoardIdentity::new(
            "AegisToken",
            PRODUCT_USB_STRING,
            "Generic RP2350",
            0,
            DEFAULT_VENDOR_ID,
            DEFAULT_PRODUCT_ID,
        ),
        hardware: BoardHardwareProfile::new(
            LedProfile::configurable_gpio(25, false, GENERIC_LED_CANDIDATES),
            PresenceProfile::bootsel(DEFAULT_DEBOUNCE_MS, DEFAULT_TIMEOUT_MS),
            FlashProfile::new(CONSERVATIVE_FLASH_BYTES),
        ),
    };

    // Third-party boards. Product IDs are the values Raspberry Pi sub-licenses
    // to each vendor (see `https://github.com/raspberrypi/usb-pid`); the USB
    // vendor ID is always [`RASPBERRY_PI_VENDOR_ID`].

    /// Waveshare RP2350-Zero.
    pub const WAVESHARE_RP2350_ZERO: Self = Self::third_party("Waveshare", "RP2350-Zero", 0x10B0);

    /// Waveshare RP2350-Plus.
    pub const WAVESHARE_RP2350_PLUS: Self = Self::third_party("Waveshare", "RP2350-Plus", 0x10B1);

    /// Waveshare RP2350-Tiny.
    pub const WAVESHARE_RP2350_TINY: Self = Self::third_party("Waveshare", "RP2350-Tiny", 0x10B2);

    /// Waveshare RP2350-LCD-1.28.
    pub const WAVESHARE_RP2350_LCD_1_28: Self =
        Self::third_party("Waveshare", "RP2350-LCD-1.28", 0x10B3);

    /// Waveshare RP2350-Touch-LCD-1.28.
    pub const WAVESHARE_RP2350_TOUCH_LCD_1_28: Self =
        Self::third_party("Waveshare", "RP2350-Touch-LCD-1.28", 0x10B4);

    /// Waveshare RP2350-One.
    pub const WAVESHARE_RP2350_ONE: Self = Self::third_party("Waveshare", "RP2350-One", 0x10B5);

    /// Waveshare RP2350-GEEK.
    pub const WAVESHARE_RP2350_GEEK: Self = Self::third_party("Waveshare", "RP2350-GEEK", 0x10B6);

    /// Waveshare RP2350-LCD-0.96.
    pub const WAVESHARE_RP2350_LCD_096: Self =
        Self::third_party("Waveshare", "RP2350-LCD-0.96", 0x10B7);

    /// Waveshare RP2350-ETH.
    pub const WAVESHARE_RP2350_ETH: Self = Self::third_party("Waveshare", "RP2350-ETH", 0x10C3);

    /// Pimoroni Pico Plus 2.
    pub const PIMORONI_PICO_PLUS_2: Self = Self::third_party("Pimoroni", "Pico Plus 2", 0x10A3);

    /// Pimoroni Tiny 2350.
    pub const PIMORONI_TINY_2350: Self = Self::third_party("Pimoroni", "Tiny 2350", 0x10A4);

    /// Pimoroni Plasma 2350.
    pub const PIMORONI_PLASMA_2350: Self = Self::third_party("Pimoroni", "Plasma 2350", 0x10A5);

    /// Pimoroni PGA2350.
    pub const PIMORONI_PGA2350: Self = Self::third_party("Pimoroni", "PGA2350", 0x10A6);

    /// Datanoise PicoADK v2.
    pub const DATANOISE_PICOADK_V2: Self = Self::third_party("Datanoise", "PicoADK v2", 0x10AE);

    /// Soldered NULA Max RP2350.
    pub const SOLDERED_NULA_MAX: Self = Self::third_party("Soldered", "NULA Max RP2350", 0x10EC);

    /// Invector Labs Challenger+ RP2350 NB-IoT.
    pub const INVECTOR_CHALLENGER_PLUS: Self =
        Self::third_party("Invector Labs", "Challenger+ RP2350 NB-IoT", 0x110D);
}

/// Every third-party carrier profile, used to enforce a unique USB identity at
/// compile time so two boards can never collide on the same VID/PID.
const THIRD_PARTY_PROFILES: [BoardProfile; 16] = [
    BoardProfile::WAVESHARE_RP2350_ZERO,
    BoardProfile::WAVESHARE_RP2350_PLUS,
    BoardProfile::WAVESHARE_RP2350_TINY,
    BoardProfile::WAVESHARE_RP2350_LCD_1_28,
    BoardProfile::WAVESHARE_RP2350_TOUCH_LCD_1_28,
    BoardProfile::WAVESHARE_RP2350_ONE,
    BoardProfile::WAVESHARE_RP2350_GEEK,
    BoardProfile::WAVESHARE_RP2350_LCD_096,
    BoardProfile::WAVESHARE_RP2350_ETH,
    BoardProfile::PIMORONI_PICO_PLUS_2,
    BoardProfile::PIMORONI_TINY_2350,
    BoardProfile::PIMORONI_PLASMA_2350,
    BoardProfile::PIMORONI_PGA2350,
    BoardProfile::DATANOISE_PICOADK_V2,
    BoardProfile::SOLDERED_NULA_MAX,
    BoardProfile::INVECTOR_CHALLENGER_PLUS,
];

/// Compile-time invariants every board profile must satisfy.
///
/// The profile pins are claimed by number (`AnyPin::steal`) at runtime, so the
/// checks that keep them away from the QSPI flash (GPIO 0..=5) and from each
/// other must fail the build, not boot.
const fn assert_profile_invariants(profile: &BoardProfile) {
    let identity = profile.identity;
    // Every identity string is copied into a fixed 64-byte USB string in
    // `DeviceInfo`, which would panic at runtime if it did not fit.
    assert!(identity.manufacturer.len() <= MAX_BOARD_IDENTITY_LEN);
    assert!(identity.product.len() <= MAX_BOARD_IDENTITY_LEN);
    assert!(identity.board.len() <= MAX_BOARD_IDENTITY_LEN);

    let led = profile.hardware.led;
    if led.driver.is_some() {
        let gpio = match led.gpio {
            Some(gpio) => gpio,
            None => panic!("LED profile with a driver must declare a gpio"),
        };
        assert!(gpio >= 6, "LED pin overlaps the QSPI flash pins");
    }
    if led.configurable_gpio {
        let default = match led.gpio {
            Some(gpio) => gpio,
            None => panic!("configurable LED profile must declare a default gpio"),
        };
        let mut found = false;
        let mut index = 0;
        while index < led.candidate_gpios.len() {
            let gpio = led.candidate_gpios[index];
            assert!(gpio >= 6, "LED candidate overlaps the QSPI flash pins");
            if gpio == default {
                found = true;
            }
            index += 1;
        }
        assert!(found, "default LED pin must be a candidate");
    }

    if let PresenceSource::ExternalButton = profile.hardware.presence.source {
        let button = match profile.hardware.presence.gpio {
            Some(gpio) => gpio,
            None => panic!("external button profile must declare a gpio"),
        };
        assert!(button >= 6, "external button overlaps the QSPI flash pins");
        if let Some(led_gpio) = led.gpio {
            assert!(button != led_gpio, "external button shares the LED pin");
        }
        let mut index = 0;
        while index < led.candidate_gpios.len() {
            assert!(
                led.candidate_gpios[index] != button,
                "external button shares an LED candidate pin"
            );
            index += 1;
        }
    }
}

const _: () = {
    assert_profile_invariants(&BoardProfile::GENERIC);

    let mut left = 0;
    while left < THIRD_PARTY_PROFILES.len() {
        let profile = &THIRD_PARTY_PROFILES[left];
        assert!(
            profile.identity.vendor_id == RASPBERRY_PI_VENDOR_ID,
            "third-party boards must use the Raspberry Pi sub-licensed vendor id"
        );
        assert_profile_invariants(profile);
        let identity = profile.identity;
        let mut right = left + 1;
        while right < THIRD_PARTY_PROFILES.len() {
            assert!(
                identity.vendor_id != THIRD_PARTY_PROFILES[right].identity.vendor_id
                    || identity.product_id != THIRD_PARTY_PROFILES[right].identity.product_id,
                "duplicate third-party USB identity"
            );
            right += 1;
        }
        left += 1;
    }

    // The generic carrier must not collide with a sub-licensed third-party id.
    assert!(BoardProfile::GENERIC.identity.vendor_id != RASPBERRY_PI_VENDOR_ID);
};

/// Read the JEDEC JEP-106 chip identifier.
#[must_use]
pub fn read_chip_id() -> u32 {
    pac::SYSINFO.chip_id().read().0
}

/// Read the chip revision from `SYSINFO.CHIP_ID`.
#[must_use]
pub fn read_chip_revision() -> u8 {
    aegis_core::identity::chip_revision(read_chip_id())
}

/// Read the JEDEC part number from `SYSINFO.CHIP_ID`.
#[must_use]
pub fn read_chip_part() -> u16 {
    aegis_core::identity::chip_part(read_chip_id())
}

/// Read `SYSINFO.PACKAGE_SEL`: `true` means the QFN-60 package.
#[must_use]
pub fn read_package_sel() -> bool {
    pac::SYSINFO.package_sel().read().package_sel()
}

/// Derive the capability set from the board hardware profile and the MCU
/// variant selected at build time.
#[must_use]
pub fn discover(profile: &BoardProfile, family: Rp2350Family) -> DeviceCapabilities {
    let package = Rp2350Package::from_package_sel(read_package_sel());
    derive_capabilities(&profile.hardware, family, package)
}

/// Discover the MCU identity from the chip identification registers and OTP.
///
/// `family` is the build-time variant; the package and silicon revision are
/// read from `SYSINFO` and the unique id from OTP (falling back to `0` when OTP
/// is not readable, e.g. locked by the boot process).
#[must_use]
pub fn discover_mcu_identity(family: Rp2350Family) -> McuIdentity {
    let revision = read_chip_revision();
    let package = Rp2350Package::from_package_sel(read_package_sel());
    let unique_id =
        crate::otp::read_unique_id().unwrap_or(aegis_core::identity::FALLBACK_UNIQUE_ID);
    McuIdentity::new(family, package, revision, unique_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_profile_uses_aegistoken_usb_identity() {
        let profile = BoardProfile::GENERIC;
        assert_eq!(profile.identity.manufacturer, "AegisToken");
        assert_eq!(profile.identity.product, PRODUCT_USB_STRING);
        assert_eq!(profile.identity.vendor_id, DEFAULT_VENDOR_ID);
        assert_eq!(profile.identity.product_id, DEFAULT_PRODUCT_ID);
        assert!(profile.hardware.led.available());
    }

    #[test]
    fn generic_profile_offers_runtime_led_pins() {
        let led = BoardProfile::GENERIC.hardware.led;
        assert!(led.configurable_gpio);
        assert!(led.candidate_gpios.contains(&25));
        assert!(!led.candidate_gpios.contains(&5));
    }

    #[test]
    fn third_party_profile_uses_allocated_usb_identity() {
        let profile = BoardProfile::WAVESHARE_RP2350_ZERO;
        assert_eq!(profile.identity.manufacturer, "Waveshare");
        assert_eq!(profile.identity.product, PRODUCT_USB_STRING);
        assert_eq!(profile.identity.board, "RP2350-Zero");
        assert_eq!(profile.identity.vendor_id, RASPBERRY_PI_VENDOR_ID);
        assert_eq!(profile.identity.product_id, 0x10B0);
        assert!(!profile.hardware.led.available());
    }

    #[test]
    fn third_party_product_ids_are_unique() {
        for (index, profile) in THIRD_PARTY_PROFILES.iter().enumerate() {
            assert_eq!(profile.identity.vendor_id, RASPBERRY_PI_VENDOR_ID);
            for other in &THIRD_PARTY_PROFILES[index + 1..] {
                assert_ne!(profile.identity.product_id, other.identity.product_id);
            }
        }
    }
}
