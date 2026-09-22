//! Device capability model (PRD §9, §26, §28).
//!
//! The firmware is the authority on what the hardware can do. The Desktop
//! Manager adapts its UI to these capabilities and may never request a feature
//! that is not declared here.

/// RP2350 die family. Distinguishes parts with and without in-package flash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rp2350Family {
    /// RP2350 / RP2350A / RP2350B — external QSPI flash.
    Rp2350,
    /// RP2354 / RP2354A / RP2354B — 2 MiB stacked flash.
    Rp2354,
}

/// Physical package / pin count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rp2350Package {
    /// QFN-60, 30 GPIO.
    Qfn60,
    /// QFN-80, 48 GPIO.
    Qfn80,
}

impl Rp2350Package {
    /// Number of user-addressable GPIO pins for this package.
    #[must_use]
    pub const fn gpio_count(self) -> u8 {
        match self {
            Rp2350Package::Qfn60 => 30,
            Rp2350Package::Qfn80 => 48,
        }
    }

    /// Map the RP2350 `SYSINFO.PACKAGE_SEL` bit to a package.
    ///
    /// The hardware encodes `PACKAGE_SEL = 1` for the QFN-60 part.
    #[must_use]
    pub const fn from_package_sel(qfn60: bool) -> Self {
        if qfn60 {
            Rp2350Package::Qfn60
        } else {
            Rp2350Package::Qfn80
        }
    }
}

/// Flash capability description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashCapabilities {
    /// External QSPI flash is present.
    pub external: bool,
    /// In-package (stacked) flash is present.
    pub internal: bool,
    /// Nominal capacity in bytes.
    pub size_bytes: u32,
}

/// USB capability description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbCapabilities {
    /// A USB device controller is present.
    pub device: bool,
    /// The FIDO HID interface can be exposed.
    pub fido_hid: bool,
    /// The Management HID interface can be exposed.
    pub management_hid: bool,
    /// Maximum supported USB product string length, in bytes.
    pub max_product_string_len: u8,
    /// USB identity (VID, PID, product string) may be provisioned post-flash.
    pub configurable_identity: bool,
}

/// LED driver technology supported by the hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedDriverCapabilities {
    /// Plain digital GPIO on/off.
    pub gpio: bool,
    /// PWM dimming.
    pub pwm: bool,
    /// Addressable (e.g. WS2812) LEDs.
    pub ws2812: bool,
}

/// LED capability description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedCapabilities {
    /// Any controllable LED is present.
    pub available: bool,
    /// The LED GPIO may be chosen by configuration.
    pub configurable_gpio: bool,
    /// GPIOs configuration may select, as a bitmask (`bit n` = GPIO `n`).
    ///
    /// Only meaningful when `configurable_gpio` is true.
    pub candidate_gpio_mask: u64,
    /// Brightness may be configured.
    pub brightness: bool,
    /// Supported drivers.
    pub drivers: LedDriverCapabilities,
    /// GPIO used when `configurable_gpio` is false.
    pub default_gpio: Option<u8>,
    /// Brightness used when `brightness` is false.
    pub default_brightness: u8,
}

/// User-presence capability description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceCapabilities {
    /// BOOTSEL may be used as a presence source.
    pub bootsel: bool,
    /// A dedicated external button is present.
    pub external_button: bool,
    /// GPIO of the external button, when present.
    pub external_button_gpio: Option<u8>,
}

/// Complete capability set advertised by the firmware.
///
/// The struct is intentionally extensible (PRD §9): new optional fields may be
/// added without breaking the management protocol, which serializes a versioned
/// view rather than the raw layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceCapabilities {
    /// Die family.
    pub family: Rp2350Family,
    /// Physical package.
    pub package: Rp2350Package,
    /// Number of addressable GPIO pins.
    pub gpio_count: u8,
    /// Flash capabilities.
    pub flash: FlashCapabilities,
    /// USB capabilities.
    pub usb: UsbCapabilities,
    /// LED capabilities.
    pub led: LedCapabilities,
    /// Presence capabilities.
    pub presence: PresenceCapabilities,
}

impl DeviceCapabilities {
    /// Capabilities for an RP2350A (QFN-60, external flash).
    #[must_use]
    pub const fn rp2350a() -> Self {
        Self::for_variant(Rp2350Family::Rp2350, Rp2350Package::Qfn60)
    }

    /// Capabilities for an RP2350B (QFN-80, external flash).
    #[must_use]
    pub const fn rp2350b() -> Self {
        Self::for_variant(Rp2350Family::Rp2350, Rp2350Package::Qfn80)
    }

    /// Capabilities for an RP2354A (QFN-60, stacked flash).
    #[must_use]
    pub const fn rp2354a() -> Self {
        Self::for_variant(Rp2350Family::Rp2354, Rp2350Package::Qfn60)
    }

    /// Capabilities for an RP2354B (QFN-80, stacked flash).
    #[must_use]
    pub const fn rp2354b() -> Self {
        Self::for_variant(Rp2350Family::Rp2354, Rp2350Package::Qfn80)
    }

    /// Synthetic reference capability set for a family/package combination.
    ///
    /// This models a fully-featured development carrier (LED on GPIO 25 with a
    /// candidate mask, dimmable, external button optional). The firmware never
    /// uses it: real devices derive their set with
    /// [`crate::discovery::derive_capabilities`] from the board hardware
    /// profile, which may report fewer features. It remains as a stable fixture
    /// for host tests and simulations.
    #[must_use]
    pub const fn for_variant(family: Rp2350Family, package: Rp2350Package) -> Self {
        let internal_flash = matches!(family, Rp2350Family::Rp2354);
        Self {
            family,
            package,
            gpio_count: package.gpio_count(),
            flash: FlashCapabilities {
                external: !internal_flash,
                internal: internal_flash,
                size_bytes: 2 * 1024 * 1024,
            },
            usb: UsbCapabilities {
                device: true,
                fido_hid: true,
                management_hid: true,
                max_product_string_len: 64,
                configurable_identity: true,
            },
            led: LedCapabilities {
                available: true,
                configurable_gpio: true,
                candidate_gpio_mask: 1 << 25,
                brightness: true,
                drivers: LedDriverCapabilities {
                    gpio: true,
                    pwm: true,
                    ws2812: false,
                },
                default_gpio: Some(25),
                default_brightness: 255,
            },
            presence: PresenceCapabilities {
                bootsel: true,
                external_button: false,
                external_button_gpio: None,
            },
        }
    }
}

/// Alias kept for readability in the constructors above.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpio_counts_match_packages() {
        assert_eq!(Rp2350Package::Qfn60.gpio_count(), 30);
        assert_eq!(Rp2350Package::Qfn80.gpio_count(), 48);
        assert_eq!(DeviceCapabilities::rp2350a().gpio_count, 30);
        assert_eq!(DeviceCapabilities::rp2350b().gpio_count, 48);
    }

    #[test]
    fn flash_kind_tracks_family() {
        let a = DeviceCapabilities::rp2350a();
        assert!(a.flash.external && !a.flash.internal);

        let b = DeviceCapabilities::rp2354b();
        assert!(!b.flash.external && b.flash.internal);
        assert_eq!(b.package, Rp2350Package::Qfn80);
    }

    #[test]
    fn usb_always_declares_both_hid_interfaces() {
        let c = DeviceCapabilities::rp2350a();
        assert!(c.usb.device && c.usb.fido_hid && c.usb.management_hid);
    }
}
