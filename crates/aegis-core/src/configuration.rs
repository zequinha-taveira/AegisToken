//! Persistent configuration model, validation and atomic record encoding
//! (PRD §10, §11, §24, §27).
//!
//! The firmware is the authority on configuration validity. The Desktop
//! Manager merely proposes; [`DeviceConfig::validate`] decides. Records are
//! self-describing and integrity-protected so a torn write can never yield a
//! silently corrupt configuration.

use crate::PRODUCT_USB_STRING;
use crate::capabilities::{DeviceCapabilities, LedCapabilities, PresenceCapabilities};
use crate::codec;
use crate::error::CoreError;
use crate::lifecycle::LifecycleState;

/// Current configuration schema version.
pub const CONFIG_VERSION: u16 = 1;

/// Magic prefix identifying an AegisToken configuration record.
pub const CONFIG_MAGIC: [u8; 4] = *b"AGSC";

/// Size of the record header: magic (4) + version (2) + CRC-32 (4).
pub const CONFIG_HEADER_LEN: usize = 10;

/// Baseline USB vendor identifier.
pub const DEFAULT_VENDOR_ID: u16 = 0x1209;

/// Baseline USB product identifier.
pub const DEFAULT_PRODUCT_ID: u16 = 0x0001;

/// USB identities the firmware is permitted to present.
pub const ALLOWED_USB_IDS: [(u16, u16); 1] = [(DEFAULT_VENDOR_ID, DEFAULT_PRODUCT_ID)];

/// Minimum accepted presence debounce interval.
pub const MIN_DEBOUNCE_MS: u16 = 5;

/// Maximum accepted presence debounce interval.
pub const MAX_DEBOUNCE_MS: u16 = 1_000;

/// Minimum accepted presence timeout.
pub const MIN_TIMEOUT_MS: u16 = 1_000;

/// Maximum accepted presence timeout.
pub const MAX_TIMEOUT_MS: u16 = 60_000;

/// An owned, bounded UTF-8 string that participates in CBOR encoding.
#[derive(Clone, PartialEq, Eq)]
pub struct FixedString<const N: usize> {
    bytes: heapless::String<N>,
}

impl<const N: usize> FixedString<N> {
    /// Build from a string slice, rejecting values that do not fit.
    pub fn new(value: &str) -> Result<Self, CoreError> {
        let mut bytes = heapless::String::new();
        bytes
            .push_str(value)
            .map_err(|_| CoreError::InvalidConfiguration)?;
        Ok(Self { bytes })
    }

    /// Borrow as `str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.bytes.as_str()
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<const N: usize> core::fmt::Debug for FixedString<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("FixedString").field(&self.as_str()).finish()
    }
}

impl<C, const N: usize> minicbor::Encode<C> for FixedString<N> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.str(self.as_str())?;
        Ok(())
    }
}

impl<'b, C, const N: usize> minicbor::Decode<'b, C> for FixedString<N> {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let value = d.str()?;
        Self::new(value).map_err(|_| minicbor::decode::Error::message("fixed string too long"))
    }
}

macro_rules! cbor_u8_enum {
    ($ty:ty { $($variant:ident => $value:expr),+ $(,)? }) => {
        impl<C> minicbor::Encode<C> for $ty {
            fn encode<W: minicbor::encode::Write>(
                &self,
                e: &mut minicbor::Encoder<W>,
                _ctx: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                let value: u8 = match self { $(<$ty>::$variant => $value),+ };
                e.u8(value)?;
                Ok(())
            }
        }

        impl<'b, C> minicbor::Decode<'b, C> for $ty {
            fn decode(
                d: &mut minicbor::Decoder<'b>,
                _ctx: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                match d.u8()? {
                    $($value => Ok(<$ty>::$variant),)+
                    _ => Err(minicbor::decode::Error::message("invalid enum discriminant")),
                }
            }
        }
    };
}

/// LED driver selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedDriver {
    /// Digital on/off.
    Gpio,
    /// PWM dimming.
    Pwm,
    /// Addressable LED.
    Ws2812,
}

cbor_u8_enum!(LedDriver { Gpio => 0, Pwm => 1, Ws2812 => 2 });

/// LED behaviour policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedBehavior {
    /// Always off.
    Off,
    /// Steady on.
    Solid,
    /// Blink while active.
    Activity,
    /// Blink.
    Blink,
}

cbor_u8_enum!(LedBehavior { Off => 0, Solid => 1, Activity => 2, Blink => 3 });

/// Physical source used for User Presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceSource {
    /// The BOOTSEL button.
    Bootsel,
    /// A dedicated external button.
    ExternalButton,
}

cbor_u8_enum!(PresenceSource { Bootsel => 0, ExternalButton => 1 });

/// USB identity configuration (PRD §27).
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct UsbConfig {
    /// USB product string.
    #[n(0)]
    pub product_string: FixedString<64>,
    /// USB vendor id.
    #[n(1)]
    pub vid: u16,
    /// USB product id.
    #[n(2)]
    pub pid: u16,
}

/// LED configuration (PRD §26).
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct LedConfig {
    /// Whether the LED is managed by the firmware.
    #[n(0)]
    pub enabled: bool,
    /// GPIO driving the LED.
    #[n(1)]
    pub gpio: u8,
    /// Brightness, 0..=255.
    #[n(2)]
    pub brightness: u8,
    /// Driver selection.
    #[n(3)]
    pub driver: LedDriver,
    /// Behaviour policy.
    #[n(4)]
    pub behavior: LedBehavior,
}

impl LedConfig {
    fn validate(&self, caps: LedCapabilities, gpio_count: u8) -> Result<(), CoreError> {
        if !caps.available {
            return if self.enabled {
                Err(CoreError::InvalidCapability)
            } else {
                Ok(())
            };
        }
        if !self.enabled {
            return Ok(());
        }
        if self.gpio >= gpio_count {
            return Err(CoreError::InvalidConfiguration);
        }
        if !caps.configurable_gpio && Some(self.gpio) != caps.default_gpio {
            return Err(CoreError::InvalidCapability);
        }
        if !caps.brightness && self.brightness != caps.default_brightness {
            return Err(CoreError::InvalidCapability);
        }
        let driver_supported = match self.driver {
            LedDriver::Gpio => caps.drivers.gpio,
            LedDriver::Pwm => caps.drivers.pwm,
            LedDriver::Ws2812 => caps.drivers.ws2812,
        };
        if !driver_supported {
            return Err(CoreError::InvalidCapability);
        }
        Ok(())
    }
}

/// User-presence configuration (PRD §16, §18).
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct PresenceConfig {
    /// Presence source.
    #[n(0)]
    pub source: PresenceSource,
    /// Debounce interval in milliseconds.
    #[n(1)]
    pub debounce_ms: u16,
    /// Presence timeout in milliseconds.
    #[n(2)]
    pub timeout_ms: u16,
}

impl PresenceConfig {
    fn validate(&self, caps: PresenceCapabilities, gpio_count: u8) -> Result<(), CoreError> {
        match self.source {
            PresenceSource::Bootsel if !caps.bootsel => return Err(CoreError::InvalidCapability),
            PresenceSource::ExternalButton if !caps.external_button => {
                return Err(CoreError::InvalidCapability);
            }
            _ => {}
        }
        if let (PresenceSource::ExternalButton, Some(gpio)) =
            (self.source, caps.external_button_gpio)
        {
            if gpio >= gpio_count {
                return Err(CoreError::InvalidConfiguration);
            }
        }
        if self.debounce_ms < MIN_DEBOUNCE_MS || self.debounce_ms > MAX_DEBOUNCE_MS {
            return Err(CoreError::InvalidConfiguration);
        }
        if self.timeout_ms < MIN_TIMEOUT_MS || self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(CoreError::InvalidConfiguration);
        }
        if self.timeout_ms <= self.debounce_ms {
            return Err(CoreError::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Complete persistent device configuration.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct DeviceConfig {
    /// Schema version.
    #[n(0)]
    pub version: u16,
    /// USB identity.
    #[n(1)]
    pub usb: UsbConfig,
    /// LED settings.
    #[n(2)]
    pub led: LedConfig,
    /// Presence settings.
    #[n(3)]
    pub presence: PresenceConfig,
}

/// Inputs required to validate a configuration against the device.
#[derive(Debug, Clone, Copy)]
pub struct ValidationContext<'a> {
    /// Capabilities discovered on this device.
    pub capabilities: &'a DeviceCapabilities,
    /// Current lifecycle state.
    pub lifecycle: LifecycleState,
}

impl DeviceConfig {
    /// The factory configuration shipped in the universal image.
    ///
    /// # Panics
    ///
    /// Never panics: the official product string always fits.
    #[must_use]
    pub fn official_defaults() -> Self {
        Self {
            version: CONFIG_VERSION,
            usb: UsbConfig {
                product_string: FixedString::new(PRODUCT_USB_STRING)
                    .expect("official product string fits"),
                vid: DEFAULT_VENDOR_ID,
                pid: DEFAULT_PRODUCT_ID,
            },
            led: LedConfig {
                enabled: true,
                gpio: 25,
                brightness: 255,
                driver: LedDriver::Gpio,
                behavior: LedBehavior::Activity,
            },
            presence: PresenceConfig {
                source: PresenceSource::Bootsel,
                debounce_ms: 20,
                timeout_ms: 15_000,
            },
        }
    }

    /// Validate against capabilities and lifecycle (PRD §11).
    ///
    /// Checks are ordered: identity/security, lifecycle, capability, range and
    /// cross-field consistency.
    pub fn validate(&self, ctx: &ValidationContext<'_>) -> Result<(), CoreError> {
        if self.version != CONFIG_VERSION {
            return Err(CoreError::InvalidConfiguration);
        }

        // USB identity policy: the official product string and an approved
        // VID/PID pair are required; arbitrary identity changes are rejected.
        if self.usb.product_string.as_str() != PRODUCT_USB_STRING {
            return Err(CoreError::Unauthorized);
        }
        if self.usb.product_string.len() > usize::from(ctx.capabilities.usb.max_product_string_len)
        {
            return Err(CoreError::InvalidConfiguration);
        }
        if !ALLOWED_USB_IDS.contains(&(self.usb.vid, self.usb.pid)) {
            return Err(CoreError::Unauthorized);
        }

        // Lifecycle gate.
        if !ctx.lifecycle.allows_config_change() {
            return Err(CoreError::Unauthorized);
        }

        self.led
            .validate(ctx.capabilities.led, ctx.capabilities.gpio_count)?;
        self.presence
            .validate(ctx.capabilities.presence, ctx.capabilities.gpio_count)?;

        // Cross-field consistency: the external button and the LED must not
        // share a pin.
        if let (PresenceSource::ExternalButton, true, Some(button)) = (
            self.presence.source,
            self.led.enabled,
            ctx.capabilities.presence.external_button_gpio,
        ) {
            if self.led.gpio == button {
                return Err(CoreError::InvalidConfiguration);
            }
        }

        Ok(())
    }

    /// Validate and serialize into an integrity-protected record.
    ///
    /// The caller is responsible for writing the returned bytes atomically.
    pub fn prepare_commit(
        &self,
        ctx: &ValidationContext<'_>,
        out: &mut [u8],
    ) -> Result<usize, CoreError> {
        self.validate(ctx)?;
        encode_stored(self, out)
    }

    /// Serialize as bare CBOR (no record header).
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, CoreError> {
        Ok(codec::encode_into(self, out)?)
    }

    /// Deserialize from bare CBOR (no record header).
    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        Ok(codec::decode_from(bytes)?)
    }
}

/// CRC-32 (IEEE 802.3, reflected) over `data`.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Serialize `config` into an integrity-protected record.
///
/// Layout: `magic | version (LE u16) | crc32 (LE u32) | cbor payload`.
pub fn encode_stored(config: &DeviceConfig, out: &mut [u8]) -> Result<usize, CoreError> {
    if out.len() < CONFIG_HEADER_LEN {
        return Err(CoreError::StorageError);
    }
    let mut payload = [0u8; codec::MAX_STORED_CONFIG_LEN - CONFIG_HEADER_LEN];
    let payload_len = codec::encode_into(config, &mut payload)?;
    let total = CONFIG_HEADER_LEN + payload_len;
    if total > out.len() {
        return Err(CoreError::StorageError);
    }
    out[0..4].copy_from_slice(&CONFIG_MAGIC);
    out[4..6].copy_from_slice(&config.version.to_le_bytes());
    out[6..10].copy_from_slice(&crc32(&payload[..payload_len]).to_le_bytes());
    out[CONFIG_HEADER_LEN..total].copy_from_slice(&payload[..payload_len]);
    Ok(total)
}

/// Parse and verify an integrity-protected record.
pub fn decode_stored(bytes: &[u8]) -> Result<DeviceConfig, CoreError> {
    if bytes.len() < CONFIG_HEADER_LEN {
        return Err(CoreError::StorageError);
    }
    if bytes[0..4] != CONFIG_MAGIC {
        return Err(CoreError::StorageError);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != CONFIG_VERSION {
        return Err(CoreError::InvalidConfiguration);
    }
    let expected_crc = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let payload = &bytes[CONFIG_HEADER_LEN..];
    if crc32(payload) != expected_crc {
        return Err(CoreError::StorageError);
    }
    DeviceConfig::decode(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::DeviceCapabilities;

    fn ctx() -> ValidationContext<'static> {
        static CAPS: DeviceCapabilities = DeviceCapabilities::rp2350a();
        ValidationContext {
            capabilities: &CAPS,
            lifecycle: LifecycleState::Commissioning,
        }
    }

    #[test]
    fn defaults_are_valid() {
        assert_eq!(DeviceConfig::official_defaults().validate(&ctx()), Ok(()));
    }

    #[test]
    fn bare_cbor_round_trips() {
        let config = DeviceConfig::official_defaults();
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = config.encode(&mut buf).unwrap();
        assert_eq!(DeviceConfig::decode(&buf[..len]).unwrap(), config);
    }

    #[test]
    fn stored_record_round_trips() {
        let config = DeviceConfig::official_defaults();
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = encode_stored(&config, &mut buf).unwrap();
        assert_eq!(&buf[0..4], &CONFIG_MAGIC);
        assert_eq!(decode_stored(&buf[..len]).unwrap(), config);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let config = DeviceConfig::official_defaults();
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = encode_stored(&config, &mut buf).unwrap();
        let last = len - 1;
        buf[last] ^= 0xFF;
        assert_eq!(decode_stored(&buf[..len]), Err(CoreError::StorageError));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = encode_stored(&DeviceConfig::official_defaults(), &mut buf).unwrap();
        buf[0] = b'X';
        assert_eq!(decode_stored(&buf[..len]), Err(CoreError::StorageError));
    }

    #[test]
    fn wrong_identity_is_unauthorized() {
        let mut config = DeviceConfig::official_defaults();
        config.usb.vid = 0xDEAD;
        assert_eq!(config.validate(&ctx()), Err(CoreError::Unauthorized));

        config.usb.vid = DEFAULT_VENDOR_ID;
        config.usb.product_string = FixedString::new("Evil Key").unwrap();
        assert_eq!(config.validate(&ctx()), Err(CoreError::Unauthorized));
    }

    #[test]
    fn config_change_requires_commissioning_lifecycle() {
        let config = DeviceConfig::official_defaults();
        let c = ctx();
        let mut operational = c;
        operational.lifecycle = LifecycleState::Active;
        assert_eq!(config.validate(&operational), Err(CoreError::Unauthorized));
    }

    #[test]
    fn led_gpio_out_of_range_is_rejected() {
        let mut config = DeviceConfig::official_defaults();
        config.led.gpio = 99;
        assert_eq!(
            config.validate(&ctx()),
            Err(CoreError::InvalidConfiguration)
        );
    }

    #[test]
    fn led_rejected_when_hardware_lacks_it() {
        static CAPS: DeviceCapabilities = {
            let mut c = DeviceCapabilities::rp2350a();
            c.led.available = false;
            c
        };
        let context = ValidationContext {
            capabilities: &CAPS,
            lifecycle: LifecycleState::Commissioning,
        };
        let mut config = DeviceConfig::official_defaults();
        config.led.enabled = true;
        assert_eq!(config.validate(&context), Err(CoreError::InvalidCapability));
        config.led.enabled = false;
        assert_eq!(config.validate(&context), Ok(()));
    }

    #[test]
    fn unsupported_driver_is_rejected() {
        let mut config = DeviceConfig::official_defaults();
        config.led.driver = LedDriver::Ws2812;
        assert_eq!(config.validate(&ctx()), Err(CoreError::InvalidCapability));
    }

    #[test]
    fn presence_source_must_be_supported() {
        let mut config = DeviceConfig::official_defaults();
        config.presence.source = PresenceSource::ExternalButton;
        assert_eq!(config.validate(&ctx()), Err(CoreError::InvalidCapability));
    }

    #[test]
    fn presence_timing_ranges_enforced() {
        let mut config = DeviceConfig::official_defaults();
        config.presence.debounce_ms = 0;
        assert_eq!(
            config.validate(&ctx()),
            Err(CoreError::InvalidConfiguration)
        );

        let mut config = DeviceConfig::official_defaults();
        config.presence.timeout_ms = config.presence.debounce_ms;
        assert_eq!(
            config.validate(&ctx()),
            Err(CoreError::InvalidConfiguration)
        );
    }

    #[test]
    fn led_and_button_pin_conflict_is_rejected() {
        static CAPS: DeviceCapabilities = {
            let mut c = DeviceCapabilities::rp2350a();
            c.presence.external_button = true;
            c.presence.external_button_gpio = Some(25);
            c
        };
        let context = ValidationContext {
            capabilities: &CAPS,
            lifecycle: LifecycleState::Commissioning,
        };
        let mut config = DeviceConfig::official_defaults();
        config.presence.source = PresenceSource::ExternalButton;
        config.led.gpio = 25;
        assert_eq!(
            config.validate(&context),
            Err(CoreError::InvalidConfiguration)
        );
    }

    #[test]
    fn prepare_commit_validates_before_encoding() {
        let mut config = DeviceConfig::official_defaults();
        config.usb.pid = 0xBAD;
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        assert_eq!(
            config.prepare_commit(&ctx(), &mut buf),
            Err(CoreError::Unauthorized)
        );
    }
}
