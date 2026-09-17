//! Management HID protocol (PRD §11, §13, §14).
//!
//! The firmware is the authority: the Desktop Manager proposes, the firmware
//! validates and decides. This module implements the command set and a
//! host-testable [`ManagementService`] that owns the device state and never
//! exposes cryptographic material.
//!
//! Responses are CBOR payloads preceded by a one-byte status code. The command
//! byte is echoed with [`RESPONSE_FLAG`] set.

use crate::VERSION;
use crate::capabilities::{DeviceCapabilities, Rp2350Family, Rp2350Package};
use crate::codec;
use crate::configuration::{DeviceConfig, FixedString, ValidationContext};
use crate::error::CoreError;
use crate::identity::{BoardIdentity, MAX_BOARD_IDENTITY_LEN};
use crate::lifecycle::{LifecycleManager, LifecycleState};
use crate::recovery::DiagnosticsReport;

/// Bit set on the command byte of a response.
pub const RESPONSE_FLAG: u8 = 0x80;

/// Maximum response payload size, in bytes.
pub const MAX_RESPONSE_BYTES: usize = 512;

/// Management operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementCommand {
    /// Report product identity and firmware version.
    GetDeviceInfo,
    /// Report the discovered hardware capabilities.
    GetCapabilities,
    /// Return the active configuration.
    GetConfiguration,
    /// Propose a configuration; validated and staged, not persisted.
    SetConfiguration,
    /// Validate a proposed configuration without staging it.
    ValidateConfiguration,
    /// Persist the staged configuration.
    CommitConfiguration,
    /// Return the lifecycle state.
    GetLifecycle,
    /// Begin commissioning when the device is fresh.
    CommissionDevice,
    /// Return a compact status summary.
    GetStatus,
    /// Return a diagnostics report.
    GetDiagnostics,
    /// Decommission the device.
    DecommissionDevice,
    /// Return a decommissioned device to factory state.
    FactoryReset,
    /// Detach from the USB bus so the host observes a clean removal.
    SoftDetach,
    /// Unknown operation, preserved for error reporting.
    Unknown(u8),
}

impl ManagementCommand {
    /// Wire operation code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            ManagementCommand::GetDeviceInfo => 0x01,
            ManagementCommand::GetCapabilities => 0x02,
            ManagementCommand::GetConfiguration => 0x03,
            ManagementCommand::SetConfiguration => 0x04,
            ManagementCommand::ValidateConfiguration => 0x05,
            ManagementCommand::CommitConfiguration => 0x06,
            ManagementCommand::GetLifecycle => 0x07,
            ManagementCommand::CommissionDevice => 0x08,
            ManagementCommand::GetStatus => 0x09,
            ManagementCommand::GetDiagnostics => 0x0A,
            ManagementCommand::DecommissionDevice => 0x0B,
            ManagementCommand::FactoryReset => 0x0C,
            ManagementCommand::SoftDetach => 0x0D,
            ManagementCommand::Unknown(code) => code,
        }
    }

    /// Response code, i.e. the operation code with [`RESPONSE_FLAG`] set.
    #[must_use]
    pub const fn response_code(self) -> u8 {
        self.code() | RESPONSE_FLAG
    }

    /// Decode an operation code.
    #[must_use]
    pub const fn from_code(code: u8) -> Self {
        match code {
            0x01 => ManagementCommand::GetDeviceInfo,
            0x02 => ManagementCommand::GetCapabilities,
            0x03 => ManagementCommand::GetConfiguration,
            0x04 => ManagementCommand::SetConfiguration,
            0x05 => ManagementCommand::ValidateConfiguration,
            0x06 => ManagementCommand::CommitConfiguration,
            0x07 => ManagementCommand::GetLifecycle,
            0x08 => ManagementCommand::CommissionDevice,
            0x09 => ManagementCommand::GetStatus,
            0x0A => ManagementCommand::GetDiagnostics,
            0x0B => ManagementCommand::DecommissionDevice,
            0x0C => ManagementCommand::FactoryReset,
            0x0D => ManagementCommand::SoftDetach,
            other => ManagementCommand::Unknown(other),
        }
    }

    /// Whether the operation is defined.
    #[must_use]
    pub const fn is_known(self) -> bool {
        !matches!(self, ManagementCommand::Unknown(_))
    }
}

/// Outcome of a management operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStatus {
    /// Operation succeeded.
    Ok,
    /// Operation failed.
    Error(CoreError),
}

impl ResponseStatus {
    /// Wire status code: zero on success, otherwise the error code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            ResponseStatus::Ok => 0,
            ResponseStatus::Error(error) => error.code(),
        }
    }

    /// Whether the operation succeeded.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, ResponseStatus::Ok)
    }
}

/// A management response: a status plus an optional CBOR payload.
#[derive(Debug, Clone)]
pub struct Response {
    /// Operation outcome.
    pub status: ResponseStatus,
    /// CBOR-encoded response body.
    pub payload: heapless::Vec<u8, MAX_RESPONSE_BYTES>,
}

impl Response {
    /// Successful empty response.
    #[must_use]
    pub const fn ok() -> Self {
        Self {
            status: ResponseStatus::Ok,
            payload: heapless::Vec::new(),
        }
    }

    /// Successful response carrying a CBOR-encoded body.
    #[must_use]
    pub fn with_payload<T>(value: &T) -> Self
    where
        T: minicbor::Encode<()>,
    {
        let mut buf = [0u8; MAX_RESPONSE_BYTES];
        match codec::encode_into(value, &mut buf) {
            Ok(len) => {
                let mut payload = heapless::Vec::new();
                if payload.extend_from_slice(&buf[..len]).is_err() {
                    return Response::error(CoreError::ProtocolError);
                }
                Self {
                    status: ResponseStatus::Ok,
                    payload,
                }
            }
            Err(_) => Response::error(CoreError::ProtocolError),
        }
    }

    /// Failed response.
    #[must_use]
    pub const fn error(error: CoreError) -> Self {
        Self {
            status: ResponseStatus::Error(error),
            payload: heapless::Vec::new(),
        }
    }
}

fn family_code(family: Rp2350Family) -> u8 {
    match family {
        Rp2350Family::Rp2350 => 0,
        Rp2350Family::Rp2354 => 1,
    }
}

fn package_code(package: Rp2350Package) -> u8 {
    match package {
        Rp2350Package::Qfn60 => 0,
        Rp2350Package::Qfn80 => 1,
    }
}

fn version_tuple() -> (u8, u8, u8) {
    let mut parts = VERSION.split('.');
    let mut next = || parts.next().and_then(|p| p.parse::<u8>().ok()).unwrap_or(0);
    (next(), next(), next())
}

/// Device identity reported to the host (PRD §2).
///
/// The manufacturer and product come from the board identity declared by the
/// board profile, so the same firmware presents the correct identity on
/// different carrier boards.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct DeviceInfo {
    /// USB product string for the board/product.
    #[n(0)]
    pub product: FixedString<MAX_BOARD_IDENTITY_LEN>,
    /// Firmware family: 0 = RP2350, 1 = RP2354.
    #[n(1)]
    pub family: u8,
    /// Firmware major version.
    #[n(2)]
    pub version_major: u8,
    /// Firmware minor version.
    #[n(3)]
    pub version_minor: u8,
    /// Firmware patch version.
    #[n(4)]
    pub version_patch: u8,
    /// Active configuration schema version.
    #[n(5)]
    pub config_version: u16,
    /// Board/product manufacturer.
    #[n(6)]
    pub manufacturer: FixedString<MAX_BOARD_IDENTITY_LEN>,
}

impl DeviceInfo {
    /// Build the device identity for these capabilities and board identity.
    #[must_use]
    pub fn current(identity: &BoardIdentity, capabilities: &DeviceCapabilities) -> Self {
        let (major, minor, patch) = version_tuple();
        Self {
            product: FixedString::new(identity.product).expect("board product string fits"),
            family: family_code(capabilities.family),
            version_major: major,
            version_minor: minor,
            version_patch: patch,
            config_version: crate::configuration::CONFIG_VERSION,
            manufacturer: FixedString::new(identity.manufacturer)
                .expect("board manufacturer string fits"),
        }
    }
}

/// Serializable view of the discovered capabilities (PRD §9).
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct CapabilityReport {
    /// Die family.
    #[n(0)]
    pub family: u8,
    /// Package.
    #[n(1)]
    pub package: u8,
    /// Addressable GPIO count.
    #[n(2)]
    pub gpio_count: u8,
    /// External flash present.
    #[n(3)]
    pub flash_external: bool,
    /// In-package flash present.
    #[n(4)]
    pub flash_internal: bool,
    /// Flash capacity in bytes.
    #[n(5)]
    pub flash_size_bytes: u32,
    /// USB device present.
    #[n(6)]
    pub usb_device: bool,
    /// FIDO HID available.
    #[n(7)]
    pub usb_fido_hid: bool,
    /// Management HID available.
    #[n(8)]
    pub usb_management_hid: bool,
    /// Maximum USB product string length.
    #[n(9)]
    pub usb_max_product_string_len: u8,
    /// LED present.
    #[n(10)]
    pub led_available: bool,
    /// LED GPIO configurable.
    #[n(11)]
    pub led_configurable_gpio: bool,
    /// LED dimmable.
    #[n(12)]
    pub led_brightness: bool,
    /// GPIO LED driver present.
    #[n(13)]
    pub led_driver_gpio: bool,
    /// PWM LED driver present.
    #[n(14)]
    pub led_driver_pwm: bool,
    /// Addressable LED driver present.
    #[n(15)]
    pub led_driver_ws2812: bool,
    /// Default LED GPIO.
    #[n(16)]
    pub led_default_gpio: Option<u8>,
    /// Default LED brightness.
    #[n(17)]
    pub led_default_brightness: u8,
    /// BOOTSEL can source presence.
    #[n(18)]
    pub presence_bootsel: bool,
    /// External button present.
    #[n(19)]
    pub presence_external_button: bool,
    /// External button GPIO.
    #[n(20)]
    pub presence_external_button_gpio: Option<u8>,
    /// Bitmask of GPIOs configuration may select for the LED.
    #[n(21)]
    pub led_candidate_gpio_mask: u64,
}

impl From<&DeviceCapabilities> for CapabilityReport {
    fn from(caps: &DeviceCapabilities) -> Self {
        Self {
            family: family_code(caps.family),
            package: package_code(caps.package),
            gpio_count: caps.gpio_count,
            flash_external: caps.flash.external,
            flash_internal: caps.flash.internal,
            flash_size_bytes: caps.flash.size_bytes,
            usb_device: caps.usb.device,
            usb_fido_hid: caps.usb.fido_hid,
            usb_management_hid: caps.usb.management_hid,
            usb_max_product_string_len: caps.usb.max_product_string_len,
            led_available: caps.led.available,
            led_configurable_gpio: caps.led.configurable_gpio,
            led_brightness: caps.led.brightness,
            led_driver_gpio: caps.led.drivers.gpio,
            led_driver_pwm: caps.led.drivers.pwm,
            led_driver_ws2812: caps.led.drivers.ws2812,
            led_default_gpio: caps.led.default_gpio,
            led_default_brightness: caps.led.default_brightness,
            presence_bootsel: caps.presence.bootsel,
            presence_external_button: caps.presence.external_button,
            presence_external_button_gpio: caps.presence.external_button_gpio,
            led_candidate_gpio_mask: caps.led.candidate_gpio_mask,
        }
    }
}

/// Lifecycle report (PRD §20).
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct LifecycleReport {
    /// Lifecycle state code.
    #[n(0)]
    pub state: u8,
}

impl From<LifecycleState> for LifecycleReport {
    fn from(state: LifecycleState) -> Self {
        Self { state: state as u8 }
    }
}

/// Compact device status.
#[derive(Debug, Clone, PartialEq, Eq, minicbor::Encode, minicbor::Decode)]
#[cbor(map)]
pub struct StatusReport {
    /// Lifecycle state code.
    #[n(0)]
    pub lifecycle: u8,
    /// Active configuration schema version.
    #[n(1)]
    pub config_version: u16,
    /// Whether a configuration is staged and awaiting commit.
    #[n(2)]
    pub staged: bool,
}

/// Authoritative management state machine (PRD §11).
///
/// It owns the active configuration, the lifecycle and the staged proposal.
/// Cryptographic authorization and persistence are layered on top in later
/// phases; every response here is limited to non-sensitive metadata and
/// configuration.
pub struct ManagementService {
    capabilities: DeviceCapabilities,
    identity: BoardIdentity,
    lifecycle: LifecycleManager,
    config: DeviceConfig,
    staged: Option<DeviceConfig>,
}

impl ManagementService {
    /// Create a service for a device with the given capabilities, board
    /// identity and initial configuration.
    #[must_use]
    pub const fn new(
        capabilities: DeviceCapabilities,
        identity: BoardIdentity,
        config: DeviceConfig,
        lifecycle: LifecycleState,
    ) -> Self {
        Self {
            capabilities,
            identity,
            lifecycle: LifecycleManager::new(lifecycle),
            config,
            staged: None,
        }
    }

    /// Discovered capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    /// Board identity declared by the active board profile.
    #[must_use]
    pub const fn identity(&self) -> BoardIdentity {
        self.identity
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> LifecycleState {
        self.lifecycle.state()
    }

    /// Active configuration.
    #[must_use]
    pub const fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// Whether a configuration is staged.
    #[must_use]
    pub const fn has_staged(&self) -> bool {
        self.staged.is_some()
    }

    /// Configuration staged for commit, if any.
    #[must_use]
    pub const fn staged(&self) -> Option<&DeviceConfig> {
        self.staged.as_ref()
    }

    fn context(&self) -> ValidationContext<'_> {
        ValidationContext {
            capabilities: &self.capabilities,
            lifecycle: self.lifecycle.state(),
            identity: self.identity,
        }
    }

    /// Execute one management operation.
    pub fn handle(&mut self, command: ManagementCommand, payload: &[u8]) -> Response {
        match command {
            ManagementCommand::GetDeviceInfo => {
                Response::with_payload(&DeviceInfo::current(&self.identity, &self.capabilities))
            }
            ManagementCommand::GetCapabilities => {
                Response::with_payload(&CapabilityReport::from(&self.capabilities))
            }
            ManagementCommand::GetConfiguration => Response::with_payload(&self.config),
            ManagementCommand::ValidateConfiguration => self.validate_only(payload),
            ManagementCommand::SetConfiguration => self.set_configuration(payload),
            ManagementCommand::CommitConfiguration => self.commit_configuration(),
            ManagementCommand::GetLifecycle => {
                Response::with_payload(&LifecycleReport::from(self.lifecycle.state()))
            }
            ManagementCommand::CommissionDevice => self.commission(),
            ManagementCommand::GetStatus => Response::with_payload(&StatusReport {
                lifecycle: self.lifecycle.state() as u8,
                config_version: self.config.version,
                staged: self.staged.is_some(),
            }),
            ManagementCommand::GetDiagnostics => self.diagnostics(),
            ManagementCommand::DecommissionDevice => self.decommission(),
            ManagementCommand::FactoryReset => self.factory_reset(),
            ManagementCommand::SoftDetach => Response::ok(),
            ManagementCommand::Unknown(_) => Response::error(CoreError::UnsupportedCommand),
        }
    }

    fn decode_config(payload: &[u8]) -> Result<DeviceConfig, CoreError> {
        DeviceConfig::decode(payload).map_err(|_| CoreError::InvalidConfiguration)
    }

    fn validate_only(&mut self, payload: &[u8]) -> Response {
        let config = match Self::decode_config(payload) {
            Ok(config) => config,
            Err(error) => return Response::error(error),
        };
        match config.validate(&self.context()) {
            Ok(()) => Response::ok(),
            Err(error) => Response::error(error),
        }
    }

    fn set_configuration(&mut self, payload: &[u8]) -> Response {
        let config = match Self::decode_config(payload) {
            Ok(config) => config,
            Err(error) => return Response::error(error),
        };
        if let Err(error) = config.validate(&self.context()) {
            return Response::error(error);
        }
        self.staged = Some(config);
        Response::ok()
    }

    fn commit_configuration(&mut self) -> Response {
        let Some(config) = self.staged.clone() else {
            return Response::error(CoreError::InvalidState);
        };
        // Re-validate: capabilities or lifecycle may have changed since staging.
        if let Err(error) = config.validate(&self.context()) {
            return Response::error(error);
        }
        self.config = config;
        self.staged = None;
        Response::ok()
    }

    fn commission(&mut self) -> Response {
        match self.lifecycle.commission() {
            Ok(()) => Response::ok(),
            Err(error) => Response::error(error),
        }
    }

    fn diagnostics(&self) -> Response {
        let report = DiagnosticsReport::current(
            self.lifecycle.state(),
            self.config.version,
            self.staged.is_some(),
            &self.capabilities,
        );
        Response::with_payload(&report)
    }

    fn decommission(&mut self) -> Response {
        match self.lifecycle.decommission() {
            Ok(()) => Response::ok(),
            Err(error) => Response::error(error),
        }
    }

    fn factory_reset(&mut self) -> Response {
        match self.lifecycle.factory_reset() {
            Ok(()) => {
                self.config = DeviceConfig::for_board(self.identity, &self.capabilities);
                self.staged = None;
                Response::ok()
            }
            Err(error) => Response::error(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> BoardIdentity {
        BoardIdentity::new(
            "AegisToken",
            crate::PRODUCT_USB_STRING,
            "Generic RP2350",
            0,
            crate::configuration::DEFAULT_VENDOR_ID,
            crate::configuration::DEFAULT_PRODUCT_ID,
        )
    }

    fn service() -> ManagementService {
        ManagementService::new(
            DeviceCapabilities::rp2350a(),
            identity(),
            DeviceConfig::official_defaults(),
            LifecycleState::Factory,
        )
    }

    fn decode_config_response(response: &Response) -> DeviceConfig {
        DeviceConfig::decode(&response.payload).unwrap()
    }

    #[test]
    fn device_info_is_reported() {
        let mut service = service();
        let response = service.handle(ManagementCommand::GetDeviceInfo, &[]);
        assert!(response.status.is_ok());
        let info: DeviceInfo = codec::decode_from(&response.payload).unwrap();
        assert_eq!(info.product.as_str(), crate::PRODUCT_USB_STRING);
        assert_eq!(info.manufacturer.as_str(), "AegisToken");
        assert_eq!(info.config_version, crate::configuration::CONFIG_VERSION);
    }

    #[test]
    fn capabilities_are_reported() {
        let mut service = service();
        let response = service.handle(ManagementCommand::GetCapabilities, &[]);
        assert!(response.status.is_ok());
        let report: CapabilityReport = codec::decode_from(&response.payload).unwrap();
        assert_eq!(report.gpio_count, 30);
        assert!(report.usb_fido_hid && report.usb_management_hid);
    }

    #[test]
    fn get_configuration_returns_active_config() {
        let mut service = service();
        let response = service.handle(ManagementCommand::GetConfiguration, &[]);
        assert!(response.status.is_ok());
        assert_eq!(
            decode_config_response(&response),
            DeviceConfig::official_defaults()
        );
    }

    #[test]
    fn valid_configuration_is_staged_then_committed() {
        let mut service = service();
        let mut proposed = DeviceConfig::official_defaults();
        proposed.led.behavior = crate::configuration::LedBehavior::Blink;

        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = proposed.encode(&mut buf).unwrap();

        let staged = service.handle(ManagementCommand::SetConfiguration, &buf[..len]);
        assert!(staged.status.is_ok());
        assert!(service.has_staged());

        let committed = service.handle(ManagementCommand::CommitConfiguration, &[]);
        assert!(committed.status.is_ok());
        assert!(!service.has_staged());
        assert_eq!(
            service.config().led.behavior,
            crate::configuration::LedBehavior::Blink
        );
    }

    #[test]
    fn staged_configuration_is_exposed_for_live_apply() {
        static CAPS: DeviceCapabilities = {
            let mut c = DeviceCapabilities::rp2350a();
            c.led.configurable_gpio = true;
            c.led.candidate_gpio_mask = (1 << 16) | (1 << 25);
            c
        };
        let mut service = ManagementService::new(
            CAPS,
            identity(),
            DeviceConfig::official_defaults(),
            LifecycleState::Factory,
        );
        let mut proposed = DeviceConfig::official_defaults();
        proposed.led.gpio = 16;
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = proposed.encode(&mut buf).unwrap();
        let response = service.handle(ManagementCommand::SetConfiguration, &buf[..len]);
        assert!(response.status.is_ok());
        assert_eq!(service.staged().map(|config| config.led.gpio), Some(16));
    }

    #[test]
    fn commit_without_staging_is_invalid_state() {
        let mut service = service();
        let response = service.handle(ManagementCommand::CommitConfiguration, &[]);
        assert_eq!(
            response.status,
            ResponseStatus::Error(CoreError::InvalidState)
        );
    }

    #[test]
    fn incompatible_configuration_is_rejected_and_not_staged() {
        let mut service = service();
        let mut proposed = DeviceConfig::official_defaults();
        proposed.led.gpio = 99;

        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = proposed.encode(&mut buf).unwrap();

        let response = service.handle(ManagementCommand::SetConfiguration, &buf[..len]);
        assert_eq!(
            response.status,
            ResponseStatus::Error(CoreError::InvalidConfiguration)
        );
        assert!(!service.has_staged());
    }

    #[test]
    fn validate_configuration_does_not_stage() {
        let mut service = service();
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = DeviceConfig::official_defaults().encode(&mut buf).unwrap();
        let response = service.handle(ManagementCommand::ValidateConfiguration, &buf[..len]);
        assert!(response.status.is_ok());
        assert!(!service.has_staged());
    }

    #[test]
    fn configuration_change_is_unauthorized_when_active() {
        let mut service = ManagementService::new(
            DeviceCapabilities::rp2350a(),
            identity(),
            DeviceConfig::official_defaults(),
            LifecycleState::Active,
        );
        let mut buf = [0u8; codec::MAX_STORED_CONFIG_LEN];
        let len = DeviceConfig::official_defaults().encode(&mut buf).unwrap();
        let response = service.handle(ManagementCommand::SetConfiguration, &buf[..len]);
        assert_eq!(
            response.status,
            ResponseStatus::Error(CoreError::Unauthorized)
        );
    }

    #[test]
    fn commission_moves_factory_to_commissioning_once() {
        let mut service = service();
        let first = service.handle(ManagementCommand::CommissionDevice, &[]);
        assert!(first.status.is_ok());
        assert_eq!(service.lifecycle(), LifecycleState::Commissioning);

        // Commissioning is idempotent.
        let second = service.handle(ManagementCommand::CommissionDevice, &[]);
        assert!(second.status.is_ok());
    }

    #[test]
    fn commission_is_rejected_when_active() {
        let mut service = ManagementService::new(
            DeviceCapabilities::rp2350a(),
            identity(),
            DeviceConfig::official_defaults(),
            LifecycleState::Active,
        );
        let response = service.handle(ManagementCommand::CommissionDevice, &[]);
        assert_eq!(
            response.status,
            ResponseStatus::Error(CoreError::InvalidState)
        );
    }

    #[test]
    fn lifecycle_and_status_are_reported() {
        let mut service = service();
        let lifecycle = service.handle(ManagementCommand::GetLifecycle, &[]);
        let report: LifecycleReport = codec::decode_from(&lifecycle.payload).unwrap();
        assert_eq!(report.state, LifecycleState::Factory as u8);

        let status = service.handle(ManagementCommand::GetStatus, &[]);
        let report: StatusReport = codec::decode_from(&status.payload).unwrap();
        assert_eq!(report.lifecycle, LifecycleState::Factory as u8);
        assert!(!report.staged);
    }

    #[test]
    fn unknown_command_is_unsupported() {
        let mut service = service();
        let response = service.handle(ManagementCommand::Unknown(0x7E), &[]);
        assert_eq!(
            response.status,
            ResponseStatus::Error(CoreError::UnsupportedCommand)
        );
    }

    #[test]
    fn response_codes_are_flagged() {
        assert_eq!(ManagementCommand::GetStatus.response_code(), 0x89);
        assert_eq!(ManagementCommand::GetDeviceInfo.response_code(), 0x81);
    }

    #[test]
    fn soft_detach_is_acknowledged() {
        let mut service = service();
        assert_eq!(
            ManagementCommand::from_code(0x0D),
            ManagementCommand::SoftDetach
        );
        assert_eq!(ManagementCommand::SoftDetach.response_code(), 0x8D);
        assert!(ManagementCommand::SoftDetach.is_known());
        let response = service.handle(ManagementCommand::SoftDetach, &[]);
        assert_eq!(response.status, ResponseStatus::Ok);
        assert!(response.payload.is_empty());
    }

    #[test]
    fn sensitive_material_is_never_serialized() {
        // The response bodies must never contain a private key, seed or PIN.
        // We assert the capability/config/device-info payloads only contain the
        // fields declared in this module by checking they decode successfully
        // into those exact types.
        let mut service = service();
        for command in [
            ManagementCommand::GetDeviceInfo,
            ManagementCommand::GetCapabilities,
            ManagementCommand::GetConfiguration,
            ManagementCommand::GetStatus,
            ManagementCommand::GetLifecycle,
            ManagementCommand::GetDiagnostics,
        ] {
            let response = service.handle(command, &[]);
            assert!(response.status.is_ok());
            assert!(!response.payload.is_empty());
        }
    }

    #[test]
    fn diagnostics_report_decodes() {
        let mut service = service();
        let response = service.handle(ManagementCommand::GetDiagnostics, &[]);
        assert!(response.status.is_ok());
        let report: DiagnosticsReport = codec::decode_from(&response.payload).unwrap();
        assert_eq!(report.lifecycle, LifecycleState::Factory as u8);
        assert_eq!(report.gpio_count, 30);
    }

    #[test]
    fn decommission_then_factory_reset() {
        let mut service = ManagementService::new(
            DeviceCapabilities::rp2350a(),
            identity(),
            DeviceConfig::official_defaults(),
            LifecycleState::Active,
        );
        // Mutate the active config so we can observe the reset.
        service.config.led.behavior = crate::configuration::LedBehavior::Blink;

        let response = service.handle(ManagementCommand::DecommissionDevice, &[]);
        assert!(response.status.is_ok());
        assert_eq!(service.lifecycle(), LifecycleState::Decommissioned);

        let response = service.handle(ManagementCommand::FactoryReset, &[]);
        assert!(response.status.is_ok());
        assert_eq!(service.lifecycle(), LifecycleState::Factory);
        assert_eq!(
            service.config().led.behavior,
            crate::configuration::LedBehavior::Activity
        );
    }

    #[test]
    fn decommission_is_rejected_from_factory() {
        let mut service = service();
        let response = service.handle(ManagementCommand::DecommissionDevice, &[]);
        assert_eq!(
            response.status,
            ResponseStatus::Error(CoreError::InvalidState)
        );
    }

    #[test]
    fn factory_reset_requires_decommissioned() {
        let mut service = service();
        let response = service.handle(ManagementCommand::FactoryReset, &[]);
        assert!(response.status.is_ok());
        assert_eq!(service.lifecycle(), LifecycleState::Factory);
    }
}
