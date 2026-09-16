//! Command-line interface for the AegisToken host tool.
//!
//! The CLI speaks the Management HID protocol over libusb. It exposes one
//! subcommand per management operation, a raw `send`, and a `validate` harness
//! that runs the Management HID acceptance checks on attached hardware.

use core::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use aegis_core::codec;
use aegis_core::configuration::{DeviceConfig, FixedString, LedBehavior};
use aegis_core::management_protocol::{
    CapabilityReport, DeviceInfo, LifecycleReport, StatusReport,
};
use aegis_core::recovery::DiagnosticsReport;

use crate::framing::Response;
use crate::transport::{self, ManagementDevice, Options};

/// `GET_LAST_FIDO_STATUS`, a diagnostics-only extension command.
const GET_LAST_FIDO_STATUS: u8 = 0x14;

/// Parsed command line.
struct Cli {
    options: Options,
    command: Option<String>,
    positional: Vec<String>,
    help: bool,
    version: bool,
}

/// Parse arguments and run the requested command.
pub fn run(args: impl IntoIterator<Item = String>) -> Result<ExitCode, String> {
    let cli = parse(args)?;

    if cli.version {
        println!("aegistoken-host {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    let Some(command) = cli.command.as_deref() else {
        print_help();
        return Ok(ExitCode::SUCCESS);
    };
    if cli.help || command == "help" {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }

    if command == "list" {
        return list(&cli.options);
    }

    let mut device = ManagementDevice::open(&cli.options).map_err(|error| error.to_string())?;
    if command == "validate" {
        return validate(&mut device);
    }
    dispatch(&mut device, command, &cli.positional)
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    let mut cli = Cli {
        options: Options::default(),
        command: None,
        positional: Vec::new(),
        help: false,
        version: false,
    };
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        let (name, inline) = split_option(&arg);
        match name {
            "--help" | "-h" => cli.help = true,
            "--version" | "-V" => cli.version = true,
            "--vid" => cli.options.vid = parse_u16(&option_value(inline, &mut args, name)?)?,
            "--pid" => cli.options.pid = parse_u16(&option_value(inline, &mut args, name)?)?,
            "--interface" | "-i" => {
                cli.options.interface = Some(parse_u8(&option_value(inline, &mut args, name)?)?);
            }
            "--timeout" => {
                let millis = parse_u64(&option_value(inline, &mut args, name)?)?;
                cli.options.timeout = Duration::from_millis(millis.max(1));
            }
            _ if arg.starts_with('-') && arg.len() > 1 => {
                return Err(format!("unknown option: {arg}"));
            }
            _ => {
                if cli.command.is_none() {
                    cli.command = Some(arg);
                } else {
                    cli.positional.push(arg);
                }
            }
        }
    }
    Ok(cli)
}

/// Split `--opt=value` into `("--opt", Some("value"))`.
fn split_option(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((name, value)) if name.starts_with("--") => (name, Some(value)),
        _ => (arg, None),
    }
}

fn option_value(
    inline: Option<&str>,
    args: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, String> {
    if let Some(value) = inline {
        return Ok(value.to_string());
    }
    args.next()
        .ok_or_else(|| format!("option {name} requires a value"))
}

fn list(options: &Options) -> Result<ExitCode, String> {
    let lines = transport::describe(options).map_err(|error| error.to_string())?;
    if lines.is_empty() {
        println!(
            "no AegisToken device with VID {:04x}:{:04x} found",
            options.vid, options.pid
        );
        return Ok(ExitCode::FAILURE);
    }
    for line in lines {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Execute one command against an open device.
fn dispatch(
    device: &mut ManagementDevice,
    command: &str,
    positional: &[String],
) -> Result<ExitCode, String> {
    let (code, payload) = match command {
        "info" => (0x01, Vec::new()),
        "capabilities" => (0x02, Vec::new()),
        "config" | "get-configuration" => (0x03, Vec::new()),
        "set-config" | "set-configuration" => (0x04, payload_argument(positional, 0)?),
        "validate-config" | "validate-configuration" => (0x05, payload_argument(positional, 0)?),
        "commit" | "commit-configuration" => (0x06, Vec::new()),
        "lifecycle" => (0x07, Vec::new()),
        "commission" => (0x08, Vec::new()),
        "status" => (0x09, Vec::new()),
        "diagnostics" => (0x0A, Vec::new()),
        "decommission" => (0x0B, Vec::new()),
        "factory-reset" => (0x0C, Vec::new()),
        "soft-detach" => (0x0D, Vec::new()),
        "last-fido" => (GET_LAST_FIDO_STATUS, Vec::new()),
        "send" => {
            let code = positional
                .first()
                .ok_or_else(|| "send requires a command code".to_string())?;
            let payload = match positional.get(1) {
                Some(value) => payload_from(value)?,
                None => Vec::new(),
            };
            (parse_u8(code)?, payload)
        }
        other => return Err(format!("unknown command: {other}")),
    };

    let response = device
        .request(code, &payload)
        .map_err(|error| error.to_string())?;
    print_response(code, &response)
}

fn print_response(code: u8, response: &Response) -> Result<ExitCode, String> {
    if response.status != 0 {
        println!(
            "status: 0x{:02x} ({})",
            response.status,
            status_name(response.status)
        );
        return Ok(ExitCode::FAILURE);
    }
    if response.body.is_empty() {
        println!("ok");
        return Ok(ExitCode::SUCCESS);
    }

    match code {
        0x01 => show::<DeviceInfo>(&response.body),
        0x02 => show::<CapabilityReport>(&response.body),
        0x03 => show::<DeviceConfig>(&response.body),
        0x07 => show::<LifecycleReport>(&response.body),
        0x09 => show::<StatusReport>(&response.body),
        0x0A => show::<DiagnosticsReport>(&response.body),
        GET_LAST_FIDO_STATUS => print_last_fido(&response.body),
        _ => print_hex(&response.body),
    }
    Ok(ExitCode::SUCCESS)
}

/// Decode `body` into `T` and pretty-print it, falling back to hex.
fn show<T>(body: &[u8])
where
    T: for<'b> minicbor::Decode<'b, ()> + core::fmt::Debug,
{
    match codec::decode_from::<T>(body) {
        Ok(value) => println!("{value:#?}"),
        Err(_) => print_hex(body),
    }
}

fn print_last_fido(body: &[u8]) {
    if let [command, status, ..] = body {
        println!(
            "last FIDO command=0x{command:02x} status=0x{status:02x} ({})",
            ctap_status_name(*status)
        );
    } else {
        print_hex(body);
    }
}

fn payload_argument(positional: &[String], index: usize) -> Result<Vec<u8>, String> {
    let value = positional
        .get(index)
        .ok_or_else(|| "command requires a hex payload or @file".to_string())?;
    payload_from(value)
}

fn payload_from(value: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = value.strip_prefix('@') {
        std::fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))
    } else {
        parse_hex(value)
    }
}

// --- Acceptance harness -----------------------------------------------------

struct Harness {
    results: Vec<(String, bool)>,
}

impl Harness {
    fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    fn record(&mut self, name: &str, passed: bool, detail: &str) {
        let flag = if passed { "PASS" } else { "FAIL" };
        if detail.is_empty() {
            println!("[{flag}] {name}");
        } else {
            println!("[{flag}] {name} — {detail}");
        }
        self.results.push((name.to_string(), passed));
    }

    fn check<F>(&mut self, name: &str, f: F)
    where
        F: FnOnce() -> Result<(bool, String), Box<dyn std::error::Error>>,
    {
        match f() {
            Ok((passed, detail)) => self.record(name, passed, &detail),
            Err(error) => self.record(name, false, &error.to_string()),
        }
    }

    fn summarize(&self) -> ExitCode {
        let passed = self.results.iter().filter(|(_, ok)| *ok).count();
        let total = self.results.len();
        println!("\n{passed}/{total} checks passed");
        if passed == total {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

/// Run the Management HID acceptance checks (AC-003..AC-009).
fn validate(device: &mut ManagementDevice) -> Result<ExitCode, String> {
    let mut harness = Harness::new();

    // On Windows, driverless access depends on libusb's HID backend; when it is
    // unavailable the tool would need a WinUSB-class driver installed. There is
    // no public libusb API that reports which sub-API opened the device, so this
    // is the closest enforceable guarantee.
    #[cfg(windows)]
    {
        let hid = rusb::has_hid_access();
        harness.record(
            "Windows driverless access (libusb HID backend, no WinUSB)",
            hid,
            if hid {
                "HID backend available"
            } else {
                "HID backend unavailable; a WinUSB driver would be required"
            },
        );
    }

    harness.record(
        "AC-003 Management HID enumeration",
        true,
        &format!("interface {}", device.interface()),
    );

    harness.check("AC-004 GET_DEVICE_INFO", || {
        let response = device.request(0x01, &[])?;
        if let Ok(info) = codec::decode_from::<DeviceInfo>(&response.body) {
            println!("    device info: {info:#?}");
        }
        Ok((
            response.status == 0 && !response.body.is_empty(),
            format!("status={}", response.status),
        ))
    });

    harness.check("AC-005 GET_CAPABILITIES", || {
        let response = device.request(0x02, &[])?;
        let capabilities = codec::decode_from::<CapabilityReport>(&response.body).ok();
        if let Some(caps) = &capabilities {
            println!("    capabilities: {caps:#?}");
        }
        Ok((
            response.status == 0 && capabilities.is_some(),
            format!("status={}", response.status),
        ))
    });

    let config = match device.request(0x03, &[]) {
        Ok(response) => {
            let decoded = if response.status == 0 {
                DeviceConfig::decode(&response.body).ok()
            } else {
                None
            };
            harness.record(
                "AC-006a GET_CONFIGURATION",
                decoded.is_some(),
                &format!("status={}", response.status),
            );
            decoded
        }
        Err(error) => {
            harness.record("AC-006a GET_CONFIGURATION", false, &error.to_string());
            None
        }
    };

    if let Some(mut config) = config {
        if let Some(caps) = device
            .request(0x02, &[])
            .ok()
            .and_then(|response| codec::decode_from::<CapabilityReport>(&response.body).ok())
        {
            harness.record(
                "AC-009 automatic discovery",
                matches!(caps.gpio_count, 30 | 48),
                &format!("gpio_count={}", caps.gpio_count),
            );
            harness.record(
                "capabilities advertise both HID interfaces",
                caps.usb_fido_hid && caps.usb_management_hid,
                "",
            );
        }

        let original_behavior = config.led.behavior;
        let original_gpio = config.led.gpio;
        let toggled = if original_behavior == LedBehavior::Solid {
            LedBehavior::Activity
        } else {
            LedBehavior::Solid
        };
        config.led.behavior = toggled;

        harness.check("AC-006 valid configuration applied", || {
            let mut buffer = [0u8; codec::MAX_STORED_CONFIG_LEN];
            let length = config.encode(&mut buffer)?;
            let set_status = device.request(0x04, &buffer[..length])?.status;
            let commit_status = device.request(0x06, &[])?.status;
            let response = device.request(0x03, &[])?;
            let applied = DeviceConfig::decode(&response.body)
                .ok()
                .map(|config| config.led.behavior);
            Ok((
                set_status == 0 && commit_status == 0 && applied == Some(toggled),
                format!("set={set_status} commit={commit_status}"),
            ))
        });

        // Restore the value that was active before the harness ran.
        config.led.behavior = original_behavior;
        restore(device, &config);

        harness.check("AC-007 reject out-of-range GPIO", || {
            let mut invalid = config.clone();
            // Force the LED on so the range check is reached even on a board
            // whose default configuration disables the LED (e.g. a third-party
            // carrier with no plain-GPIO status LED).
            invalid.led.enabled = true;
            invalid.led.gpio = 99;
            let mut buffer = [0u8; codec::MAX_STORED_CONFIG_LEN];
            let length = invalid.encode(&mut buffer)?;
            let status = device.request(0x04, &buffer[..length])?.status;
            Ok((status != 0, format!("status={status}")))
        });

        harness.check("AC-007 reject bad USB identity", || {
            let mut invalid = config.clone();
            invalid.usb.product_string = FixedString::new("Evil Key")?;
            let mut buffer = [0u8; codec::MAX_STORED_CONFIG_LEN];
            let length = invalid.encode(&mut buffer)?;
            let status = device.request(0x04, &buffer[..length])?.status;
            Ok((status != 0, format!("status={status}")))
        });

        config.led.gpio = original_gpio;
        restore(device, &config);
    }

    for (name, code) in [
        ("GET_LIFECYCLE", 0x07u8),
        ("GET_STATUS", 0x09),
        ("GET_DIAGNOSTICS", 0x0A),
    ] {
        match device.request(code, &[]) {
            Ok(response) => harness.record(
                name,
                response.status == 0 && !response.body.is_empty(),
                &format!("status={}", response.status),
            ),
            Err(error) => harness.record(name, false, &error.to_string()),
        }
    }

    match device.request(GET_LAST_FIDO_STATUS, &[]) {
        Ok(response) if response.status == 0 && response.body.len() >= 2 => {
            print_last_fido(&response.body);
        }
        Ok(_) => {}
        Err(error) => println!("    last FIDO status unavailable: {error}"),
    }

    Ok(harness.summarize())
}

/// Best-effort re-apply of a known-good configuration.
fn restore(device: &mut ManagementDevice, config: &DeviceConfig) {
    let mut buffer = [0u8; codec::MAX_STORED_CONFIG_LEN];
    if let Ok(length) = config.encode(&mut buffer) {
        let _ = device.request(0x04, &buffer[..length]);
        let _ = device.request(0x06, &[]);
    }
}

// --- Parsing helpers --------------------------------------------------------

fn parse_u8(value: &str) -> Result<u8, String> {
    u8::try_from(parse_u64(value)?).map_err(|_| format!("value out of range: {value}"))
}

fn parse_u16(value: &str) -> Result<u16, String> {
    u16::try_from(parse_u64(value)?).map_err(|_| format!("value out of range: {value}"))
}

fn parse_u64(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    let (radix, digits) = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(rest) => (16, rest),
        None => (10, trimmed),
    };
    u64::from_str_radix(digits, radix).map_err(|_| format!("invalid number: {value}"))
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ':')
        .collect();
    let digits = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if digits.len() % 2 != 0 {
        return Err("hex payload must have an even number of digits".to_string());
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16)
                .map_err(|_| format!("invalid hex payload: {value}"))
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn print_hex(bytes: &[u8]) {
    if bytes.is_empty() {
        println!("(empty)");
    } else {
        println!("{}", to_hex(bytes));
    }
}

fn status_name(code: u8) -> &'static str {
    match code {
        0x01 => "invalid command",
        0x02 => "unsupported command",
        0x03 => "invalid capability",
        0x04 => "invalid configuration",
        0x05 => "invalid state",
        0x06 => "unauthorized",
        0x07 => "storage error",
        0x08 => "crypto error",
        0x09 => "firmware error",
        0x0A => "protocol error",
        _ => "unknown status",
    }
}

fn ctap_status_name(code: u8) -> &'static str {
    match code {
        0x00 => "CTAP2_OK",
        0x01 => "ERR_INVALID_COMMAND",
        0x02 => "ERR_INVALID_PARAMETER",
        0x03 => "ERR_INVALID_LENGTH",
        0x0A => "ERR_TIMEOUT",
        0x2E => "CTAP2_ERR_NO_CREDENTIALS",
        0x33 => "CTAP2_ERR_PIN_AUTH_INVALID",
        0x34 => "CTAP2_ERR_PIN_AUTH_BLOCKED",
        0x36 => "CTAP2_ERR_PIN_REQUIRED",
        0x39 => "CTAP2_ERR_OPERATION_DENIED",
        0x3B => "CTAP2_ERR_UP_REQUIRED",
        0x3D => "CTAP2_ERR_PIN_AUTH_REQUIRED",
        _ => "unknown",
    }
}

fn print_help() {
    println!(
        "\
aegistoken-host — host CLI for AegisToken (Management HID over libusb)

USAGE:
  aegistoken-host [OPTIONS] <COMMAND> [ARGS]

OPTIONS:
  --vid <HEX>           USB vendor id (default 0x1209)
  --pid <HEX>           USB product id (default 0x0001)
  -i, --interface <N>   Management HID interface number (skip name discovery)
  --timeout <MS>        transfer timeout in milliseconds (default 2000)
  -h, --help            show this help
  -V, --version         show version

COMMANDS:
  list                  list matching USB devices and HID interfaces
  info                  GET_DEVICE_INFO
  capabilities          GET_CAPABILITIES
  config                GET_CONFIGURATION
  set-config <HEX|@FILE>       SET_CONFIGURATION
  validate-config <HEX|@FILE>  VALIDATE_CONFIGURATION
  commit                COMMIT_CONFIGURATION
  lifecycle             GET_LIFECYCLE
  commission            COMMISSION_DEVICE
  status                GET_STATUS
  diagnostics           GET_DIAGNOSTICS
  decommission          DECOMMISSION_DEVICE
  factory-reset         FACTORY_RESET
  soft-detach           SOFT_DETACH (acknowledged, then leave the bus)
  last-fido             GET_LAST_FIDO_STATUS
  send <CMD> [HEX|@FILE]       send a raw command (CMD decimal or 0x hex)
  validate              run the Management HID acceptance checks"
    );
}
