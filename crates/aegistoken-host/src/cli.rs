//! Command-line interface for the AegisToken host tool.
//!
//! The CLI speaks the Management HID protocol over libusb. It exposes one
//! subcommand per management operation, a raw `send`, and a `validate` harness
//! that runs the Management HID acceptance checks on attached hardware.

use core::fmt::Write as _;
use std::io::BufRead;
use std::process::ExitCode;
use std::time::Duration;

use aegis_core::codec;
use aegis_core::configuration::{DeviceConfig, FixedString, LedBehavior};
use aegis_core::management_protocol::{
    CapabilityReport, DeviceInfo, LifecycleReport, StatusReport,
};
use aegis_core::recovery::DiagnosticsReport;

use crate::framing::Response;
use crate::secret;
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
    /// `--key-stdin`: read the new PIV management key from stdin.
    key_stdin: bool,
    /// `--old-key-stdin`: read the current PIV management key from stdin.
    old_key_stdin: bool,
    /// `--reader`: reader filter for `piv-set-mgmt-key`.
    reader: Option<String>,
    alg: Option<String>,
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

    reject_misplaced_options(&cli, command)?;

    if command == "list" {
        return list(&cli.options);
    }

    // --- Smart card / CCID commands (do not require ManagementDevice) ---
    let reader_filter = cli.positional.first().map(|s| s.as_str());
    match command {
        "card-list" => return crate::card::list_readers(),
        "card-status" => return crate::card::card_status(reader_filter),
        "card-select" => {
            let aid = cli
                .positional
                .first()
                .ok_or("card-select requires an AID argument (piv, oath, openpgp or hex)")?;
            let reader = cli.positional.get(1).map(|s| s.as_str());
            return crate::card::select_applet(aid, reader);
        }
        "card-apdu" => {
            let apdu_hex = cli
                .positional
                .first()
                .ok_or("card-apdu requires a hex APDU argument")?;
            let reader = cli.positional.get(1).map(|s| s.as_str());
            return crate::card::transmit_raw(apdu_hex, reader);
        }
        "piv-list" => {
            let reader = cli.positional.first().map(|s| s.as_str());
            return crate::piv_cmd::piv_list(reader);
        }
        "piv-import-cert" => {
            let slot = cli
                .positional
                .first()
                .ok_or("piv-import-cert requires <SLOT> (9A, 9C, 9D, 9E)")?;
            let cert_path = cli
                .positional
                .get(1)
                .ok_or("piv-import-cert requires <CERT_FILE>")?;
            let reader = cli.positional.get(2).map(|s| s.as_str());
            let mut stdin = std::io::stdin().lock();
            let mgmt_key = acquire_import_key(&cli, secret::stdin_is_tty(), &mut stdin)?;
            return crate::piv_cmd::piv_import_cert(slot, cert_path, mgmt_key.as_deref(), reader);
        }
        "piv-set-mgmt-key" => {
            if !cli.positional.is_empty() {
                // Never echo the positional: it may be a legacy key.
                return Err(
                    "piv-set-mgmt-key does not accept positional arguments: the key comes \
                     from --key-stdin or the interactive prompt, and the reader from --reader"
                        .to_string(),
                );
            }
            let mut stdin = std::io::stdin().lock();
            let mut prompt = |text: &str| secret::prompt(text);
            let (new_key, old_key) =
                acquire_mgmt_key(&cli, secret::stdin_is_tty(), &mut stdin, &mut prompt)?;
            return crate::piv_cmd::piv_set_mgmt_key(
                &new_key,
                old_key.as_deref(),
                cli.alg.as_deref(),
                cli.reader.as_deref(),
            );
        }
        _ => {}
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
        key_stdin: false,
        old_key_stdin: false,
        reader: None,
        alg: None,
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
            "--key" | "--old-key" => {
                return Err(format!(
                    "option {name} is not accepted: a secret must never be passed in argv; \
                     use {} or the interactive prompt",
                    if name == "--key" {
                        "--key-stdin"
                    } else {
                        "--old-key-stdin (with --key-stdin)"
                    }
                ));
            }
            "--key-stdin" => {
                if inline.is_some() {
                    return Err("option --key-stdin takes no value".to_string());
                }
                cli.key_stdin = true;
            }
            "--old-key-stdin" => {
                if inline.is_some() {
                    return Err("option --old-key-stdin takes no value".to_string());
                }
                cli.old_key_stdin = true;
            }
            "--reader" => cli.reader = Some(option_value(inline, &mut args, name)?),
            "--alg" => cli.alg = Some(option_value(inline, &mut args, name)?),
            _ if arg.starts_with('-') && arg.len() > 1 => {
                // Report the option name only: `--key=value` must not echo the
                // value, and an unknown option is not a place to log a secret.
                return Err(format!("unknown option: {name}"));
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

/// Split `-opt=value`/`--opt=value` into `("--opt", Some("value"))`.
fn split_option(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        // Split on the first `=` for any dash-prefixed token: a single-dash
        // typo (`-key=secret`) must not smuggle the value into the message.
        Some((name, value)) if name.starts_with('-') && name.len() > 1 => (name, Some(value)),
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

/// Reject options that only make sense for a different command.
fn reject_misplaced_options(cli: &Cli, command: &str) -> Result<(), String> {
    let mgmt = command == "piv-set-mgmt-key";
    let import = command == "piv-import-cert";
    if cli.reader.is_some() && !mgmt {
        return Err("--reader is only valid with piv-set-mgmt-key".to_string());
    }
    if cli.old_key_stdin && !mgmt {
        return Err("--old-key-stdin is only valid with piv-set-mgmt-key".to_string());
    }
    if cli.key_stdin && !(mgmt || import) {
        return Err(
            "--key-stdin is only valid with piv-set-mgmt-key or piv-import-cert".to_string(),
        );
    }
    if cli.alg.is_some() && !mgmt {
        return Err("--alg is only valid with piv-set-mgmt-key".to_string());
    }
    Ok(())
}

/// Acquire the new and (optional) current management key for
/// `piv-set-mgmt-key`.
///
/// `stdin` and `prompt` are injected so the acquisition rules are testable
/// without a terminal or hardware.
fn acquire_mgmt_key(
    cli: &Cli,
    is_tty: bool,
    stdin: &mut impl BufRead,
    prompt: &mut impl FnMut(&str) -> Result<String, String>,
) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    let (new_text, old_text) = if cli.key_stdin {
        if is_tty {
            return Err(
                "--key-stdin expects a pipe: redirect stdin or use the interactive prompt"
                    .to_string(),
            );
        }
        let new_text = secret::read_line(stdin)?;
        let old_text = if cli.old_key_stdin {
            Some(secret::read_line(stdin)?)
        } else {
            None
        };
        (new_text, old_text)
    } else {
        if cli.old_key_stdin {
            return Err("--old-key-stdin requires --key-stdin".to_string());
        }
        if !is_tty {
            return Err(
                "no terminal for the interactive prompt: use --key-stdin (and \
                 --old-key-stdin) with a pipe"
                    .to_string(),
            );
        }
        let first = prompt("New PIV management key (hex): ")?;
        let second = prompt("Repeat the new PIV management key: ")?;
        if first != second {
            return Err("the two prompted keys do not match".to_string());
        }
        let old = prompt("Current PIV management key (empty = NIST default): ")?;
        (first, if old.is_empty() { None } else { Some(old) })
    };
    let new_key = secret::parse_hex(&new_text, "new management key")?;
    let old_key = match old_text {
        Some(text) => Some(secret::parse_hex(&text, "current management key")?),
        None => None,
    };
    Ok((new_key, old_key))
}

/// Acquire the optional management key for `piv-import-cert`.
///
/// There is no prompt here: an import is a non-interactive operation, so a
/// non-default key must arrive through `--key-stdin`.
fn acquire_import_key(
    cli: &Cli,
    is_tty: bool,
    stdin: &mut impl BufRead,
) -> Result<Option<Vec<u8>>, String> {
    if !cli.key_stdin {
        return Ok(None);
    }
    if is_tty {
        return Err("--key-stdin expects a pipe: redirect stdin".to_string());
    }
    let text = secret::read_line(stdin)?;
    let key = secret::parse_hex(&text, "management key")?;
    // Validate the length before opening PC/SC: a bad key must fail in the
    // acquisition layer, without touching the card.
    match key.len() {
        16 | 24 | 32 => Ok(Some(key)),
        len => Err(format!(
            "invalid management key length {len} bytes (must be 16, 24, or 32)"
        )),
    }
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
        "provision" | "provision-board" => return provision_board(device, positional),
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
            invalid.usb.vid = 0;
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

/// Provision a board post-flash with custom identity and hardware parameters.
fn provision_board(device: &mut ManagementDevice, args: &[String]) -> Result<ExitCode, String> {
    let info_res = device.request(0x01, &[]).map_err(|e| e.to_string())?;
    let info = codec::decode_from::<DeviceInfo>(&info_res.body)
        .map_err(|e| format!("decode DeviceInfo: {e:?}"))?;

    let caps_res = device.request(0x02, &[]).map_err(|e| e.to_string())?;
    let caps = codec::decode_from::<CapabilityReport>(&caps_res.body)
        .map_err(|e| format!("decode CapabilityReport: {e:?}"))?;

    println!("Detected device:");
    println!("  Product:       {}", info.product.as_str());
    println!("  Manufacturer:  {}", info.manufacturer.as_str());
    println!(
        "  Hardware:      Family=0x{:02x} Package=0x{:02x} ({} GPIOs)",
        caps.family, caps.package, caps.gpio_count
    );
    println!("  Flash:         {} KiB", caps.flash_size_bytes / 1024);
    println!(
        "  Configurable:  USB identity={}",
        caps.usb_configurable_identity
    );

    let config_res = device.request(0x03, &[]).map_err(|e| e.to_string())?;
    let mut config = DeviceConfig::decode(&config_res.body)
        .map_err(|e| format!("decode DeviceConfig: {e:?}"))?;

    let mut i = 0;
    let mut product_override = None;
    let mut vid_override = None;
    let mut pid_override = None;
    let mut led_gpio_override = None;
    let mut led_behavior_override = None;
    let mut led_brightness_override = None;

    while i < args.len() {
        let arg = &args[i];
        if arg == "--product" && i + 1 < args.len() {
            product_override = Some(args[i + 1].clone());
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--product=") {
            product_override = Some(val.to_string());
            i += 1;
        } else if arg == "--vid" && i + 1 < args.len() {
            vid_override = Some(parse_u16(&args[i + 1])?);
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--vid=") {
            vid_override = Some(parse_u16(val)?);
            i += 1;
        } else if arg == "--pid" && i + 1 < args.len() {
            pid_override = Some(parse_u16(&args[i + 1])?);
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--pid=") {
            pid_override = Some(parse_u16(val)?);
            i += 1;
        } else if arg == "--led-gpio" && i + 1 < args.len() {
            led_gpio_override = Some(parse_u8(&args[i + 1])?);
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--led-gpio=") {
            led_gpio_override = Some(parse_u8(val)?);
            i += 1;
        } else if arg == "--led-behavior" && i + 1 < args.len() {
            led_behavior_override = Some(args[i + 1].clone());
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--led-behavior=") {
            led_behavior_override = Some(val.to_string());
            i += 1;
        } else if arg == "--led-brightness" && i + 1 < args.len() {
            led_brightness_override = Some(parse_u8(&args[i + 1])?);
            i += 2;
        } else if let Some(val) = arg.strip_prefix("--led-brightness=") {
            led_brightness_override = Some(parse_u8(val)?);
            i += 1;
        } else {
            return Err(format!("unknown provision option: {arg}"));
        }
    }

    if let Some(p) = product_override {
        config.usb.product_string =
            FixedString::new(&p).map_err(|e| format!("product string invalid: {e:?}"))?;
    }
    if let Some(vid) = vid_override {
        config.usb.vid = vid;
    }
    if let Some(pid) = pid_override {
        config.usb.pid = pid;
    }
    if let Some(gpio) = led_gpio_override {
        if caps.led_configurable_gpio && (caps.led_candidate_gpio_mask & (1 << gpio)) == 0 {
            return Err(format!(
                "GPIO {gpio} is not a valid candidate pin for this board (mask=0x{:x})",
                caps.led_candidate_gpio_mask
            ));
        }
        config.led.gpio = gpio;
        config.led.enabled = true;
    }
    if let Some(b) = led_behavior_override {
        config.led.behavior = match b.to_lowercase().as_str() {
            "solid" => LedBehavior::Solid,
            "blink" => LedBehavior::Blink,
            "activity" => LedBehavior::Activity,
            "off" => LedBehavior::Off,
            other => return Err(format!("unknown led behavior: {other}")),
        };
    }
    if let Some(brightness) = led_brightness_override {
        config.led.brightness = brightness;
    }

    println!("\nApplying provisioned configuration:");
    println!(
        "  USB VID:PID:   {:04x}:{:04x}",
        config.usb.vid, config.usb.pid
    );
    println!("  Product:       {}", config.usb.product_string.as_str());
    println!(
        "  LED:           enabled={} gpio={} behavior={:?} brightness={}",
        config.led.enabled, config.led.gpio, config.led.behavior, config.led.brightness
    );

    let mut buffer = [0u8; codec::MAX_STORED_CONFIG_LEN];
    let len = config
        .encode(&mut buffer)
        .map_err(|e| format!("encode error: {e:?}"))?;
    let set_res = device
        .request(0x04, &buffer[..len])
        .map_err(|e| e.to_string())?;
    if set_res.status != 0 {
        return Err(format!(
            "SET_CONFIGURATION failed with status 0x{:02x} ({})",
            set_res.status,
            status_name(set_res.status)
        ));
    }
    println!("  [OK] Staged configuration accepted");

    let commit_res = device.request(0x06, &[]).map_err(|e| e.to_string())?;
    if commit_res.status != 0 {
        return Err(format!(
            "COMMIT_CONFIGURATION failed with status 0x{:02x} ({})",
            commit_res.status,
            status_name(commit_res.status)
        ));
    }
    println!("  [OK] Configuration committed to flash");

    let comm_res = device.request(0x08, &[]).map_err(|e| e.to_string())?;
    if comm_res.status != 0 {
        println!(
            "  Note: COMMISSION_DEVICE returned status 0x{:02x} ({})",
            comm_res.status,
            status_name(comm_res.status)
        );
    } else {
        println!("  [OK] Device lifecycle transitioned to Commissioned");
    }

    println!(
        "\nProvisioning complete! Device will detach and re-enumerate with the new descriptors."
    );
    Ok(ExitCode::SUCCESS)
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
  --key-stdin           read the PIV management key from stdin (pipe, no echo)
  --old-key-stdin       read the current PIV management key from stdin (needs --key-stdin)
  --reader <SUBSTR>     reader filter for piv-set-mgmt-key
  --alg <ALG>           PIV management algorithm (tdes, aes128, aes192, aes256)
  -h, --help            show this help
  -V, --version         show version

SECRETS:
  Secrets are never accepted in argv (the OS exposes the command line and shell
  history). Use the hidden interactive prompt when stdin is a terminal, or pipe
  the secret through --key-stdin/--old-key-stdin for automation. If a secret was
  ever passed in argv, rotate it and clear the shell history.

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
  provision [OPTIONS]   provision board hardware post-flash (product, VID/PID, LED, ...)
  status                GET_STATUS
  diagnostics           GET_DIAGNOSTICS
  decommission          DECOMMISSION_DEVICE
  factory-reset         FACTORY_RESET
  soft-detach           SOFT_DETACH (acknowledged, then leave the bus)
  last-fido             GET_LAST_FIDO_STATUS
  send <CMD> [HEX|@FILE]       send a raw command (CMD decimal or 0x hex)
  validate              run the Management HID acceptance checks

SMART CARD / CCID COMMANDS (PC/SC):
  card-list                                   list PC/SC smart card readers
  card-status [READER]                        connect and show ATR and protocol
  card-select <AID> [READER]                  SELECT an applet by AID (piv, oath, openpgp or hex)
  card-apdu <HEX> [READER]                    transmit a raw APDU and show the response

PIV / NIST SP 800-73-4 COMMANDS (PC/SC):
  piv-list [READER]                           list certificates in slots (9A, 9C, 9D, 9E)
  piv-import-cert <SLOT> <CERT_FILE> [READER] [--key-stdin]
                                              import X.509 cert (PEM/DER) into PIV slot
  piv-set-mgmt-key [--reader SUBSTR] [--alg ALG] [--key-stdin [--old-key-stdin]]
                                              replace PIV management key (3DES/AES)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const SECRET: &str = "00112233445566778899aabbccddeeff";

    fn parse_ok(args: &[&str]) -> Cli {
        parse(args.iter().map(|arg| arg.to_string())).expect("parse")
    }

    #[test]
    fn secret_options_are_rejected_without_echoing_the_value() {
        let cases = [
            vec![
                "piv-set-mgmt-key".to_string(),
                "--key".to_string(),
                SECRET.to_string(),
            ],
            vec!["piv-set-mgmt-key".to_string(), format!("--key={SECRET}")],
            vec![
                "piv-set-mgmt-key".to_string(),
                "--old-key".to_string(),
                SECRET.to_string(),
            ],
            vec![
                "piv-set-mgmt-key".to_string(),
                format!("--old-key={SECRET}"),
            ],
            // Single-dash typos must not smuggle the value into the message.
            vec!["piv-set-mgmt-key".to_string(), format!("-key={SECRET}")],
            vec!["piv-set-mgmt-key".to_string(), format!("-old-key={SECRET}")],
            // The import command shares the same option parser.
            vec![
                "piv-import-cert".to_string(),
                "9A".to_string(),
                "cert.pem".to_string(),
                "--key".to_string(),
                SECRET.to_string(),
            ],
            vec![
                "piv-import-cert".to_string(),
                "9A".to_string(),
                "cert.pem".to_string(),
                format!("--key={SECRET}"),
            ],
        ];
        for args in cases {
            let error = parse(args).err().expect("rejected");
            assert!(
                error.contains("--key-stdin")
                    || error.contains("--old-key-stdin")
                    || error.contains("unknown option"),
                "{error}"
            );
            assert!(!error.contains(SECRET), "{error}");
        }
    }

    #[test]
    fn unknown_option_reports_only_the_name() {
        for token in [format!("--keyx={SECRET}"), format!("-keyx={SECRET}")] {
            let error = parse([token]).err().expect("rejected");
            assert!(error.contains("keyx"), "{error}");
            assert!(!error.contains(SECRET), "{error}");
        }
    }

    #[test]
    fn stdin_flags_reject_an_inline_value() {
        for args in [
            vec!["piv-set-mgmt-key", "--key-stdin=x"],
            vec!["piv-set-mgmt-key", "--key-stdin", "--old-key-stdin=x"],
        ] {
            let error = parse(args.iter().map(|arg| arg.to_string()))
                .err()
                .expect("rejected");
            assert!(error.contains("takes no value"), "{error}");
        }
    }

    #[test]
    fn positional_management_key_is_rejected_without_echo() {
        let error = run(["piv-set-mgmt-key".to_string(), SECRET.to_string()]).unwrap_err();
        assert!(error.contains("positional"), "{error}");
        assert!(!error.contains(SECRET), "{error}");
    }

    #[test]
    fn stdin_key_needs_no_terminal_and_reads_new_then_old() {
        let cli = parse_ok(&["piv-set-mgmt-key", "--key-stdin", "--old-key-stdin"]);
        let mut stdin = Cursor::new(format!("{SECRET}\nffeeddccbbaa99887766554433221100\n"));
        let (new_key, old_key) =
            acquire_mgmt_key(&cli, false, &mut stdin, &mut |_| unreachable!()).unwrap();
        assert_eq!(new_key, secret::parse_hex(SECRET, "k").unwrap());
        assert_eq!(
            old_key,
            Some(secret::parse_hex("ffeeddccbbaa99887766554433221100", "k").unwrap())
        );
    }

    #[test]
    fn stdin_key_without_old_key_keeps_the_nist_default() {
        let cli = parse_ok(&["piv-set-mgmt-key", "--key-stdin"]);
        let mut stdin = Cursor::new(format!("{SECRET}\n"));
        let (_, old_key) =
            acquire_mgmt_key(&cli, false, &mut stdin, &mut |_| unreachable!()).unwrap();
        assert_eq!(old_key, None);
    }

    #[test]
    fn stdin_key_refuses_a_terminal() {
        let cli = parse_ok(&["piv-set-mgmt-key", "--key-stdin"]);
        let mut stdin = Cursor::new(format!("{SECRET}\n"));
        let error = acquire_mgmt_key(&cli, true, &mut stdin, &mut |_| unreachable!()).unwrap_err();
        assert!(error.contains("pipe"), "{error}");
    }

    #[test]
    fn old_key_stdin_requires_key_stdin() {
        let cli = parse_ok(&["piv-set-mgmt-key", "--old-key-stdin"]);
        let mut stdin = Cursor::new("");
        let error = acquire_mgmt_key(&cli, false, &mut stdin, &mut |_| unreachable!()).unwrap_err();
        assert!(error.contains("--key-stdin"), "{error}");
    }

    #[test]
    fn prompt_path_requires_a_terminal() {
        let cli = parse_ok(&["piv-set-mgmt-key"]);
        let mut stdin = Cursor::new("");
        let error = acquire_mgmt_key(&cli, false, &mut stdin, &mut |_| unreachable!()).unwrap_err();
        assert!(error.contains("--key-stdin"), "{error}");
    }

    #[test]
    fn prompt_path_confirms_and_defaults_an_empty_old_key() {
        let cli = parse_ok(&["piv-set-mgmt-key"]);
        let mut stdin = Cursor::new("");
        let mut answers = vec![SECRET, SECRET, ""].into_iter();
        let mut prompt = |_: &str| Ok(answers.next().expect("prompted").to_string());
        let (new_key, old_key) = acquire_mgmt_key(&cli, true, &mut stdin, &mut prompt).unwrap();
        assert_eq!(new_key.len(), 16);
        assert_eq!(old_key, None);
    }

    #[test]
    fn prompt_path_rejects_a_mismatch_without_echo() {
        let cli = parse_ok(&["piv-set-mgmt-key"]);
        let mut stdin = Cursor::new("");
        let mut answers = vec![SECRET, "ffeeddccbbaa99887766554433221100"].into_iter();
        let mut prompt = |_: &str| Ok(answers.next().expect("prompted").to_string());
        let error = acquire_mgmt_key(&cli, true, &mut stdin, &mut prompt).unwrap_err();
        assert!(error.contains("match"), "{error}");
        assert!(!error.contains(SECRET), "{error}");
    }

    #[test]
    fn import_key_is_stdin_only() {
        let cli = parse_ok(&["piv-import-cert", "9A", "cert.pem", "--key-stdin"]);
        let mut stdin = Cursor::new(format!("{SECRET}\n"));
        assert_eq!(
            acquire_import_key(&cli, false, &mut stdin).unwrap(),
            Some(secret::parse_hex(SECRET, "k").unwrap())
        );

        let cli = parse_ok(&["piv-import-cert", "9A", "cert.pem"]);
        let mut stdin = Cursor::new("");
        assert_eq!(acquire_import_key(&cli, false, &mut stdin).unwrap(), None);

        let cli = parse_ok(&["piv-import-cert", "9A", "cert.pem", "--key-stdin"]);
        let mut stdin = Cursor::new(format!("{SECRET}\n"));
        assert!(acquire_import_key(&cli, true, &mut stdin).is_err());
    }

    #[test]
    fn import_key_validates_the_length_before_touching_the_card() {
        let cli = parse_ok(&["piv-import-cert", "9A", "cert.pem", "--key-stdin"]);
        let mut stdin = Cursor::new("001122334455\n");
        let error = acquire_import_key(&cli, false, &mut stdin).unwrap_err();
        assert!(error.contains("length 6"), "{error}");
        assert!(error.contains("16, 24, or 32"), "{error}");
    }

    #[test]
    fn misplaced_options_are_rejected() {
        let cli = parse_ok(&["--reader", "X", "info"]);
        assert!(reject_misplaced_options(&cli, "info").is_err());

        let cli = parse_ok(&["--alg", "aes256", "info"]);
        assert!(reject_misplaced_options(&cli, "info").is_err());

        // `list` must not silently swallow secret/reader options either.
        let cli = parse_ok(&["--key-stdin", "list"]);
        assert!(reject_misplaced_options(&cli, "list").is_err());

        let cli = parse_ok(&["piv-set-mgmt-key", "--reader", "X", "--alg", "aes256"]);
        assert!(reject_misplaced_options(&cli, "piv-set-mgmt-key").is_ok());
    }
}
