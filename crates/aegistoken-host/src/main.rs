//! `aegistoken-host` — host-side CLI for the AegisToken device.
//!
//! Talks to the Management HID interface through libusb. On Windows libusb uses
//! its HID backend, so no WinUSB/Zadig driver is required.

#![forbid(unsafe_code)]

mod cli;
mod framing;
mod transport;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run(std::env::args().skip(1)) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
