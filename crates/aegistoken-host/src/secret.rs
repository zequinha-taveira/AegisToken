//! Secret acquisition for the host CLI.
//!
//! A secret is never accepted from `argv`: the OS exposes a process command
//! line to other local processes (`ps`, `/proc/<pid>/cmdline`, Task Manager,
//! WMI) and keeps it in shell history. The only channels are a hidden
//! interactive prompt (TTY) and stdin (automation, fed by a pipe).
//!
//! Error messages describe only the *shape* of an invalid secret, never the
//! value or a fragment of it.

use std::io::BufRead;

/// Read one secret line from `reader`, stripping the trailing line ending.
///
/// An empty line or a closed stdin is an error: silently falling back to an
/// empty secret would turn a broken pipe into a failed operation with an
/// unexpected key.
pub fn read_line(reader: &mut impl BufRead) -> Result<String, String> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|error| format!("cannot read the secret from stdin: {error}"))?;
    if read == 0 {
        return Err("stdin closed before a secret was read".to_string());
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err("empty line on stdin: expected the secret".to_string());
    }
    Ok(trimmed.to_string())
}

/// Parse a hex-encoded secret, reporting only its shape on failure.
pub fn parse_hex(value: &str, what: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != ':')
        .collect();
    let digits = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if digits.is_empty() {
        return Err(format!("{what}: expected hexadecimal, got an empty value"));
    }
    if digits.len() % 2 != 0 {
        return Err(format!(
            "{what}: expected an even number of hex digits, got {}",
            digits.len()
        ));
    }
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{what}: expected hexadecimal ({} digits, {} bytes)",
            digits.len(),
            digits.len() / 2
        ));
    }
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16)
                .map_err(|_| format!("{what}: expected hexadecimal"))
        })
        .collect()
}

/// Read a secret from the terminal without echoing it.
pub fn prompt(prompt: &str) -> Result<String, String> {
    rpassword::prompt_password(prompt)
        .map_err(|error| format!("cannot read the secret from the terminal: {error}"))
}

/// Whether stdin is an interactive terminal.
pub fn stdin_is_tty() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_one_line_without_the_line_ending() {
        let mut input = Cursor::new(b"0123456789abcdef\r\nsecond\n");
        assert_eq!(
            read_line(&mut input).unwrap(),
            "0123456789abcdef".to_string()
        );
        assert_eq!(read_line(&mut input).unwrap(), "second".to_string());
    }

    #[test]
    fn rejects_empty_and_closed_input() {
        assert!(read_line(&mut Cursor::new(b"\n")).is_err());
        assert!(read_line(&mut Cursor::new(b"\r\n")).is_err());
        assert!(read_line(&mut Cursor::new(b"")).is_err());
    }

    #[test]
    fn parses_hex_with_separators() {
        assert_eq!(
            parse_hex("00 11:22_33", "key").unwrap(),
            vec![0x00, 0x11, 0x22, 0x33]
        );
        assert_eq!(parse_hex("0xAABB", "key").unwrap(), vec![0xAA, 0xBB]);
    }

    #[test]
    fn errors_never_echo_the_value() {
        let sentinel = "S3NT1NELzz";
        for input in [sentinel, "ABC", "", "0x", "GG"] {
            let error = parse_hex(input, "management key").unwrap_err();
            assert!(!error.contains(sentinel), "{error}");
            assert!(!error.contains('z'), "{error}");
            assert!(error.starts_with("management key: "), "{error}");
        }
    }
}
