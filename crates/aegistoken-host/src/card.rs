//! Smart card / CCID interface over PC/SC for AegisToken.
//!
//! Provides reader enumeration, card activation, status/ATR inspection,
//! AID selection and raw APDU transmission using the safe `pcsc` crate.

use std::ffi::CStr;
use std::process::ExitCode;

use iso7816::Status as IsoStatus;
use iso7816::command::CommandView;
use pcsc::{
    Card, Context, MAX_ATR_SIZE, MAX_BUFFER_SIZE, Protocol, Protocols, Scope, ShareMode, Status,
};

/// Known Application Identifiers (AIDs) in AegisToken.
pub const AID_PIV: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];
pub const AID_OATH: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
pub const AID_OPENPGP: &[u8] = &[
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Resolve an AID from an alias ("piv", "oath", "openpgp") or hex string.
pub fn resolve_aid(input: &str) -> Result<Vec<u8>, String> {
    match input.to_ascii_lowercase().as_str() {
        "piv" => Ok(AID_PIV.to_vec()),
        "oath" => Ok(AID_OATH.to_vec()),
        "openpgp" | "gpg" | "pgp" => Ok(AID_OPENPGP.to_vec()),
        _ => parse_hex(input),
    }
}

/// Parse a hex string (ignoring spaces and colons).
pub fn parse_hex(hex: &str) -> Result<Vec<u8>, String> {
    let clean: String = hex
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if clean.len() % 2 != 0 {
        return Err(format!(
            "hex string has odd length ({} digits)",
            clean.len()
        ));
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16)
                .map_err(|e| format!("invalid hex byte '{}': {e}", &clean[i..i + 2]))
        })
        .collect()
}

/// Format bytes as uppercase hex string.
pub fn format_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Format an ISO 7816 status word (SW1, SW2) with mnemonic.
pub fn format_iso_status(sw1: u8, sw2: u8) -> String {
    let status = IsoStatus::from([sw1, sw2]);
    format!("{sw1:02X}{sw2:02X} ({status:?})")
}

/// List all available PC/SC smart card readers.
pub fn list_readers() -> Result<ExitCode, String> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;

    let mut readers_buf = [0; 2048];
    let readers = match ctx.list_readers(&mut readers_buf) {
        Ok(r) => r,
        Err(pcsc::Error::NoReadersAvailable) => {
            println!("No PC/SC smart card readers found.");
            println!(
                "  * Windows: verify that the smart card service is running and CCID driver is bound."
            );
            println!("  * Linux: verify pcscd daemon is active ('systemctl status pcscd').");
            return Ok(ExitCode::SUCCESS);
        }
        Err(e) => return Err(format!("failed to list smart card readers: {e}")),
    };

    let list: Vec<&CStr> = readers.collect();
    if list.is_empty() {
        println!("No PC/SC smart card readers found.");
        return Ok(ExitCode::SUCCESS);
    }

    println!("Available PC/SC Smart Card Readers ({}):", list.len());
    for (i, reader) in list.iter().enumerate() {
        let name = reader.to_str().unwrap_or("<invalid utf-8>");
        let is_aegis = name.to_ascii_lowercase().contains("aegis");
        let marker = if is_aegis { " [AegisToken]" } else { "" };
        println!("  [{i}] {name}{marker}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Connect to a reader matching the filter, or the first AegisToken reader, or the first reader.
pub fn connect_card<'a>(
    ctx: &'a Context,
    reader_filter: Option<&str>,
    readers_buf: &'a mut [u8],
) -> Result<(Card, String), String> {
    let readers = ctx
        .list_readers(readers_buf)
        .map_err(|e| format!("failed to list readers: {e}"))?;
    let list: Vec<&CStr> = readers.collect();
    if list.is_empty() {
        return Err("no PC/SC smart card readers found".to_string());
    }

    let target = if let Some(needle) = reader_filter {
        let needle_lower = needle.to_ascii_lowercase();
        list.into_iter()
            .find(|r| {
                r.to_str()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&needle_lower)
            })
            .ok_or_else(|| format!("no reader matching '{needle}' found"))?
    } else {
        // Prefer reader with "aegis" in name, otherwise first reader
        if let Some(aegis) = list.iter().copied().find(|r| {
            r.to_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("aegis")
        }) {
            aegis
        } else {
            list[0]
        }
    };

    let reader_name = target.to_str().unwrap_or("unknown").to_string();
    let card = ctx
        .connect(target, ShareMode::Shared, Protocols::ANY)
        .map_err(|e| format!("failed to connect to card on '{reader_name}': {e}"))?;
    Ok((card, reader_name))
}

/// Print status and ATR of the connected card.
pub fn card_status(reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    let mut reader_name_buf = [0; 256];
    let mut atr_buf = [0; MAX_ATR_SIZE];
    let status = card
        .status2(&mut reader_name_buf, &mut atr_buf)
        .map_err(|e| format!("failed to query card status: {e}"))?;

    let atr = status.atr();
    let proto_desc = match status.protocol2() {
        Some(Protocol::T0) => "T=0",
        Some(Protocol::T1) => "T=1",
        Some(Protocol::RAW) => "RAW",
        None => "Unknown / Undefined",
    };

    let card_st = status.status();
    let state_desc = if card_st.contains(Status::PRESENT) {
        "Card Present"
    } else if card_st.contains(Status::ABSENT) {
        "Card Absent"
    } else {
        "Connected"
    };

    println!("Reader:   {reader_name}");
    println!("State:    {state_desc}");
    println!("Protocol: {proto_desc}");
    println!("ATR:      {}", format_hex(atr));
    if atr == [0x3B, 0x00] {
        println!("          (Standard AegisToken CCID short ATR: 3B 00)");
    }

    Ok(ExitCode::SUCCESS)
}

/// Select an applet by AID and display the response and status word.
pub fn select_applet(aid_arg: &str, reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let aid = resolve_aid(aid_arg)?;
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader:     {reader_name}");
    println!("Target AID: {} ({aid_arg})", format_hex(&aid));

    // Construct SELECT APDU: CLA=00 INS=A4 P1=04 P2=00 Lc=len(AID) Data=AID
    let mut apdu = Vec::with_capacity(5 + aid.len());
    apdu.extend_from_slice(&[0x00, 0xA4, 0x04, 0x00, aid.len() as u8]);
    apdu.extend_from_slice(&aid);

    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card
        .transmit(&apdu, &mut rapdu_buf)
        .map_err(|e| format!("APDU transmission failed: {e}"))?;

    if rapdu.len() < 2 {
        return Err("response too short (less than 2 bytes)".to_string());
    }

    let sw1 = rapdu[rapdu.len() - 2];
    let sw2 = rapdu[rapdu.len() - 1];
    let body = &rapdu[..rapdu.len() - 2];

    println!("Status:     {}", format_iso_status(sw1, sw2));
    if !body.is_empty() {
        println!("Response:   {} ({} bytes)", format_hex(body), body.len());
    }

    if (sw1, sw2) == (0x90, 0x00) {
        println!("Result:     OK (Applet successfully selected)");
        Ok(ExitCode::SUCCESS)
    } else if (sw1, sw2) == (0x6A, 0x82) {
        println!("Result:     File/Application Not Found (6A82)");
        Ok(ExitCode::FAILURE)
    } else {
        println!("Result:     Returned SW {sw1:02X}{sw2:02X}");
        Ok(ExitCode::FAILURE)
    }
}

/// Transmit a raw APDU in hexadecimal and display the response.
pub fn transmit_raw(apdu_hex: &str, reader_filter: Option<&str>) -> Result<ExitCode, String> {
    let apdu = parse_hex(apdu_hex)?;
    let ctx = Context::establish(Scope::User)
        .map_err(|e| format!("failed to establish PC/SC context: {e}"))?;
    let mut readers_buf = [0; 2048];
    let (card, reader_name) = connect_card(&ctx, reader_filter, &mut readers_buf)?;

    println!("Reader:   {reader_name}");
    println!("Tx APDU:  {} ({} bytes)", format_hex(&apdu), apdu.len());
    if let Ok(cmd) = CommandView::try_from(apdu.as_slice()) {
        println!(
            "ISO 7816: {:?} (0x{:02X}), P1=0x{:02X}, P2=0x{:02X}, Lc={}, Le={}",
            cmd.instruction(),
            u8::from(cmd.instruction()),
            cmd.p1,
            cmd.p2,
            cmd.data().len(),
            cmd.expected()
        );
    }

    let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
    let rapdu = card
        .transmit(&apdu, &mut rapdu_buf)
        .map_err(|e| format!("APDU transmission failed: {e}"))?;

    if rapdu.len() < 2 {
        return Err("response too short (less than 2 bytes)".to_string());
    }

    let sw1 = rapdu[rapdu.len() - 2];
    let sw2 = rapdu[rapdu.len() - 1];
    let body = &rapdu[..rapdu.len() - 2];

    println!("Status:   {}", format_iso_status(sw1, sw2));
    if !body.is_empty() {
        println!("Rx Body:  {} ({} bytes)", format_hex(body), body.len());
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_valid() {
        assert_eq!(
            parse_hex("00 a4 04 00").unwrap(),
            vec![0x00, 0xA4, 0x04, 0x00]
        );
        assert_eq!(parse_hex("3B:00").unwrap(), vec![0x3B, 0x00]);
        assert_eq!(
            parse_hex("A000000308").unwrap(),
            vec![0xA0, 0x00, 0x00, 0x03, 0x08]
        );
    }

    #[test]
    fn parse_hex_invalid() {
        assert!(parse_hex("ABC").is_err());
        assert!(parse_hex("ZZ").is_err());
    }

    #[test]
    fn resolve_aid_aliases() {
        assert_eq!(resolve_aid("piv").unwrap(), AID_PIV);
        assert_eq!(resolve_aid("oath").unwrap(), AID_OATH);
        assert_eq!(resolve_aid("openpgp").unwrap(), AID_OPENPGP);
        assert_eq!(resolve_aid("A0000005272101").unwrap(), AID_OATH);
    }

    #[test]
    fn format_hex_works() {
        assert_eq!(format_hex(&[0x3B, 0x00, 0x90, 0x00]), "3B009000");
    }

    #[test]
    fn iso_status_formatting() {
        let ok = format_iso_status(0x90, 0x00);
        assert!(ok.contains("9000"));
        assert!(ok.contains("Success"));

        let not_found = format_iso_status(0x6A, 0x82);
        assert!(not_found.contains("6A82"));
        assert!(not_found.contains("NotFound"));
    }

    #[test]
    fn iso_command_view_decodes_select() {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, 0x07];
        apdu.extend_from_slice(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00]);
        let cmd = CommandView::try_from(apdu.as_slice()).expect("valid SELECT APDU");
        assert_eq!(cmd.instruction(), iso7816::Instruction::Select);
        assert_eq!(cmd.p1, 0x04);
        assert_eq!(cmd.p2, 0x00);
        assert_eq!(cmd.data().len(), 7);
    }
}
