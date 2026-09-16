//! Device identity (PRD §8, §9).
//!
//! Identity is split into three independent entities so none of them leaks into
//! the others:
//!
//! - **Board Identity** ([`BoardIdentity`]) — the vendor, product, board model,
//!   hardware revision and USB `vendor_id`/`product_id` a carrier board
//!   declares. It changes with the board and product.
//! - **MCU Identity** ([`McuIdentity`]) — the RP2350 variant (family, package,
//!   silicon revision) and the unique 64-bit `CHIPID` fused into OTP. It comes
//!   from the chip installed on the board, so replacing or resourcing the board
//!   never confuses which chip is which.
//! - **Board Hardware Profile** ([`crate::hardware_profile`]) — the LED,
//!   presence and flash wiring, which varies per board without touching the
//!   firmware core.

use crate::capabilities::{Rp2350Family, Rp2350Package};

/// Number of lowercase hex digits in a formatted chip identifier.
pub const CHIP_ID_HEX_LEN: usize = 16;

/// Chip identifier used when OTP is not readable (e.g. locked by the boot
/// process).
///
/// A single constant keeps the MCU identity reported to the host and the USB
/// serial number derived from it consistent.
pub const FALLBACK_UNIQUE_ID: u64 = 0;

/// Maximum length, in bytes, of a board identity string.
pub const MAX_BOARD_IDENTITY_LEN: usize = 64;

/// Identity declared by a carrier board and the product built around it.
///
/// This is the **Board Identity**: vendor, product, board model, hardware
/// revision and the USB `vendor_id`/`product_id` presented to the host. It
/// changes with the carrier board, whereas the MCU identity ([`McuIdentity`])
/// comes from the RP2350 installed on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoardIdentity {
    /// Board/product manufacturer (USB `iManufacturer`).
    pub manufacturer: &'static str,
    /// Product string (USB `iProduct`).
    pub product: &'static str,
    /// Carrier board model (e.g. `RP2350-Zero`, `Pico 2`).
    pub board: &'static str,
    /// Hardware revision of the carrier board.
    pub revision: u8,
    /// USB vendor identifier presented to the host.
    pub vendor_id: u16,
    /// USB product identifier presented to the host.
    pub product_id: u16,
}

impl BoardIdentity {
    /// Build a board identity from its strings, board revision and USB IDs.
    #[must_use]
    pub const fn new(
        manufacturer: &'static str,
        product: &'static str,
        board: &'static str,
        revision: u8,
        vendor_id: u16,
        product_id: u16,
    ) -> Self {
        Self {
            manufacturer,
            product,
            board,
            revision,
            vendor_id,
            product_id,
        }
    }
}

/// Identity of the MCU the firmware is running on, discovered from the chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McuIdentity {
    /// Die family (RP2350 or RP2354).
    pub family: Rp2350Family,
    /// Physical package, from `SYSINFO.PACKAGE_SEL`.
    pub package: Rp2350Package,
    /// Silicon revision, from `SYSINFO.CHIP_ID.REVISION`.
    pub revision: u8,
    /// Unique 64-bit `CHIPID` fused into OTP.
    ///
    /// Highly likely, though not guaranteed, to be unique; it is an
    /// identifier, never a cryptographic secret.
    pub unique_id: u64,
}

impl McuIdentity {
    /// Build an MCU identity from the discovered chip facts.
    #[must_use]
    pub const fn new(
        family: Rp2350Family,
        package: Rp2350Package,
        revision: u8,
        unique_id: u64,
    ) -> Self {
        Self {
            family,
            package,
            revision,
            unique_id,
        }
    }

    /// The unique chip identifier as 16 lowercase hex digits, MSB first.
    #[must_use]
    pub fn unique_id_hex(&self) -> [u8; CHIP_ID_HEX_LEN] {
        chip_id_hex(self.unique_id)
    }
}

/// Format a unique 64-bit chip identifier as 16 lowercase hex digits, most
/// significant nibble first.
#[must_use]
pub fn chip_id_hex(chip_id: u64) -> [u8; CHIP_ID_HEX_LEN] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [b'0'; CHIP_ID_HEX_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        let shift = 4 * (CHIP_ID_HEX_LEN - 1 - index);
        *byte = HEX[((chip_id >> shift) & 0xF) as usize];
    }
    out
}

/// Extract the silicon revision from a raw `SYSINFO.CHIP_ID` value.
///
/// `REVISION` occupies bits 31:28 of the JEDEC JEP-106 register.
#[must_use]
pub const fn chip_revision(chip_id: u32) -> u8 {
    ((chip_id >> 28) & 0x0F) as u8
}

/// Extract the JEDEC part number from a raw `SYSINFO.CHIP_ID` value.
///
/// `PART` occupies bits 27:12 of the JEDEC JEP-106 register.
#[must_use]
pub const fn chip_part(chip_id: u32) -> u16 {
    ((chip_id >> 12) & 0xFFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_nibbles_most_significant_first() {
        assert_eq!(chip_id_hex(0), *b"0000000000000000");
        assert_eq!(chip_id_hex(0x0123_4567_89AB_CDEF), *b"0123456789abcdef");
        assert_eq!(chip_id_hex(u64::MAX), *b"ffffffffffffffff");
    }

    #[test]
    fn output_is_always_ascii_hex() {
        let formatted = chip_id_hex(0xDEAD_BEEF_CAFE_1234);
        assert_eq!(&formatted, b"deadbeefcafe1234");
        assert!(formatted.iter().all(u8::is_ascii_hexdigit));
    }

    #[test]
    fn chip_id_fields_match_the_jedec_layout() {
        // REVISION=0x3 (bits 31:28), PART=0x0004 (bits 27:12),
        // MANUFACTURER=0x493 (bits 11:1), STOP=1 (bit 0).
        let chip_id = 0x3000_4927;
        assert_eq!(chip_revision(chip_id), 0x3);
        assert_eq!(chip_part(chip_id), 0x0004);
    }

    #[test]
    fn chip_id_field_extraction_masks_to_the_field_width() {
        assert_eq!(chip_revision(0xFFFF_FFFF), 0xF);
        assert_eq!(chip_part(0xFFFF_FFFF), 0xFFFF);
        assert_eq!(chip_revision(0), 0);
        assert_eq!(chip_part(0), 0);
    }

    #[test]
    fn board_identity_carries_fields_verbatim() {
        let identity = BoardIdentity::new(
            "Waveshare",
            "RP2350 FIDO Token",
            "RP2350-Zero",
            2,
            0x2E8A,
            0x10B0,
        );
        assert_eq!(identity.manufacturer, "Waveshare");
        assert_eq!(identity.product, "RP2350 FIDO Token");
        assert_eq!(identity.board, "RP2350-Zero");
        assert_eq!(identity.revision, 2);
        assert_eq!(identity.vendor_id, 0x2E8A);
        assert_eq!(identity.product_id, 0x10B0);
        assert!(identity.manufacturer.len() <= MAX_BOARD_IDENTITY_LEN);
        assert!(identity.product.len() <= MAX_BOARD_IDENTITY_LEN);
    }

    #[test]
    fn mcu_identity_formats_unique_id() {
        let mcu = McuIdentity::new(
            Rp2350Family::Rp2350,
            Rp2350Package::Qfn60,
            3,
            0x0123_4567_89AB_CDEF,
        );
        assert_eq!(mcu.unique_id_hex(), *b"0123456789abcdef");
        assert_eq!(mcu.family, Rp2350Family::Rp2350);
        assert_eq!(mcu.package, Rp2350Package::Qfn60);
        assert_eq!(mcu.revision, 3);
    }
}
