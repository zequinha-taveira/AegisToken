//! OTP-backed device root key (PRD §25).
//!
//! The 256-bit root key is read from a reserved OTP row range and never leaves
//! the chip. Provisioning (fusing) is a production step performed with the
//! vendor tooling; this module only reads and fails closed when the key is not
//! present.

use aegis_core::error::CoreError;
use aegis_core::secret::KEY_LEN;
use embassy_rp::otp::{NUM_ROWS, read_ecc_word};

/// First OTP row of the device root key (ECC rows, 16-bit words).
pub const ROOT_KEY_ROW: usize = 0x0E90;

/// Number of 16-bit OTP words making up the root key.
pub const ROOT_KEY_WORDS: usize = KEY_LEN / 2;

/// Read the device root key from OTP.
///
/// Returns [`CoreError::StorageError`] when the range is out of bounds or the
/// key has not been provisioned (all-zero or all-ones).
pub fn read_root_key() -> Result<[u8; KEY_LEN], CoreError> {
    if ROOT_KEY_ROW + ROOT_KEY_WORDS > NUM_ROWS {
        return Err(CoreError::StorageError);
    }

    let mut key = [0u8; KEY_LEN];
    let mut all_zero = true;
    let mut all_ones = true;

    for index in 0..ROOT_KEY_WORDS {
        let word = read_ecc_word(ROOT_KEY_ROW + index).map_err(|_| CoreError::StorageError)?;
        key[index * 2..index * 2 + 2].copy_from_slice(&word.to_le_bytes());
        all_zero &= word == 0;
        all_ones &= word == 0xFFFF;
    }

    if all_zero || all_ones {
        return Err(CoreError::StorageError);
    }
    Ok(key)
}

/// Read the unique 64-bit chip identifier fused into OTP rows `0x0..=0x3`.
///
/// This is the chip serial number, distinct from the JEDEC `SYSINFO.CHIP_ID`
/// part/revision. It gives each device a stable identity independent of the
/// carrier board, and is used to derive the USB serial number.
///
/// Raspberry Pi describes this serial as highly likely but not guaranteed to be
/// unique, so it must not be treated as a cryptographic identifier; the sealed
/// per-device key remains the security boundary.
///
/// Returns [`CoreError::StorageError`] when OTP is not readable (e.g. locked by
/// the boot process).
pub fn read_unique_id() -> Result<u64, CoreError> {
    embassy_rp::otp::get_chipid().map_err(|_| CoreError::StorageError)
}
