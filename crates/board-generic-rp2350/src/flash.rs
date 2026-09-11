//! QSPI flash storage (PRD §24).
//!
//! Wraps the blocking `embassy-rp` flash driver so the firmware can persist
//! configuration and, later, sealed secrets through the hardware-agnostic
//! [`Storage`] trait. Callers are responsible for atomic record layout; this
//! type only maps offsets to the flash device.

use aegis_core::error::CoreError;
use aegis_core::traits::Storage;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;

/// Blocking flash storage adapter.
pub struct FlashStorage<const FLASH_SIZE: usize> {
    flash: Flash<'static, FLASH, Blocking, FLASH_SIZE>,
}

impl<const FLASH_SIZE: usize> FlashStorage<FLASH_SIZE> {
    /// Wrap an initialized blocking flash driver.
    #[must_use]
    pub fn new(flash: Flash<'static, FLASH, Blocking, FLASH_SIZE>) -> Self {
        Self { flash }
    }
}

impl<const FLASH_SIZE: usize> Storage for FlashStorage<FLASH_SIZE> {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), CoreError> {
        self.flash
            .blocking_read(offset, buf)
            .map_err(|_| CoreError::StorageError)
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), CoreError> {
        self.flash
            .blocking_write(offset, data)
            .map_err(|_| CoreError::StorageError)
    }

    fn erase(&mut self, offset: u32, len: u32) -> Result<(), CoreError> {
        self.flash
            .blocking_erase(offset, offset + len)
            .map_err(|_| CoreError::StorageError)
    }
}
