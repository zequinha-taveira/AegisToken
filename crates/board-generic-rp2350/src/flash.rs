//! QSPI flash storage (PRD §24).
//!
//! Wraps the blocking `embassy-rp` flash driver so the firmware can persist
//! configuration and, later, sealed secrets through the hardware-agnostic
//! [`Storage`] trait. Callers are responsible for atomic record layout; this
//! type only maps offsets to the flash device.

use aegis_core::error::CoreError;
use aegis_core::traits::Storage;
use core::cell::RefCell;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use embassy_sync::blocking_mutex::CriticalSectionMutex;

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

/// A base-offset window into the shared flash, usable as [`Storage`].
///
/// Housekeeping (config, staging) and the CCID task (applet stores) touch
/// disjoint flash regions through the same peripheral. Each `Storage` call
/// locks briefly; callers must never hold the guard across `.await`, and each
/// flash region has exactly one writer task, so per-call locking is safe.
#[derive(Clone, Copy)]
pub struct RegionStorage<'a, const FLASH_SIZE: usize> {
    lock: &'a CriticalSectionMutex<RefCell<FlashStorage<FLASH_SIZE>>>,
    base: u32,
}

impl<'a, const FLASH_SIZE: usize> RegionStorage<'a, FLASH_SIZE> {
    /// Open a window starting at the absolute flash `base` offset.
    #[must_use]
    pub const fn new(
        lock: &'a CriticalSectionMutex<RefCell<FlashStorage<FLASH_SIZE>>>,
        base: u32,
    ) -> Self {
        Self { lock, base }
    }

    /// A sub-window `offset` bytes into this window.
    #[must_use]
    pub const fn at(&self, offset: u32) -> Self {
        Self {
            lock: self.lock,
            base: self.base + offset,
        }
    }
}

impl<const FLASH_SIZE: usize> Storage for RegionStorage<'_, FLASH_SIZE> {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), CoreError> {
        let Some(base) = self.base.checked_add(offset) else {
            return Err(CoreError::StorageError);
        };
        self.lock.lock(|cell| {
            let mut storage = cell.borrow_mut();
            storage.read(base, buf)
        })
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), CoreError> {
        let Some(base) = self.base.checked_add(offset) else {
            return Err(CoreError::StorageError);
        };
        self.lock.lock(|cell| {
            let mut storage = cell.borrow_mut();
            storage.write(base, data)
        })
    }

    fn erase(&mut self, offset: u32, len: u32) -> Result<(), CoreError> {
        let Some(base) = self.base.checked_add(offset) else {
            return Err(CoreError::StorageError);
        };
        self.lock.lock(|cell| {
            let mut storage = cell.borrow_mut();
            storage.erase(base, len)
        })
    }
}
