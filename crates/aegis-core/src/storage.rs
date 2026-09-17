//! Atomic, power-fail-safe persistent storage (PRD §24).
//!
//! Configuration and sealed secrets are stored in two alternating slots. Each
//! record carries a monotonically increasing sequence number and a CRC-32 over
//! its payload. The newest valid record wins, so a torn erase or write leaves
//! the previous record intact and the device always boots from a consistent
//! state.

use crate::configuration::{DeviceConfig, crc32};
use crate::error::CoreError;
use crate::traits::Storage;

/// Magic identifying a storage slot record.
pub const SLOT_MAGIC: [u8; 4] = *b"AGSL";

/// Record header length: magic (4) + sequence (4) + version (2) + length (2) + CRC-32 (4).
pub const SLOT_HEADER_LEN: usize = 16;

/// On-flash record format version.
pub const RECORD_VERSION: u16 = 1;

/// Maximum payload stored in one record.
pub const MAX_PAYLOAD_BYTES: usize = 2304;

/// Number of alternating slots.
pub const SLOT_COUNT: u32 = 2;

/// A two-slot, sequence-numbered atomic record store.
pub struct SlotStore<S: Storage> {
    storage: S,
    base: u32,
    slot_size: u32,
}

impl<S: Storage> SlotStore<S> {
    /// Create a store with `slot_size` bytes per slot, starting at `base`.
    ///
    /// `slot_size` should equal the storage erase granularity (e.g. 4096).
    #[must_use]
    pub const fn new(storage: S, base: u32, slot_size: u32) -> Self {
        Self {
            storage,
            base,
            slot_size,
        }
    }

    const fn slot_offset(&self, index: u32) -> u32 {
        self.base + index * self.slot_size
    }

    fn read_slot(&mut self, index: u32, out: &mut [u8]) -> Result<Option<(u32, usize)>, CoreError> {
        let offset = self.slot_offset(index);
        let mut header = [0u8; SLOT_HEADER_LEN];
        self.storage.read(offset, &mut header)?;

        if header[0..4] != SLOT_MAGIC {
            return Ok(None);
        }
        let version = u16::from_le_bytes([header[8], header[9]]);
        if version != RECORD_VERSION {
            return Ok(None);
        }
        let sequence = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        let length = usize::from(u16::from_le_bytes([header[10], header[11]]));
        let expected_crc = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);

        if length > out.len() || length > MAX_PAYLOAD_BYTES {
            return Ok(None);
        }
        self.storage
            .read(offset + SLOT_HEADER_LEN as u32, &mut out[..length])?;
        if crc32(&out[..length]) != expected_crc {
            return Ok(None);
        }
        Ok(Some((sequence, length)))
    }

    fn scan(&mut self, scratch: &mut [u8]) -> Result<Option<(u32, u32)>, CoreError> {
        let mut best: Option<(u32, u32)> = None;
        for index in 0..SLOT_COUNT {
            if let Some((sequence, _length)) = self.read_slot(index, scratch)? {
                if best.is_none_or(|(best_sequence, _)| sequence > best_sequence) {
                    best = Some((sequence, index));
                }
            }
        }
        Ok(best)
    }

    /// Load one slot by index into `out`, returning `(sequence, length)`.
    ///
    /// Unlike [`SlotStore::load`], which resolves the newest valid record,
    /// this exposes individual slots so multi-shard stores can recover the
    /// newest generation present in *every* shard after a torn write.
    pub fn load_slot(
        &mut self,
        index: u32,
        out: &mut [u8],
    ) -> Result<Option<(u32, usize)>, CoreError> {
        if index >= SLOT_COUNT {
            return Err(CoreError::StorageError);
        }
        self.read_slot(index, out)
    }

    /// Load the newest valid record into `out`, returning `(sequence, length)`.
    pub fn load(&mut self, out: &mut [u8]) -> Result<Option<(u32, usize)>, CoreError> {
        let mut scratch = [0u8; MAX_PAYLOAD_BYTES];
        let mut best: Option<(u32, usize)> = None;
        for index in 0..SLOT_COUNT {
            if let Some((sequence, length)) = self.read_slot(index, &mut scratch)? {
                if best.is_none_or(|(best_sequence, _)| sequence > best_sequence) {
                    out[..length].copy_from_slice(&scratch[..length]);
                    best = Some((sequence, length));
                }
            }
        }
        Ok(best)
    }

    /// Atomically store a new record and return its sequence number.
    ///
    /// The inactive slot is erased and rewritten; the active slot is never
    /// touched, so an interrupted write cannot destroy the last valid record.
    pub fn store(&mut self, payload: &[u8]) -> Result<u32, CoreError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(CoreError::StorageError);
        }

        let mut scratch = [0u8; MAX_PAYLOAD_BYTES];
        let best = self.scan(&mut scratch)?;
        let (next_sequence, inactive) = match best {
            Some((sequence, index)) => (sequence.wrapping_add(1), 1 - index),
            None => (1, 0),
        };

        let mut header = [0u8; SLOT_HEADER_LEN];
        header[0..4].copy_from_slice(&SLOT_MAGIC);
        header[4..8].copy_from_slice(&next_sequence.to_le_bytes());
        header[8..10].copy_from_slice(&RECORD_VERSION.to_le_bytes());
        header[10..12].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        header[12..16].copy_from_slice(&crc32(payload).to_le_bytes());

        let offset = self.slot_offset(inactive);
        self.storage.erase(offset, self.slot_size)?;
        self.storage.write(offset, &header)?;
        self.storage
            .write(offset + SLOT_HEADER_LEN as u32, payload)?;
        Ok(next_sequence)
    }
}

/// Atomically persists the device configuration.
pub struct ConfigStorage<S: Storage> {
    slots: SlotStore<S>,
}

impl<S: Storage> ConfigStorage<S> {
    /// Create a configuration store.
    #[must_use]
    pub const fn new(storage: S, base: u32, slot_size: u32) -> Self {
        Self {
            slots: SlotStore::new(storage, base, slot_size),
        }
    }

    /// Load the persisted configuration, if any valid record exists.
    pub fn load(&mut self) -> Result<Option<DeviceConfig>, CoreError> {
        let mut buf = [0u8; MAX_PAYLOAD_BYTES];
        match self.slots.load(&mut buf)? {
            Some((_sequence, length)) => Ok(Some(DeviceConfig::decode(&buf[..length])?)),
            None => Ok(None),
        }
    }

    /// Persist a configuration, returning the new sequence number.
    pub fn commit(&mut self, config: &DeviceConfig) -> Result<u32, CoreError> {
        let mut buf = [0u8; MAX_PAYLOAD_BYTES];
        let length = config.encode(&mut buf)?;
        self.slots.store(&buf[..length])
    }
}

/// Atomically persists an opaque sealed secret blob.
///
/// There is deliberately no API that returns this material to a management
/// caller; only internal code that already holds the sealing key can open it.
pub struct SecretStorage<S: Storage> {
    slots: SlotStore<S>,
}

impl<S: Storage> SecretStorage<S> {
    /// Create a sealed-secret store.
    #[must_use]
    pub const fn new(storage: S, base: u32, slot_size: u32) -> Self {
        Self {
            slots: SlotStore::new(storage, base, slot_size),
        }
    }

    /// Load the sealed blob into `out`, returning `(sequence, length)`.
    pub fn load(&mut self, out: &mut [u8]) -> Result<Option<(u32, usize)>, CoreError> {
        self.slots.load(out)
    }

    /// Load one slot by index, returning `(sequence, length)`.
    ///
    /// Passthrough to [`SlotStore::load_slot`] for generational recovery in
    /// multi-shard sealed stores.
    pub fn load_slot(
        &mut self,
        index: u32,
        out: &mut [u8],
    ) -> Result<Option<(u32, usize)>, CoreError> {
        self.slots.load_slot(index, out)
    }

    /// Store a sealed blob, returning the new sequence number.
    pub fn store(&mut self, sealed: &[u8]) -> Result<u32, CoreError> {
        self.slots.store(sealed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{DeviceConfig, LedBehavior};

    const SLOT_SIZE: u32 = 4096;

    struct RamStorage {
        data: [u8; 16384],
    }

    impl RamStorage {
        fn new() -> Self {
            Self {
                data: [0xFF; 16384],
            }
        }
    }

    impl Storage for RamStorage {
        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), CoreError> {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(CoreError::StorageError);
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), CoreError> {
            let start = offset as usize;
            let end = start + data.len();
            if end > self.data.len() {
                return Err(CoreError::StorageError);
            }
            self.data[start..end].copy_from_slice(data);
            Ok(())
        }

        fn erase(&mut self, offset: u32, len: u32) -> Result<(), CoreError> {
            let start = offset as usize;
            let end = start + len as usize;
            if end > self.data.len() {
                return Err(CoreError::StorageError);
            }
            self.data[start..end].fill(0xFF);
            Ok(())
        }
    }

    fn config_with_behavior(behavior: LedBehavior) -> DeviceConfig {
        let mut config = DeviceConfig::official_defaults();
        config.led.behavior = behavior;
        config
    }

    #[test]
    fn empty_store_loads_nothing() {
        let mut store = ConfigStorage::new(RamStorage::new(), 0, SLOT_SIZE);
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn commit_then_load_round_trips() {
        let mut store = ConfigStorage::new(RamStorage::new(), 0, SLOT_SIZE);
        let config = config_with_behavior(LedBehavior::Solid);
        let sequence = store.commit(&config).unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(store.load().unwrap(), Some(config));
    }

    #[test]
    fn newest_record_wins_and_alternates_slots() {
        let mut store = ConfigStorage::new(RamStorage::new(), 0, SLOT_SIZE);
        let first = config_with_behavior(LedBehavior::Solid);
        let second = config_with_behavior(LedBehavior::Blink);

        assert_eq!(store.commit(&first).unwrap(), 1);
        assert_eq!(store.commit(&second).unwrap(), 2);
        assert_eq!(store.load().unwrap(), Some(second));
    }

    #[test]
    fn torn_write_falls_back_to_previous_record() {
        let mut storage = RamStorage::new();
        {
            let mut store = ConfigStorage::new(&mut storage, 0, SLOT_SIZE);
            store
                .commit(&config_with_behavior(LedBehavior::Solid))
                .unwrap();
            store
                .commit(&config_with_behavior(LedBehavior::Blink))
                .unwrap();
        }
        // Corrupt the newest slot's payload; the older record must survive.
        let newest_payload = SLOT_SIZE as usize + SLOT_HEADER_LEN;
        storage.data[newest_payload] ^= 0xFF;

        let mut store = ConfigStorage::new(&mut storage, 0, SLOT_SIZE);
        assert_eq!(
            store.load().unwrap(),
            Some(config_with_behavior(LedBehavior::Solid))
        );
    }

    #[test]
    fn power_fail_during_erase_keeps_active_record() {
        let mut storage = RamStorage::new();
        {
            let mut store = ConfigStorage::new(&mut storage, 0, SLOT_SIZE);
            store
                .commit(&config_with_behavior(LedBehavior::Solid))
                .unwrap();
        }
        // Simulate the erase of the inactive slot before the new write.
        storage.erase(SLOT_SIZE, SLOT_SIZE).unwrap();

        let mut store = ConfigStorage::new(&mut storage, 0, SLOT_SIZE);
        assert_eq!(
            store.load().unwrap(),
            Some(config_with_behavior(LedBehavior::Solid))
        );
        // The next commit lands in the freshly erased slot with a higher sequence.
        let sequence = store
            .commit(&config_with_behavior(LedBehavior::Blink))
            .unwrap();
        assert_eq!(sequence, 2);
    }

    #[test]
    fn corrupt_magic_is_ignored() {
        let mut storage = RamStorage::new();
        {
            let mut store = ConfigStorage::new(&mut storage, 0, SLOT_SIZE);
            store.commit(&DeviceConfig::official_defaults()).unwrap();
        }
        storage.data[0] = b'X';
        let mut store = ConfigStorage::new(&mut storage, 0, SLOT_SIZE);
        assert_eq!(store.load().unwrap(), None);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut store = SlotStore::new(RamStorage::new(), 0, SLOT_SIZE);
        let payload = [0u8; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(store.store(&payload), Err(CoreError::StorageError));
    }

    #[test]
    fn secret_blob_round_trips() {
        let mut store = SecretStorage::new(RamStorage::new(), 0, SLOT_SIZE);
        let sealed = [0xAB; 48];
        assert_eq!(store.store(&sealed).unwrap(), 1);
        let mut out = [0u8; 64];
        assert_eq!(store.load(&mut out).unwrap(), Some((1, 48)));
        assert_eq!(&out[..48], &sealed);
    }
}
