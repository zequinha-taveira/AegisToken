//! Encrypted, persistent credential store (PRD §15, §25).
//!
//! The credential database and PIN state are serialized to CBOR, sealed with
//! AES-256-GCM under the device root key, and committed atomically through
//! [`SecretStorage`]. A monotonic counter provides unique AEAD nonces across
//! writes.

use minicbor::decode::Decoder;
use minicbor::encode::Encoder;
use minicbor::{Decode, Encode};

use crate::authenticator::{Credential, CredentialStore, MAX_CREDENTIALS};
use crate::codec::SliceWriter;
use crate::error::CoreError;
use crate::secret::{AesGcmSealer, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::storage::{MAX_PAYLOAD_BYTES, SecretStorage};
use crate::traits::Storage;

/// Maximum size of the unsealed credential database.
pub const MAX_SEALED_PLAIN: usize = 2048;

/// PIN retry budget when a PIN is set.
pub const DEFAULT_PIN_RETRIES: u8 = 8;

/// The decrypted database contents.
struct Database {
    cache: heapless::Vec<Credential, MAX_CREDENTIALS>,
    counter: u64,
    pin_hash: Option<[u8; 32]>,
    pin_retries: u8,
}

/// Credential store persisted as a single sealed blob.
pub struct SealedCredentialStore<S: Storage> {
    storage: SecretStorage<S>,
    sealer: AesGcmSealer,
    cache: heapless::Vec<Credential, MAX_CREDENTIALS>,
    counter: u64,
    pin_hash: Option<[u8; 32]>,
    pin_retries: u8,
}

fn encode_db(
    cache: &heapless::Vec<Credential, MAX_CREDENTIALS>,
    counter: u64,
    pin_hash: Option<&[u8; 32]>,
    pin_retries: u8,
    out: &mut [u8],
) -> Result<usize, CoreError> {
    let mut writer = SliceWriter::new(out);
    {
        let mut encoder = Encoder::new(&mut writer);
        let write = || CoreError::StorageError;
        encoder.map(4).map_err(|_| write())?;
        encoder.u8(0).map_err(|_| write())?;
        encoder.u64(counter).map_err(|_| write())?;
        encoder.u8(1).map_err(|_| write())?;
        encoder.array(cache.len() as u64).map_err(|_| write())?;
        for credential in cache {
            credential
                .encode(&mut encoder, &mut ())
                .map_err(|_| write())?;
        }
        encoder.u8(2).map_err(|_| write())?;
        match pin_hash {
            Some(hash) => {
                encoder.bytes(hash).map_err(|_| write())?;
            }
            None => {
                encoder.null().map_err(|_| write())?;
            }
        }
        encoder.u8(3).map_err(|_| write())?;
        encoder.u8(pin_retries).map_err(|_| write())?;
    }
    Ok(writer.len())
}

fn decode_db(plain: &[u8]) -> Result<Database, CoreError> {
    let mut decoder = Decoder::new(plain);
    let entries = decoder
        .map()
        .map_err(|_| CoreError::StorageError)?
        .ok_or(CoreError::StorageError)?;

    let mut database = Database {
        cache: heapless::Vec::new(),
        counter: 0,
        pin_hash: None,
        pin_retries: DEFAULT_PIN_RETRIES,
    };

    for _ in 0..entries {
        match decoder.u8().map_err(|_| CoreError::StorageError)? {
            0 => database.counter = decoder.u64().map_err(|_| CoreError::StorageError)?,
            1 => {
                let count = decoder
                    .array()
                    .map_err(|_| CoreError::StorageError)?
                    .ok_or(CoreError::StorageError)?;
                for _ in 0..count {
                    let credential = Credential::decode(&mut decoder, &mut ())
                        .map_err(|_| CoreError::StorageError)?;
                    database
                        .cache
                        .push(credential)
                        .map_err(|_| CoreError::StorageError)?;
                }
            }
            2 => {
                let is_null = matches!(
                    decoder.datatype().map_err(|_| CoreError::StorageError)?,
                    minicbor::data::Type::Null
                );
                if is_null {
                    decoder.null().map_err(|_| CoreError::StorageError)?;
                    database.pin_hash = None;
                } else {
                    let bytes = decoder.bytes().map_err(|_| CoreError::StorageError)?;
                    if bytes.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(bytes);
                        database.pin_hash = Some(hash);
                    }
                }
            }
            3 => database.pin_retries = decoder.u8().map_err(|_| CoreError::StorageError)?,
            _ => decoder.skip().map_err(|_| CoreError::StorageError)?,
        }
    }
    Ok(database)
}

impl<S: Storage> SealedCredentialStore<S> {
    /// Open (or create) the store at `base`, sealing under the device root key.
    ///
    /// Both flash slots are scanned and the valid record with the highest
    /// database counter wins. Scanning the decrypted counters (instead of
    /// trusting the slot sequence alone) prevents AEAD nonce reuse after a
    /// torn write falls back to the older slot: the next `flush()` always
    /// uses `max(observed) + 1`.
    ///
    /// If stored sealed records exist but none authenticate and decode, this
    /// returns `CoreError::StorageError` instead of opening an empty store.
    pub fn open(
        storage: S,
        base: u32,
        slot_size: u32,
        key: &[u8; KEY_LEN],
    ) -> Result<Self, CoreError> {
        let sealer = AesGcmSealer::new(key)?;
        let mut secret_storage = SecretStorage::new(storage, base, slot_size);

        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut blob1 = [0u8; MAX_PAYLOAD_BYTES];
        let mut state = Database {
            cache: heapless::Vec::new(),
            counter: 0,
            pin_hash: None,
            pin_retries: DEFAULT_PIN_RETRIES,
        };
        let mut state_sequence = None;
        let mut saw_blob = false;
        let mut newest_auth_failed_sequence = None;

        for index in 0..crate::storage::SLOT_COUNT {
            let slot_blob = if index == 0 { &mut blob } else { &mut blob1 };
            let Some((sequence, length)) = secret_storage.load_slot(index, slot_blob)? else {
                continue;
            };
            saw_blob = true;
            if length < NONCE_LEN + TAG_LEN {
                if newest_auth_failed_sequence.is_none_or(|failed| sequence > failed) {
                    newest_auth_failed_sequence = Some(sequence);
                }
                continue;
            }
            let nonce: [u8; NONCE_LEN] = slot_blob[..NONCE_LEN]
                .try_into()
                .map_err(|_| CoreError::StorageError)?;
            let mut plain = [0u8; MAX_SEALED_PLAIN];
            match sealer.open(&nonce, &slot_blob[NONCE_LEN..length], &mut plain) {
                Ok(plain_len) => {
                    match decode_db(&plain[..plain_len]) {
                        Ok(candidate) => {
                            if state_sequence.is_none() || candidate.counter > state.counter {
                                state = candidate;
                                state_sequence = Some(sequence);
                            }
                        }
                        Err(_) => {
                            // Valid tag but undecodable body: treat as
                            // tamper and fail closed below.
                            if newest_auth_failed_sequence.is_none_or(|failed| sequence > failed) {
                                newest_auth_failed_sequence = Some(sequence);
                            }
                        }
                    }
                }
                Err(_) => {
                    if newest_auth_failed_sequence.is_none_or(|failed| sequence > failed) {
                        newest_auth_failed_sequence = Some(sequence);
                    }
                }
            }
        }

        // Fail closed if nothing decrypted, or if a newer physical record
        // failed authentication. Falling back in the latter case would roll
        // back to stale state after authenticated storage was tampered with.
        if saw_blob
            && newest_auth_failed_sequence
                .is_some_and(|failed| state_sequence.is_none_or(|selected| failed > selected))
        {
            return Err(CoreError::StorageError);
        }

        Ok(Self {
            storage: secret_storage,
            sealer,
            cache: state.cache,
            counter: state.counter,
            pin_hash: state.pin_hash,
            pin_retries: state.pin_retries,
        })
    }

    fn flush(&mut self) -> Result<(), CoreError> {
        self.counter = self.counter.wrapping_add(1);

        let mut nonce: [u8; NONCE_LEN] = Default::default();
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());

        let mut plain = [0u8; MAX_SEALED_PLAIN];
        let plain_len = encode_db(
            &self.cache,
            self.counter,
            self.pin_hash.as_ref(),
            self.pin_retries,
            &mut plain,
        )?;

        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        blob[..NONCE_LEN].copy_from_slice(&nonce);
        let sealed_len = self
            .sealer
            .seal(&nonce, &plain[..plain_len], &mut blob[NONCE_LEN..])?;
        self.storage.store(&blob[..NONCE_LEN + sealed_len])?;
        Ok(())
    }

    /// Stored PIN hash, if a PIN is set.
    #[must_use]
    pub const fn pin_hash(&self) -> Option<[u8; 32]> {
        self.pin_hash
    }

    /// Remaining PIN retries.
    #[must_use]
    pub const fn pin_retries(&self) -> u8 {
        self.pin_retries
    }

    /// Set the PIN hash and reset the retry budget.
    pub fn set_pin(&mut self, hash: [u8; 32]) -> Result<(), CoreError> {
        self.pin_hash = Some(hash);
        self.pin_retries = DEFAULT_PIN_RETRIES;
        self.flush()
    }

    /// Remove the PIN.
    pub fn clear_pin(&mut self) -> Result<(), CoreError> {
        self.pin_hash = None;
        self.pin_retries = DEFAULT_PIN_RETRIES;
        self.flush()
    }

    /// Update the remaining retry count.
    pub fn set_pin_retries(&mut self, retries: u8) -> Result<(), CoreError> {
        self.pin_retries = retries;
        self.flush()
    }

    /// Factory reset: remove all credentials and the PIN.
    pub fn reset(&mut self) -> Result<(), CoreError> {
        self.cache.clear();
        self.pin_hash = None;
        self.pin_retries = DEFAULT_PIN_RETRIES;
        self.flush()
    }
}

impl<S: Storage> CredentialStore for SealedCredentialStore<S> {
    fn get(&self, credential_id: &[u8]) -> Option<Credential> {
        self.cache
            .iter()
            .find(|credential| credential.id.as_slice() == credential_id)
            .cloned()
    }

    fn find_by_rp(&self, rp_id: &str) -> Option<Credential> {
        self.cache
            .iter()
            .filter(|credential| credential.rp_id.as_str() == rp_id)
            .max_by_key(|credential| credential.discoverable)
            .cloned()
    }

    fn insert(&mut self, credential: Credential) -> Result<(), CoreError> {
        if let Some(slot) = self
            .cache
            .iter_mut()
            .find(|existing| existing.id == credential.id)
        {
            *slot = credential;
        } else {
            self.cache
                .push(credential)
                .map_err(|_| CoreError::StorageError)?;
        }
        self.flush()
    }

    fn next_sign_count(&mut self, credential_id: &[u8]) -> Option<u32> {
        let credential = self
            .cache
            .iter_mut()
            .find(|credential| credential.id.as_slice() == credential_id)?;
        credential.sign_count = credential.sign_count.saturating_add(1);
        let count = credential.sign_count;
        self.flush().ok()?;
        Some(count)
    }

    fn count(&self) -> usize {
        self.cache.len()
    }

    fn remove(&mut self, credential_id: &[u8]) -> Result<(), CoreError> {
        if let Some(index) = self
            .cache
            .iter()
            .position(|credential| credential.id.as_slice() == credential_id)
        {
            self.cache.swap_remove(index);
        }
        self.flush()
    }

    fn clear(&mut self) {
        self.cache.clear();
        let _ = self.flush();
    }
}

impl<S: Storage> crate::pin::PinState for SealedCredentialStore<S> {
    fn pin_hash(&self) -> Option<[u8; 32]> {
        self.pin_hash
    }

    fn pin_retries(&self) -> u8 {
        self.pin_retries
    }

    fn set_pin_hash(&mut self, hash: [u8; 32]) -> Result<(), CoreError> {
        self.set_pin(hash)
    }

    fn set_pin_retries(&mut self, retries: u8) -> Result<(), CoreError> {
        self.set_pin_retries(retries)
    }

    fn clear_pin_state(&mut self) -> Result<(), CoreError> {
        self.clear_pin()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::Credential;
    use crate::configuration::{FixedString, crc32};
    use crate::storage::SLOT_HEADER_LEN;

    const SLOT_SIZE: u32 = 4096;
    fn test_key(seed: u8) -> [u8; KEY_LEN] {
        core::array::from_fn(|i| seed ^ (i as u8))
    }

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

    fn credential(id: u8) -> Credential {
        Credential {
            id: heapless::Vec::from_slice(&[id; 16]).unwrap(),
            rp_id: FixedString::new("example.com").unwrap(),
            user_id: heapless::Vec::from_slice(&[id]).unwrap(),
            private_key: [id; 32],
            algorithm: crate::ctap2::COSE_ALG_ES256,
            sign_count: 0,
            discoverable: true,
        }
    }

    fn store_sealed_plain<S: Storage>(
        slots: &mut SecretStorage<S>,
        counter: u64,
        plain: &[u8],
        key: &[u8; KEY_LEN],
    ) -> u32 {
        let nonce: [u8; NONCE_LEN] = core::array::from_fn(|i| {
            let bytes = counter.to_le_bytes();
            if i < bytes.len() { bytes[i] } else { 0 }
        });
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        blob[..NONCE_LEN].copy_from_slice(&nonce);
        let sealed_len = AesGcmSealer::new(key)
            .unwrap()
            .seal(&nonce, plain, &mut blob[NONCE_LEN..])
            .unwrap();
        slots.store(&blob[..NONCE_LEN + sealed_len]).unwrap()
    }

    fn store_database<S: Storage>(
        slots: &mut SecretStorage<S>,
        counter: u64,
        credential_ids: &[u8],
        key: &[u8; KEY_LEN],
    ) -> u32 {
        let mut cache = heapless::Vec::<Credential, MAX_CREDENTIALS>::new();
        for &id in credential_ids {
            cache.push(credential(id)).unwrap();
        }
        let mut plain = [0u8; MAX_SEALED_PLAIN];
        let plain_len = encode_db(&cache, counter, None, DEFAULT_PIN_RETRIES, &mut plain).unwrap();
        store_sealed_plain(slots, counter, &plain[..plain_len], key)
    }

    fn corrupt_slot_payload_preserving_crc(storage: &mut RamStorage, index: u32) {
        let slot_offset = (index * SLOT_SIZE) as usize;
        let length = usize::from(u16::from_le_bytes([
            storage.data[slot_offset + 10],
            storage.data[slot_offset + 11],
        ]));
        let payload_offset = slot_offset + SLOT_HEADER_LEN;

        storage.data[payload_offset + NONCE_LEN] ^= 0x01;
        let checksum = crc32(&storage.data[payload_offset..payload_offset + length]);
        storage.data[slot_offset + 12..slot_offset + 16].copy_from_slice(&checksum.to_le_bytes());
    }

    #[test]
    fn empty_store_opens() {
        let store =
            SealedCredentialStore::open(RamStorage::new(), 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        assert_eq!(store.count(), 0);
        assert!(store.pin_hash().is_none());
    }

    #[test]
    fn open_prefers_max_counter_over_slot_sequence() {
        let mut storage = RamStorage::new();
        {
            let mut slots = SecretStorage::new(&mut storage, 0, SLOT_SIZE);
            // The older physical slot carries the higher database counter,
            // simulating sequence rollback after a torn write.
            assert_eq!(store_database(&mut slots, 9, &[9], &test_key(0x5A)), 1);
            assert_eq!(store_database(&mut slots, 4, &[4], &test_key(0x5A)), 2);
        }

        let mut store =
            SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        assert_eq!(store.counter, 9);
        assert!(store.get(&[9u8; 16]).is_some());
        assert!(store.get(&[4u8; 16]).is_none());

        // The next flush must advance beyond the selected counter so its
        // nonce cannot collide with either recovered record.
        store.insert(credential(10)).unwrap();
        drop(store);

        let store =
            SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        assert_eq!(store.counter, 10);
        assert_eq!(store.count(), 2);
        assert!(store.get(&[9u8; 16]).is_some());
        assert!(store.get(&[10u8; 16]).is_some());
    }

    #[test]
    fn open_recovers_valid_slot_when_other_slot_fails_authentication() {
        let mut storage = RamStorage::new();
        {
            let mut slots = SecretStorage::new(&mut storage, 0, SLOT_SIZE);
            store_database(&mut slots, 99, &[9], &test_key(0x5B));
            store_database(&mut slots, 3, &[3], &test_key(0x5A));
        }

        let store =
            SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        assert_eq!(store.counter, 3);
        assert_eq!(store.count(), 1);
        assert!(store.get(&[3u8; 16]).is_some());
        assert!(store.get(&[9u8; 16]).is_none());
    }

    #[test]
    fn newer_crc_valid_slot_failing_authentication_fails_closed() {
        let mut storage = RamStorage::new();
        {
            let mut slots = SecretStorage::new(&mut storage, 0, SLOT_SIZE);
            store_database(&mut slots, 1, &[1], &test_key(0x5A));
            store_database(&mut slots, 2, &[2], &test_key(0x5A));
        }

        // Keep the record CRC-valid so the changed ciphertext reaches AES-GCM
        // authentication instead of being discarded by SlotStore::read_slot.
        corrupt_slot_payload_preserving_crc(&mut storage, 1);

        let result = SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A));
        assert!(matches!(result, Err(CoreError::StorageError)));
    }

    #[test]
    fn undersized_record_fails_closed() {
        let mut storage = RamStorage::new();
        {
            let mut slots = SecretStorage::new(&mut storage, 0, SLOT_SIZE);
            slots.store(&[0u8; NONCE_LEN + TAG_LEN - 1]).unwrap();
        }

        let result = SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A));
        assert!(matches!(result, Err(CoreError::StorageError)));
    }

    #[test]
    fn authenticated_but_malformed_database_fails_closed() {
        let mut storage = RamStorage::new();
        {
            let mut slots = SecretStorage::new(&mut storage, 0, SLOT_SIZE);
            store_sealed_plain(&mut slots, 1, &[0x01], &test_key(0x5A));
        }

        let result = SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A));
        assert!(matches!(result, Err(CoreError::StorageError)));
    }

    #[test]
    fn credentials_and_pin_persist_across_reopen() {
        let mut storage = RamStorage::new();
        {
            let mut store =
                SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
            store.insert(credential(1)).unwrap();
            store.set_pin([0x77; 32]).unwrap();
        }
        let store =
            SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        assert_eq!(store.count(), 1);
        assert_eq!(store.get(&[1u8; 16]).unwrap().user_id[0], 1);
        assert_eq!(store.pin_hash(), Some([0x77; 32]));
    }

    #[test]
    fn wrong_key_fails_closed() {
        let mut storage = RamStorage::new();
        {
            let mut store =
                SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
            store.insert(credential(2)).unwrap();
        }
        let result = SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5B));
        assert!(result.is_err());
    }

    #[test]
    fn reset_clears_everything() {
        let mut storage = RamStorage::new();
        let mut store =
            SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        store.insert(credential(3)).unwrap();
        store.set_pin([0x11; 32]).unwrap();
        store.reset().unwrap();
        assert_eq!(store.count(), 0);
        assert!(store.pin_hash().is_none());
    }

    #[test]
    fn sign_count_increments_and_persists() {
        let mut storage = RamStorage::new();
        {
            let mut store =
                SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
            store.insert(credential(4)).unwrap();
            assert_eq!(store.next_sign_count(&[4u8; 16]), Some(1));
            assert_eq!(store.next_sign_count(&[4u8; 16]), Some(2));
        }
        let store =
            SealedCredentialStore::open(&mut storage, 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        assert_eq!(store.get(&[4u8; 16]).unwrap().sign_count, 2);
    }
}
