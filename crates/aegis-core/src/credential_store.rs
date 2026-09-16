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
    pub fn open(
        storage: S,
        base: u32,
        slot_size: u32,
        key: &[u8; KEY_LEN],
    ) -> Result<Self, CoreError> {
        let sealer = AesGcmSealer::new(key)?;
        let mut secret_storage = SecretStorage::new(storage, base, slot_size);

        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut state = Database {
            cache: heapless::Vec::new(),
            counter: 0,
            pin_hash: None,
            pin_retries: DEFAULT_PIN_RETRIES,
        };

        if let Some((_sequence, length)) = secret_storage.load(&mut blob)? {
            if length >= NONCE_LEN + TAG_LEN {
                let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN]
                    .try_into()
                    .map_err(|_| CoreError::StorageError)?;
                let mut plain = [0u8; MAX_SEALED_PLAIN];
                let plain_len = sealer.open(&nonce, &blob[NONCE_LEN..length], &mut plain)?;
                state = decode_db(&plain[..plain_len])?;
            }
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
    use crate::configuration::FixedString;

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

    #[test]
    fn empty_store_opens() {
        let store =
            SealedCredentialStore::open(RamStorage::new(), 0, SLOT_SIZE, &test_key(0x5A)).unwrap();
        assert_eq!(store.count(), 0);
        assert!(store.pin_hash().is_none());
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
