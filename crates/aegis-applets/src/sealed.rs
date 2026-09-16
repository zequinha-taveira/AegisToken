//! Sealed applet persistence.
//!
//! The PIV, OATH and OpenPGP applets keep retry counters, keys, certificates
//! and credentials that must survive power cycles without ever resting in
//! flash in the clear. This module backs the applet store traits
//! ([`PivStore`], [`OathStore`], [`OpenPgpStore`]) with AES-256-GCM sealed
//! records in dedicated two-slot flash regions:
//!
//! - [`SealedPivStore`] maps each PIV record onto its own sealed cell: one
//!   cell holding the PIN/PUK/management-key/key-entry map, plus one cell per
//!   data object. Every applet write touches exactly one cell, so the
//!   two-slot atomicity of [`SecretStorage`] applies unchanged.
//! - [`SealedOathStore`] and [`SealedOpenPgpStore`] persist whole applet
//!   blobs sharded across several cells plus a commit cell. All shards of one
//!   save share a generation counter written last to the commit cell; loading
//!   picks the newest generation present in *every* shard, so a torn
//!   multi-shard write falls back to the previous complete generation instead
//!   of mixing halves.
//!
//! Every sealed payload is `[generation:u64 LE][body]`, encrypted with a nonce
//! of `[generation:u64 LE][applet:u16 LE][shard:u16 LE]`. The per-shard
//! generation is always `max(observed) + 1`, freshly scanned at each write,
//! so a nonce is never reused even if a previous write was interrupted.
//!
//! [`PivStore`]: crate::piv::PivStore
//! [`OathStore`]: crate::oath::OathStore
//! [`OpenPgpStore`]: crate::openpgp::OpenPgpStore

use aegis_core::error::CoreError;
use aegis_core::secret::aead::rand_core::{OsRng, RngCore};
use aegis_core::secret::{AesGcmSealer, KEY_LEN, NONCE_LEN, TAG_LEN};
use aegis_core::storage::{MAX_PAYLOAD_BYTES, SLOT_COUNT, SecretStorage};
use aegis_core::traits::Storage;

use crate::oath::OathStore;
use crate::openpgp::OpenPgpStore;
use crate::piv::{
    MAX_RECORD_BYTES, PivStore, RECORD_KEY_BASE, RECORD_MGMT_KEY, RECORD_OBJECT_BASE, RECORD_PIN,
    RECORD_PUK,
};

/// Length of the generation prefix on every sealed payload.
const GEN_LEN: usize = 8;
/// Length of the presence flag on single-record cells.
const PRESENT_LEN: usize = 1;
/// Length of the total-length prefix on commit cells.
const COMMIT_LEN: usize = 4;

/// Maximum sealed body per shard: payload cap minus nonce, tag and generation.
pub const SHARD_BODY_MAX: usize = MAX_PAYLOAD_BYTES - NONCE_LEN - TAG_LEN - GEN_LEN;

/// Nonce domain tag for PIV shards.
pub const PIV_APPLET_TAG: u16 = 1;
/// Nonce domain tag for OATH shards.
pub const OATH_APPLET_TAG: u16 = 2;
/// Nonce domain tag for OpenPGP shards.
pub const OPENPGP_APPLET_TAG: u16 = 3;

/// Applet-store index of the PIV metadata cell (PIN/PUK/mgmt/keys).
pub const PIV_META_STORE: u32 = 0;
/// First applet-store index of the PIV object cells.
pub const PIV_OBJECT_STORE_BASE: u32 = 1;
/// Number of PIV object cells (object indices `0..10`).
pub const PIV_OBJECT_STORES: usize = 10;
/// First applet-store index of the OATH data shards.
pub const OATH_DATA_STORE_BASE: u32 = 11;
/// Number of OATH data shards (state cap 4096).
pub const OATH_SHARDS: usize = 2;
/// Applet-store index of the OATH commit shard.
pub const OATH_COMMIT_STORE: u32 = 13;
/// First applet-store index of the OpenPGP data shards.
pub const OPENPGP_DATA_STORE_BASE: u32 = 14;
/// Number of OpenPGP data shards (state cap 8192).
pub const OPENPGP_SHARDS: usize = 4;
/// Applet-store index of the OpenPGP commit shard.
pub const OPENPGP_COMMIT_STORE: u32 = 18;
/// Applet-store indices consumed by all sealed applet stores (`0..19`).
pub const APPLET_STORE_COUNT: u32 = 19;

/// PIV records packed into the metadata cell.
const META_RECORDS: [u16; 6] = [
    RECORD_PIN,
    RECORD_PUK,
    RECORD_MGMT_KEY,
    RECORD_KEY_BASE,
    RECORD_KEY_BASE + 1,
    RECORD_KEY_BASE + 2,
];

/// Build a 12-byte GCM nonce from generation and domain tags.
///
/// The `(applet, shard)` domain keeps nonces unique across shards even when
/// Generate a fresh nonce for every seal operation.
fn random_nonce() -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut out);
    out
}

/// Seal `[generation][present][body]` into `out` as `[nonce][ciphertext][tag]`.
fn seal_cell(
    sealer: &AesGcmSealer,
    applet: u16,
    shard: u16,
    generation: u64,
    present: bool,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, CoreError> {
    let total = NONCE_LEN + GEN_LEN + PRESENT_LEN + body.len() + TAG_LEN;
    if out.len() < total {
        return Err(CoreError::StorageError);
    }
    let nonce = random_nonce();
    out[..NONCE_LEN].copy_from_slice(&nonce);
    let mut plain = [0u8; GEN_LEN + PRESENT_LEN + SHARD_BODY_MAX];
    plain[..GEN_LEN].copy_from_slice(&generation.to_le_bytes());
    plain[GEN_LEN] = u8::from(present);
    plain[GEN_LEN + PRESENT_LEN..GEN_LEN + PRESENT_LEN + body.len()].copy_from_slice(body);
    let sealed_len = sealer.seal(
        &nonce,
        &plain[..GEN_LEN + PRESENT_LEN + body.len()],
        &mut out[NONCE_LEN..],
    )?;
    Ok(NONCE_LEN + sealed_len)
}

/// Open a sealed cell blob, returning `(generation, present, body length)`.
///
/// `out` receives `[present][body]`; the caller slices off the flag byte.
fn open_cell(
    sealer: &AesGcmSealer,
    applet: u16,
    shard: u16,
    blob: &[u8],
    out: &mut [u8],
) -> Result<(u64, usize), CoreError> {
    if blob.len() < NONCE_LEN + GEN_LEN + PRESENT_LEN + TAG_LEN || out.len() < GEN_LEN + PRESENT_LEN
    {
        return Err(CoreError::StorageError);
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN]
        .try_into()
        .map_err(|_| CoreError::StorageError)?;
    let plain_len = sealer.open(&nonce, &blob[NONCE_LEN..], out)?;
    if plain_len < GEN_LEN + PRESENT_LEN {
        return Err(CoreError::StorageError);
    }
    // The nonce domain is reconstructed from our own parameters and compared
    // against the stored nonce, so a shard mapped to the wrong adapter fails
    // closed instead of decrypting foreign state.
    let generation = u64::from_le_bytes(
        out[..GEN_LEN]
            .try_into()
            .map_err(|_| CoreError::StorageError)?,
    );
    if nonce != self_nonce(generation, applet, shard) {
        return Err(CoreError::StorageError);
    }
    Ok((generation, plain_len))
}

/// Recompute the expected nonce for domain checking.
fn self_nonce(generation: u64, applet: u16, shard: u16) -> [u8; NONCE_LEN] {
    nonce(generation, applet, shard)
}

/// Read the newest valid sealed blob from a store into `out`.
fn load_newest<S: Storage>(
    storage: &mut SecretStorage<S>,
    out: &mut [u8],
) -> Result<Option<usize>, CoreError> {
    match storage.load(out)? {
        Some((_sequence, len)) => Ok(Some(len)),
        None => Ok(None),
    }
}

/// One sealed record: `[generation][present][body]` under AES-256-GCM.
///
/// Tombstones (`present == false`) make erases atomic: a torn erase leaves the
/// previous record intact instead of resurrecting deleted state.
pub struct SealedCell<S: Storage> {
    storage: SecretStorage<S>,
    sealer: AesGcmSealer,
    applet: u16,
    shard: u16,
}

impl<S: Storage> SealedCell<S> {
    /// Open the cell at `base`, validating any existing sealed state.
    ///
    /// Fails closed when a record is present but does not open under `key`.
    /// A blank region opens empty.
    pub fn open(
        storage: S,
        base: u32,
        slot_size: u32,
        key: &[u8; KEY_LEN],
        applet: u16,
        shard: u16,
    ) -> Result<Self, CoreError> {
        let sealer = AesGcmSealer::new(key)?;
        let mut storage = SecretStorage::new(storage, base, slot_size);
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        if let Some(len) = load_newest(&mut storage, &mut blob)? {
            let mut plain = [0u8; GEN_LEN + PRESENT_LEN + SHARD_BODY_MAX];
            let _ = open_cell(&sealer, applet, shard, &blob[..len], &mut plain)?;
        }
        Ok(Self {
            storage,
            sealer,
            applet,
            shard,
        })
    }

    /// Fresh generation for the next write: above every generation observed in
    /// either slot, so nonces are never reused after interrupted writes.
    fn fresh_gen(&mut self) -> Result<u64, CoreError> {
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut plain = [0u8; GEN_LEN + PRESENT_LEN + SHARD_BODY_MAX];
        let mut generation = 0u64;
        for index in 0..SLOT_COUNT {
            if let Some((_sequence, len)) = self.storage.load_slot(index, &mut blob)? {
                let (slot_gen, _) = open_cell(
                    &self.sealer,
                    self.applet,
                    self.shard,
                    &blob[..len],
                    &mut plain,
                )?;
                generation = generation.max(slot_gen);
            }
        }
        Ok(generation.wrapping_add(1))
    }

    /// Load the record body into `out`, returning its length.
    ///
    /// Returns `Ok(None)` for blank or tombstoned records, mirroring the
    /// volatile stores. `Err` means corruption or tamper: fail closed.
    pub fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, CoreError> {
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let Some(len) = load_newest(&mut self.storage, &mut blob)? else {
            return Ok(None);
        };
        let mut plain = [0u8; GEN_LEN + PRESENT_LEN + SHARD_BODY_MAX];
        let (_, plain_len) = open_cell(
            &self.sealer,
            self.applet,
            self.shard,
            &blob[..len],
            &mut plain,
        )?;
        if plain[GEN_LEN] == 0 {
            return Ok(None);
        }
        let body = &plain[GEN_LEN + PRESENT_LEN..plain_len];
        if out.len() < body.len() {
            return Ok(None);
        }
        out[..body.len()].copy_from_slice(body);
        Ok(Some(body.len()))
    }

    /// Atomically replace the record.
    pub fn store(&mut self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > SHARD_BODY_MAX {
            return Err(CoreError::StorageError);
        }
        let generation = self.fresh_gen()?;
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let len = seal_cell(
            &self.sealer,
            self.applet,
            self.shard,
            generation,
            true,
            data,
            &mut blob,
        )?;
        self.storage.store(&blob[..len]).map(|_| ())
    }

    /// Atomically erase the record via tombstone.
    pub fn erase(&mut self) -> Result<(), CoreError> {
        let generation = self.fresh_gen()?;
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let len = seal_cell(
            &self.sealer,
            self.applet,
            self.shard,
            generation,
            false,
            &[],
            &mut blob,
        )?;
        self.storage.store(&blob[..len]).map(|_| ())
    }
}

/// Whole PIV record map persisted as one metadata cell plus one cell per data
/// object. Every applet write touches exactly one cell, preserving per-record
/// atomicity without any cross-cell protocol.
pub struct SealedPivStore<S: Storage + Clone> {
    meta: SealedCell<S>,
    objects: [SealedCell<S>; PIV_OBJECT_STORES],
}

/// Flash bases for [`SealedPivStore::open`]: metadata cell plus one base per
/// object index (`RECORD_OBJECT_BASE + index`).
pub struct PivLayout {
    /// Base of the metadata cell (PIN/PUK/management key/key entries).
    pub meta: u32,
    /// Bases of the ten object cells, indexed by object index.
    pub objects: [u32; PIV_OBJECT_STORES],
}

impl<S: Storage + Clone> SealedPivStore<S> {
    /// Open the metadata and object cells, validating existing state.
    pub fn open(
        storage: S,
        layout: &PivLayout,
        slot_size: u32,
        key: &[u8; KEY_LEN],
    ) -> Result<Self, CoreError> {
        let meta = SealedCell::open(
            storage.clone(),
            layout.meta,
            slot_size,
            key,
            PIV_APPLET_TAG,
            0,
        )?;
        let mut objects: [Option<SealedCell<S>>; PIV_OBJECT_STORES] =
            core::array::from_fn(|_| None);
        for (index, slot) in objects.iter_mut().enumerate() {
            *slot = Some(SealedCell::open(
                storage.clone(),
                layout.objects[index],
                slot_size,
                key,
                PIV_APPLET_TAG,
                1 + index as u16,
            )?);
        }
        let objects = objects.map(|slot| slot.expect("filled above"));
        Ok(Self { meta, objects })
    }

    fn meta_entry(record: u16) -> Option<usize> {
        META_RECORDS.iter().position(|id| *id == record)
    }

    fn load_meta(&mut self) -> Result<Option<VecMap>, CoreError> {
        let mut body = [0u8; META_BODY_MAX];
        let Some(len) = self.meta.load(&mut body)? else {
            return Ok(None);
        };
        VecMap::decode(&body[..len])
            .map(Some)
            .ok_or(CoreError::StorageError)
    }

    fn store_meta(&mut self, map: &VecMap) -> Result<(), CoreError> {
        let mut body = [0u8; META_BODY_MAX];
        let len = map.encode(&mut body).ok_or(CoreError::StorageError)?;
        self.meta.store(&body[..len])
    }
}

/// Encoded PIV metadata map: the six small records in fixed order.
struct VecMap {
    entries: [Option<MapEntry>; META_RECORDS.len()],
}

struct MapEntry {
    len: usize,
    data: [u8; MAX_RECORD_BYTES],
}

const META_BODY_MAX: usize = META_RECORDS.len() * (2 + MAX_RECORD_BYTES);

impl VecMap {
    fn empty() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
        }
    }

    fn decode(body: &[u8]) -> Option<Self> {
        let mut map = Self::empty();
        let mut cursor = 0;
        for slot in map.entries.iter_mut() {
            let present = *body.get(cursor)?;
            cursor += 1;
            if present == 0 {
                continue;
            }
            if present != 1 {
                return None;
            }
            let len = u16::from_le_bytes([*body.get(cursor)?, *body.get(cursor + 1)?]) as usize;
            cursor += 2;
            if len > MAX_RECORD_BYTES {
                return None;
            }
            let data = body.get(cursor..cursor + len)?;
            cursor += len;
            let mut entry = MapEntry {
                len,
                data: [0; MAX_RECORD_BYTES],
            };
            entry.data[..len].copy_from_slice(data);
            *slot = Some(entry);
        }
        if cursor != body.len() {
            return None;
        }
        Some(map)
    }

    fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let mut cursor = 0;
        for slot in &self.entries {
            match slot {
                Some(entry) => {
                    *out.get_mut(cursor)? = 1;
                    cursor += 1;
                    out.get_mut(cursor..cursor + 2)?
                        .copy_from_slice(&(entry.len as u16).to_le_bytes());
                    cursor += 2;
                    out.get_mut(cursor..cursor + entry.len)?
                        .copy_from_slice(&entry.data[..entry.len]);
                    cursor += entry.len;
                }
                None => {
                    *out.get_mut(cursor)? = 0;
                    cursor += 1;
                }
            }
        }
        Some(cursor)
    }
}

impl<S: Storage + Clone> PivStore for SealedPivStore<S> {
    fn read(&mut self, record: u16, out: &mut [u8]) -> Option<usize> {
        if SealedPivStore::<S>::meta_entry(record).is_some() {
            let map = self.load_meta().ok()??;
            let entry = map.entries[SealedPivStore::<S>::meta_entry(record)?].as_ref()?;
            if out.len() < entry.len {
                return None;
            }
            out[..entry.len].copy_from_slice(&entry.data[..entry.len]);
            Some(entry.len)
        } else {
            let index = usize::from(record.checked_sub(RECORD_OBJECT_BASE)?);
            if index >= PIV_OBJECT_STORES {
                return None;
            }
            let mut body = [0u8; MAX_RECORD_BYTES];
            let len = self.objects[index].load(&mut body).ok()??;
            if out.len() < len {
                return None;
            }
            out[..len].copy_from_slice(&body[..len]);
            Some(len)
        }
    }

    fn write(&mut self, record: u16, data: &[u8]) -> bool {
        if data.len() > MAX_RECORD_BYTES {
            return false;
        }
        if let Some(position) = SealedPivStore::<S>::meta_entry(record) {
            let mut map = match self.load_meta() {
                Ok(Some(map)) => map,
                Ok(None) => VecMap::empty(),
                Err(_) => return false,
            };
            let mut entry = MapEntry {
                len: data.len(),
                data: [0; MAX_RECORD_BYTES],
            };
            entry.data[..data.len()].copy_from_slice(data);
            map.entries[position] = Some(entry);
            self.store_meta(&map).is_ok()
        } else {
            let index = usize::from(record.wrapping_sub(RECORD_OBJECT_BASE));
            if index >= PIV_OBJECT_STORES {
                return false;
            }
            self.objects[index].store(data).is_ok()
        }
    }

    fn erase(&mut self, record: u16) -> bool {
        if SealedPivStore::<S>::meta_entry(record).is_some() {
            let mut map = match self.load_meta() {
                Ok(Some(map)) => map,
                Ok(None) => VecMap::empty(),
                Err(_) => return false,
            };
            map.entries[SealedPivStore::<S>::meta_entry(record).expect("checked")] = None;
            self.store_meta(&map).is_ok()
        } else {
            let index = usize::from(record.wrapping_sub(RECORD_OBJECT_BASE));
            if index >= PIV_OBJECT_STORES {
                return false;
            }
            self.objects[index].erase().is_ok()
        }
    }
}

/// A whole applet blob sharded across `SHARDS` data cells plus one commit
/// cell. Saves share one fresh generation across every shard and land the
/// commit last; loads take the newest generation present in *all* shards, so
/// an interrupted save recovers the previous complete generation.
pub struct SealedBlob<S: Storage + Clone, const SHARDS: usize> {
    sealer: AesGcmSealer,
    applet: u16,
    data: [SecretStorage<S>; SHARDS],
    commit: SecretStorage<S>,
}

impl<S: Storage + Clone, const SHARDS: usize> SealedBlob<S, SHARDS> {
    /// Open data and commit cells, validating the commit cell's newest state.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        storage: S,
        data_bases: [u32; SHARDS],
        commit_base: u32,
        slot_size: u32,
        key: &[u8; KEY_LEN],
        applet: u16,
    ) -> Result<Self, CoreError> {
        let sealer = AesGcmSealer::new(key)?;
        let data: [SecretStorage<S>; SHARDS] =
            core::array::from_fn(|i| SecretStorage::new(storage.clone(), data_bases[i], slot_size));
        let mut commit = SecretStorage::new(storage, commit_base, slot_size);
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut plain = [0u8; MAX_PAYLOAD_BYTES];
        if let Some(len) = load_newest(&mut commit, &mut blob)? {
            let (generation, body_len) =
                open_shard(&sealer, applet, SHARDS as u16, &blob[..len], &mut plain)?;
            if body_len != COMMIT_LEN {
                return Err(CoreError::StorageError);
            }
            let _ = generation;
        }
        Ok(Self {
            sealer,
            applet,
            data,
            commit,
        })
    }

    /// Highest generation observed anywhere, plus one.
    fn fresh_gen(&mut self) -> Result<u64, CoreError> {
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut plain = [0u8; MAX_PAYLOAD_BYTES];
        let mut generation = 0u64;
        for (index, shard) in self.data.iter_mut().enumerate() {
            for slot in 0..SLOT_COUNT {
                if let Some((_sequence, len)) = shard.load_slot(slot, &mut blob)? {
                    generation = generation.max(Self::blob_gen(
                        &self.sealer,
                        self.applet,
                        index as u16,
                        &blob[..len],
                        &mut plain,
                    )?);
                }
            }
        }
        for slot in 0..SLOT_COUNT {
            if let Some((_sequence, len)) = self.commit.load_slot(slot, &mut blob)? {
                generation = generation.max(Self::commit_gen(
                    &self.sealer,
                    self.applet,
                    &blob[..len],
                    &mut plain,
                )?);
            }
        }
        Ok(generation.wrapping_add(1))
    }

    /// Open a data-shard blob, returning its generation.
    fn blob_gen(
        sealer: &AesGcmSealer,
        applet: u16,
        shard: u16,
        blob: &[u8],
        plain: &mut [u8],
    ) -> Result<u64, CoreError> {
        let (generation, _body_len) = open_shard(sealer, applet, shard, blob, plain)?;
        Ok(generation)
    }

    /// Open a commit blob, returning its generation.
    fn commit_gen(
        sealer: &AesGcmSealer,
        applet: u16,
        blob: &[u8],
        plain: &mut [u8],
    ) -> Result<u64, CoreError> {
        // Commit shard id is `SHARDS`, outside the data shard range.
        let (generation, body_len) = open_shard(sealer, applet, SHARDS as u16, blob, plain)?;
        if body_len != COMMIT_LEN {
            return Err(CoreError::StorageError);
        }
        Ok(generation)
    }

    /// Persist `data`, returning false when it exceeds shard capacity.
    pub fn save(&mut self, data: &[u8]) -> Result<(), CoreError> {
        if data.len() > SHARDS * SHARD_BODY_MAX {
            return Err(CoreError::StorageError);
        }
        let generation = self.fresh_gen()?;
        let applet = self.applet;
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut plain = [0u8; GEN_LEN + SHARD_BODY_MAX];
        for (index, shard) in self.data.iter_mut().enumerate() {
            let start = index * SHARD_BODY_MAX;
            let end = (start + SHARD_BODY_MAX).min(data.len());
            let chunk = if start < data.len() {
                &data[start..end]
            } else {
                &[]
            };
            plain[..GEN_LEN].copy_from_slice(&generation.to_le_bytes());
            plain[GEN_LEN..GEN_LEN + chunk.len()].copy_from_slice(chunk);
            let body_len = GEN_LEN + chunk.len();
            let nonce = random_nonce();
            blob[..NONCE_LEN].copy_from_slice(&nonce);
            let sealed_len =
                self.sealer
                    .seal(&nonce, &plain[..body_len], &mut blob[NONCE_LEN..])?;
            shard.store(&blob[..NONCE_LEN + sealed_len])?;
        }
        plain[..GEN_LEN].copy_from_slice(&generation.to_le_bytes());
        plain[GEN_LEN..GEN_LEN + COMMIT_LEN].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let nonce = random_nonce();
        blob[..NONCE_LEN].copy_from_slice(&nonce);
        let sealed_len = self.sealer.seal(
            &nonce,
            &plain[..GEN_LEN + COMMIT_LEN],
            &mut blob[NONCE_LEN..],
        )?;
        self.commit.store(&blob[..NONCE_LEN + sealed_len])?;
        Ok(())
    }

    /// Load the newest complete generation into `out`.
    ///
    /// Chunks assemble directly into the caller's buffer; a failed candidate
    /// leaves `out` untouched for the caller to ignore.
    pub fn load(&mut self, out: &mut [u8]) -> Result<Option<usize>, CoreError> {
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut plain = [0u8; MAX_PAYLOAD_BYTES];
        // Candidate generations, newest commit first.
        let mut candidates = [0u64; SLOT_COUNT as usize];
        let mut candidate_count = 0;
        for slot in 0..SLOT_COUNT {
            if let Some((_sequence, len)) = self.commit.load_slot(slot, &mut blob)? {
                let (generation, body_len) = open_shard(
                    &self.sealer,
                    self.applet,
                    SHARDS as u16,
                    &blob[..len],
                    &mut plain,
                )?;
                if body_len == COMMIT_LEN {
                    candidates[candidate_count] = generation;
                    candidate_count += 1;
                }
            }
        }
        if candidate_count == 0 {
            return Ok(None);
        }
        // Newest commit generation first (higher slot sequence first is not
        // guaranteed across power cycles, so order by generation).
        if candidate_count == 2 && candidates[1] > candidates[0] {
            candidates.swap(0, 1);
        }
        for candidate in candidates.iter().take(candidate_count) {
            if let Some(len) = self.assemble(*candidate, out)? {
                return Ok(Some(len));
            }
        }
        Err(CoreError::StorageError)
    }

    /// Try assembling `generation` from every data shard into `out`.
    fn assemble(&mut self, generation: u64, out: &mut [u8]) -> Result<Option<usize>, CoreError> {
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let mut plain = [0u8; MAX_PAYLOAD_BYTES];
        let mut total: Option<usize> = None;
        let mut cursor = 0;
        // Read the expected total from this generation's commit record.
        for slot in 0..SLOT_COUNT {
            if let Some((_sequence, len)) = self.commit.load_slot(slot, &mut blob)? {
                let (slot_gen, body_len) = open_shard(
                    &self.sealer,
                    self.applet,
                    SHARDS as u16,
                    &blob[..len],
                    &mut plain,
                )?;
                if slot_gen == generation && body_len == COMMIT_LEN {
                    total = Some(u32::from_le_bytes(
                        plain[GEN_LEN..GEN_LEN + COMMIT_LEN]
                            .try_into()
                            .map_err(|_| CoreError::StorageError)?,
                    ) as usize);
                    break;
                }
            }
        }
        let total = total.ok_or(CoreError::StorageError)?;
        if total > SHARDS * SHARD_BODY_MAX || out.len() < total {
            return Err(CoreError::StorageError);
        }
        for (index, shard) in self.data.iter_mut().enumerate() {
            let mut found = false;
            for slot in 0..SLOT_COUNT {
                if let Some((_sequence, len)) = shard.load_slot(slot, &mut blob)? {
                    let (slot_gen, body_len) = open_shard(
                        &self.sealer,
                        self.applet,
                        index as u16,
                        &blob[..len],
                        &mut plain,
                    )?;
                    if slot_gen == generation {
                        let take = body_len.min(total - cursor);
                        out[cursor..cursor + take].copy_from_slice(&plain[GEN_LEN..GEN_LEN + take]);
                        cursor += take;
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return Ok(None);
            }
        }
        if cursor < total {
            return Ok(None);
        }
        Ok(Some(total))
    }
}

/// Open a data/commit shard blob: `[nonce][generation][body...][tag]`.
fn open_shard(
    sealer: &AesGcmSealer,
    applet: u16,
    shard: u16,
    blob: &[u8],
    plain: &mut [u8],
) -> Result<(u64, usize), CoreError> {
    if blob.len() < NONCE_LEN + GEN_LEN + TAG_LEN || plain.len() < GEN_LEN {
        return Err(CoreError::StorageError);
    }
    let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN]
        .try_into()
        .map_err(|_| CoreError::StorageError)?;
    let plain_len = sealer.open(&nonce, &blob[NONCE_LEN..], plain)?;
    if plain_len < GEN_LEN {
        return Err(CoreError::StorageError);
    }
    let generation = u64::from_le_bytes(
        plain[..GEN_LEN]
            .try_into()
            .map_err(|_| CoreError::StorageError)?,
    );
    if nonce != self_nonce(generation, applet, shard) {
        return Err(CoreError::StorageError);
    }
    Ok((generation, plain_len - GEN_LEN))
}

/// OATH state persisted as a sealed two-shard blob plus commit cell.
pub struct SealedOathStore<S: Storage + Clone> {
    inner: SealedBlob<S, OATH_SHARDS>,
}

impl<S: Storage + Clone> SealedOathStore<S> {
    /// Open the OATH shards, validating the commit cell's newest state.
    pub fn open(
        storage: S,
        data_bases: [u32; OATH_SHARDS],
        commit_base: u32,
        slot_size: u32,
        key: &[u8; KEY_LEN],
    ) -> Result<Self, CoreError> {
        Ok(Self {
            inner: SealedBlob::open(
                storage,
                data_bases,
                commit_base,
                slot_size,
                key,
                OATH_APPLET_TAG,
            )?,
        })
    }
}

impl<S: Storage + Clone> OathStore for SealedOathStore<S> {
    fn load(&mut self, out: &mut [u8]) -> Option<usize> {
        self.inner.load(out).ok()?
    }

    fn save(&mut self, data: &[u8]) -> bool {
        self.inner.save(data).is_ok()
    }

    fn clear(&mut self) -> bool {
        self.inner.save(&[]).is_ok()
    }
}

/// OpenPGP state persisted as a sealed four-shard blob plus commit cell.
pub struct SealedOpenPgpStore<S: Storage + Clone> {
    inner: SealedBlob<S, OPENPGP_SHARDS>,
}

impl<S: Storage + Clone> SealedOpenPgpStore<S> {
    /// Open the OpenPGP shards, validating the commit cell's newest state.
    pub fn open(
        storage: S,
        data_bases: [u32; OPENPGP_SHARDS],
        commit_base: u32,
        slot_size: u32,
        key: &[u8; KEY_LEN],
    ) -> Result<Self, CoreError> {
        Ok(Self {
            inner: SealedBlob::open(
                storage,
                data_bases,
                commit_base,
                slot_size,
                key,
                OPENPGP_APPLET_TAG,
            )?,
        })
    }
}

impl<S: Storage + Clone> OpenPgpStore for SealedOpenPgpStore<S> {
    fn load(&mut self, out: &mut [u8]) -> Option<usize> {
        self.inner.load(out).ok()?
    }

    fn save(&mut self, data: &[u8]) -> bool {
        self.inner.save(data).is_ok()
    }

    fn clear(&mut self) -> bool {
        self.inner.save(&[]).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    const BACKING_LEN: usize = 192 * 1024;

    #[derive(Clone)]
    struct TestFlash {
        mem: Rc<RefCell<[u8; BACKING_LEN]>>,
        base: u32,
    }

    impl TestFlash {
        fn new(base: u32) -> (Self, Rc<RefCell<[u8; BACKING_LEN]>>) {
            let mem = Rc::new(RefCell::new([0xFF; BACKING_LEN]));
            (
                Self {
                    mem: mem.clone(),
                    base,
                },
                mem,
            )
        }
    }

    impl Storage for TestFlash {
        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), CoreError> {
            let start = self.base as usize + offset as usize;
            let mem = self.mem.borrow();
            let end = start + buf.len();
            if end > mem.len() {
                return Err(CoreError::StorageError);
            }
            buf.copy_from_slice(&mem[start..end]);
            Ok(())
        }

        fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), CoreError> {
            let start = self.base as usize + offset as usize;
            let mut mem = self.mem.borrow_mut();
            let end = start + data.len();
            if end > mem.len() {
                return Err(CoreError::StorageError);
            }
            mem[start..end].copy_from_slice(data);
            Ok(())
        }

        fn erase(&mut self, offset: u32, len: u32) -> Result<(), CoreError> {
            let start = self.base as usize + offset as usize;
            let mut mem = self.mem.borrow_mut();
            let end = start + len as usize;
            if end > mem.len() {
                return Err(CoreError::StorageError);
            }
            mem[start..end].fill(0xFF);
            Ok(())
        }
    }

    fn test_key() -> [u8; KEY_LEN] {
        core::array::from_fn(|i| 0xA5 ^ (i as u8))
    }

    fn piv_layout() -> PivLayout {
        PivLayout {
            meta: 0,
            objects: core::array::from_fn(|i| 8192 + i as u32 * 8192),
        }
    }

    #[test]
    fn sealed_cell_round_trips_across_reopen() {
        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let mut cell = SealedCell::open(flash.clone(), 0, 4096, &key, PIV_APPLET_TAG, 0).unwrap();
        cell.store(b"pin-state").unwrap();
        drop(cell);
        let mut cell = SealedCell::open(flash, 0, 4096, &key, PIV_APPLET_TAG, 0).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(cell.load(&mut out).unwrap(), Some(9));
        assert_eq!(&out[..9], b"pin-state");
    }

    #[test]
    fn sealed_cell_wrong_key_fails_open() {
        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let mut cell = SealedCell::open(flash.clone(), 0, 4096, &key, PIV_APPLET_TAG, 0).unwrap();
        cell.store(b"secret").unwrap();
        drop(cell);
        let mut other = test_key();
        other[0] ^= 0xFF;
        assert!(SealedCell::open(flash, 0, 4096, &other, PIV_APPLET_TAG, 0).is_err());
    }

    #[test]
    fn sealed_cell_torn_newest_falls_back() {
        let (flash, mem) = TestFlash::new(0);
        let key = test_key();
        let mut cell = SealedCell::open(flash.clone(), 0, 4096, &key, PIV_APPLET_TAG, 0).unwrap();
        cell.store(b"first").unwrap();
        cell.store(b"second").unwrap();
        drop(cell);
        // Corrupt the newest slot payload so its CRC fails; the older record
        // must survive.
        mem.borrow_mut()[4096 + 16] ^= 0xFF;
        let mut cell = SealedCell::open(flash, 0, 4096, &key, PIV_APPLET_TAG, 0).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(cell.load(&mut out).unwrap(), Some(5));
        assert_eq!(&out[..5], b"first");
    }

    #[test]
    fn sealed_cell_erase_uses_tombstones() {
        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let mut cell = SealedCell::open(flash.clone(), 0, 4096, &key, PIV_APPLET_TAG, 0).unwrap();
        cell.store(b"data").unwrap();
        cell.erase().unwrap();
        drop(cell);
        let mut cell = SealedCell::open(flash, 0, 4096, &key, PIV_APPLET_TAG, 0).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(cell.load(&mut out).unwrap(), None);
    }

    #[test]
    fn sealed_piv_records_persist_across_reopen() {
        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let mut store = SealedPivStore::open(flash.clone(), &piv_layout(), 4096, &key).unwrap();
        assert!(store.write(1, b"pin-1"));
        assert!(store.write(30, b"chuid-bytes"));
        drop(store);
        let mut store = SealedPivStore::open(flash, &piv_layout(), 4096, &key).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(store.read(1, &mut out), Some(5));
        assert_eq!(&out[..5], b"pin-1");
        assert_eq!(store.read(30, &mut out), Some(11));
        assert_eq!(&out[..11], b"chuid-bytes");
        assert_eq!(store.read(2, &mut out), None);
        assert!(store.erase(30));
        assert_eq!(store.read(30, &mut out), None);
    }

    #[test]
    fn sealed_piv_rejects_unknown_records() {
        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let mut store = SealedPivStore::open(flash, &piv_layout(), 4096, &key).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(store.read(999, &mut out), None);
        assert!(!store.write(999, b"x"));
        assert!(!store.erase(999));
    }

    #[test]
    fn sealed_oath_blob_persists_across_reopen() {
        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let mut store =
            SealedOathStore::open(flash.clone(), [8192 * 20, 8192 * 21], 8192 * 22, 4096, &key)
                .unwrap();
        let state = [0x55u8; 3000];
        assert!(store.save(&state));
        drop(store);
        let mut store =
            SealedOathStore::open(flash, [8192 * 20, 8192 * 21], 8192 * 22, 4096, &key).unwrap();
        let mut out = [0u8; 4096];
        assert_eq!(store.load(&mut out), Some(3000));
        assert_eq!(&out[..3000], &state[..]);
    }

    #[test]
    fn sealed_blob_torn_save_recovers_previous_generation() {
        let (flash, mem) = TestFlash::new(0);
        let key = test_key();
        let data = [8192 * 20, 8192 * 21];
        let commit = 8192 * 22;
        let mut store = SealedOathStore::open(flash.clone(), data, commit, 4096, &key).unwrap();
        assert!(store.save(&[0x11; 100]));
        drop(store);
        // Simulate a torn second save: commit moved to generation 2 while a
        // data shard still only holds generation 1.
        let sealer = AesGcmSealer::new(&key).unwrap();
        let mut blob = [0u8; MAX_PAYLOAD_BYTES];
        let nonce = random_nonce();
        blob[..NONCE_LEN].copy_from_slice(&nonce);
        let mut plain = [0u8; GEN_LEN + COMMIT_LEN];
        plain[..GEN_LEN].copy_from_slice(&2u64.to_le_bytes());
        plain[GEN_LEN..].copy_from_slice(&100u32.to_le_bytes());
        let sealed_len = sealer.seal(&nonce, &plain, &mut blob[NONCE_LEN..]).unwrap();
        {
            let region = TestFlash {
                mem: mem.clone(),
                base: commit,
            };
            let mut commit_store = SecretStorage::new(region, 0, 4096);
            commit_store.store(&blob[..NONCE_LEN + sealed_len]).unwrap();
        }
        let mut store = SealedOathStore::open(flash, data, commit, 4096, &key).unwrap();
        let mut out = [0u8; 4096];
        assert_eq!(store.load(&mut out), Some(100));
        assert_eq!(&out[..100], &[0x11; 100]);
    }

    #[test]
    fn sealed_blob_rejects_oversize_state() {
        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let mut store =
            SealedOathStore::open(flash, [8192 * 20, 8192 * 21], 8192 * 22, 4096, &key).unwrap();
        assert!(!store.save(&[0u8; OATH_SHARDS * SHARD_BODY_MAX + 1]));
    }

    #[test]
    fn pin_retries_survive_reopen() {
        use crate::pin::{PinHashFormat, PinPolicy, PinSlot};

        let (flash, _mem) = TestFlash::new(0);
        let key = test_key();
        let policy = PinPolicy::new(6, 8, 3, PinHashFormat::Sha256);
        let mut slot = PinSlot::new(policy);
        slot.set(b"123456").unwrap();
        let _ = slot.verify(b"000000");
        let _ = slot.verify(b"000000");
        let mut store = SealedPivStore::open(flash.clone(), &piv_layout(), 4096, &key).unwrap();
        let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
        let len = slot.encode(&mut encoded).unwrap();
        assert!(store.write(RECORD_PIN, &encoded[..len]));
        drop(store);

        let mut store = SealedPivStore::open(flash, &piv_layout(), 4096, &key).unwrap();
        let mut read = [0u8; crate::pin::PIN_STATE_LEN];
        let len = store
            .read(RECORD_PIN, &mut read)
            .expect("retries persisted");
        let reopened = PinSlot::decode(policy, &read[..len]).unwrap();
        assert_eq!(reopened.retries_remaining(), 1);
    }
}
