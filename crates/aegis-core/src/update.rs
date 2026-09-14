//! Secure firmware update (PRD §22, §23).
//!
//! A firmware package is a fixed header plus the image. The header carries a
//! monotonic rollback counter, a semantic version, the image length and its
//! SHA-256, and an ECDSA (ES256) signature over `SHA-256(header_prefix ||
//! image)`. The image is written to a staging region that is separate from the
//! running image, so an interrupted update never destroys the installed
//! firmware.
//!
//! Production images are additionally sealed for the RP2350 boot ROM
//! (secp256k1 + OTP boot key); that layer is enforced before this code runs.

use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::traits::Storage;

/// Package magic.
pub const MAGIC: [u8; 4] = *b"AGFU";
/// Supported package format version.
pub const FORMAT_VERSION: u16 = 1;
/// Number of header bytes covered by the signature.
pub const SIGNED_HEADER_LEN: usize = 51;
/// Offset of the signature within the header.
pub const SIGNATURE_OFFSET: usize = 51;
/// Total header length.
pub const HEADER_LEN: usize = 115;
/// Signature length.
pub const SIGNATURE_LEN: usize = 64;

/// Management command code: begin an update with a package header.
pub const CMD_BEGIN: u8 = 0x10;
/// Management command code: append image bytes.
pub const CMD_WRITE: u8 = 0x11;
/// Management command code: finish and verify the staged image.
pub const CMD_FINISH: u8 = 0x12;
/// Management command code: abort and discard the staged image.
pub const CMD_ABORT: u8 = 0x13;

/// Semantic firmware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirmwareVersion {
    /// Major.
    pub major: u8,
    /// Minor.
    pub minor: u8,
    /// Patch.
    pub patch: u8,
}

impl core::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parsed package header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageHeader {
    /// Rollback counter; must be monotonic.
    pub rollback: u32,
    /// Image version.
    pub version: FirmwareVersion,
    /// Image length in bytes.
    pub image_len: u32,
    /// SHA-256 of the image.
    pub image_sha256: [u8; 32],
    /// ECDSA signature over `SHA-256(header_prefix || image)`.
    pub signature: [u8; SIGNATURE_LEN],
}

impl PackageHeader {
    /// Parse and structurally validate a header.
    pub fn parse(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < HEADER_LEN {
            return Err(CoreError::FirmwareError);
        }
        if bytes[0..4] != MAGIC {
            return Err(CoreError::FirmwareError);
        }
        let format = u16::from_le_bytes([bytes[4], bytes[5]]);
        if format != FORMAT_VERSION {
            return Err(CoreError::FirmwareError);
        }
        let header_len = u16::from_le_bytes([bytes[6], bytes[7]]);
        if usize::from(header_len) != HEADER_LEN {
            return Err(CoreError::FirmwareError);
        }

        let rollback = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let version = FirmwareVersion {
            major: bytes[12],
            minor: bytes[13],
            patch: bytes[14],
        };
        let image_len = u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]);

        let mut image_sha256 = [0u8; 32];
        image_sha256.copy_from_slice(&bytes[19..51]);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[SIGNATURE_OFFSET..HEADER_LEN]);

        Ok(Self {
            rollback,
            version,
            image_len,
            image_sha256,
            signature,
        })
    }

    fn signed_prefix(bytes: &[u8]) -> &[u8] {
        &bytes[..SIGNED_HEADER_LEN]
    }
}

/// A package that passed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedImage {
    /// Image version.
    pub version: FirmwareVersion,
    /// Rollback counter.
    pub rollback: u32,
    /// Image length.
    pub image_len: u32,
}

/// Verify a complete package against the vendor key and rollback floor.
pub fn verify_package(
    package: &[u8],
    vendor_key_sec1: &[u8],
    min_rollback: u32,
) -> Result<VerifiedImage, CoreError> {
    let header = PackageHeader::parse(package)?;
    let image_len = header.image_len as usize;
    if package.len() < HEADER_LEN + image_len {
        return Err(CoreError::FirmwareError);
    }
    let image = &package[HEADER_LEN..HEADER_LEN + image_len];

    if Sha256::digest(image).as_slice() != &header.image_sha256[..] {
        return Err(CoreError::FirmwareError);
    }
    if header.rollback < min_rollback {
        return Err(CoreError::FirmwareError);
    }

    let mut hasher = Sha256::new();
    hasher.update(PackageHeader::signed_prefix(package));
    hasher.update(image);
    let prehash = hasher.finalize();

    if !verify_signature(vendor_key_sec1, &prehash, &header.signature) {
        return Err(CoreError::FirmwareError);
    }

    Ok(VerifiedImage {
        version: header.version,
        rollback: header.rollback,
        image_len: header.image_len,
    })
}

fn verify_signature(key_sec1: &[u8], prehash: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(key_sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify_prehash(prehash, &signature).is_ok()
}

/// A chunked, fail-safe update session writing to a staging region.
pub struct UpdateSession {
    header: PackageHeader,
    signed_prefix: [u8; SIGNED_HEADER_LEN],
    key_sec1: heapless::Vec<u8, 65>,
    min_rollback: u32,
    base: u32,
    erase_size: u32,
    received: u32,
}

impl UpdateSession {
    /// Validate a header and prepare the staging region.
    ///
    /// The staging region is erased now; the caller must feed exactly
    /// `image_len` bytes before [`finish`](Self::finish).
    pub fn begin(
        header_bytes: &[u8],
        vendor_key_sec1: &[u8],
        min_rollback: u32,
        base: u32,
        erase_size: u32,
        storage: &mut dyn Storage,
    ) -> Result<Self, CoreError> {
        if vendor_key_sec1.len() > 65 || erase_size == 0 {
            return Err(CoreError::FirmwareError);
        }
        let header = PackageHeader::parse(header_bytes)?;
        if header.rollback < min_rollback {
            return Err(CoreError::FirmwareError);
        }
        // Reject an invalid vendor key up front.
        VerifyingKey::from_sec1_bytes(vendor_key_sec1).map_err(|_| CoreError::FirmwareError)?;

        let mut signed_prefix = [0u8; SIGNED_HEADER_LEN];
        signed_prefix.copy_from_slice(&header_bytes[..SIGNED_HEADER_LEN]);
        let mut key_sec1 = heapless::Vec::new();
        key_sec1
            .extend_from_slice(vendor_key_sec1)
            .map_err(|_| CoreError::FirmwareError)?;

        let erase_len = header.image_len.div_ceil(erase_size) * erase_size;
        storage.erase(base, erase_len)?;

        Ok(Self {
            header,
            signed_prefix,
            key_sec1,
            min_rollback,
            base,
            erase_size,
            received: 0,
        })
    }

    /// Number of image bytes accepted so far.
    #[must_use]
    pub const fn received(&self) -> u32 {
        self.received
    }

    /// Expected image length.
    #[must_use]
    pub const fn image_len(&self) -> u32 {
        self.header.image_len
    }

    /// Append a chunk of image data to the staging region.
    pub fn write(&mut self, storage: &mut dyn Storage, chunk: &[u8]) -> Result<(), CoreError> {
        let end = self
            .received
            .checked_add(chunk.len() as u32)
            .ok_or(CoreError::FirmwareError)?;
        if end > self.header.image_len {
            return Err(CoreError::FirmwareError);
        }
        storage.write(self.base + self.received, chunk)?;
        self.received = end;
        Ok(())
    }

    /// Read the staged image back, verifying integrity and signature.
    pub fn finish(self, storage: &mut dyn Storage) -> Result<VerifiedImage, CoreError> {
        if self.received != self.header.image_len {
            return Err(CoreError::FirmwareError);
        }
        let _ = self.erase_size;

        let mut signature_hasher = Sha256::new();
        signature_hasher.update(self.signed_prefix);
        let mut image_hasher = Sha256::new();

        let mut buffer = [0u8; 256];
        let mut offset = 0u32;
        while offset < self.header.image_len {
            let remaining = (self.header.image_len - offset) as usize;
            let length = remaining.min(buffer.len());
            storage.read(self.base + offset, &mut buffer[..length])?;
            image_hasher.update(&buffer[..length]);
            signature_hasher.update(&buffer[..length]);
            offset += length as u32;
        }

        if image_hasher.finalize().as_slice() != &self.header.image_sha256[..] {
            return Err(CoreError::FirmwareError);
        }
        if self.header.rollback < self.min_rollback {
            return Err(CoreError::FirmwareError);
        }
        let prehash = signature_hasher.finalize();
        if !verify_signature(&self.key_sec1, &prehash, &self.header.signature) {
            return Err(CoreError::FirmwareError);
        }

        Ok(VerifiedImage {
            version: self.header.version,
            rollback: self.header.rollback,
            image_len: self.header.image_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Storage;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    const ERASE: u32 = 4096;
    const BASE: u32 = 0;

    struct RamStorage {
        data: [u8; 32768],
    }

    impl RamStorage {
        fn new() -> Self {
            Self {
                data: [0xFF; 32768],
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

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[0x42; 32]).unwrap()
    }

    fn vendor_public(vendor: &SigningKey) -> Vec<u8> {
        vendor
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    fn build_package(
        vendor: &SigningKey,
        rollback: u32,
        version: (u8, u8, u8),
        image: &[u8],
    ) -> Vec<u8> {
        let mut header = [0u8; HEADER_LEN];
        header[0..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        header[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        header[8..12].copy_from_slice(&rollback.to_le_bytes());
        header[12] = version.0;
        header[13] = version.1;
        header[14] = version.2;
        header[15..19].copy_from_slice(&(image.len() as u32).to_le_bytes());
        header[19..51].copy_from_slice(Sha256::digest(image).as_slice());

        let mut hasher = Sha256::new();
        hasher.update(&header[..SIGNED_HEADER_LEN]);
        hasher.update(image);
        let prehash = hasher.finalize();
        let signature: Signature = vendor.sign_prehash(&prehash).unwrap();
        header[SIGNATURE_OFFSET..HEADER_LEN].copy_from_slice(&signature.to_bytes());

        let mut package = header.to_vec();
        package.extend_from_slice(image);
        package
    }

    #[test]
    fn valid_package_verifies() {
        let vendor = signing_key();
        let package = build_package(&vendor, 5, (1, 2, 3), b"firmware image");
        let verified = verify_package(&package, &vendor_public(&vendor), 3).unwrap();
        assert_eq!(
            verified.version,
            FirmwareVersion {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
        assert_eq!(verified.rollback, 5);
        assert_eq!(verified.image_len, 14);
    }

    #[test]
    fn tampered_image_is_rejected() {
        let vendor = signing_key();
        let mut package = build_package(&vendor, 5, (1, 0, 0), b"firmware image");
        let last = package.len() - 1;
        package[last] ^= 0x01;
        assert_eq!(
            verify_package(&package, &vendor_public(&vendor), 0),
            Err(CoreError::FirmwareError)
        );
    }

    #[test]
    fn rollback_below_floor_is_rejected() {
        let vendor = signing_key();
        let package = build_package(&vendor, 1, (1, 0, 0), b"image");
        assert_eq!(
            verify_package(&package, &vendor_public(&vendor), 2),
            Err(CoreError::FirmwareError)
        );
    }

    #[test]
    fn wrong_vendor_key_is_rejected() {
        let vendor = signing_key();
        let package = build_package(&vendor, 5, (1, 0, 0), b"image");
        let other = SigningKey::from_slice(&[0x24; 32]).unwrap();
        assert_eq!(
            verify_package(&package, &vendor_public(&other), 0),
            Err(CoreError::FirmwareError)
        );
    }

    #[test]
    fn truncated_package_is_rejected() {
        let vendor = signing_key();
        let mut package = build_package(&vendor, 5, (1, 0, 0), b"image");
        package.truncate(HEADER_LEN + 2);
        assert_eq!(
            verify_package(&package, &vendor_public(&vendor), 0),
            Err(CoreError::FirmwareError)
        );
    }

    #[test]
    fn session_stages_in_chunks_and_verifies() {
        let vendor = signing_key();
        let image = [0xABu8; 1000];
        let package = build_package(&vendor, 5, (2, 0, 1), &image);

        let mut storage = RamStorage::new();
        let mut session = UpdateSession::begin(
            &package[..HEADER_LEN],
            &vendor_public(&vendor),
            3,
            BASE,
            ERASE,
            &mut storage,
        )
        .unwrap();

        for chunk in image.chunks(64) {
            session.write(&mut storage, chunk).unwrap();
        }
        assert_eq!(session.received(), 1000);
        let verified = session.finish(&mut storage).unwrap();
        assert_eq!(
            verified.version,
            FirmwareVersion {
                major: 2,
                minor: 0,
                patch: 1
            }
        );
    }

    #[test]
    fn oversized_write_is_rejected() {
        let vendor = signing_key();
        let image = [0u8; 16];
        let package = build_package(&vendor, 1, (1, 0, 0), &image);
        let mut storage = RamStorage::new();
        let mut session = UpdateSession::begin(
            &package[..HEADER_LEN],
            &vendor_public(&vendor),
            0,
            BASE,
            ERASE,
            &mut storage,
        )
        .unwrap();
        assert_eq!(
            session.write(&mut storage, &[0u8; 17]),
            Err(CoreError::FirmwareError)
        );
    }

    #[test]
    fn interrupted_update_leaves_other_region_untouched() {
        let vendor = signing_key();
        let image = [0xCDu8; 512];
        let package = build_package(&vendor, 1, (1, 0, 0), &image);

        let mut storage = RamStorage::new();
        // Simulate the installed image at a different base.
        storage.write(0x4000, b"installed firmware").unwrap();

        {
            let mut session = UpdateSession::begin(
                &package[..HEADER_LEN],
                &vendor_public(&vendor),
                0,
                BASE,
                ERASE,
                &mut storage,
            )
            .unwrap();
            session.write(&mut storage, &image[..256]).unwrap();
            // Dropped mid-update.
        }

        let mut installed = [0u8; 18];
        storage.read(0x4000, &mut installed).unwrap();
        assert_eq!(&installed, b"installed firmware");
    }
}
