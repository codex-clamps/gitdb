//! Stable object identity primitives used by the Reflink Forest on-disk format.
//!
//! No Rust memory layout is used as persistent data.  The byte encodings below
//! are explicit, versioned by their callers, and use fixed-width big-endian
//! lengths where required.

use core::fmt;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// The object kinds defined by Git's object model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ObjectKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl ObjectKind {
    /// Stable one-byte representation used by canonical encodings.
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Decodes a stable object-kind tag.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Commit),
            2 => Some(Self::Tree),
            3 => Some(Self::Blob),
            4 => Some(Self::Tag),
            _ => None,
        }
    }
}

/// Native hash algorithm of a Git repository/object ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum HashAlgorithm {
    Sha1 = 1,
    Sha256 = 2,
}

impl HashAlgorithm {
    /// Stable one-byte representation used by canonical encodings.
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Expected native Git OID length for this algorithm.
    pub const fn oid_len(self) -> u8 {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    /// Decodes a stable hash-algorithm tag.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Sha1),
            2 => Some(Self::Sha256),
            _ => None,
        }
    }
}

/// Error returned when native Git object-ID bytes do not match their algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidGitOidLength {
    pub algorithm: HashAlgorithm,
    pub actual: usize,
}

impl fmt::Display for InvalidGitOidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} Git object IDs must be {} bytes, got {}",
            self.algorithm,
            self.algorithm.oid_len(),
            self.actual
        )
    }
}

impl std::error::Error for InvalidGitOidLength {}

/// A validated native Git object ID.
///
/// The unused tail of `bytes` is always zero, allowing a fixed in-memory size
/// without making the in-memory layout part of the on-disk format.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GitOid {
    algorithm: HashAlgorithm,
    len: u8,
    bytes: [u8; 32],
}

impl GitOid {
    /// Validates and stores exactly one native object ID.
    pub fn new(algorithm: HashAlgorithm, oid: &[u8]) -> Result<Self, InvalidGitOidLength> {
        if oid.len() != usize::from(algorithm.oid_len()) {
            return Err(InvalidGitOidLength {
                algorithm,
                actual: oid.len(),
            });
        }

        let mut bytes = [0_u8; 32];
        bytes[..oid.len()].copy_from_slice(oid);
        Ok(Self {
            algorithm,
            len: algorithm.oid_len(),
            bytes,
        })
    }

    pub const fn algorithm(self) -> HashAlgorithm {
        self.algorithm
    }

    pub const fn len(self) -> u8 {
        self.len
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Canonical repo-alias suffix: algorithm tag, length, then native bytes.
    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(2 + usize::from(self.len));
        output.push(self.algorithm.tag());
        output.push(self.len);
        output.extend_from_slice(self.as_bytes());
        output
    }
}

/// The domain separator for internal, algorithm-independent object identities.
pub const CONTENT_ID_DOMAIN: &[u8] = b"reflink-forest-object-v1\0";

/// SHA-256 identity of a canonical raw Git object representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Computes `SHA256(domain || kind || raw_length_be || raw_payload)`.
    ///
    /// `raw_payload` is the uncompressed object payload; the native Git OID is
    /// intentionally not included so identical objects deduplicate across
    /// SHA-1 and SHA-256 repositories.
    pub fn for_object(kind: ObjectKind, raw_payload: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(CONTENT_ID_DOMAIN);
        digest.update([kind.tag()]);
        digest.update((raw_payload.len() as u64).to_be_bytes());
        digest.update(raw_payload);
        Self(digest.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Creates a new sparse image with the requested logical capacity.
///
/// This deliberately uses `set_len` instead of `fallocate`: logical capacity
/// does not reserve host blocks. Callers must therefore retain host headroom
/// checks throughout the image's lifetime.
pub fn create_sparse_image(path: &Path, logical_size: u64) -> io::Result<()> {
    if logical_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sparse image size must be non-zero",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "image path has no parent directory",
        )
    })?;
    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    image.set_len(logical_size)?;
    image.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Logical and host-allocated bytes reported for one regular file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileAllocation {
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

/// Measures allocation using POSIX `st_blocks` (512-byte units).
pub fn file_allocation(path: &Path) -> io::Result<FileAllocation> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "allocation can only be measured for a regular file",
        ));
    }
    Ok(FileAllocation {
        logical_bytes: metadata.len(),
        allocated_bytes: metadata.blocks().saturating_mul(512),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn tags_are_explicit_and_round_trip() {
        for kind in [
            ObjectKind::Commit,
            ObjectKind::Tree,
            ObjectKind::Blob,
            ObjectKind::Tag,
        ] {
            assert_eq!(ObjectKind::from_tag(kind.tag()), Some(kind));
        }
        assert_eq!(ObjectKind::from_tag(0), None);
        assert_eq!(ObjectKind::from_tag(5), None);

        for algorithm in [HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
            assert_eq!(HashAlgorithm::from_tag(algorithm.tag()), Some(algorithm));
        }
        assert_eq!(HashAlgorithm::from_tag(3), None);
    }

    #[test]
    fn git_oid_validates_length_and_canonicalizes() {
        let sha1 = GitOid::new(HashAlgorithm::Sha1, &[0xAB; 20]).unwrap();
        assert_eq!(sha1.len(), 20);
        assert_eq!(sha1.as_bytes(), &[0xAB; 20]);
        assert_eq!(
            sha1.encode_canonical(),
            [1, 20].into_iter().chain([0xAB; 20]).collect::<Vec<_>>()
        );

        let error = GitOid::new(HashAlgorithm::Sha256, &[0; 20]).unwrap_err();
        assert_eq!(error.algorithm, HashAlgorithm::Sha256);
        assert_eq!(error.actual, 20);
    }

    #[test]
    fn content_id_has_a_stable_test_vector() {
        let id = ContentId::for_object(ObjectKind::Blob, b"hello\n");
        assert_eq!(
            id.as_bytes(),
            &[
                0x7f, 0xae, 0x3a, 0xe6, 0x76, 0x58, 0x53, 0xc1, 0x1a, 0x1c, 0x5a, 0xde, 0x3d, 0xb4,
                0xc4, 0x95, 0xc0, 0xa7, 0x01, 0xb9, 0x40, 0x6d, 0xe8, 0x0a, 0x07, 0xb2, 0x54, 0x8f,
                0x94, 0xaa, 0x2a, 0x7c,
            ]
        );
    }

    #[test]
    fn content_id_is_separated_by_kind_and_unambiguous_length() {
        assert_ne!(
            ContentId::for_object(ObjectKind::Blob, b"abc"),
            ContentId::for_object(ObjectKind::Tree, b"abc")
        );
        assert_ne!(
            ContentId::for_object(ObjectKind::Blob, b"a"),
            ContentId::for_object(ObjectKind::Blob, b"a\0")
        );
    }

    #[test]
    fn sparse_image_has_requested_logical_length() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("reflink-forest-core-{unique}"));
        fs::create_dir(&directory).unwrap();
        let image = directory.join("hot.btrfs");

        create_sparse_image(&image, 16 * 1024 * 1024).unwrap();
        let allocation = file_allocation(&image).unwrap();
        assert_eq!(allocation.logical_bytes, 16 * 1024 * 1024);
        assert!(allocation.allocated_bytes <= allocation.logical_bytes);

        fs::remove_dir_all(directory).unwrap();
    }
}
