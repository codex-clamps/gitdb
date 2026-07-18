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

    /// Computes the native Git object ID for one raw object payload.
    ///
    /// Unlike [`ContentId`], a Git object ID includes the Git type name and
    /// ASCII-decimal payload length.  Marking uses this to ensure a
    /// repository-scoped OID alias actually names the cold record it selects.
    pub fn for_object(algorithm: HashAlgorithm, kind: ObjectKind, raw_payload: &[u8]) -> Self {
        let mut header = Vec::with_capacity(32);
        header.extend_from_slice(git_object_kind_name(kind).as_bytes());
        header.push(b' ');
        header.extend_from_slice(raw_payload.len().to_string().as_bytes());
        header.push(0);

        match algorithm {
            HashAlgorithm::Sha1 => {
                let mut digest = sha1::Sha1::new();
                digest.update(&header);
                digest.update(raw_payload);
                Self::new(algorithm, &digest.finalize()).expect("SHA-1 digest has a fixed length")
            }
            HashAlgorithm::Sha256 => {
                let mut digest = Sha256::new();
                digest.update(&header);
                digest.update(raw_payload);
                Self::new(algorithm, &digest.finalize()).expect("SHA-256 digest has a fixed length")
            }
        }
    }

    pub const fn algorithm(self) -> HashAlgorithm {
        self.algorithm
    }

    pub const fn len(self) -> u8 {
        self.len
    }

    /// Git object IDs always have a native algorithm-defined, non-zero width.
    pub const fn is_empty(self) -> bool {
        false
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

fn git_object_kind_name(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Commit => "commit",
        ObjectKind::Tree => "tree",
        ObjectKind::Blob => "blob",
        ObjectKind::Tag => "tag",
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
        let mut hasher = ContentHasher::new(kind, raw_payload.len() as u64);
        hasher.update(raw_payload);
        hasher.finalize()
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Incremental hasher for a canonical [`ContentId`].
///
/// Supplying the known raw length up front preserves the same canonical byte
/// sequence as [`ContentId::for_object`] while allowing cold hydration to hash
/// a large raw blob in bounded I/O buffers.
#[derive(Clone, Debug)]
pub struct ContentHasher(Sha256);

impl ContentHasher {
    pub fn new(kind: ObjectKind, raw_length: u64) -> Self {
        let mut digest = Sha256::new();
        digest.update(CONTENT_ID_DOMAIN);
        digest.update([kind.tag()]);
        digest.update(raw_length.to_be_bytes());
        Self(digest)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finalize(self) -> ContentId {
        ContentId(self.0.finalize().into())
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
    fn content_hasher_matches_one_shot_content_id() {
        let payload = b"a payload split across several bounded cold reads";
        let mut hasher = ContentHasher::new(ObjectKind::Blob, payload.len() as u64);
        for part in payload.chunks(7) {
            hasher.update(part);
        }
        assert_eq!(
            hasher.finalize(),
            ContentId::for_object(ObjectKind::Blob, payload)
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
