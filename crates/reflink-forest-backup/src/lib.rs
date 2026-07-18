//! Verified cold-tier checkpoints.
//!
//! A caller must hold the store writer lock before calling [`checkpoint`]. The
//! result is a self-describing snapshot tree that is published only after all
//! files and its manifest have been synchronized.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    num::TryFromIntError,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// The filename containing a checkpoint's authenticated inventory.
pub const MANIFEST_FILE_NAME: &str = "manifest-v1";
pub const COLD_DESCRIPTOR_FILE_NAME: &str = "cold-tier-v1";
const COLD_DESCRIPTOR_MAGIC: &[u8; 8] = b"RFCOLD01";

const MANIFEST_MAGIC: &[u8; 8] = b"RFBKMAN1";
const MANIFEST_HEADER_LEN: usize = MANIFEST_MAGIC.len() + 8;
const MANIFEST_DIGEST_LEN: usize = 32;
const MIN_MANIFEST_ENTRY_LEN: usize = 4 + 1 + 8 + 32;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_ENTRIES: u64 = 1_000_000;
const MAX_MANIFEST_PATH_BYTES: u32 = 1024 * 1024;
const COLD_DESCRIPTOR_HEADER_LEN: usize = COLD_DESCRIPTOR_MAGIC.len() + 2 + 4 + 4 + 4;
const COLD_DESCRIPTOR_CHUNK_LEN: usize = 24;
const COLD_DESCRIPTOR_DIGESTS_LEN: usize = 3 * 32;
const COLD_DESCRIPTOR_CHECKSUM_LEN: usize = 32;
/// Maximum chunk locations retained in one cold-tier checkpoint descriptor.
///
/// This also bounds decoder allocation when the descriptor is supplied by an
/// untrusted backup source.  A million locations need about 24 MiB on disk,
/// which is already substantially larger than normal production checkpoints.
pub const MAX_COLD_DESCRIPTOR_CHUNKS: usize = 1_000_000;
const MAX_COLD_DESCRIPTOR_BYTES: usize = COLD_DESCRIPTOR_HEADER_LEN
    + MAX_COLD_DESCRIPTOR_CHUNKS * COLD_DESCRIPTOR_CHUNK_LEN
    + COLD_DESCRIPTOR_DIGESTS_LEN
    + COLD_DESCRIPTOR_CHECKSUM_LEN;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupFile {
    pub relative: PathBuf,
    pub bytes: u64,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupManifest {
    pub files: Vec<BackupFile>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkClassification {
    Open,
    Sealed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdChunkDescriptor {
    pub generation: u32,
    pub chunk_id: u64,
    pub classification: ChunkClassification,
    /// Complete durable prefix for an open chunk; sealed chunks use their full size.
    pub valid_prefix: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdTierCheckpointDescriptor {
    pub catalog_schema_version: u32,
    pub active_generation: u32,
    pub chunks: Vec<ColdChunkDescriptor>,
    pub catalog_digest: [u8; 32],
    pub config_digest: [u8; 32],
    pub pins_manifest_digest: [u8; 32],
}

/// The three authoritative metadata files whose content digests are carried
/// by a [`ColdTierCheckpointDescriptor`].
///
/// Reflink Forest deliberately does not prescribe names for these files.  The
/// owning catalog/daemon supplies paths relative to its cold-tier root, and
/// the backup layer validates them before it uses them.  This keeps the backup
/// format independent of a particular on-disk catalog implementation while
/// making the descriptor's metadata binding explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdTierAuthoritativePaths {
    catalog: PathBuf,
    config: PathBuf,
    pins_manifest: PathBuf,
}

/// Content digests for a [`ColdTierAuthoritativePaths`] layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColdTierAuthoritativeDigests {
    pub catalog_digest: [u8; 32],
    pub config_digest: [u8; 32],
    pub pins_manifest_digest: [u8; 32],
}

impl ColdTierAuthoritativePaths {
    /// Creates an explicit authoritative metadata layout.
    ///
    /// Every path must be a distinct, normalized path relative to the cold
    /// tier root; absolute paths, traversal, and empty components are
    /// rejected.  The paths are intentionally supplied by the caller instead
    /// of being inferred from production-specific filenames.
    pub fn new(
        catalog: impl Into<PathBuf>,
        config: impl Into<PathBuf>,
        pins_manifest: impl Into<PathBuf>,
    ) -> Result<Self, BackupError> {
        let paths = Self {
            catalog: catalog.into(),
            config: config.into(),
            pins_manifest: pins_manifest.into(),
        };
        paths.validate()?;
        Ok(paths)
    }

    /// The catalog metadata path, relative to the cold-tier root.
    pub fn catalog(&self) -> &Path {
        &self.catalog
    }

    /// The cold-tier configuration path, relative to the cold-tier root.
    pub fn config(&self) -> &Path {
        &self.config
    }

    /// The pin-manifest path, relative to the cold-tier root.
    pub fn pins_manifest(&self) -> &Path {
        &self.pins_manifest
    }

    /// Hashes the three authoritative regular files below `root`.
    ///
    /// This is useful when the catalog layer constructs a descriptor after it
    /// has durably synchronized its own authoritative metadata.
    pub fn digests(
        &self,
        root: impl AsRef<Path>,
    ) -> Result<ColdTierAuthoritativeDigests, BackupError> {
        self.validate()?;
        let root = root.as_ref();
        Ok(ColdTierAuthoritativeDigests {
            catalog_digest: hash_authoritative_file(root, &self.catalog)?,
            config_digest: hash_authoritative_file(root, &self.config)?,
            pins_manifest_digest: hash_authoritative_file(root, &self.pins_manifest)?,
        })
    }

    fn validate(&self) -> Result<(), BackupError> {
        for path in [&self.catalog, &self.config, &self.pins_manifest] {
            path_to_bytes(path).map_err(|_| BackupError::InvalidColdTierLayout)?;
        }
        if self.catalog == self.config
            || self.catalog == self.pins_manifest
            || self.config == self.pins_manifest
        {
            return Err(BackupError::InvalidColdTierLayout);
        }
        Ok(())
    }
}

/// The daemon supplies this guard to pause writers and force the catalog/chunk
/// durability boundary before authoritative cold-tier paths are copied.
pub trait CheckpointGuard {
    fn quiesce_and_sync(&self) -> Result<(), BackupError>;
}
#[derive(Debug)]
pub enum BackupError {
    Io(io::Error),
    UnsafeSource(PathBuf),
    InvalidManifest,
    InvalidColdTierLayout,
    VerificationFailed(PathBuf),
    DestinationExists,
    UnsafeDestination(PathBuf),
}
impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "backup I/O error: {error}"),
            Self::UnsafeSource(path) => write!(
                f,
                "backup source contains unsupported path: {}",
                path.display()
            ),
            Self::InvalidManifest => write!(f, "invalid backup manifest"),
            Self::InvalidColdTierLayout => {
                write!(f, "invalid cold-tier authoritative metadata layout")
            }
            Self::VerificationFailed(path) => {
                write!(f, "backup verification failed: {}", path.display())
            }
            Self::DestinationExists => write!(f, "backup destination already exists"),
            Self::UnsafeDestination(path) => write!(
                f,
                "unsafe restore/checkpoint destination: {}",
                path.display()
            ),
        }
    }
}

/// Writes an authenticated v1 cold-tier descriptor next to a generic checkpoint.
///
/// The descriptor's catalog, configuration, and pin-manifest digests are
/// compared with the caller-supplied authoritative files before copying and
/// again in the checkpoint tree before publishing the descriptor.  The generic
/// file inventory remains backward compatible; consumers requiring cold-tier
/// recovery must also supply this same explicit layout to [`restore_cold_tier`].
pub fn checkpoint_cold_tier<G: CheckpointGuard>(
    guard: &G,
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    descriptor: &ColdTierCheckpointDescriptor,
    authoritative_paths: &ColdTierAuthoritativePaths,
) -> Result<BackupManifest, BackupError> {
    guard.quiesce_and_sync()?;
    validate_cold_descriptor(descriptor)?;
    let source = source.as_ref();
    verify_cold_descriptor_authority(source, descriptor, authoritative_paths)?;
    let manifest = checkpoint(source, &destination)?;
    let root = destination.as_ref();
    verify_cold_descriptor_authority(root, descriptor, authoritative_paths)?;
    let path = root.join(COLD_DESCRIPTOR_FILE_NAME);
    let bytes = encode_cold_descriptor(descriptor)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(manifest)
}
pub fn load_cold_tier_descriptor(
    root: impl AsRef<Path>,
) -> Result<ColdTierCheckpointDescriptor, BackupError> {
    let mut bytes = Vec::new();
    File::open(root.as_ref().join(COLD_DESCRIPTOR_FILE_NAME))?
        .take((MAX_COLD_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    decode_cold_descriptor(&bytes)
}
/// Requires generic inventory verification, a valid cold-tier descriptor, and
/// descriptor-digest matches for the supplied authoritative files before
/// accepting a restore.  The restored files are checked again after the generic
/// restore publishes its destination.
pub fn restore_cold_tier(
    backup_root: impl AsRef<Path>,
    manifest: &BackupManifest,
    destination: impl AsRef<Path>,
    authoritative_paths: &ColdTierAuthoritativePaths,
) -> Result<(), BackupError> {
    let backup_root = backup_root.as_ref();
    let descriptor = load_cold_tier_descriptor(backup_root)?;
    verify_cold_descriptor_authority(backup_root, &descriptor, authoritative_paths)?;
    let destination = destination.as_ref();
    restore(backup_root, manifest, destination)?;
    verify_cold_descriptor_authority(destination, &descriptor, authoritative_paths)
}
impl std::error::Error for BackupError {}
impl From<io::Error> for BackupError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Copies a quiescent source tree to a new, verified checkpoint directory.
pub fn checkpoint(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<BackupManifest, BackupError> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    if destination.exists() {
        return Err(BackupError::DestinationExists);
    }
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup destination has no parent",
        )
    })?;
    if fs::symlink_metadata(parent)?.file_type().is_symlink() || !parent.is_dir() {
        return Err(BackupError::UnsafeDestination(parent.to_path_buf()));
    }
    let temporary = parent.join(format!(".checkpoint-{}-{}", process::id(), nonce()));
    fs::create_dir(&temporary)?;
    let result = (|| {
        let mut files = Vec::new();
        copy_tree(source, source, &temporary, &mut files)?;
        files.sort_by(|left, right| left.relative.cmp(&right.relative));
        let manifest = BackupManifest { files };
        write_manifest(&temporary, &manifest)?;
        verify_tree(&temporary, &manifest)?;
        File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, destination)?;
        File::open(parent)?.sync_all()?;
        Ok(manifest)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

/// Reads and validates the `manifest-v1` file in a checkpoint directory.
///
/// The manifest is an inventory, rather than proof that the copied bytes are
/// still present. Call [`verify_tree`] after loading it before using a
/// checkpoint as a restore source.
pub fn load_manifest(root: impl AsRef<Path>) -> Result<BackupManifest, BackupError> {
    read_manifest(root.as_ref().join(MANIFEST_FILE_NAME))
}

/// Reads one manifest file from its exact path.
///
/// The v1 encoding is binary and checksummed. Paths are stored as raw native
/// path bytes on Unix, not lossy UTF-8 text, so a valid filename need not be
/// UTF-8. The decoder rejects unknown versions, non-canonical paths, duplicate
/// entries, truncated input, trailing bytes, and a bad manifest digest.
pub fn read_manifest(path: impl AsRef<Path>) -> Result<BackupManifest, BackupError> {
    let path = path.as_ref();
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    decode_manifest(&bytes)
}

/// Verifies copied data against the manifest before accepting a restore point.
pub fn verify_tree(root: impl AsRef<Path>, manifest: &BackupManifest) -> Result<(), BackupError> {
    for file in &manifest.files {
        path_to_bytes(&file.relative)?;
        let path = root.as_ref().join(&file.relative);
        let (bytes, digest) = hash_file(&path)?;
        if bytes != file.bytes || digest != file.sha256 {
            return Err(BackupError::VerificationFailed(file.relative.clone()));
        }
    }
    Ok(())
}

/// Restores a verified checkpoint to a new destination. The manifest must come
/// from the caller's authenticated backup metadata; an existing destination is
/// never overwritten.
pub fn restore(
    backup_root: impl AsRef<Path>,
    manifest: &BackupManifest,
    destination: impl AsRef<Path>,
) -> Result<(), BackupError> {
    let backup_root = backup_root.as_ref();
    let destination = destination.as_ref();
    if destination.exists() {
        return Err(BackupError::DestinationExists);
    }
    verify_tree(backup_root, manifest)?;
    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "restore destination has no parent",
        )
    })?;
    if fs::symlink_metadata(parent)?.file_type().is_symlink() || !parent.is_dir() {
        return Err(BackupError::UnsafeDestination(parent.to_path_buf()));
    }
    let temporary = parent.join(format!(".restore-{}-{}", process::id(), nonce()));
    fs::create_dir(&temporary)?;
    let result = (|| -> Result<(), BackupError> {
        for entry in &manifest.files {
            path_to_bytes(&entry.relative)?;
            if entry
                .relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err(BackupError::InvalidManifest);
            }
            let source = backup_root.join(&entry.relative);
            let target = temporary.join(&entry.relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut input = File::open(source)?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(target)?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()?;
        }
        verify_tree(&temporary, manifest)?;
        File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, destination)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

fn copy_tree(
    source_root: &Path,
    current: &Path,
    destination: &Path,
    files: &mut Vec<BackupFile>,
) -> Result<(), BackupError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let source = entry.path();
        let metadata = fs::symlink_metadata(&source)?;
        let relative = source
            .strip_prefix(source_root)
            .expect("source remains beneath root");
        let target = destination.join(relative);
        if metadata.is_dir() {
            fs::create_dir(&target)?;
            copy_tree(source_root, &source, destination, files)?;
            File::open(&target)?.sync_all()?;
        } else if metadata.is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut input = File::open(&source)?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            let (bytes, sha256) = hash_file(&target)?;
            files.push(BackupFile {
                relative: relative.to_path_buf(),
                bytes,
                sha256,
            });
        } else {
            return Err(BackupError::UnsafeSource(relative.to_path_buf()));
        }
    }
    Ok(())
}
fn hash_file(path: &Path) -> Result<(u64, [u8; 32]), BackupError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes = bytes
            .checked_add(read as u64)
            .ok_or(BackupError::InvalidManifest)?;
    }
    Ok((bytes, hasher.finalize().into()))
}

fn hash_authoritative_file(root: &Path, relative: &Path) -> Result<[u8; 32], BackupError> {
    let path = root.join(relative);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Err(BackupError::VerificationFailed(relative.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(BackupError::VerificationFailed(relative.to_path_buf()))
        }
        Err(error) => return Err(BackupError::Io(error)),
    }
    match hash_file(&path) {
        Ok((_, digest)) => Ok(digest),
        Err(BackupError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            Err(BackupError::VerificationFailed(relative.to_path_buf()))
        }
        Err(error) => Err(error),
    }
}

fn verify_cold_descriptor_authority(
    root: &Path,
    descriptor: &ColdTierCheckpointDescriptor,
    authoritative_paths: &ColdTierAuthoritativePaths,
) -> Result<(), BackupError> {
    let actual = authoritative_paths.digests(root)?;
    if actual.catalog_digest != descriptor.catalog_digest {
        return Err(BackupError::VerificationFailed(
            authoritative_paths.catalog.clone(),
        ));
    }
    if actual.config_digest != descriptor.config_digest {
        return Err(BackupError::VerificationFailed(
            authoritative_paths.config.clone(),
        ));
    }
    if actual.pins_manifest_digest != descriptor.pins_manifest_digest {
        return Err(BackupError::VerificationFailed(
            authoritative_paths.pins_manifest.clone(),
        ));
    }
    Ok(())
}

fn write_manifest(root: &Path, manifest: &BackupManifest) -> Result<(), BackupError> {
    let path = root.join(MANIFEST_FILE_NAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let bytes = encode_manifest(manifest)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn encode_manifest(manifest: &BackupManifest) -> Result<Vec<u8>, BackupError> {
    let entry_count: u64 = manifest
        .files
        .len()
        .try_into()
        .map_err(|_: TryFromIntError| BackupError::InvalidManifest)?;
    if entry_count > MAX_MANIFEST_ENTRIES {
        return Err(BackupError::InvalidManifest);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(MANIFEST_MAGIC);
    bytes.extend_from_slice(&entry_count.to_be_bytes());
    let mut previous_path = None;
    for entry in &manifest.files {
        let path = path_to_bytes(&entry.relative)?;
        validate_path_bytes(&path)?;
        if previous_path
            .as_ref()
            .is_some_and(|previous: &Vec<u8>| previous >= &path)
        {
            return Err(BackupError::InvalidManifest);
        }
        previous_path = Some(path.clone());
        let path_len: u32 = path
            .len()
            .try_into()
            .map_err(|_: TryFromIntError| BackupError::InvalidManifest)?;
        bytes.extend_from_slice(&path_len.to_be_bytes());
        bytes.extend_from_slice(&path);
        bytes.extend_from_slice(&entry.bytes.to_be_bytes());
        bytes.extend_from_slice(&entry.sha256);
    }
    let digest = Sha256::digest(&bytes);
    bytes.extend_from_slice(&digest);
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(BackupError::InvalidManifest);
    }
    Ok(bytes)
}

fn decode_manifest(bytes: &[u8]) -> Result<BackupManifest, BackupError> {
    if bytes.len() < MANIFEST_HEADER_LEN + MANIFEST_DIGEST_LEN
        || bytes.len() as u64 > MAX_MANIFEST_BYTES
    {
        return Err(BackupError::InvalidManifest);
    }
    let (payload, stored_digest) = bytes.split_at(bytes.len() - MANIFEST_DIGEST_LEN);
    if Sha256::digest(payload).as_slice() != stored_digest {
        return Err(BackupError::InvalidManifest);
    }
    if !payload.starts_with(MANIFEST_MAGIC) {
        return Err(BackupError::InvalidManifest);
    }

    let mut offset = MANIFEST_MAGIC.len();
    let count = read_u64(payload, &mut offset)?;
    if count > MAX_MANIFEST_ENTRIES {
        return Err(BackupError::InvalidManifest);
    }
    let count: usize = count
        .try_into()
        .map_err(|_: TryFromIntError| BackupError::InvalidManifest)?;
    if count > (payload.len() - offset) / MIN_MANIFEST_ENTRY_LEN {
        return Err(BackupError::InvalidManifest);
    }
    let mut files = Vec::with_capacity(count);
    let mut previous_path = None;
    for _ in 0..count {
        let path_len = read_u32(payload, &mut offset)?;
        if path_len > MAX_MANIFEST_PATH_BYTES {
            return Err(BackupError::InvalidManifest);
        }
        let path_len: usize = path_len
            .try_into()
            .map_err(|_: TryFromIntError| BackupError::InvalidManifest)?;
        let path = read_bytes(payload, &mut offset, path_len)?;
        validate_path_bytes(path)?;
        if previous_path
            .as_ref()
            .is_some_and(|previous: &&[u8]| *previous >= path)
        {
            return Err(BackupError::InvalidManifest);
        }
        previous_path = Some(path);
        let bytes = read_u64(payload, &mut offset)?;
        let sha256: [u8; 32] = read_bytes(payload, &mut offset, 32)?
            .try_into()
            .expect("length checked");
        files.push(BackupFile {
            relative: path_from_bytes(path)?,
            bytes,
            sha256,
        });
    }
    if offset != payload.len() {
        return Err(BackupError::InvalidManifest);
    }
    Ok(BackupManifest { files })
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], BackupError> {
    let end = offset
        .checked_add(len)
        .ok_or(BackupError::InvalidManifest)?;
    let result = bytes
        .get(*offset..end)
        .ok_or(BackupError::InvalidManifest)?;
    *offset = end;
    Ok(result)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32, BackupError> {
    Ok(u32::from_be_bytes(
        read_bytes(bytes, offset, 4)?
            .try_into()
            .expect("length checked"),
    ))
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, BackupError> {
    Ok(u64::from_be_bytes(
        read_bytes(bytes, offset, 8)?
            .try_into()
            .expect("length checked"),
    ))
}

fn validate_path_bytes(path: &[u8]) -> Result<(), BackupError> {
    if path.is_empty()
        || path.len() > MAX_MANIFEST_PATH_BYTES as usize
        || path.contains(&0)
        || path.starts_with(b"/")
        || path.ends_with(b"/")
    {
        return Err(BackupError::InvalidManifest);
    }
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(BackupError::InvalidManifest);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn path_to_bytes(path: &Path) -> Result<Vec<u8>, BackupError> {
    let bytes = path.as_os_str().as_bytes();
    validate_path_bytes(bytes)?;
    Ok(bytes.to_vec())
}

#[cfg(not(unix))]
fn path_to_bytes(path: &Path) -> Result<Vec<u8>, BackupError> {
    let path = path.to_str().ok_or(BackupError::InvalidManifest)?;
    validate_path_bytes(path.as_bytes())?;
    Ok(path.as_bytes().to_vec())
}

#[cfg(unix)]
fn path_from_bytes(bytes: &[u8]) -> Result<PathBuf, BackupError> {
    validate_path_bytes(bytes)?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn path_from_bytes(bytes: &[u8]) -> Result<PathBuf, BackupError> {
    validate_path_bytes(bytes)?;
    let path = std::str::from_utf8(bytes).map_err(|_| BackupError::InvalidManifest)?;
    Ok(PathBuf::from(path))
}
fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}

fn validate_cold_descriptor(descriptor: &ColdTierCheckpointDescriptor) -> Result<(), BackupError> {
    if descriptor.chunks.len() > MAX_COLD_DESCRIPTOR_CHUNKS {
        return Err(BackupError::InvalidManifest);
    }
    if descriptor.chunks.windows(2).any(|pair| {
        (pair[0].generation, pair[0].chunk_id) >= (pair[1].generation, pair[1].chunk_id)
    }) {
        return Err(BackupError::InvalidManifest);
    }
    if descriptor
        .chunks
        .iter()
        .any(|chunk| chunk.valid_prefix == 0)
    {
        return Err(BackupError::InvalidManifest);
    }
    Ok(())
}
fn encode_cold_descriptor(
    descriptor: &ColdTierCheckpointDescriptor,
) -> Result<Vec<u8>, BackupError> {
    validate_cold_descriptor(descriptor)?;
    let count: u32 = descriptor
        .chunks
        .len()
        .try_into()
        .map_err(|_: TryFromIntError| BackupError::InvalidManifest)?;
    let capacity = COLD_DESCRIPTOR_HEADER_LEN
        .checked_add(
            descriptor
                .chunks
                .len()
                .checked_mul(COLD_DESCRIPTOR_CHUNK_LEN)
                .ok_or(BackupError::InvalidManifest)?,
        )
        .and_then(|len| len.checked_add(COLD_DESCRIPTOR_DIGESTS_LEN))
        .and_then(|len| len.checked_add(COLD_DESCRIPTOR_CHECKSUM_LEN))
        .ok_or(BackupError::InvalidManifest)?;
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(COLD_DESCRIPTOR_MAGIC);
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&descriptor.catalog_schema_version.to_be_bytes());
    out.extend_from_slice(&descriptor.active_generation.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    for chunk in &descriptor.chunks {
        out.extend_from_slice(&chunk.generation.to_be_bytes());
        out.extend_from_slice(&chunk.chunk_id.to_be_bytes());
        out.push(match chunk.classification {
            ChunkClassification::Open => 1,
            ChunkClassification::Sealed => 2,
        });
        out.extend_from_slice(&[0; 3]);
        out.extend_from_slice(&chunk.valid_prefix.to_be_bytes());
    }
    out.extend_from_slice(&descriptor.catalog_digest);
    out.extend_from_slice(&descriptor.config_digest);
    out.extend_from_slice(&descriptor.pins_manifest_digest);
    let digest = Sha256::digest(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}
fn decode_cold_descriptor(bytes: &[u8]) -> Result<ColdTierCheckpointDescriptor, BackupError> {
    if bytes.len()
        < COLD_DESCRIPTOR_HEADER_LEN + COLD_DESCRIPTOR_DIGESTS_LEN + COLD_DESCRIPTOR_CHECKSUM_LEN
        || bytes.len() > MAX_COLD_DESCRIPTOR_BYTES
    {
        return Err(BackupError::InvalidManifest);
    }
    let (payload, stored) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(payload).as_slice() != stored
        || &payload[..8] != COLD_DESCRIPTOR_MAGIC
        || u16::from_be_bytes([payload[8], payload[9]]) != 1
    {
        return Err(BackupError::InvalidManifest);
    }
    let mut offset = 10;
    let schema = read_u32(payload, &mut offset)?;
    let active = read_u32(payload, &mut offset)?;
    let count = read_u32(payload, &mut offset)? as usize;
    if count > MAX_COLD_DESCRIPTOR_CHUNKS {
        return Err(BackupError::InvalidManifest);
    }
    let expected = COLD_DESCRIPTOR_HEADER_LEN
        .checked_add(
            count
                .checked_mul(COLD_DESCRIPTOR_CHUNK_LEN)
                .ok_or(BackupError::InvalidManifest)?,
        )
        .and_then(|n| n.checked_add(COLD_DESCRIPTOR_DIGESTS_LEN))
        .ok_or(BackupError::InvalidManifest)?;
    if payload.len() != expected {
        return Err(BackupError::InvalidManifest);
    }
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        let generation = read_u32(payload, &mut offset)?;
        let chunk_id = read_u64(payload, &mut offset)?;
        let classification = match read_bytes(payload, &mut offset, 1)?[0] {
            1 => ChunkClassification::Open,
            2 => ChunkClassification::Sealed,
            _ => return Err(BackupError::InvalidManifest),
        };
        if read_bytes(payload, &mut offset, 3)? != [0; 3] {
            return Err(BackupError::InvalidManifest);
        }
        let valid_prefix = read_u64(payload, &mut offset)?;
        chunks.push(ColdChunkDescriptor {
            generation,
            chunk_id,
            classification,
            valid_prefix,
        });
    }
    let catalog_digest = read_bytes(payload, &mut offset, 32)?
        .try_into()
        .map_err(|_| BackupError::InvalidManifest)?;
    let config_digest = read_bytes(payload, &mut offset, 32)?
        .try_into()
        .map_err(|_| BackupError::InvalidManifest)?;
    let pins_manifest_digest = read_bytes(payload, &mut offset, 32)?
        .try_into()
        .map_err(|_| BackupError::InvalidManifest)?;
    let descriptor = ColdTierCheckpointDescriptor {
        catalog_schema_version: schema,
        active_generation: active,
        chunks,
        catalog_digest,
        config_digest,
        pins_manifest_digest,
    };
    validate_cold_descriptor(&descriptor)?;
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("reflink-forest-backup-{label}-{}", nonce()))
    }
    struct Guard;
    impl CheckpointGuard for Guard {
        fn quiesce_and_sync(&self) -> Result<(), BackupError> {
            Ok(())
        }
    }
    fn descriptor() -> ColdTierCheckpointDescriptor {
        ColdTierCheckpointDescriptor {
            catalog_schema_version: 1,
            active_generation: 7,
            chunks: vec![ColdChunkDescriptor {
                generation: 7,
                chunk_id: 1,
                classification: ChunkClassification::Open,
                valid_prefix: 4096,
            }],
            catalog_digest: [1; 32],
            config_digest: [2; 32],
            pins_manifest_digest: [3; 32],
        }
    }

    fn authoritative_paths() -> ColdTierAuthoritativePaths {
        ColdTierAuthoritativePaths::new(
            "metadata/catalog.bin",
            "metadata/config.bin",
            "metadata/pins.bin",
        )
        .unwrap()
    }

    fn write_authoritative_files(root: &Path, paths: &ColdTierAuthoritativePaths) {
        fs::create_dir_all(root.join("metadata")).unwrap();
        fs::write(root.join(paths.catalog()), b"catalog bytes").unwrap();
        fs::write(root.join(paths.config()), b"config bytes").unwrap();
        fs::write(root.join(paths.pins_manifest()), b"pin bytes").unwrap();
    }

    fn descriptor_for(
        root: &Path,
        paths: &ColdTierAuthoritativePaths,
    ) -> ColdTierCheckpointDescriptor {
        let digests = paths.digests(root).unwrap();
        ColdTierCheckpointDescriptor {
            catalog_schema_version: 1,
            active_generation: 7,
            chunks: vec![ColdChunkDescriptor {
                generation: 7,
                chunk_id: 1,
                classification: ChunkClassification::Open,
                valid_prefix: 4096,
            }],
            catalog_digest: digests.catalog_digest,
            config_digest: digests.config_digest,
            pins_manifest_digest: digests.pins_manifest_digest,
        }
    }

    #[test]
    fn cold_descriptor_round_trips_and_rejects_corruption() {
        let encoded = encode_cold_descriptor(&descriptor()).unwrap();
        assert_eq!(decode_cold_descriptor(&encoded).unwrap(), descriptor());
        let mut corrupt = encoded;
        corrupt[15] ^= 1;
        assert!(matches!(
            decode_cold_descriptor(&corrupt),
            Err(BackupError::InvalidManifest)
        ));
    }

    #[test]
    fn guarded_cold_checkpoint_verifies_authoritative_files_and_restores_fresh_root() {
        let source = dir("cold-source");
        let parent = dir("cold-parent");
        fs::create_dir_all(source.join("chunks")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(source.join("chunks/a"), b"cold").unwrap();
        let paths = authoritative_paths();
        write_authoritative_files(&source, &paths);
        let descriptor = descriptor_for(&source, &paths);
        let checkpoint_root = parent.join("checkpoint");
        let manifest =
            checkpoint_cold_tier(&Guard, &source, &checkpoint_root, &descriptor, &paths).unwrap();
        assert_eq!(
            load_cold_tier_descriptor(&checkpoint_root).unwrap(),
            descriptor
        );
        fs::remove_dir_all(source).unwrap();
        let restore = parent.join("restore");
        restore_cold_tier(&checkpoint_root, &manifest, &restore, &paths).unwrap();
        assert_eq!(
            fs::read(restore.join(paths.catalog())).unwrap(),
            b"catalog bytes"
        );
        assert_eq!(
            fs::read(restore.join(paths.config())).unwrap(),
            b"config bytes"
        );
        assert_eq!(
            fs::read(restore.join(paths.pins_manifest())).unwrap(),
            b"pin bytes"
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn cold_checkpoint_rejects_descriptor_that_does_not_match_authoritative_files() {
        let source = dir("cold-mismatch-source");
        let parent = dir("cold-mismatch-parent");
        fs::create_dir_all(source.join("chunks")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(source.join("chunks/a"), b"cold").unwrap();
        let paths = authoritative_paths();
        write_authoritative_files(&source, &paths);
        let checkpoint = parent.join("checkpoint");

        assert!(matches!(
            checkpoint_cold_tier(&Guard, &source, &checkpoint, &descriptor(), &paths),
            Err(BackupError::VerificationFailed(path)) if path == paths.catalog()
        ));
        assert!(!checkpoint.exists());
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn cold_restore_rejects_tampered_authoritative_file_before_publication() {
        let source = dir("cold-tamper-source");
        let parent = dir("cold-tamper-parent");
        fs::create_dir_all(source.join("chunks")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(source.join("chunks/a"), b"cold").unwrap();
        let paths = authoritative_paths();
        write_authoritative_files(&source, &paths);
        let descriptor = descriptor_for(&source, &paths);
        let checkpoint = parent.join("checkpoint");
        let manifest =
            checkpoint_cold_tier(&Guard, &source, &checkpoint, &descriptor, &paths).unwrap();
        fs::write(checkpoint.join(paths.config()), b"tampered config").unwrap();

        let restore = parent.join("restore");
        assert!(matches!(
            restore_cold_tier(&checkpoint, &manifest, &restore, &paths),
            Err(BackupError::VerificationFailed(path)) if path == paths.config()
        ));
        assert!(!restore.exists());
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
    #[test]
    fn checkpoint_is_verified_and_rejects_symlinks() {
        let source = dir("source");
        let parent = dir("parent");
        fs::create_dir_all(source.join("chunks")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(source.join("chunks/a"), b"cold bytes").unwrap();
        let destination = parent.join("checkpoint");
        let manifest = checkpoint(&source, &destination).unwrap();
        assert_eq!(manifest.files.len(), 1);
        verify_tree(&destination, &manifest).unwrap();
        let restored = parent.join("restored");
        restore(&destination, &manifest, &restored).unwrap();
        verify_tree(&restored, &manifest).unwrap();
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn manifest_round_trips_from_checkpoint_and_preserves_path_bytes() {
        let source = dir("round-trip-source");
        let parent = dir("round-trip-parent");
        fs::create_dir_all(source.join("chunks")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(source.join("chunks/ordinary"), b"ordinary bytes").unwrap();
        #[cfg(unix)]
        {
            let non_utf8 = PathBuf::from(std::ffi::OsString::from_vec(
                b"chunks/non-utf8-\xff".to_vec(),
            ));
            fs::write(source.join(non_utf8), b"opaque path bytes").unwrap();
        }

        let destination = parent.join("checkpoint");
        let written = checkpoint(&source, &destination).unwrap();
        let loaded = load_manifest(&destination).unwrap();
        assert_eq!(loaded, written);
        #[cfg(unix)]
        assert!(loaded
            .files
            .iter()
            .any(|file| { file.relative.as_os_str().as_bytes() == b"chunks/non-utf8-\xff" }));
        verify_tree(&destination, &loaded).unwrap();
        let restored = parent.join("restored");
        restore(&destination, &loaded, &restored).unwrap();
        verify_tree(&restored, &loaded).unwrap();

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn manifest_loader_rejects_corruption_truncation_and_unsafe_paths() {
        let source = dir("corrupt-source");
        let parent = dir("corrupt-parent");
        fs::create_dir_all(source.join("chunks")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::write(source.join("chunks/a"), b"cold bytes").unwrap();
        let checkpoint_root = parent.join("checkpoint");
        checkpoint(&source, &checkpoint_root).unwrap();
        let manifest_path = checkpoint_root.join(MANIFEST_FILE_NAME);
        let manifest = fs::read(&manifest_path).unwrap();
        assert!(read_manifest(&manifest_path).is_ok());

        for truncated_len in 0..manifest.len() {
            fs::write(&manifest_path, &manifest[..truncated_len]).unwrap();
            assert!(matches!(
                load_manifest(&checkpoint_root),
                Err(BackupError::InvalidManifest)
            ));
        }

        let mut bad_digest = manifest.clone();
        bad_digest[MANIFEST_HEADER_LEN] ^= 1;
        fs::write(&manifest_path, bad_digest).unwrap();
        assert!(matches!(
            load_manifest(&checkpoint_root),
            Err(BackupError::InvalidManifest)
        ));

        let mut unsafe_path = manifest.clone();
        let path_start = MANIFEST_HEADER_LEN + 4;
        unsafe_path[path_start..path_start + b"chunks/a".len()].copy_from_slice(b"../evil!");
        let digest_offset = unsafe_path.len() - MANIFEST_DIGEST_LEN;
        let digest = Sha256::digest(&unsafe_path[..digest_offset]);
        unsafe_path[digest_offset..].copy_from_slice(&digest);
        fs::write(&manifest_path, unsafe_path).unwrap();
        assert!(matches!(
            load_manifest(&checkpoint_root),
            Err(BackupError::InvalidManifest)
        ));

        let mut trailing = manifest;
        trailing.push(0);
        fs::write(&manifest_path, trailing).unwrap();
        assert!(matches!(
            load_manifest(&checkpoint_root),
            Err(BackupError::InvalidManifest)
        ));

        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    fn corpus_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut value = state;
                value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                (value ^ (value >> 31)) as u8
            })
            .collect()
    }

    fn with_digest(mut payload: Vec<u8>) -> Vec<u8> {
        let digest = Sha256::digest(&payload);
        payload.extend_from_slice(&digest);
        payload
    }

    #[test]
    fn untrusted_backup_decoders_fuzz_corpus_is_total_and_count_bounded() {
        let lengths = [0, 1, 7, 8, 9, 21, 22, 63, 127, 255, 1024, 4096];
        for seed in 0..64 {
            for len in lengths {
                let bytes = corpus_bytes(seed, len);
                assert!(std::panic::catch_unwind(|| {
                    let _ = decode_manifest(&bytes);
                    let _ = decode_cold_descriptor(&bytes);
                })
                .is_ok());
            }
        }

        let mut impossible_manifest = Vec::new();
        impossible_manifest.extend_from_slice(MANIFEST_MAGIC);
        impossible_manifest.extend_from_slice(&u64::MAX.to_be_bytes());
        let impossible_manifest = with_digest(impossible_manifest);
        assert!(matches!(
            decode_manifest(&impossible_manifest),
            Err(BackupError::InvalidManifest)
        ));

        let mut impossible_descriptor = Vec::new();
        impossible_descriptor.extend_from_slice(COLD_DESCRIPTOR_MAGIC);
        impossible_descriptor.extend_from_slice(&1_u16.to_be_bytes());
        impossible_descriptor.extend_from_slice(&0_u32.to_be_bytes()); // schema
        impossible_descriptor.extend_from_slice(&0_u32.to_be_bytes()); // active generation
        impossible_descriptor.extend_from_slice(&u32::MAX.to_be_bytes());
        impossible_descriptor.extend_from_slice(&[0; COLD_DESCRIPTOR_DIGESTS_LEN]);
        let impossible_descriptor = with_digest(impossible_descriptor);
        assert!(matches!(
            decode_cold_descriptor(&impossible_descriptor),
            Err(BackupError::InvalidManifest)
        ));
    }
}
