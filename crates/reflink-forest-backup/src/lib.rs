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

const MANIFEST_MAGIC: &[u8; 8] = b"RFBKMAN1";
const MANIFEST_HEADER_LEN: usize = MANIFEST_MAGIC.len() + 8;
const MANIFEST_DIGEST_LEN: usize = 32;
const MIN_MANIFEST_ENTRY_LEN: usize = 4 + 1 + 8 + 32;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_MANIFEST_ENTRIES: u64 = 1_000_000;
const MAX_MANIFEST_PATH_BYTES: u32 = 1024 * 1024;

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
#[derive(Debug)]
pub enum BackupError {
    Io(io::Error),
    UnsafeSource(PathBuf),
    InvalidManifest,
    VerificationFailed(PathBuf),
    DestinationExists,
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
            Self::VerificationFailed(path) => {
                write!(f, "backup verification failed: {}", path.display())
            }
            Self::DestinationExists => write!(f, "backup destination already exists"),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    fn dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("reflink-forest-backup-{label}-{}", nonce()))
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
}
