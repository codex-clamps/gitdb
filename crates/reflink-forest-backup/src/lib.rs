//! Verified cold-tier checkpoints.
//!
//! A caller must hold the store writer lock before calling [`checkpoint`]. The
//! result is a self-describing snapshot tree that is published only after all
//! files and its manifest have been synchronized.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

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

/// Verifies copied data against the manifest before accepting a restore point.
pub fn verify_tree(root: impl AsRef<Path>, manifest: &BackupManifest) -> Result<(), BackupError> {
    for file in &manifest.files {
        let path = root.as_ref().join(&file.relative);
        let (bytes, digest) = hash_file(&path)?;
        if bytes != file.bytes || digest != file.sha256 {
            return Err(BackupError::VerificationFailed(file.relative.clone()));
        }
    }
    Ok(())
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
    let path = root.join("manifest-v1");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    for entry in &manifest.files {
        if entry
            .relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(BackupError::InvalidManifest);
        }
        writeln!(
            file,
            "{}\t{}\t{}",
            hex(&entry.sha256),
            entry.bytes,
            entry.relative.to_string_lossy()
        )?;
    }
    file.sync_all()?;
    Ok(())
}
fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[usize::from(byte >> 4)] as char);
        result.push(DIGITS[usize::from(byte & 15)] as char);
    }
    result
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
        fs::remove_dir_all(source).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
}
