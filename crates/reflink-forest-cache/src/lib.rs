//! Derived, atomically published blob cache.
//!
//! Cache entries use internal content IDs, never Git paths. A caller can
//! discard the cache at any time because this crate has no authority over the
//! cold store; it only receives already-verified blob bytes.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_core::{ContentId, ObjectKind};

const FICLONE: std::ffi::c_ulong = 0x4004_9409;

unsafe extern "C" {
    fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
}

#[derive(Debug)]
pub enum CacheError {
    Io(io::Error),
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    NotCached(ContentId),
}
impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cache I/O error: {error}"),
            Self::ContentMismatch { .. } => {
                write!(f, "cache payload does not match its content ID")
            }
            Self::NotCached(_) => write!(f, "cache entry is missing"),
        }
    }
}
impl std::error::Error for CacheError {}
impl From<io::Error> for CacheError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Debug)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Opens a service-owned cache root. The caller is responsible for placing
    /// it inside the verified Btrfs clone domain.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    pub fn path_for(&self, id: ContentId) -> PathBuf {
        let hex = hex(id.as_bytes());
        self.root.join(&hex[..2]).join(&hex[2..4]).join(hex)
    }

    /// Returns an entry only after recomputing its blob content ID.
    pub fn verified_path(&self, id: ContentId) -> Result<PathBuf, CacheError> {
        let path = self.path_for(id);
        let bytes = fs::read(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CacheError::NotCached(id)
            } else {
                CacheError::Io(error)
            }
        })?;
        let actual = ContentId::for_object(ObjectKind::Blob, &bytes);
        if actual != id {
            return Err(CacheError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        Ok(path)
    }

    /// Writes and verifies blob bytes before atomically publishing the cache
    /// entry. A racing publisher either wins with the same validated content
    /// or leaves the existing entry untouched.
    pub fn publish_blob(&self, id: ContentId, bytes: &[u8]) -> Result<PathBuf, CacheError> {
        let actual = ContentId::for_object(ObjectKind::Blob, bytes);
        if actual != id {
            return Err(CacheError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        let destination = self.path_for(id);
        if destination.exists() {
            return self.verified_path(id);
        }
        let parent = destination.parent().expect("cache filename has parent");
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        let temporary = parent.join(format!(".{}.{}", process::id(), nonce()));
        let result = (|| -> Result<(), CacheError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {
                    fs::remove_file(&temporary)?;
                    File::open(parent)?.sync_all()?;
                    Ok(())
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary)?;
                    Ok(())
                }
                Err(error) => Err(CacheError::Io(error)),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        self.verified_path(id)
    }

    /// Creates a Btrfs reflink at `destination`. It never falls back to a
    /// payload copy: that policy decision belongs to checkout orchestration.
    pub fn clone_blob(
        &self,
        id: ContentId,
        destination: impl AsRef<Path>,
    ) -> Result<(), CacheError> {
        let source_path = self.verified_path(id)?;
        let source = File::open(source_path)?;
        let destination = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(destination)?;
        // SAFETY: both FDs refer to regular files and FICLONE consumes the
        // source descriptor by value only for the duration of this syscall.
        if unsafe { ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) } != 0 {
            return Err(CacheError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!("reflink-forest-cache-{}", nonce()))
    }
    #[test]
    fn valid_blob_is_atomically_published_and_revalidated() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let id = ContentId::for_object(ObjectKind::Blob, b"cache bytes");
        let path = cache.publish_blob(id, b"cache bytes").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"cache bytes");
        assert_eq!(cache.verified_path(id).unwrap(), path);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn incorrect_content_is_not_published() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let id = ContentId::for_object(ObjectKind::Blob, b"expected");
        assert!(matches!(
            cache.publish_blob(id, b"wrong"),
            Err(CacheError::ContentMismatch { .. })
        ));
        assert!(!cache.path_for(id).exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
