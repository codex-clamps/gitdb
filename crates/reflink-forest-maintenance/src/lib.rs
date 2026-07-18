//! Cold-generation reader leases and durable generation publication.
//!
//! GC must not remove a retired generation while a reader can still resolve a
//! location in it. Leases make that dependency explicit and survive a process
//! crash as files that startup reconciliation can inspect.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub enum MaintenanceError {
    Io(io::Error),
    InvalidGenerationPointer,
    ActiveReaders(u32),
    DestinationExists(PathBuf),
}
impl std::fmt::Display for MaintenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "maintenance I/O error: {error}"),
            Self::InvalidGenerationPointer => write!(f, "invalid active-generation pointer"),
            Self::ActiveReaders(generation) => {
                write!(f, "generation {generation} still has active readers")
            }
            Self::DestinationExists(path) => write!(
                f,
                "maintenance destination already exists: {}",
                path.display()
            ),
        }
    }
}
impl std::error::Error for MaintenanceError {}
impl From<io::Error> for MaintenanceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub struct GenerationLease {
    path: PathBuf,
}
impl GenerationLease {
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for GenerationLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Clone, Debug)]
pub struct GenerationManager {
    root: PathBuf,
}
impl GenerationManager {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, MaintenanceError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("leases"))?;
        Ok(Self { root })
    }
    fn pointer_path(&self) -> PathBuf {
        self.root.join("active-generation")
    }
    fn generation_leases(&self, generation: u32) -> PathBuf {
        self.root.join("leases").join(generation.to_string())
    }

    /// Publishes a new active generation through a synchronized temp file and
    /// atomic rename. Catalog publication must occur first and remains the
    /// authoritative source during recovery.
    pub fn publish_active(&self, generation: u32) -> Result<(), MaintenanceError> {
        let temporary = self.root.join(format!(".active-generation.{}", nonce()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        write!(file, "{generation}\n")?;
        file.sync_all()?;
        fs::rename(&temporary, self.pointer_path())?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    pub fn active_generation(&self) -> Result<Option<u32>, MaintenanceError> {
        let mut content = String::new();
        match File::open(self.pointer_path()) {
            Ok(mut file) => {
                file.read_to_string(&mut content)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let generation = content
            .trim()
            .parse()
            .map_err(|_| MaintenanceError::InvalidGenerationPointer)?;
        Ok(Some(generation))
    }
    /// Acquires a crash-visible lease before reading generation data.
    pub fn lease(&self, generation: u32) -> Result<GenerationLease, MaintenanceError> {
        let directory = self.generation_leases(generation);
        fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{}-{}", process::id(), nonce()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.sync_all()?;
        Ok(GenerationLease { path })
    }
    /// A retired generation may be reclaimed only when no leases remain.
    pub fn may_reclaim(&self, generation: u32) -> Result<bool, MaintenanceError> {
        let directory = self.generation_leases(generation);
        match fs::read_dir(directory) {
            Ok(mut entries) => Ok(entries.next().is_none()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    /// Moves an unleased retired generation out of the live chunk namespace.
    /// The caller may remove the returned trash path asynchronously; existing
    /// readers are protected because the operation refuses active leases.
    pub fn retire_generation(
        &self,
        generation: u32,
        generation_path: impl AsRef<Path>,
        trash_root: impl AsRef<Path>,
    ) -> Result<PathBuf, MaintenanceError> {
        if !self.may_reclaim(generation)? {
            return Err(MaintenanceError::ActiveReaders(generation));
        }
        let generation_path = generation_path.as_ref();
        let trash_root = trash_root.as_ref();
        fs::create_dir_all(trash_root)?;
        let destination = trash_root.join(format!("generation-{generation}-retired"));
        if destination.exists() {
            return Err(MaintenanceError::DestinationExists(destination));
        }
        fs::rename(generation_path, &destination)?;
        File::open(trash_root)?.sync_all()?;
        Ok(destination)
    }
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
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("reflink-forest-maintenance-{}", nonce()))
    }
    #[test]
    fn generation_pointer_and_leases_are_durable_state() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        assert_eq!(manager.active_generation().unwrap(), None);
        manager.publish_active(7).unwrap();
        assert_eq!(manager.active_generation().unwrap(), Some(7));
        let lease = manager.lease(6).unwrap();
        assert!(!manager.may_reclaim(6).unwrap());
        drop(lease);
        assert!(manager.may_reclaim(6).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generations_move_to_trash_only_after_last_lease() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let generation = root.join("generation-4");
        let trash = root.join("trash");
        fs::create_dir(&generation).unwrap();
        let lease = manager.lease(4).unwrap();
        assert!(matches!(
            manager.retire_generation(4, &generation, &trash),
            Err(MaintenanceError::ActiveReaders(4))
        ));
        drop(lease);
        let retired = manager.retire_generation(4, &generation, &trash).unwrap();
        assert!(retired.is_dir());
        assert!(!generation.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
