//! Cold-generation reader leases and durable generation publication.
//!
//! GC must not remove a retired generation while a reader can still resolve a
//! location in it. Leases make that dependency explicit and survive a process
//! crash as files that startup reconciliation can inspect.

use reflink_forest_core::ContentId;
use reflink_forest_index::{Catalog, CatalogBatch, ObjectLocation};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

const LOCK_EX: std::ffi::c_int = 2;
const LOCK_UN: std::ffi::c_int = 8;

unsafe extern "C" {
    fn flock(fd: std::ffi::c_int, operation: std::ffi::c_int) -> std::ffi::c_int;
}

#[derive(Debug)]
pub enum MaintenanceError {
    Io(io::Error),
    InvalidGenerationPointer,
    ActiveReaders(u32),
    RetiringGeneration(u32),
    CannotRetireActiveGeneration(u32),
    DestinationExists(PathBuf),
    UnsafeLeaseEntry(PathBuf),
    Catalog(String),
}
impl std::fmt::Display for MaintenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "maintenance I/O error: {error}"),
            Self::InvalidGenerationPointer => write!(f, "invalid active-generation pointer"),
            Self::ActiveReaders(generation) => {
                write!(f, "generation {generation} still has active readers")
            }
            Self::RetiringGeneration(generation) => {
                write!(f, "generation {generation} no longer admits new readers")
            }
            Self::CannotRetireActiveGeneration(generation) => {
                write!(f, "cannot retire the active generation {generation}")
            }
            Self::DestinationExists(path) => write!(
                f,
                "maintenance destination already exists: {}",
                path.display()
            ),
            Self::UnsafeLeaseEntry(path) => write!(
                f,
                "unsafe or unexpected generation lease entry: {}",
                path.display()
            ),
            Self::Catalog(error) => write!(f, "generation catalog error: {error}"),
        }
    }
}
impl std::error::Error for MaintenanceError {}
impl From<io::Error> for MaintenanceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Atomically commits all new object locations and the catalog's active
/// generation, then publishes the derived filesystem pointer. If the latter
/// fails, startup reconciliation repairs it from the catalog; it never rolls
/// back the authoritative catalog commit.
pub fn publish_generation<C: Catalog>(
    catalog: &mut C,
    manager: &GenerationManager,
    generation: u32,
    locations: impl IntoIterator<Item = (ContentId, ObjectLocation)>,
) -> Result<(), MaintenanceError> {
    let mut batch = CatalogBatch::new();
    for (id, location) in locations {
        batch.put_object_location(id, location);
    }
    batch.put_current_generation(generation);
    catalog
        .apply(batch)
        .map_err(|error| MaintenanceError::Catalog(format!("{error:?}")))?;
    manager.publish_active(generation)
}

/// Repairs the derived pointer after startup. The external pointer is never a
/// source of truth: absent catalog state yields `None`; a catalog generation
/// overwrites a stale, missing, or corrupt pointer.
pub fn reconcile_active_generation<C: Catalog>(
    catalog: &C,
    manager: &GenerationManager,
) -> Result<Option<u32>, MaintenanceError> {
    let generation = catalog.current_generation();
    if let Some(generation) = generation {
        manager.publish_active(generation)?;
    }
    Ok(generation)
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
        if fs::remove_file(&self.path).is_ok() {
            if let Some(parent) = self.path.parent() {
                let _ = File::open(parent).and_then(|directory| directory.sync_all());
            }
        }
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
        fs::create_dir_all(root.join("retiring"))?;
        let manager = Self { root };
        // The daemon holds the instance/store lock before opening maintenance
        // state. Every lease found at that point belongs to a dead daemon, so
        // it is safe to remove rather than guessing from reused process IDs.
        manager.reconcile_abandoned_leases()?;
        Ok(manager)
    }
    fn pointer_path(&self) -> PathBuf {
        self.root.join("active-generation")
    }
    fn generation_leases(&self, generation: u32) -> PathBuf {
        self.root.join("leases").join(generation.to_string())
    }
    fn retiring_marker(&self, generation: u32) -> PathBuf {
        self.root.join("retiring").join(generation.to_string())
    }
    fn state_lock_path(&self) -> PathBuf {
        self.root.join("generation-state.lock")
    }

    fn state_lock(&self) -> Result<StateLock, MaintenanceError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.state_lock_path())?;
        // SAFETY: `file` is a valid open descriptor for the lifetime of the
        // returned guard. `flock` does not retain the pointer.
        if unsafe { flock(file.as_raw_fd(), LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(StateLock { file })
    }

    /// Publishes a new active generation through a synchronized temp file and
    /// atomic rename. Catalog publication must occur first and remains the
    /// authoritative source during recovery.
    pub fn publish_active(&self, generation: u32) -> Result<(), MaintenanceError> {
        let _lock = self.state_lock()?;
        let temporary = self.root.join(format!(".active-generation.{}", nonce()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        writeln!(file, "{generation}")?;
        file.sync_all()?;
        fs::rename(&temporary, self.pointer_path())?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    pub fn active_generation(&self) -> Result<Option<u32>, MaintenanceError> {
        let _lock = self.state_lock()?;
        self.active_generation_locked()
    }
    fn active_generation_locked(&self) -> Result<Option<u32>, MaintenanceError> {
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
        let _lock = self.state_lock()?;
        if self.retiring_marker(generation).exists() {
            return Err(MaintenanceError::RetiringGeneration(generation));
        }
        let directory = self.generation_leases(generation);
        fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{}-{}", process::id(), nonce()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(file, "generation={generation}\npid={}", process::id())?;
        file.sync_all()?;
        File::open(&directory)?.sync_all()?;
        Ok(GenerationLease { path })
    }
    /// A retired generation may be reclaimed only when no leases remain.
    pub fn may_reclaim(&self, generation: u32) -> Result<bool, MaintenanceError> {
        let _lock = self.state_lock()?;
        self.may_reclaim_locked(generation)
    }
    fn may_reclaim_locked(&self, generation: u32) -> Result<bool, MaintenanceError> {
        let directory = self.generation_leases(generation);
        match fs::read_dir(directory) {
            Ok(entries) => {
                let mut active = false;
                for entry in entries {
                    let entry = entry?;
                    if !entry.file_type()?.is_file() {
                        return Err(MaintenanceError::UnsafeLeaseEntry(entry.path()));
                    }
                    active = true;
                }
                Ok(!active)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    /// Removes leases left by a stopped daemon. Callers must own the instance
    /// lock; a live daemon must never have its leases reconciled underneath it.
    /// This method is also used by [`Self::open`] before request acceptance.
    pub fn reconcile_abandoned_leases(&self) -> Result<usize, MaintenanceError> {
        let _lock = self.state_lock()?;
        let mut removed = 0;
        for generation in fs::read_dir(self.root.join("leases"))? {
            let generation = generation?;
            if !generation.file_type()?.is_dir() {
                return Err(MaintenanceError::UnsafeLeaseEntry(generation.path()));
            }
            for lease in fs::read_dir(generation.path())? {
                let lease = lease?;
                if !lease.file_type()?.is_file() {
                    return Err(MaintenanceError::UnsafeLeaseEntry(lease.path()));
                }
                fs::remove_file(lease.path())?;
                removed += 1;
            }
            File::open(generation.path())?.sync_all()?;
        }
        Ok(removed)
    }

    /// Reopens admission for a generation only when a higher-level compaction
    /// aborts before publication. A successfully retired generation never
    /// calls this method.
    pub fn cancel_retirement(&self, generation: u32) -> Result<(), MaintenanceError> {
        let _lock = self.state_lock()?;
        let marker = self.retiring_marker(generation);
        match fs::remove_file(marker) {
            Ok(()) => File::open(self.root.join("retiring"))?
                .sync_all()
                .map_err(Into::into),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
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
        let _lock = self.state_lock()?;
        if self.active_generation_locked()? == Some(generation) {
            return Err(MaintenanceError::CannotRetireActiveGeneration(generation));
        }
        self.stop_admitting_leases_locked(generation)?;
        if !self.may_reclaim_locked(generation)? {
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

    fn stop_admitting_leases_locked(&self, generation: u32) -> Result<(), MaintenanceError> {
        let marker = self.retiring_marker(generation);
        if marker.exists() {
            return Ok(());
        }
        let temporary = self
            .root
            .join("retiring")
            .join(format!(".{generation}.{}", nonce()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        writeln!(file, "retiring={generation}")?;
        file.sync_all()?;
        fs::rename(temporary, marker)?;
        File::open(self.root.join("retiring"))?.sync_all()?;
        Ok(())
    }
}

#[derive(Debug)]
struct StateLock {
    file: File,
}
impl Drop for StateLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still live during Drop and unlock does not
        // retain it.
        unsafe {
            flock(self.file.as_raw_fd(), LOCK_UN);
        }
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
    use reflink_forest_core::ObjectKind;
    use reflink_forest_format::Codec;
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

    #[test]
    fn retirement_closes_lease_admission_before_waiting_for_readers() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        manager.publish_active(2).unwrap();
        let generation = root.join("generation-1");
        let trash = root.join("trash");
        fs::create_dir(&generation).unwrap();
        let lease = manager.lease(1).unwrap();
        assert!(matches!(
            manager.retire_generation(1, &generation, &trash),
            Err(MaintenanceError::ActiveReaders(1))
        ));
        assert!(matches!(
            manager.lease(1),
            Err(MaintenanceError::RetiringGeneration(1))
        ));
        drop(lease);
        manager.retire_generation(1, &generation, &trash).unwrap();
        assert!(matches!(
            manager.retire_generation(2, root.join("generation-2"), &trash),
            Err(MaintenanceError::CannotRetireActiveGeneration(2))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn open_reconciles_abandoned_lease_files_after_daemon_restart() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let lease = manager.lease(7).unwrap();
        let lease_path = lease.path().to_path_buf();
        // Simulate a process crash: a stale file remains after its in-memory
        // guard disappears without running Drop.
        std::mem::forget(lease);
        drop(manager);
        let reopened = GenerationManager::open(&root).unwrap();
        assert!(!lease_path.exists());
        assert!(reopened.may_reclaim(7).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    fn location() -> ObjectLocation {
        ObjectLocation {
            generation: 8,
            chunk_id: 1,
            offset: 0,
            record_length: 128,
            stored_length: 16,
            raw_length: 16,
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            payload_crc32c: 4,
        }
    }

    #[test]
    fn publication_commits_locations_and_generation_before_derived_pointer() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let mut catalog = reflink_forest_index::InMemoryCatalog::default();
        let id = ContentId([7; 32]);
        publish_generation(&mut catalog, &manager, 8, [(id, location())]).unwrap();
        assert_eq!(catalog.current_generation(), Some(8));
        assert_eq!(catalog.object_location(id), Some(location()));
        assert_eq!(manager.active_generation().unwrap(), Some(8));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_reconciliation_repairs_pointer_from_catalog_and_catalog_survives_pointer_failure() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let mut catalog = reflink_forest_index::InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_current_generation(12);
        catalog.apply(batch).unwrap();
        fs::write(root.join("active-generation"), b"not-a-generation\n").unwrap();
        assert_eq!(
            reconcile_active_generation(&catalog, &manager).unwrap(),
            Some(12)
        );
        assert_eq!(manager.active_generation().unwrap(), Some(12));
        fs::remove_dir_all(&root).unwrap();
        assert!(publish_generation(&mut catalog, &manager, 13, []).is_err());
        assert_eq!(catalog.current_generation(), Some(13));
    }
}
