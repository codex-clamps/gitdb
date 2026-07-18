//! Derived, atomically published blob cache.
//!
//! Cache entries use internal content IDs, never Git paths. A caller can
//! discard the cache at any time because this crate has no authority over the
//! cold store; it only receives already-verified blob bytes.

use std::{
    collections::HashMap,
    ffi::{CString, OsStr},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process,
    sync::{Arc, Condvar, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_core::{ContentHasher, ContentId, ObjectKind};
use reflink_forest_format::Codec;
use reflink_forest_index::{Catalog, ObjectLocation};
use reflink_forest_store::{stream_decoded_record_at, StoreError};

const FICLONE: std::ffi::c_ulong = 0x4004_9409;

unsafe extern "C" {
    fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
}

#[derive(Debug)]
pub enum CacheError {
    Io(io::Error),
    AccountingOverflow,
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    UnsafeRoot(PathBuf),
    UnsafeEntry(ContentId),
    NotCached(ContentId),
}
impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cache I/O error: {error}"),
            Self::AccountingOverflow => write!(f, "cache byte accounting overflowed u64"),
            Self::ContentMismatch { .. } => {
                write!(f, "cache payload does not match its content ID")
            }
            Self::UnsafeRoot(path) => {
                write!(f, "cache root is not a real directory: {}", path.display())
            }
            Self::UnsafeEntry(_) => write!(f, "cache entry is not a regular file"),
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

/// One canonical, regular cache leaf discovered beneath the two-level fanout.
///
/// `logical_bytes` is the file's logical length. Btrfs sharing and compression
/// make physical reclamation filesystem-dependent, so callers should remeasure
/// free space after eviction rather than treating this value as allocated bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheEntry {
    pub content_id: ContentId,
    pub logical_bytes: u64,
}

/// Logical-byte accounting for canonical regular leaves in the cache fanout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CacheUsage {
    pub entries: u64,
    pub logical_bytes: u64,
    /// Entries ignored because they are malformed, non-regular, symlinks, or
    /// disappeared while the scan was in progress.
    pub skipped: u64,
}

/// Result of a deterministic cache eviction pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheEviction {
    pub target_logical_bytes: u64,
    pub before: CacheUsage,
    pub after: CacheUsage,
    pub evicted_entries: u64,
    pub evicted_logical_bytes: u64,
    /// Candidates that changed into an unsafe/missing entry before deletion.
    pub skipped_entries: u64,
}

impl CacheEviction {
    /// Whether the post-eviction logical cache usage is at or below the target.
    pub const fn target_reached(self) -> bool {
        self.after.logical_bytes <= self.target_logical_bytes
    }
}

/// Per-domain free-space floors enforced before allocating more derived data.
///
/// The same projected allocation is checked against both domains. This is
/// conservative for a sparse Btrfs image, where guest allocation can consume
/// host capacity as well as guest free capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservePolicy {
    pub host_reserve_bytes: u64,
    pub guest_reserve_bytes: u64,
}

impl ReservePolicy {
    pub const fn new(host_reserve_bytes: u64, guest_reserve_bytes: u64) -> Self {
        Self {
            host_reserve_bytes,
            guest_reserve_bytes,
        }
    }

    /// Admits an allocation only if both host and guest retain their required
    /// reserve after the caller's projected allocation.
    pub fn admit(
        self,
        host_available_bytes: u64,
        guest_available_bytes: u64,
        projected_allocation_bytes: u64,
    ) -> Result<(), AdmissionError> {
        let host = ReserveViolation::new(
            host_available_bytes,
            projected_allocation_bytes,
            self.host_reserve_bytes,
        );
        let guest = ReserveViolation::new(
            guest_available_bytes,
            projected_allocation_bytes,
            self.guest_reserve_bytes,
        );
        match (host, guest) {
            (None, None) => Ok(()),
            (Some(host), None) => Err(AdmissionError::HostReserve(host)),
            (None, Some(guest)) => Err(AdmissionError::GuestReserve(guest)),
            (Some(host), Some(guest)) => Err(AdmissionError::HostAndGuestReserve { host, guest }),
        }
    }
}

/// Exact shortfall for a capacity domain after an attempted allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReserveViolation {
    pub available_bytes: u64,
    pub projected_allocation_bytes: u64,
    pub reserve_bytes: u64,
    pub available_after_allocation_bytes: u64,
    pub shortfall_bytes: u64,
}

impl ReserveViolation {
    fn new(
        available_bytes: u64,
        projected_allocation_bytes: u64,
        reserve_bytes: u64,
    ) -> Option<Self> {
        let available_after_allocation_bytes =
            available_bytes.saturating_sub(projected_allocation_bytes);
        if available_after_allocation_bytes >= reserve_bytes {
            return None;
        }
        Some(Self {
            available_bytes,
            projected_allocation_bytes,
            reserve_bytes,
            available_after_allocation_bytes,
            shortfall_bytes: reserve_bytes - available_after_allocation_bytes,
        })
    }
}

/// Precise reason an allocation was rejected by [`ReservePolicy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    HostReserve(ReserveViolation),
    GuestReserve(ReserveViolation),
    HostAndGuestReserve {
        host: ReserveViolation,
        guest: ReserveViolation,
    },
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostReserve(violation) => write!(
                f,
                "host reserve would be short by {} bytes after allocating {} bytes",
                violation.shortfall_bytes, violation.projected_allocation_bytes
            ),
            Self::GuestReserve(violation) => write!(
                f,
                "guest reserve would be short by {} bytes after allocating {} bytes",
                violation.shortfall_bytes, violation.projected_allocation_bytes
            ),
            Self::HostAndGuestReserve { host, guest } => write!(
                f,
                "host and guest reserves would be short by {} and {} bytes after allocation",
                host.shortfall_bytes, guest.shortfall_bytes
            ),
        }
    }
}

impl std::error::Error for AdmissionError {}

impl AdmissionError {
    /// The minimum logical cache reclamation to attempt before taking a new
    /// measurement. A cache entry may share extents or be compressed, so this
    /// is deliberately only an eviction target, not a claim about physical
    /// space that will be returned.
    pub const fn required_reclaim_bytes(self) -> u64 {
        match self {
            Self::HostReserve(host) => host.shortfall_bytes,
            Self::GuestReserve(guest) => guest.shortfall_bytes,
            Self::HostAndGuestReserve { host, guest } => {
                if host.shortfall_bytes > guest.shortfall_bytes {
                    host.shortfall_bytes
                } else {
                    guest.shortfall_bytes
                }
            }
        }
    }
}

/// A host/guest free-space measurement used for cache admission.
///
/// `host_available_bytes` should measure the filesystem containing the sparse
/// image or other cold/hot backing allocation. `guest_available_bytes` should
/// measure the mounted Btrfs clone domain. They may be the same filesystem,
/// but they are kept distinct because sparse-image allocation can exhaust
/// either domain first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacitySnapshot {
    pub host_available_bytes: u64,
    pub guest_available_bytes: u64,
}

/// Source of host and guest capacity measurements.
///
/// Keeping this trait small makes admission decisions portable to test: a
/// caller can inject a scripted source instead of relying on host free space.
pub trait CapacityMeter {
    fn measure(&self) -> io::Result<CapacitySnapshot>;
}

/// `statvfs`-based [`CapacityMeter`] for a host backing path and a mounted
/// guest Btrfs path.
#[derive(Clone, Debug)]
pub struct FilesystemCapacityMeter {
    host_path: PathBuf,
    guest_path: PathBuf,
}

impl FilesystemCapacityMeter {
    pub fn new(host_path: impl AsRef<Path>, guest_path: impl AsRef<Path>) -> Self {
        Self {
            host_path: host_path.as_ref().to_path_buf(),
            guest_path: guest_path.as_ref().to_path_buf(),
        }
    }

    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    pub fn guest_path(&self) -> &Path {
        &self.guest_path
    }
}

impl CapacityMeter for FilesystemCapacityMeter {
    fn measure(&self) -> io::Result<CapacitySnapshot> {
        Ok(CapacitySnapshot {
            host_available_bytes: statvfs_available_bytes(&self.host_path)?,
            guest_available_bytes: statvfs_available_bytes(&self.guest_path)?,
        })
    }
}

/// The observable outcome of a cache capacity admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityAdmission {
    pub projected_allocation_bytes: u64,
    /// Free space measured before the reserve policy was first applied.
    pub before: CapacitySnapshot,
    /// Free space measured after any eviction and immediately before
    /// allocation. It equals `before` when no eviction was necessary.
    pub admitted: CapacitySnapshot,
    /// The deterministic eviction pass used to make room, if one was needed.
    pub eviction: Option<CacheEviction>,
}

/// Details retained when eviction could not restore capacity reserves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityReserveFailure {
    pub before: CapacitySnapshot,
    pub after_eviction: CapacitySnapshot,
    pub eviction: CacheEviction,
    pub violation: AdmissionError,
}

/// Why a cache capacity admission could not be completed.
#[derive(Debug)]
pub enum CapacityAdmissionError {
    Measurement(io::Error),
    Cache(CacheError),
    /// Deterministic cache eviction was attempted, but the remeasurement still
    /// could not retain both configured reserves after allocation.
    ReservesStillUnmet(Box<CapacityReserveFailure>),
}

impl std::fmt::Display for CapacityAdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Measurement(error) => write!(f, "capacity measurement failed: {error}"),
            Self::Cache(error) => write!(f, "cache eviction failed: {error}"),
            Self::ReservesStillUnmet(failure) => {
                write!(
                    f,
                    "cache admission refused after eviction: {}",
                    failure.violation
                )
            }
        }
    }
}

impl std::error::Error for CapacityAdmissionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Measurement(error) => Some(error),
            Self::Cache(error) => Some(error),
            Self::ReservesStillUnmet(failure) => Some(&failure.violation),
        }
    }
}

impl From<CacheError> for CapacityAdmissionError {
    fn from(value: CacheError) -> Self {
        Self::Cache(value)
    }
}

/// Failure from work protected by reserve admission.
///
/// The `Admission` variant means the protected operation was never invoked.
/// `Operation` preserves the error from work that began only after both
/// host- and guest-space reserves were admitted.
#[derive(Debug)]
pub enum CapacityAdmissionOperationError<E> {
    Admission(CapacityAdmissionError),
    Operation(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CapacityAdmissionOperationError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admission(error) => write!(f, "capacity admission failed: {error}"),
            Self::Operation(error) => write!(f, "admitted operation failed: {error}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CapacityAdmissionOperationError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            Self::Operation(error) => Some(error),
        }
    }
}

/// Coordinates derived-cache allocations with host and guest reserve floors.
///
/// When the initial measurement fails the policy, the coordinator evicts cache
/// leaves in [`Cache::evict_to`] order, remeasures both domains, and only then
/// admits the allocation. The cache is derived data, so it is the only state
/// this coordinator deletes. The operating system remains authoritative: use
/// [`Self::with_reserve_admission`] to keep this coordinator's admission lock
/// across the immediate allocation, and still handle an allocation-time
/// `ENOSPC` or quota error.
pub struct CacheCapacityCoordinator<M> {
    cache: Cache,
    meter: M,
    policy: ReservePolicy,
    admission_lock: Mutex<()>,
}

impl<M> CacheCapacityCoordinator<M> {
    pub fn new(cache: Cache, meter: M, policy: ReservePolicy) -> Self {
        Self {
            cache,
            meter,
            policy,
            admission_lock: Mutex::new(()),
        }
    }

    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    pub const fn policy(&self) -> ReservePolicy {
        self.policy
    }

    pub fn meter(&self) -> &M {
        &self.meter
    }
}

impl<M: CapacityMeter> CacheCapacityCoordinator<M> {
    /// Preflights a derived-cache allocation and, if needed, evicts toward the
    /// exact largest reserve shortfall before remeasuring both domains.
    ///
    /// Prefer [`Self::with_admission`] when the allocation is a cache
    /// operation: it keeps this coordinator's admission lock until that
    /// operation returns.
    pub fn admit(
        &self,
        projected_allocation_bytes: u64,
    ) -> Result<CapacityAdmission, CapacityAdmissionError> {
        let _guard = self
            .admission_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.admit_locked(projected_allocation_bytes)
    }

    /// Runs a cache allocation only after it has passed reserve admission.
    ///
    /// `projected_allocation_bytes` must conservatively include the expected
    /// new cache payload and any caller-known expansion. Allocation errors are
    /// reported unchanged as [`CapacityAdmissionError::Cache`].
    pub fn with_admission<T, F>(
        &self,
        projected_allocation_bytes: u64,
        allocate: F,
    ) -> Result<(CapacityAdmission, T), CapacityAdmissionError>
    where
        F: FnOnce(&Cache) -> Result<T, CacheError>,
    {
        let _guard = self
            .admission_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let admission = self.admit_locked(projected_allocation_bytes)?;
        let result = allocate(&self.cache)?;
        Ok((admission, result))
    }

    /// Runs arbitrary allocation work only after preserving both configured
    /// reserves.
    ///
    /// This is the shared guard for cold-import staging and output,
    /// compaction output, and guest-image growth. The projected byte count
    /// must conservatively include every allocation the closure can make;
    /// the admission lock remains held until the closure returns. If initial
    /// capacity is short, only derived cache entries are evicted before a
    /// fresh measurement decides whether to invoke the closure.
    pub fn with_reserve_admission<T, E, F>(
        &self,
        projected_allocation_bytes: u64,
        operation: F,
    ) -> Result<(CapacityAdmission, T), CapacityAdmissionOperationError<E>>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let _guard = self
            .admission_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let admission = self
            .admit_locked(projected_allocation_bytes)
            .map_err(CapacityAdmissionOperationError::Admission)?;
        let result = operation().map_err(CapacityAdmissionOperationError::Operation)?;
        Ok((admission, result))
    }

    fn admit_locked(
        &self,
        projected_allocation_bytes: u64,
    ) -> Result<CapacityAdmission, CapacityAdmissionError> {
        let before = self
            .meter
            .measure()
            .map_err(CapacityAdmissionError::Measurement)?;
        let initial = self.policy.admit(
            before.host_available_bytes,
            before.guest_available_bytes,
            projected_allocation_bytes,
        );
        let Err(initial_violation) = initial else {
            return Ok(CapacityAdmission {
                projected_allocation_bytes,
                before,
                admitted: before,
                eviction: None,
            });
        };

        let usage = self.cache.usage()?;
        let target_logical_bytes = usage
            .logical_bytes
            .saturating_sub(initial_violation.required_reclaim_bytes());
        let eviction = self.cache.evict_to(target_logical_bytes)?;
        let after_eviction = self
            .meter
            .measure()
            .map_err(CapacityAdmissionError::Measurement)?;
        match self.policy.admit(
            after_eviction.host_available_bytes,
            after_eviction.guest_available_bytes,
            projected_allocation_bytes,
        ) {
            Ok(()) => Ok(CapacityAdmission {
                projected_allocation_bytes,
                before,
                admitted: after_eviction,
                eviction: Some(eviction),
            }),
            Err(violation) => Err(CapacityAdmissionError::ReservesStillUnmet(Box::new(
                CapacityReserveFailure {
                    before,
                    after_eviction,
                    eviction,
                    violation,
                },
            ))),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CacheReconciliation {
    /// Valid, content-addressed blobs retained in the cache.
    pub retained: u64,
    /// Invalid leaf entries moved to the cache-local quarantine directory.
    pub quarantined: u64,
    /// Paths deliberately ignored because they are outside the cache fanout
    /// layout, or disappeared while the scan was running.
    pub skipped: u64,
}

#[derive(Clone, Debug)]
pub struct Cache {
    root: PathBuf,
    state: Arc<CacheState>,
}

#[derive(Debug)]
struct CacheState {
    /// A small, fixed lock stripe set serializes publication and invalid-entry
    /// recovery for the same content ID without retaining one mutex per blob.
    entry_locks: Vec<Mutex<()>>,
    hydrations: Mutex<HashMap<ContentId, Arc<HydrationFlight>>>,
}

#[derive(Debug)]
struct HydrationFlight {
    completed: Mutex<bool>,
    completed_wakeup: Condvar,
}

impl CacheState {
    const ENTRY_LOCK_STRIPES: usize = 64;

    fn new() -> Self {
        Self {
            entry_locks: (0..Self::ENTRY_LOCK_STRIPES)
                .map(|_| Mutex::new(()))
                .collect(),
            hydrations: Mutex::new(HashMap::new()),
        }
    }
}

impl HydrationFlight {
    fn new() -> Self {
        Self {
            completed: Mutex::new(false),
            completed_wakeup: Condvar::new(),
        }
    }
}

impl Cache {
    /// Opens a service-owned cache root. The caller is responsible for placing
    /// it inside the verified Btrfs clone domain.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(CacheError::UnsafeRoot(root));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(&root)?,
            Err(error) => return Err(CacheError::Io(error)),
        }
        // Reopen the final root without following it after creation. This
        // catches a symlink substitution before permissions or cache content
        // can be touched through the configured root.
        let root_directory = open_directory_no_follow(&root).map_err(|error| {
            if is_missing_or_unsafe(&error) {
                CacheError::UnsafeRoot(root.clone())
            } else {
                CacheError::Io(error)
            }
        })?;
        root_directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root,
            state: Arc::new(CacheState::new()),
        })
    }

    pub fn path_for(&self, id: ContentId) -> PathBuf {
        let hex = hex(id.as_bytes());
        self.root.join(&hex[..2]).join(&hex[2..4]).join(hex)
    }

    /// Returns an entry only after recomputing its blob content ID.
    pub fn verified_path(&self, id: ContentId) -> Result<PathBuf, CacheError> {
        let path = self.path_for(id);
        let bytes = self.read_entry(&path, id)?;
        let actual = ContentId::for_object(ObjectKind::Blob, &bytes);
        if actual != id {
            return Err(CacheError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        Ok(path)
    }

    /// Opens one cache entry through retained no-follow fanout descriptors
    /// and returns the exact file descriptor whose contents were verified.
    ///
    /// Callers that consume cache data (especially FICLONE checkout) must use
    /// this instead of validating a pathname and then reopening that pathname:
    /// a cache leaf can otherwise be replaced between those two operations.
    /// The returned descriptor remains valid even if reconciliation later
    /// unlinks its directory entry.
    pub fn open_verified_blob(&self, id: ContentId) -> Result<File, CacheError> {
        let lock = self.entry_lock(id);
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.open_verified_blob_locked(id)
    }

    fn open_verified_blob_locked(&self, id: ContentId) -> Result<File, CacheError> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let parent = self.open_fanout_parent_no_follow(id).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CacheError::NotCached(id)
            } else if is_missing_or_unsafe(&error) {
                CacheError::UnsafeEntry(id)
            } else {
                CacheError::Io(error)
            }
        })?;
        let name = CString::new(hex(id.as_bytes()))
            .expect("canonical content ID names never contain a NUL byte");
        // SAFETY: `parent` is a retained directory descriptor and `name` is a
        // canonical single filename. O_NOFOLLOW keeps a swapped leaf from
        // resolving to a symlink target.
        let descriptor = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Err(CacheError::NotCached(id))
            } else if is_missing_or_unsafe(&error) {
                Err(CacheError::UnsafeEntry(id))
            } else {
                Err(CacheError::Io(error))
            };
        }
        // SAFETY: `openat` returned an owned file descriptor above.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        let length = match file.metadata() {
            Ok(metadata) if metadata.file_type().is_file() => metadata.len(),
            Ok(_) => return Err(CacheError::UnsafeEntry(id)),
            Err(error) => return Err(CacheError::Io(error)),
        };

        let mut hasher = ContentHasher::new(ObjectKind::Blob, length);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(CacheError::Io)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual = hasher.finalize();
        if actual != id {
            return Err(CacheError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        file.seek(SeekFrom::Start(0)).map_err(CacheError::Io)?;
        Ok(file)
    }

    /// Removes a cache file only when it fails the cache's content-ID check.
    ///
    /// This is the recovery operation used by cold hydration after an
    /// interrupted or corrupt prior publication. A candidate is first moved
    /// to a private quarantine name. If it became valid before that move, it
    /// is restored without overwriting a concurrently repaired entry.
    pub fn discard_invalid_blob(&self, id: ContentId) -> Result<bool, CacheError> {
        let lock = self.entry_lock(id);
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.discard_invalid_blob_locked(id)
    }

    fn discard_invalid_blob_locked(&self, id: ContentId) -> Result<bool, CacheError> {
        let path = self.path_for(id);
        match self.entry_status(&path, id)? {
            EntryStatus::Missing | EntryStatus::Valid => return Ok(false),
            EntryStatus::Invalid => {}
        }

        let Some(quarantined) = self.move_to_quarantine(&path)? else {
            return Ok(false);
        };

        // The name can have changed between inspection and the atomic rename.
        // Never destroy a valid entry that a concurrent repair put in place.
        if self.entry_status(&quarantined, id)? == EntryStatus::Valid {
            self.restore_quarantined(&quarantined, &path)?;
            return Ok(false);
        }

        fs::remove_file(&quarantined)?;
        self.sync_directory(
            quarantined
                .parent()
                .expect("cache quarantine filename has parent"),
        )?;
        Ok(true)
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
        let lock = self.entry_lock(id);
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.publish_blob_locked(id, bytes)
    }

    fn publish_blob_locked(&self, id: ContentId, bytes: &[u8]) -> Result<PathBuf, CacheError> {
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

    /// Streams a pre-validated blob into a temporary cache file, checks its
    /// incremental content ID, then uses the same durable hard-link
    /// publication protocol as [`Self::publish_blob`].
    ///
    /// The caller receives the temporary file only through `write`; a failed
    /// cold-record validation leaves no cache entry behind.
    fn publish_blob_streamed<F>(&self, id: ContentId, write: F) -> Result<PathBuf, HydrationError>
    where
        F: FnOnce(&mut File) -> Result<ContentId, HydrationError>,
    {
        let lock = self.entry_lock(id);
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.publish_blob_streamed_locked(id, write)
    }

    fn publish_blob_streamed_locked<F>(
        &self,
        id: ContentId,
        write: F,
    ) -> Result<PathBuf, HydrationError>
    where
        F: FnOnce(&mut File) -> Result<ContentId, HydrationError>,
    {
        let destination = self.path_for(id);
        if destination.exists() {
            return self.verified_path(id).map_err(Into::into);
        }
        let parent = destination.parent().expect("cache filename has parent");
        fs::create_dir_all(parent).map_err(CacheError::Io)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(CacheError::Io)?;
        let temporary = parent.join(format!(".{}.{}", process::id(), nonce()));
        let result = (|| -> Result<(), HydrationError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(CacheError::Io)?;
            let actual = write(&mut file)?;
            if actual != id {
                return Err(HydrationError::ContentMismatch {
                    expected: id,
                    actual,
                });
            }
            file.sync_all().map_err(CacheError::Io)?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))
                .map_err(CacheError::Io)?;
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {
                    fs::remove_file(&temporary).map_err(CacheError::Io)?;
                    File::open(parent)
                        .and_then(|directory| directory.sync_all())
                        .map_err(CacheError::Io)?;
                    Ok(())
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary).map_err(CacheError::Io)?;
                    Ok(())
                }
                Err(error) => Err(CacheError::Io(error).into()),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        self.verified_path(id).map_err(Into::into)
    }

    /// Revalidates all regular cache leaves and moves invalid leaves to
    /// `.quarantine` below the cache root. Fanout directory symlinks are
    /// quarantined as entries and are never descended into.
    pub fn reconcile(&self) -> Result<CacheReconciliation, CacheError> {
        let mut report = CacheReconciliation::default();
        for first in fs::read_dir(&self.root)? {
            let first = first?;
            let first_name = first.file_name();
            if first_name.as_bytes() == b".quarantine" || !is_hex_name(&first_name, 2) {
                report.skipped += 1;
                continue;
            }
            let first_path = first.path();
            if !is_real_directory(&first_path)? {
                self.quarantine_untrusted(&first_path, &mut report)?;
                continue;
            }

            for second in fs::read_dir(&first_path)? {
                let second = second?;
                let second_name = second.file_name();
                if !is_hex_name(&second_name, 2) {
                    report.skipped += 1;
                    continue;
                }
                let second_path = second.path();
                if !is_real_directory(&second_path)? {
                    self.quarantine_untrusted(&second_path, &mut report)?;
                    continue;
                }

                for leaf in fs::read_dir(&second_path)? {
                    let leaf = leaf?;
                    self.reconcile_leaf(&leaf.path(), &leaf.file_name(), &mut report)?;
                }
            }
        }
        Ok(report)
    }

    /// Lists canonical regular leaves in deterministic ContentId-byte order.
    ///
    /// The scanner opens every fanout directory with `O_NOFOLLOW` and only
    /// accounts for a leaf after opening it with `O_NOFOLLOW` as a regular
    /// file. Symlinks, malformed paths, and concurrently removed entries are
    /// skipped rather than traversed.
    pub fn fanout_entries(&self) -> Result<Vec<CacheEntry>, CacheError> {
        Ok(self.scan_fanout()?.entries)
    }

    /// Returns logical-byte accounting for safe canonical cache leaves.
    pub fn usage(&self) -> Result<CacheUsage, CacheError> {
        Ok(self.scan_fanout()?.usage)
    }

    /// Evicts canonical regular leaves in deterministic ContentId-byte order
    /// until logical cache usage is at or below `target_logical_bytes`.
    ///
    /// Every unlink is relative to an already-open fanout directory and is
    /// followed by a directory sync. The result reports a target miss rather
    /// than guessing if concurrent publication or Btrfs sharing prevents the
    /// caller from reclaiming the expected space.
    pub fn evict_to(&self, target_logical_bytes: u64) -> Result<CacheEviction, CacheError> {
        let scan = self.scan_fanout()?;
        let before = scan.usage;
        let mut remaining_logical_bytes = before.logical_bytes;
        let mut evicted_entries = 0_u64;
        let mut evicted_logical_bytes = 0_u64;
        let mut skipped_entries = 0_u64;

        for entry in scan.entries {
            if remaining_logical_bytes <= target_logical_bytes {
                break;
            }
            match self.evict_entry(entry.content_id)? {
                Some(logical_bytes) => {
                    remaining_logical_bytes = remaining_logical_bytes.saturating_sub(logical_bytes);
                    evicted_entries = evicted_entries
                        .checked_add(1)
                        .ok_or(CacheError::AccountingOverflow)?;
                    evicted_logical_bytes = evicted_logical_bytes
                        .checked_add(logical_bytes)
                        .ok_or(CacheError::AccountingOverflow)?;
                }
                None => {
                    skipped_entries = skipped_entries
                        .checked_add(1)
                        .ok_or(CacheError::AccountingOverflow)?;
                }
            }
        }

        let after = self.usage()?;
        Ok(CacheEviction {
            target_logical_bytes,
            before,
            after,
            evicted_entries,
            evicted_logical_bytes,
            skipped_entries,
        })
    }

    /// Converts a caller-measured free-space deficit into a logical cache
    /// target and evicts toward it. Because Btrfs extent sharing and
    /// compression can make physical reclamation smaller than the deleted
    /// logical length, callers must remeasure available bytes before admitting
    /// the next allocation.
    pub fn evict_for_reserve(
        &self,
        available_bytes: u64,
        reserve_bytes: u64,
    ) -> Result<CacheEviction, CacheError> {
        let usage = self.usage()?;
        let required_reclaim = reserve_bytes.saturating_sub(available_bytes);
        self.evict_to(usage.logical_bytes.saturating_sub(required_reclaim))
    }

    fn scan_fanout(&self) -> Result<FanoutScan, CacheError> {
        let root = open_directory_no_follow(&self.root)?;
        let root_path = directory_fd_path(&root);
        let mut scan = FanoutScan::default();

        for first in fs::read_dir(&root_path)? {
            let first = match first {
                Ok(first) => first,
                Err(error) if is_missing_or_unsafe(&error) => {
                    scan.skip()?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let first_name = first.file_name();
            if first_name.as_bytes() == b".quarantine" {
                continue;
            }
            if !is_hex_name(&first_name, 2) {
                scan.skip()?;
                continue;
            }
            let first_directory = match open_directory_no_follow(&root_path.join(&first_name)) {
                Ok(directory) => directory,
                Err(error) if is_missing_or_unsafe(&error) => {
                    scan.skip()?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            self.scan_second_fanout(&first_name, &first_directory, &mut scan)?;
        }

        scan.entries.sort_unstable_by(|left, right| {
            left.content_id.as_bytes().cmp(right.content_id.as_bytes())
        });
        Ok(scan)
    }

    fn scan_second_fanout(
        &self,
        first_name: &OsStr,
        first_directory: &File,
        scan: &mut FanoutScan,
    ) -> Result<(), CacheError> {
        let first_path = directory_fd_path(first_directory);
        for second in fs::read_dir(&first_path)? {
            let second = match second {
                Ok(second) => second,
                Err(error) if is_missing_or_unsafe(&error) => {
                    scan.skip()?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let second_name = second.file_name();
            if !is_hex_name(&second_name, 2) {
                scan.skip()?;
                continue;
            }
            let second_directory = match open_directory_no_follow(&first_path.join(&second_name)) {
                Ok(directory) => directory,
                Err(error) if is_missing_or_unsafe(&error) => {
                    scan.skip()?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            self.scan_fanout_leaves(first_name, &second_name, &second_directory, scan)?;
        }
        Ok(())
    }

    fn scan_fanout_leaves(
        &self,
        first_name: &OsStr,
        second_name: &OsStr,
        second_directory: &File,
        scan: &mut FanoutScan,
    ) -> Result<(), CacheError> {
        let second_path = directory_fd_path(second_directory);
        for leaf in fs::read_dir(&second_path)? {
            let leaf = match leaf {
                Ok(leaf) => leaf,
                Err(error) if is_missing_or_unsafe(&error) => {
                    scan.skip()?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            let leaf_name = leaf.file_name();
            let Some(content_id) = content_id_from_hex_name(&leaf_name) else {
                scan.skip()?;
                continue;
            };
            let encoded = hex(content_id.as_bytes());
            if first_name.as_bytes() != &encoded.as_bytes()[..2]
                || second_name.as_bytes() != &encoded.as_bytes()[2..4]
                || leaf_name.as_bytes() != encoded.as_bytes()
            {
                scan.skip()?;
                continue;
            }
            let logical_bytes = match regular_file_size_no_follow(&second_path.join(&leaf_name)) {
                Ok(bytes) => bytes,
                Err(error) if is_missing_or_unsafe(&error) => {
                    scan.skip()?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            scan.push(CacheEntry {
                content_id,
                logical_bytes,
            })?;
        }
        Ok(())
    }

    fn evict_entry(&self, id: ContentId) -> Result<Option<u64>, CacheError> {
        let lock = self.entry_lock(id);
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let parent = match self.open_fanout_parent_no_follow(id) {
            Ok(parent) => parent,
            Err(error) if is_missing_or_unsafe(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let name = hex(id.as_bytes());
        let leaf = directory_fd_path(&parent).join(&name);
        let logical_bytes = match regular_file_size_no_follow(&leaf) {
            Ok(logical_bytes) => logical_bytes,
            Err(error) if is_missing_or_unsafe(&error) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        match unlink_file_at(&parent, &name) {
            Ok(()) => {
                parent.sync_all()?;
                Ok(Some(logical_bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn open_fanout_parent_no_follow(&self, id: ContentId) -> io::Result<File> {
        let encoded = hex(id.as_bytes());
        let root = open_directory_no_follow(&self.root)?;
        let first = open_directory_no_follow(&directory_fd_path(&root).join(&encoded[..2]))?;
        open_directory_no_follow(&directory_fd_path(&first).join(&encoded[2..4]))
    }

    fn reconcile_leaf(
        &self,
        path: &Path,
        leaf: &OsStr,
        report: &mut CacheReconciliation,
    ) -> Result<(), CacheError> {
        let Some(id) = content_id_from_hex_name(leaf) else {
            return self.quarantine_untrusted(path, report);
        };
        let expected = self.path_for(id);
        if expected != path {
            return self.quarantine_untrusted(path, report);
        }

        let lock = self.entry_lock(id);
        let _guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match self.entry_status(path, id)? {
            EntryStatus::Valid => report.retained += 1,
            EntryStatus::Missing => report.skipped += 1,
            EntryStatus::Invalid => self.quarantine_untrusted(path, report)?,
        }
        Ok(())
    }

    fn quarantine_untrusted(
        &self,
        path: &Path,
        report: &mut CacheReconciliation,
    ) -> Result<(), CacheError> {
        if self.move_to_quarantine(path)?.is_some() {
            report.quarantined += 1;
        } else {
            report.skipped += 1;
        }
        Ok(())
    }

    fn read_entry(&self, path: &Path, id: ContentId) -> Result<Vec<u8>, CacheError> {
        match read_regular_file_no_follow(path) {
            Ok(bytes) => Ok(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(CacheError::NotCached(id)),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                Err(CacheError::UnsafeEntry(id))
            }
            Err(error) => Err(CacheError::Io(error)),
        }
    }

    fn entry_status(&self, path: &Path, id: ContentId) -> Result<EntryStatus, CacheError> {
        match self.read_entry(path, id) {
            Ok(bytes) if ContentId::for_object(ObjectKind::Blob, &bytes) == id => {
                Ok(EntryStatus::Valid)
            }
            Ok(_) | Err(CacheError::UnsafeEntry(_)) | Err(CacheError::ContentMismatch { .. }) => {
                Ok(EntryStatus::Invalid)
            }
            Err(CacheError::NotCached(_)) => Ok(EntryStatus::Missing),
            Err(error) => Err(error),
        }
    }

    fn entry_lock(&self, id: ContentId) -> &Mutex<()> {
        let stripe = usize::from(id.as_bytes()[0]) % self.state.entry_locks.len();
        &self.state.entry_locks[stripe]
    }

    fn move_to_quarantine(&self, path: &Path) -> Result<Option<PathBuf>, CacheError> {
        let quarantine = self.quarantine_directory()?;
        let leaf = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache path has no name"))?;
        let name = format!("{}.{}.{}", hex(leaf.as_bytes()), process::id(), nonce());
        let destination = quarantine.join(name);
        match fs::rename(path, &destination) {
            Ok(()) => {
                self.sync_directory(path.parent().expect("cache path has parent"))?;
                self.sync_directory(&quarantine)?;
                Ok(Some(destination))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(CacheError::Io(error)),
        }
    }

    fn restore_quarantined(
        &self,
        quarantined: &Path,
        destination: &Path,
    ) -> Result<(), CacheError> {
        match fs::hard_link(quarantined, destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(CacheError::Io(error)),
        }
        fs::remove_file(quarantined)?;
        self.sync_directory(destination.parent().expect("cache path has parent"))?;
        self.sync_directory(
            quarantined
                .parent()
                .expect("cache quarantine filename has parent"),
        )?;
        Ok(())
    }

    fn quarantine_directory(&self) -> Result<PathBuf, CacheError> {
        let directory = self.root.join(".quarantine");
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.file_type().is_dir() => return Ok(directory),
            Ok(_) => {
                return Err(CacheError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cache quarantine path is not a directory",
                )));
            }
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            Err(_) => {}
        }

        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        if !is_real_directory(&directory)? {
            return Err(CacheError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "cache quarantine path is not a directory",
            )));
        }
        Ok(directory)
    }

    fn sync_directory(&self, path: &Path) -> Result<(), CacheError> {
        File::open(path)?.sync_all()?;
        Ok(())
    }

    fn singleflight_hydrate<F>(&self, id: ContentId, hydrate: F) -> Result<PathBuf, HydrationError>
    where
        F: FnOnce() -> Result<PathBuf, HydrationError>,
    {
        let mut hydrate = Some(hydrate);
        loop {
            match self.verified_path(id) {
                Ok(path) => return Ok(path),
                Err(
                    CacheError::NotCached(_)
                    | CacheError::ContentMismatch { .. }
                    | CacheError::UnsafeEntry(_),
                ) => {}
                Err(error) => return Err(error.into()),
            }

            let (flight, leader) = {
                let mut active = self
                    .state
                    .hydrations
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match active.get(&id) {
                    Some(flight) => (Arc::clone(flight), false),
                    None => {
                        let flight = Arc::new(HydrationFlight::new());
                        active.insert(id, Arc::clone(&flight));
                        (flight, true)
                    }
                }
            };

            if leader {
                let result = hydrate
                    .take()
                    .expect("a singleflight leader owns exactly one hydration closure")(
                );
                {
                    let mut completed = flight
                        .completed
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *completed = true;
                    flight.completed_wakeup.notify_all();
                }
                let mut active = self
                    .state
                    .hydrations
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if active
                    .get(&id)
                    .is_some_and(|current| Arc::ptr_eq(current, &flight))
                {
                    active.remove(&id);
                }
                return result;
            }

            let mut completed = flight
                .completed
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            while !*completed {
                completed = flight
                    .completed_wakeup
                    .wait(completed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
    }

    /// Creates a Btrfs reflink at `destination`. It never falls back to a
    /// payload copy: that policy decision belongs to checkout orchestration.
    pub fn clone_blob(
        &self,
        id: ContentId,
        destination: impl AsRef<Path>,
    ) -> Result<(), CacheError> {
        let source = self.open_verified_blob(id)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryStatus {
    Missing,
    Valid,
    Invalid,
}

#[derive(Default)]
struct FanoutScan {
    entries: Vec<CacheEntry>,
    usage: CacheUsage,
}

impl FanoutScan {
    fn push(&mut self, entry: CacheEntry) -> Result<(), CacheError> {
        self.usage.entries = self
            .usage
            .entries
            .checked_add(1)
            .ok_or(CacheError::AccountingOverflow)?;
        self.usage.logical_bytes = self
            .usage
            .logical_bytes
            .checked_add(entry.logical_bytes)
            .ok_or(CacheError::AccountingOverflow)?;
        self.entries.push(entry);
        Ok(())
    }

    fn skip(&mut self) -> Result<(), CacheError> {
        self.usage.skipped = self
            .usage
            .skipped
            .checked_add(1)
            .ok_or(CacheError::AccountingOverflow)?;
        Ok(())
    }
}

fn statvfs_available_bytes(path: &Path) -> io::Result<u64> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "capacity measurement path contains a NUL byte",
        )
    })?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `stat` points to valid writable
    // storage for one `statvfs` result.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `statvfs` initialized the result above.
    let stat = unsafe { stat.assume_init() };
    let fragment_size = if stat.f_frsize == 0 {
        stat.f_bsize
    } else {
        stat.f_frsize
    };
    stat.f_bavail
        .checked_mul(fragment_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "capacity measurement overflowed u64"))
}

/// Opens a directory without following a symlink in its final component.
///
/// The caller derives descendants from `/proc/self/fd/<fd>`, keeping the
/// already-checked directory descriptor as the parent during fanout traversal.
fn open_directory_no_follow(path: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache fanout component is not a directory",
        ));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache fanout directory changed while opening",
        ));
    }
    Ok(directory)
}

/// Returns a path that resolves through a retained directory descriptor, not
/// through a mutable fanout ancestor. Reflink Forest's Btrfs deployment is
/// Linux-only, where procfs provides these stable descriptor paths.
fn directory_fd_path(directory: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn regular_file_size_no_follow(path: &Path) -> io::Result<u64> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry is not a regular file",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry changed while opening",
        ));
    }
    Ok(metadata.len())
}

fn unlink_file_at(parent: &File, name: &str) -> io::Result<()> {
    let name = CString::new(name).expect("canonical content ID name contains no NUL");
    // SAFETY: `parent` is an open directory descriptor and `name` is a
    // NUL-terminated canonical hexadecimal filename with no path separator.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_missing_or_unsafe(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidData
    ) || error.raw_os_error() == Some(libc::ELOOP)
}

fn read_regular_file_no_follow(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry is not a regular file",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cache entry changed while opening",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn is_real_directory(path: &Path) -> Result<bool, CacheError> {
    Ok(fs::symlink_metadata(path)?.file_type().is_dir())
}

fn is_hex_name(name: &OsStr, expected_len: usize) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == expected_len && bytes.iter().all(|byte| byte.is_ascii_hexdigit())
}

fn content_id_from_hex_name(name: &OsStr) -> Option<ContentId> {
    let bytes = name.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(ContentId(output))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Failure while deriving a cache blob from its authoritative cold record.
#[derive(Debug)]
pub enum HydrationError {
    Cache(CacheError),
    Store(StoreError),
    MissingLocation(ContentId),
    NotBlob(ObjectKind),
    UnsupportedCodec(Codec),
    RawLengthMismatch {
        expected: u64,
        actual: u64,
    },
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
}

impl std::fmt::Display for HydrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cache(error) => write!(f, "cache hydration failed: {error}"),
            Self::Store(error) => write!(f, "cold record validation failed: {error}"),
            Self::MissingLocation(_) => write!(f, "cold object location is missing"),
            Self::NotBlob(kind) => write!(f, "cold record is not a blob: {kind:?}"),
            Self::UnsupportedCodec(codec) => {
                write!(
                    f,
                    "cold blob codec is not supported by raw hydration: {codec:?}"
                )
            }
            Self::RawLengthMismatch { .. } => {
                write!(f, "raw cold blob length does not match its payload")
            }
            Self::ContentMismatch { .. } => {
                write!(f, "cold blob payload does not match its content ID")
            }
        }
    }
}
impl std::error::Error for HydrationError {}
impl From<CacheError> for HydrationError {
    fn from(value: CacheError) -> Self {
        Self::Cache(value)
    }
}
impl From<StoreError> for HydrationError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// Hydrates one raw cache blob addressed by `id` from its catalog location.
///
/// `chunk_path` is supplied by the caller's generation/manifest resolver.
/// The path cannot substitute a different chunk: its header's generation and
/// chunk ID must agree with the catalog location, and the record's duplicated
/// metadata and content ID are all revalidated before the cache atomically
/// publishes it.  A valid cache hit avoids opening the cold chunk.
pub fn hydrate_raw_blob_from_chunk<C: Catalog>(
    cache: &Cache,
    catalog: &C,
    id: ContentId,
    chunk_path: impl AsRef<Path>,
) -> Result<PathBuf, HydrationError> {
    hydrate_blob_from_chunk(cache, catalog, id, chunk_path)
}

/// Hydrates one cache blob from a raw or Zstd cold record.
///
/// The cache always receives canonical raw blob bytes. The cold record's
/// codec is decoded through a bounded stream before atomic cache publication.
pub fn hydrate_blob_from_chunk<C: Catalog>(
    cache: &Cache,
    catalog: &C,
    id: ContentId,
    chunk_path: impl AsRef<Path>,
) -> Result<PathBuf, HydrationError> {
    let chunk_path = chunk_path.as_ref().to_path_buf();
    cache.singleflight_hydrate(id, || {
        hydrate_blob_from_chunk_inner(cache, catalog, id, &chunk_path)
    })
}

fn hydrate_blob_from_chunk_inner<C: Catalog>(
    cache: &Cache,
    catalog: &C,
    id: ContentId,
    chunk_path: &Path,
) -> Result<PathBuf, HydrationError> {
    match cache.verified_path(id) {
        Ok(path) => return Ok(path),
        Err(CacheError::NotCached(_)) => {}
        Err(CacheError::ContentMismatch { .. } | CacheError::UnsafeEntry(_)) => {
            cache.discard_invalid_blob(id)?;
        }
        Err(error) => return Err(error.into()),
    }

    let location = catalog
        .object_location(id)
        .ok_or(HydrationError::MissingLocation(id))?;
    validate_blob_location(location)?;
    // An existing corrupt cache file can only be derived state.  Stream the
    // authoritative raw bytes into a temporary file while incrementally
    // hashing them; no full blob payload is materialized in memory before the
    // usual atomic publication protocol runs.
    // A racing publisher can install a corrupt derived entry after the first
    // verification.  Discard it and retry once; if another hydrator won with
    // valid content, the second publication returns that verified entry.
    match cache.publish_blob_streamed(id, |file| {
        stream_blob_into_cache(file, chunk_path, location, id)
    }) {
        Ok(path) => Ok(path),
        Err(HydrationError::Cache(
            CacheError::ContentMismatch { .. } | CacheError::UnsafeEntry(_),
        )) => {
            cache.discard_invalid_blob(id)?;
            cache.publish_blob_streamed(id, |file| {
                stream_blob_into_cache(file, chunk_path, location, id)
            })
        }
        Err(error) => Err(error),
    }
}

fn validate_blob_location(location: ObjectLocation) -> Result<(), HydrationError> {
    if location.kind != ObjectKind::Blob {
        return Err(HydrationError::NotBlob(location.kind));
    }
    Ok(())
}

fn stream_blob_into_cache(
    file: &mut File,
    chunk_path: &Path,
    location: ObjectLocation,
    expected_id: ContentId,
) -> Result<ContentId, HydrationError> {
    let mut writer = ContentHashingWriter::new(file, location.raw_length);
    let metadata = stream_decoded_record_at(chunk_path, location, &mut writer)?;
    let (actual, actual_length) = writer.finish();
    if metadata.kind != ObjectKind::Blob {
        return Err(HydrationError::NotBlob(metadata.kind));
    }
    if metadata.raw_length != actual_length {
        return Err(HydrationError::RawLengthMismatch {
            expected: metadata.raw_length,
            actual: actual_length,
        });
    }
    if actual != expected_id || metadata.content_id != expected_id {
        return Err(HydrationError::ContentMismatch {
            expected: expected_id,
            actual,
        });
    }
    Ok(actual)
}

/// A cache temporary-file writer that updates the raw blob's canonical
/// content ID as the cold-store reader supplies bounded chunks.
struct ContentHashingWriter<'a> {
    file: &'a mut File,
    hasher: ContentHasher,
    written: u64,
}

impl<'a> ContentHashingWriter<'a> {
    fn new(file: &'a mut File, raw_length: u64) -> Self {
        Self {
            file,
            hasher: ContentHasher::new(ObjectKind::Blob, raw_length),
            written: 0,
        }
    }

    fn finish(self) -> (ContentId, u64) {
        (self.hasher.finalize(), self.written)
    }
}

impl Write for ContentHashingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.file.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.written = self.written.checked_add(written as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "cold blob byte count overflowed u64",
            )
        })?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
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
    use reflink_forest_core::{GitOid, HashAlgorithm};
    use reflink_forest_format::{
        encode_object_payload, ChunkHeader, ObjectRecord, RECORD_HEADER_LEN,
    };
    use reflink_forest_index::{
        Catalog, CatalogBatch, CatalogError, ChunkMetadata, InMemoryCatalog, RepoId, WorkspaceId,
    };
    use reflink_forest_store::{ChunkWriter, RecordLocation, STREAM_COPY_BUFFER_BYTES};
    use std::{
        collections::VecDeque,
        io::{Seek, SeekFrom},
        os::unix::fs::symlink,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Barrier, Mutex,
        },
        thread,
        time::Duration,
    };

    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!("reflink-forest-cache-{}", nonce()))
    }

    struct ColdBlobFixture {
        directory: PathBuf,
        chunk: PathBuf,
        cache: Cache,
        catalog: InMemoryCatalog,
        id: ContentId,
        location: ObjectLocation,
    }

    struct CountingCatalog {
        inner: InMemoryCatalog,
        location_reads: AtomicUsize,
    }

    struct ScriptedCapacityMeter {
        measurements: Mutex<VecDeque<CapacitySnapshot>>,
    }

    impl ScriptedCapacityMeter {
        fn new(measurements: impl IntoIterator<Item = CapacitySnapshot>) -> Self {
            Self {
                measurements: Mutex::new(measurements.into_iter().collect()),
            }
        }

        fn remaining(&self) -> usize {
            self.measurements.lock().unwrap().len()
        }
    }

    impl CapacityMeter for ScriptedCapacityMeter {
        fn measure(&self) -> io::Result<CapacitySnapshot> {
            self.measurements
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "no measurement"))
        }
    }

    impl CountingCatalog {
        fn new(inner: InMemoryCatalog) -> Self {
            Self {
                inner,
                location_reads: AtomicUsize::new(0),
            }
        }
    }

    impl Catalog for CountingCatalog {
        fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
            self.inner.apply(batch)
        }

        fn object_location(&self, id: ContentId) -> Option<ObjectLocation> {
            self.location_reads.fetch_add(1, Ordering::SeqCst);
            self.inner.object_location(id)
        }

        fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId> {
            self.inner.oid_alias(repo, oid)
        }

        fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata> {
            self.inner.chunk(generation, chunk_id)
        }

        fn meta(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.meta(key)
        }

        fn workspace(&self, id: WorkspaceId) -> Option<Vec<u8>> {
            self.inner.workspace(id)
        }

        fn workspace_name(&self, name: &[u8]) -> Option<WorkspaceId> {
            self.inner.workspace_name(name)
        }

        fn workspace_pin(&self, id: WorkspaceId) -> Option<u32> {
            self.inner.workspace_pin(id)
        }

        fn job(&self, job_id: &[u8]) -> Option<Vec<u8>> {
            self.inner.job(job_id)
        }
    }

    fn cold_blob_fixture(payload: &[u8]) -> ColdBlobFixture {
        cold_blob_fixture_with_id(payload, ContentId::for_object(ObjectKind::Blob, payload))
    }

    fn cold_blob_fixture_with_id(payload: &[u8], id: ContentId) -> ColdBlobFixture {
        cold_blob_fixture_with_codec(payload, id, Codec::Raw)
    }

    fn cold_blob_fixture_with_codec(
        payload: &[u8],
        id: ContentId,
        codec: Codec,
    ) -> ColdBlobFixture {
        let directory = directory();
        fs::create_dir(&directory).unwrap();
        let chunk = directory.join("0000000000000001.open");
        // Store writes now verify `record.content_id` before accepting a
        // record. Keep the physical record valid, then deliberately attach
        // its location to `id` in the fixture catalog below so hydration must
        // detect the catalog-to-record content-ID disagreement.
        let record = ObjectRecord {
            kind: ObjectKind::Blob,
            codec,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: ContentId::for_object(ObjectKind::Blob, payload),
            primary_oid: GitOid::new(HashAlgorithm::Sha1, &[7; 20]).unwrap(),
            payload: encode_object_payload(codec, payload).unwrap(),
        };
        let header = ChunkHeader {
            generation: 3,
            chunk_id: 9,
            created_unix_secs: 0,
            flags: 0,
        };
        let mut writer = ChunkWriter::create(&chunk, header).unwrap();
        let record_location = writer.append(&record).unwrap();
        writer.sync_data().unwrap();
        drop(writer);

        let location = object_location(&record, record_location, header);
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_object_location(id, location);
        catalog.apply(batch).unwrap();
        let cache = Cache::open(directory.join("cache")).unwrap();
        ColdBlobFixture {
            directory,
            chunk,
            cache,
            catalog,
            id,
            location,
        }
    }

    fn object_location(
        record: &ObjectRecord,
        record_location: RecordLocation,
        header: ChunkHeader,
    ) -> ObjectLocation {
        ObjectLocation {
            generation: header.generation,
            chunk_id: header.chunk_id,
            offset: record_location.offset,
            record_length: record_location.record_length,
            stored_length: record.payload.len() as u64,
            raw_length: record.raw_length,
            kind: record.kind,
            codec: record.codec,
            flags: record.flags,
            payload_crc32c: reflink_forest_format::crc32c(&record.payload),
        }
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
    fn cache_open_rejects_a_final_component_symlink() {
        use std::os::unix::fs::symlink;

        let directory = directory();
        let target = directory.join("target");
        let cache_root = directory.join("cache");
        fs::create_dir(&directory).unwrap();
        fs::create_dir(&target).unwrap();
        symlink(&target, &cache_root).unwrap();

        assert!(matches!(
            Cache::open(&cache_root),
            Err(CacheError::UnsafeRoot(path)) if path == cache_root
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn verified_blob_descriptor_never_follows_a_cache_leaf_symlink() {
        use std::os::unix::fs::symlink;

        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let payload = b"descriptor must stay beneath cache";
        let id = ContentId::for_object(ObjectKind::Blob, payload);
        cache.publish_blob(id, payload).unwrap();

        let outside = directory.join("outside-cache");
        fs::write(&outside, payload).unwrap();
        let leaf = cache.path_for(id);
        fs::remove_file(&leaf).unwrap();
        symlink(&outside, &leaf).unwrap();

        assert!(matches!(
            cache.open_verified_blob(id),
            Err(CacheError::UnsafeEntry(actual)) if actual == id
        ));
        assert_eq!(fs::read(&outside).unwrap(), payload);
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

    #[test]
    fn fanout_accounting_and_eviction_use_stable_content_id_order() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let payloads: [&[u8]; 3] = [b"seven!!", b"three", b"twelve bytes"];
        let mut ids = Vec::new();
        for payload in payloads {
            let id = ContentId::for_object(ObjectKind::Blob, payload);
            cache.publish_blob(id, payload).unwrap();
            ids.push(id);
        }

        let entries = cache.fanout_entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries
            .windows(2)
            .all(|pair| { pair[0].content_id.as_bytes() < pair[1].content_id.as_bytes() }));
        let usage = cache.usage().unwrap();
        assert_eq!(usage.entries, 3);
        assert_eq!(usage.skipped, 0);
        assert_eq!(
            usage.logical_bytes,
            payloads.iter().map(|payload| payload.len() as u64).sum()
        );

        let first = entries[0];
        let report = cache
            .evict_to(usage.logical_bytes - first.logical_bytes)
            .unwrap();
        assert_eq!(report.before, usage);
        assert_eq!(report.evicted_entries, 1);
        assert_eq!(report.evicted_logical_bytes, first.logical_bytes);
        assert!(report.target_reached());
        assert!(matches!(
            cache.verified_path(first.content_id),
            Err(CacheError::NotCached(_))
        ));
        for id in ids.into_iter().filter(|id| *id != first.content_id) {
            assert!(cache.verified_path(id).is_ok());
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn fanout_scan_never_follows_leaf_or_directory_symlinks() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();

        let outside_file = directory.join("outside-file");
        let outside_bytes = b"outside cache";
        fs::write(&outside_file, outside_bytes).unwrap();
        let symlink_id = ContentId::for_object(ObjectKind::Blob, outside_bytes);
        let symlink_path = cache.path_for(symlink_id);
        fs::create_dir_all(symlink_path.parent().unwrap()).unwrap();
        symlink(&outside_file, &symlink_path).unwrap();

        let outside_directory = directory.join("outside-directory");
        fs::create_dir(&outside_directory).unwrap();
        fs::write(outside_directory.join("unrelated"), b"must not scan").unwrap();
        symlink(&outside_directory, cache.root.join("aa")).unwrap();

        let usage = cache.usage().unwrap();
        assert_eq!(usage.entries, 0);
        assert_eq!(usage.logical_bytes, 0);
        assert!(usage.skipped >= 2);
        assert!(cache.fanout_entries().unwrap().is_empty());
        assert_eq!(fs::read(&outside_file).unwrap(), outside_bytes);
        assert_eq!(
            fs::read(outside_directory.join("unrelated")).unwrap(),
            b"must not scan"
        );
        assert!(fs::symlink_metadata(&symlink_path)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reserve_policy_reports_exact_host_and_guest_shortfalls() {
        let policy = ReservePolicy::new(100, 80);
        assert_eq!(policy.admit(180, 160, 60), Ok(()));

        assert_eq!(
            policy.admit(150, 200, 60),
            Err(AdmissionError::HostReserve(ReserveViolation {
                available_bytes: 150,
                projected_allocation_bytes: 60,
                reserve_bytes: 100,
                available_after_allocation_bytes: 90,
                shortfall_bytes: 10,
            }))
        );
        assert_eq!(
            policy.admit(200, 120, 60),
            Err(AdmissionError::GuestReserve(ReserveViolation {
                available_bytes: 120,
                projected_allocation_bytes: 60,
                reserve_bytes: 80,
                available_after_allocation_bytes: 60,
                shortfall_bytes: 20,
            }))
        );
        assert_eq!(
            policy.admit(150, 120, 60),
            Err(AdmissionError::HostAndGuestReserve {
                host: ReserveViolation {
                    available_bytes: 150,
                    projected_allocation_bytes: 60,
                    reserve_bytes: 100,
                    available_after_allocation_bytes: 90,
                    shortfall_bytes: 10,
                },
                guest: ReserveViolation {
                    available_bytes: 120,
                    projected_allocation_bytes: 60,
                    reserve_bytes: 80,
                    available_after_allocation_bytes: 60,
                    shortfall_bytes: 20,
                },
            })
        );
    }

    #[test]
    fn capacity_coordinator_evicts_deterministically_then_remeasures_before_publish() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        cache
            .publish_blob(
                ContentId::for_object(ObjectKind::Blob, b"first 16 bytes!!"),
                b"first 16 bytes!!",
            )
            .unwrap();
        cache
            .publish_blob(
                ContentId::for_object(ObjectKind::Blob, b"second payload is longer"),
                b"second payload is longer",
            )
            .unwrap();
        let usage = cache.usage().unwrap();
        assert!(usage.logical_bytes >= 20);

        let meter = ScriptedCapacityMeter::new([
            CapacitySnapshot {
                host_available_bytes: 115,
                guest_available_bytes: 80,
            },
            CapacitySnapshot {
                host_available_bytes: 125,
                guest_available_bytes: 105,
            },
        ]);
        let coordinator = CacheCapacityCoordinator::new(cache, meter, ReservePolicy::new(100, 80));
        let new_bytes = b"new derived cache blob";
        let new_id = ContentId::for_object(ObjectKind::Blob, new_bytes);

        let (admission, path) = coordinator
            .with_admission(20, |cache| cache.publish_blob(new_id, new_bytes))
            .unwrap();

        assert_eq!(admission.before.host_available_bytes, 115);
        assert_eq!(admission.admitted.guest_available_bytes, 105);
        let eviction = admission
            .eviction
            .expect("initial reserve shortfall evicts");
        assert_eq!(eviction.target_logical_bytes, usage.logical_bytes - 20);
        assert!(eviction.evicted_entries >= 1);
        assert!(eviction.target_reached());
        assert_eq!(fs::read(path).unwrap(), new_bytes);
        assert_eq!(coordinator.meter().remaining(), 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn capacity_coordinator_refuses_when_remeasurement_cannot_restore_reserves() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        cache
            .publish_blob(
                ContentId::for_object(ObjectKind::Blob, b"a cache leaf large enough to evict"),
                b"a cache leaf large enough to evict",
            )
            .unwrap();
        let usage = cache.usage().unwrap();
        let meter = ScriptedCapacityMeter::new([
            CapacitySnapshot {
                host_available_bytes: 110,
                guest_available_bytes: 100,
            },
            CapacitySnapshot {
                host_available_bytes: 115,
                guest_available_bytes: 99,
            },
        ]);
        let coordinator = CacheCapacityCoordinator::new(cache, meter, ReservePolicy::new(100, 80));
        let invoked = AtomicBool::new(false);

        let error = coordinator
            .with_admission(20, |_| {
                invoked.store(true, Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();

        assert!(!invoked.load(Ordering::SeqCst));
        match error {
            CapacityAdmissionError::ReservesStillUnmet(failure) => {
                let CapacityReserveFailure {
                    before,
                    after_eviction,
                    eviction,
                    violation,
                } = *failure;
                let AdmissionError::HostAndGuestReserve { host, guest } = violation else {
                    panic!("expected both reserves to remain unmet: {violation:?}");
                };
                assert_eq!(before.host_available_bytes, 110);
                assert_eq!(
                    after_eviction,
                    CapacitySnapshot {
                        host_available_bytes: 115,
                        guest_available_bytes: 99,
                    }
                );
                assert_eq!(eviction.target_logical_bytes, usage.logical_bytes - 10);
                assert_eq!(host.shortfall_bytes, 5);
                assert_eq!(guest.shortfall_bytes, 1);
            }
            other => panic!("unexpected admission result: {other:?}"),
        }
        assert_eq!(coordinator.meter().remaining(), 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reserve_admission_guard_allows_growth_work_only_after_both_reserves_pass() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let meter = ScriptedCapacityMeter::new([CapacitySnapshot {
            host_available_bytes: 101,
            guest_available_bytes: 81,
        }]);
        let coordinator = CacheCapacityCoordinator::new(cache, meter, ReservePolicy::new(100, 80));
        let grew = AtomicBool::new(false);

        let (admission, ()) = coordinator
            .with_reserve_admission(1, || {
                grew.store(true, Ordering::SeqCst);
                Ok::<(), io::Error>(())
            })
            .unwrap();

        assert!(grew.load(Ordering::SeqCst));
        assert_eq!(admission.projected_allocation_bytes, 1);
        assert_eq!(admission.eviction, None);
        assert_eq!(coordinator.meter().remaining(), 0);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn filesystem_capacity_meter_measures_the_supplied_paths() {
        let meter = FilesystemCapacityMeter::new(".", ".");
        let measured = meter.measure().unwrap();
        assert_eq!(
            measured.host_available_bytes,
            measured.guest_available_bytes
        );
    }

    #[test]
    fn hydration_reads_validated_cold_blob_and_atomically_publishes_cache() {
        let fixture = cold_blob_fixture(b"authoritative cold bytes");

        let path = hydrate_raw_blob_from_chunk(
            &fixture.cache,
            &fixture.catalog,
            fixture.id,
            &fixture.chunk,
        )
        .unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"authoritative cold bytes");
        assert_eq!(fixture.cache.verified_path(fixture.id).unwrap(), path);
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_streams_zstd_cold_blob_into_raw_cache() {
        let payload = vec![b'z'; STREAM_COPY_BUFFER_BYTES * 2 + 19];
        let id = ContentId::for_object(ObjectKind::Blob, &payload);
        let fixture = cold_blob_fixture_with_codec(&payload, id, Codec::Zstd);

        let path =
            hydrate_blob_from_chunk(&fixture.cache, &fixture.catalog, fixture.id, &fixture.chunk)
                .unwrap();

        assert_eq!(fs::read(path).unwrap(), payload);
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_streams_a_large_raw_blob_through_the_bounded_store_reader() {
        let payload = vec![0x6d; STREAM_COPY_BUFFER_BYTES * 3 + 29];
        let fixture = cold_blob_fixture(&payload);

        let path = hydrate_raw_blob_from_chunk(
            &fixture.cache,
            &fixture.catalog,
            fixture.id,
            &fixture.chunk,
        )
        .unwrap();

        assert_eq!(fs::metadata(&path).unwrap().len(), payload.len() as u64);
        assert_eq!(fs::read(&path).unwrap(), payload);
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_rejects_corrupt_cold_record_without_publishing_cache() {
        let fixture = cold_blob_fixture(b"cold data to corrupt");
        let mut chunk = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.chunk)
            .unwrap();
        chunk
            .seek(SeekFrom::Start(
                fixture.location.offset + RECORD_HEADER_LEN as u64,
            ))
            .unwrap();
        chunk.write_all(b"!").unwrap();
        chunk.sync_all().unwrap();

        assert!(matches!(
            hydrate_raw_blob_from_chunk(
                &fixture.cache,
                &fixture.catalog,
                fixture.id,
                &fixture.chunk,
            ),
            Err(HydrationError::Store(StoreError::Codec(_)))
        ));
        assert!(!fixture.cache.path_for(fixture.id).exists());
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_rejects_a_record_whose_payload_does_not_match_its_content_id() {
        let expected_id = ContentId::for_object(ObjectKind::Blob, b"expected content");
        let fixture = cold_blob_fixture_with_id(b"different content", expected_id);

        assert!(matches!(
            hydrate_raw_blob_from_chunk(
                &fixture.cache,
                &fixture.catalog,
                fixture.id,
                &fixture.chunk,
            ),
            Err(HydrationError::ContentMismatch { expected, .. }) if expected == expected_id
        ));
        assert!(!fixture.cache.path_for(fixture.id).exists());
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_rejects_missing_cold_chunk_without_publishing_cache() {
        let fixture = cold_blob_fixture(b"missing cold bytes");
        fs::remove_file(&fixture.chunk).unwrap();

        assert!(matches!(
            hydrate_raw_blob_from_chunk(
                &fixture.cache,
                &fixture.catalog,
                fixture.id,
                &fixture.chunk,
            ),
            Err(HydrationError::Store(StoreError::Io(error)))
                if error.kind() == io::ErrorKind::NotFound
        ));
        assert!(!fixture.cache.path_for(fixture.id).exists());
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_recovers_an_invalid_cache_file_from_cold_data() {
        let fixture = cold_blob_fixture(b"recoverable cold bytes");
        let cache_path = fixture.cache.path_for(fixture.id);
        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        fs::write(&cache_path, b"interrupted cache write").unwrap();

        let path = hydrate_raw_blob_from_chunk(
            &fixture.cache,
            &fixture.catalog,
            fixture.id,
            &fixture.chunk,
        )
        .unwrap();

        assert_eq!(path, cache_path);
        assert_eq!(fs::read(path).unwrap(), b"recoverable cold bytes");
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn concurrent_hydration_publishes_one_verified_cache_entry() {
        let fixture = cold_blob_fixture(b"shared concurrent blob");
        let cache = Arc::new(fixture.cache);
        let catalog = Arc::new(CountingCatalog::new(fixture.catalog));
        let chunk = Arc::new(fixture.chunk);
        let mut workers = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let catalog = Arc::clone(&catalog);
            let chunk = Arc::clone(&chunk);
            let id = fixture.id;
            workers.push(thread::spawn(move || {
                hydrate_raw_blob_from_chunk(&cache, &*catalog, id, &*chunk).unwrap()
            }));
        }
        let paths: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(paths.iter().all(|path| path == &paths[0]));
        assert_eq!(
            fs::read(cache.verified_path(fixture.id).unwrap()).unwrap(),
            b"shared concurrent blob"
        );
        assert_eq!(catalog.location_reads.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn singleflight_invokes_one_authoritative_hydration_source() {
        let directory = directory();
        let cache = Arc::new(Cache::open(&directory).unwrap());
        let id = ContentId::for_object(ObjectKind::Blob, b"singleflight source");
        let source_calls = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(8));
        let mut workers = Vec::new();

        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let source_calls = Arc::clone(&source_calls);
            let start = Arc::clone(&start);
            workers.push(thread::spawn(move || {
                start.wait();
                cache
                    .singleflight_hydrate(id, || {
                        source_calls.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(25));
                        cache
                            .publish_blob(id, b"singleflight source")
                            .map_err(Into::into)
                    })
                    .unwrap()
            }));
        }

        let paths: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(paths.iter().all(|path| path == &paths[0]));
        assert_eq!(source_calls.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn concurrent_invalid_discard_never_removes_a_repaired_entry() {
        let directory = directory();
        let cache = Arc::new(Cache::open(&directory).unwrap());
        let id = ContentId::for_object(ObjectKind::Blob, b"concurrent repair");
        let path = cache.path_for(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"corrupt cache entry").unwrap();
        let start = Arc::new(Barrier::new(2));

        let discarder_cache = Arc::clone(&cache);
        let discarder_start = Arc::clone(&start);
        let discarder = thread::spawn(move || {
            discarder_start.wait();
            discarder_cache.discard_invalid_blob(id).unwrap();
        });
        let repairer_cache = Arc::clone(&cache);
        let repairer = thread::spawn(move || {
            start.wait();
            loop {
                match repairer_cache.publish_blob(id, b"concurrent repair") {
                    Ok(path) => break path,
                    Err(CacheError::ContentMismatch { .. } | CacheError::UnsafeEntry(_)) => {
                        repairer_cache.discard_invalid_blob(id).unwrap();
                    }
                    Err(error) => panic!("unexpected repair error: {error}"),
                }
            }
        });

        discarder.join().unwrap();
        let repaired = repairer.join().unwrap();
        assert_eq!(cache.verified_path(id).unwrap(), repaired);
        assert_eq!(fs::read(repaired).unwrap(), b"concurrent repair");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reconcile_quarantines_invalid_leaves_without_following_symlinks() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let valid_id = ContentId::for_object(ObjectKind::Blob, b"valid cache entry");
        cache.publish_blob(valid_id, b"valid cache entry").unwrap();

        let corrupt_id = ContentId::for_object(ObjectKind::Blob, b"expected corrupt entry");
        let corrupt_path = cache.path_for(corrupt_id);
        fs::create_dir_all(corrupt_path.parent().unwrap()).unwrap();
        fs::write(&corrupt_path, b"wrong cache bytes").unwrap();

        let target_bytes = b"outside cache target";
        let target = directory.join("outside-target");
        fs::write(&target, target_bytes).unwrap();
        let symlink_id = ContentId::for_object(ObjectKind::Blob, target_bytes);
        let symlink_path = cache.path_for(symlink_id);
        fs::create_dir_all(symlink_path.parent().unwrap()).unwrap();
        symlink(&target, &symlink_path).unwrap();

        let report = cache.reconcile().unwrap();
        assert_eq!(report.retained, 1);
        assert_eq!(report.quarantined, 2);
        assert_eq!(fs::read(&target).unwrap(), target_bytes);
        assert!(matches!(
            cache.verified_path(corrupt_id),
            Err(CacheError::NotCached(_))
        ));
        assert!(matches!(
            cache.verified_path(symlink_id),
            Err(CacheError::NotCached(_))
        ));
        assert!(cache.verified_path(valid_id).is_ok());
        assert_eq!(
            fs::read_dir(directory.join(".quarantine")).unwrap().count(),
            2
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
