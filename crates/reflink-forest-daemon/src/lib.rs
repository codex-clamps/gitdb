//! Per-user Unix-socket daemon foundations.
//!
//! The daemon has one owner per instance and accepts requests only from that
//! Unix UID. It intentionally exposes no mount or ownership-changing action;
//! those remain a fixed-purpose privileged-helper concern.

use reflink_forest_format::crc32c;
use reflink_forest_index::{Catalog, CatalogBatch, CatalogError};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

/// On-disk format for a daemon job record.  The version is deliberately the
/// first byte in every record, matching the durable-format contract.  The
/// remaining bytes are a fixed binary header followed by byte strings; no JSON
/// parser or platform struct layout participates in recovery.
const JOB_RECORD_VERSION: u8 = 1;
const JOB_RECORD_MAGIC: [u8; 8] = *b"RFSJOBv1";
const JOB_HEADER_LEN: usize = 50;
const JOB_TRAILER_LEN: usize = 4;
const MAX_JOB_RECORD_LEN: usize = 64 * 1024 * 1024;
const JOB_TEMP_PREFIX: &str = ".reflink-forest-job-";
const JOB_TEMP_SUFFIX: &str = ".tmp";
static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

/// A stable, opaque job identifier. Its lower-case hexadecimal rendering is
/// also the record filename, so identifiers never become client-supplied
/// paths.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobId([u8; 16]);

impl JobId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    fn parse_hex(value: &str) -> Option<Self> {
        if value.len() != 32 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let start = index.checked_mul(2)?;
            *byte = (hex_nibble(value.as_bytes()[start])? << 4)
                | hex_nibble(value.as_bytes()[start + 1])?;
        }
        Some(Self(bytes))
    }

    fn random() -> Result<Self, JobError> {
        let mut bytes = [0_u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl std::fmt::Display for JobId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The only normal durable state transitions are
/// `Queued -> Running -> Succeeded|Failed` and `Failed -> Queued`. Startup
/// additionally changes persisted `Running` work to retryable `Queued` work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JobState {
    Queued = 1,
    Running = 2,
    Succeeded = 3,
    Failed = 4,
}

impl JobState {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Queued),
            2 => Some(Self::Running),
            3 => Some(Self::Succeeded),
            4 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// A persisted daemon job. Fields remain bytes to preserve byte-exact paths
/// and Git names without an accidental UTF-8 conversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRecord {
    pub id: JobId,
    pub kind: Vec<u8>,
    pub payload: Vec<u8>,
    pub state: JobState,
    /// Incremented when a queued job is claimed for execution.
    pub attempts: u32,
    /// The most recent failure; a retry retains it until success.
    pub last_error: Option<Vec<u8>>,
}

impl JobRecord {
    fn queued(id: JobId, kind: Vec<u8>, payload: Vec<u8>) -> Self {
        Self {
            id,
            kind,
            payload,
            state: JobState::Queued,
            attempts: 0,
            last_error: None,
        }
    }

    fn validate(&self) -> Result<(), JobError> {
        if self.kind.is_empty() {
            return Err(JobError::InvalidRecord("job kind is empty"));
        }
        if self.kind.len() > MAX_JOB_RECORD_LEN
            || self.payload.len() > MAX_JOB_RECORD_LEN
            || self
                .last_error
                .as_ref()
                .is_some_and(|error| error.len() > MAX_JOB_RECORD_LEN)
        {
            return Err(JobError::InvalidRecord("job field exceeds size limit"));
        }
        if self
            .last_error
            .as_ref()
            .is_some_and(|error| error.is_empty())
        {
            return Err(JobError::InvalidRecord("job error is empty"));
        }
        if self.state != JobState::Queued && self.attempts == 0 {
            return Err(JobError::InvalidRecord(
                "non-queued job has no execution attempt",
            ));
        }
        match self.state {
            JobState::Succeeded if self.last_error.is_some() => {
                Err(JobError::InvalidRecord("succeeded job retains an error"))
            }
            JobState::Failed if self.last_error.is_none() => {
                Err(JobError::InvalidRecord("failed job has no error"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug)]
pub enum JobError {
    Io(io::Error),
    AlreadyExists(JobId),
    NotFound(JobId),
    InvalidRecord(&'static str),
    UnsupportedVersion(u8),
    InvalidTransition {
        id: JobId,
        from: JobState,
        to: JobState,
    },
    AttemptOverflow(JobId),
    UnsafeJobDirectoryEntry(PathBuf),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "job I/O error: {error}"),
            Self::AlreadyExists(id) => write!(formatter, "job {id} already exists"),
            Self::NotFound(id) => write!(formatter, "job {id} does not exist"),
            Self::InvalidRecord(reason) => {
                write!(formatter, "invalid durable job record: {reason}")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported durable job record version {version}"
                )
            }
            Self::InvalidTransition { id, from, to } => {
                write!(
                    formatter,
                    "job {id} cannot transition from {from:?} to {to:?}"
                )
            }
            Self::AttemptOverflow(id) => {
                write!(formatter, "job {id} execution attempts overflowed")
            }
            Self::UnsafeJobDirectoryEntry(path) => write!(
                formatter,
                "unsafe or unexpected entry in job directory: {}",
                path.display()
            ),
        }
    }
}
impl std::error::Error for JobError {}
impl From<io::Error> for JobError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// File-backed, per-daemon durable job queue.
///
/// Every mutation writes a new version to a temporary file, synchronizes that
/// file, atomically renames it over the old version, and synchronizes the jobs
/// directory. A crash can therefore expose only a complete old or new record.
#[derive(Debug)]
pub struct JobStore {
    jobs_dir: PathBuf,
    mutation_lock: Mutex<()>,
}

impl JobStore {
    /// Opens the durable queue and reconciles interrupted work. `Running`
    /// records become `Queued`, retaining their attempt count for retry.
    pub fn open(state_root: impl AsRef<Path>) -> Result<Self, JobError> {
        Self::open_with_recovery(state_root).map(|(store, _)| store)
    }

    /// Opens the durable queue and reports how many interrupted `Running`
    /// records were made retryable before the caller can accept work.
    pub fn open_with_recovery(state_root: impl AsRef<Path>) -> Result<(Self, usize), JobError> {
        let jobs_dir = state_root.as_ref().join("jobs");
        let created = !jobs_dir.exists();
        fs::create_dir_all(&jobs_dir)?;
        fs::set_permissions(&jobs_dir, fs::Permissions::from_mode(0o700))?;
        if created {
            sync_parent_directory(&jobs_dir)?;
        }
        let store = Self {
            jobs_dir,
            mutation_lock: Mutex::new(()),
        };
        let recovered = store.recover_startup()?;
        Ok((store, recovered))
    }

    pub fn directory(&self) -> &Path {
        &self.jobs_dir
    }

    /// Enqueues under a cryptographically random opaque identifier.
    pub fn enqueue(
        &self,
        kind: impl AsRef<[u8]>,
        payload: impl AsRef<[u8]>,
    ) -> Result<JobRecord, JobError> {
        let _guard = lock_unpoisoned(&self.mutation_lock);
        for _ in 0..32 {
            let id = JobId::random()?;
            if !self.job_path(id).exists() {
                let record =
                    JobRecord::queued(id, kind.as_ref().to_vec(), payload.as_ref().to_vec());
                self.write_record_locked(&record)?;
                return Ok(record);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique job identifier",
        )
        .into())
    }

    /// Enqueues under a caller-selected identifier. Existing records are never
    /// overwritten, which lets a higher-level manifest own job identity.
    pub fn enqueue_with_id(
        &self,
        id: JobId,
        kind: impl AsRef<[u8]>,
        payload: impl AsRef<[u8]>,
    ) -> Result<JobRecord, JobError> {
        let _guard = lock_unpoisoned(&self.mutation_lock);
        if self.job_path(id).exists() {
            return Err(JobError::AlreadyExists(id));
        }
        let record = JobRecord::queued(id, kind.as_ref().to_vec(), payload.as_ref().to_vec());
        self.write_record_locked(&record)?;
        Ok(record)
    }

    pub fn get(&self, id: JobId) -> Result<JobRecord, JobError> {
        let _guard = lock_unpoisoned(&self.mutation_lock);
        self.read_record_locked(id)
    }

    /// Lists all jobs in stable identifier order. Malformed directory entries
    /// fail closed rather than being silently ignored.
    pub fn list(&self) -> Result<Vec<JobRecord>, JobError> {
        let _guard = lock_unpoisoned(&self.mutation_lock);
        self.list_records_locked()
    }

    pub fn start(&self, id: JobId) -> Result<JobRecord, JobError> {
        self.update(id, |record| {
            require_transition(record, JobState::Queued, JobState::Running)?;
            record.attempts = record
                .attempts
                .checked_add(1)
                .ok_or(JobError::AttemptOverflow(record.id))?;
            record.state = JobState::Running;
            Ok(())
        })
    }

    pub fn succeed(&self, id: JobId) -> Result<JobRecord, JobError> {
        self.update(id, |record| {
            require_transition(record, JobState::Running, JobState::Succeeded)?;
            record.state = JobState::Succeeded;
            record.last_error = None;
            Ok(())
        })
    }

    pub fn fail(&self, id: JobId, error: impl AsRef<[u8]>) -> Result<JobRecord, JobError> {
        let error = error.as_ref();
        if error.is_empty() {
            return Err(JobError::InvalidRecord("failure error is empty"));
        }
        self.update(id, |record| {
            require_transition(record, JobState::Running, JobState::Failed)?;
            record.state = JobState::Failed;
            record.last_error = Some(error.to_vec());
            Ok(())
        })
    }

    /// Requeues a failed job without erasing its diagnostic. The next claim
    /// increments `attempts`.
    pub fn retry(&self, id: JobId) -> Result<JobRecord, JobError> {
        self.update(id, |record| {
            require_transition(record, JobState::Failed, JobState::Queued)?;
            record.state = JobState::Queued;
            Ok(())
        })
    }

    /// Cleans stale temporary files and returns interrupted work to the queue.
    /// It is idempotent and is invoked automatically by [`Self::open`].
    pub fn recover_startup(&self) -> Result<usize, JobError> {
        let _guard = lock_unpoisoned(&self.mutation_lock);
        self.remove_stale_temporaries_locked()?;
        let mut recovered = 0;
        for mut record in self.list_records_locked()? {
            if record.state == JobState::Running {
                record.state = JobState::Queued;
                self.write_record_locked(&record)?;
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    fn update<F>(&self, id: JobId, change: F) -> Result<JobRecord, JobError>
    where
        F: FnOnce(&mut JobRecord) -> Result<(), JobError>,
    {
        let _guard = lock_unpoisoned(&self.mutation_lock);
        let mut record = self.read_record_locked(id)?;
        change(&mut record)?;
        self.write_record_locked(&record)?;
        Ok(record)
    }

    fn list_records_locked(&self) -> Result<Vec<JobRecord>, JobError> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.jobs_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| JobError::UnsafeJobDirectoryEntry(path.clone()))?;
            if is_temporary_name(&name) {
                return Err(JobError::UnsafeJobDirectoryEntry(path));
            }
            let Some(id) = parse_job_filename(&name) else {
                return Err(JobError::UnsafeJobDirectoryEntry(path));
            };
            if !file_type.is_file() {
                return Err(JobError::UnsafeJobDirectoryEntry(path));
            }
            ids.push(id);
        }
        ids.sort_unstable();
        ids.into_iter()
            .map(|id| self.read_record_locked(id))
            .collect()
    }

    fn read_record_locked(&self, id: JobId) -> Result<JobRecord, JobError> {
        let path = self.job_path(id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(JobError::NotFound(id))
            }
            Err(error) => return Err(error.into()),
        };
        let length = usize::try_from(metadata.len()).ok();
        if !metadata.file_type().is_file()
            || length.map_or(true, |value| value > MAX_JOB_RECORD_LEN)
        {
            return Err(JobError::UnsafeJobDirectoryEntry(path));
        }
        let bytes = fs::read(&path)?;
        let record = decode_job_record(&bytes)?;
        if record.id != id {
            return Err(JobError::InvalidRecord(
                "record identifier does not match filename",
            ));
        }
        Ok(record)
    }

    fn write_record_locked(&self, record: &JobRecord) -> Result<(), JobError> {
        let bytes = encode_job_record(record)?;
        let destination = self.job_path(record.id);
        let mut last_collision = None;
        for _ in 0..32 {
            let candidate = self.temporary_path(record.id);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&candidate)
            {
                Ok(mut file) => {
                    let result = (|| {
                        file.write_all(&bytes)?;
                        file.sync_all()?;
                        drop(file);
                        fs::rename(&candidate, &destination)?;
                        sync_directory(&self.jobs_dir)?;
                        Ok::<(), io::Error>(())
                    })();
                    if let Err(error) = result {
                        let _ = fs::remove_file(&candidate);
                        return Err(error.into());
                    }
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    last_collision = Some(error)
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(last_collision
            .unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::AlreadyExists, "temporary job file exists")
            })
            .into())
    }

    fn remove_stale_temporaries_locked(&self) -> Result<(), JobError> {
        let mut removed = false;
        for entry in fs::read_dir(&self.jobs_dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| JobError::UnsafeJobDirectoryEntry(path.clone()))?;
            if !is_temporary_name(&name) {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(JobError::UnsafeJobDirectoryEntry(path));
            }
            fs::remove_file(path)?;
            removed = true;
        }
        if removed {
            sync_directory(&self.jobs_dir)?;
        }
        Ok(())
    }

    fn job_path(&self, id: JobId) -> PathBuf {
        self.jobs_dir.join(format!("{id}.job"))
    }

    fn temporary_path(&self, id: JobId) -> PathBuf {
        let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
        self.jobs_dir.join(format!(
            "{JOB_TEMP_PREFIX}{id}-{nonce:016x}{JOB_TEMP_SUFFIX}"
        ))
    }
}

/// Catalog-v1 `jobs` column-family journal for durable daemon job snapshots.
///
/// The filesystem [`JobStore`] remains API-compatible and owns its own atomic
/// record replacement. This journal is the catalog's authoritative durable
/// mirror/persistence hook: its mutation helpers write the filesystem record
/// first, then synchronously publish the complete versioned snapshot under the
/// opaque [`JobId`]. These are deliberately not a cross-store transaction. If
/// catalog publication fails, the filesystem mutation remains durable and a
/// caller must retry [`Self::mirror_record`] or [`Self::mirror_store`].
pub struct CatalogJobJournal<'a, C: Catalog> {
    catalog: &'a mut C,
}

impl<'a, C: Catalog> CatalogJobJournal<'a, C> {
    pub fn new(catalog: &'a mut C) -> Self {
        Self { catalog }
    }

    /// Writes one complete, validated snapshot through the catalog's atomic
    /// batch interface. The inner job encoding is explicitly versioned; the
    /// catalog independently wraps its opaque value in its catalog-v1 format.
    pub fn mirror_record(&mut self, record: &JobRecord) -> Result<(), CatalogJobJournalError> {
        let snapshot = encode_job_record(record)?;
        let mut batch = CatalogBatch::new();
        batch.put_job(record.id.as_bytes(), snapshot);
        self.catalog.apply(batch)?;
        Ok(())
    }

    /// Mirrors every visible filesystem job. This is suitable for startup
    /// reconciliation after [`JobStore::open_with_recovery`] requeues work.
    pub fn mirror_store(&mut self, store: &JobStore) -> Result<usize, CatalogJobJournalError> {
        let records = store.list()?;
        for record in &records {
            self.mirror_record(record)?;
        }
        Ok(records.len())
    }

    /// Reads and fully validates one catalog snapshot. Missing, corrupt,
    /// unknown-version, or key/record-ID mismatched values are never exposed
    /// as a usable job record.
    pub fn read_snapshot(&self, id: JobId) -> Result<JobRecord, CatalogJobJournalError> {
        let snapshot = self
            .catalog
            .job(id.as_bytes())
            .ok_or(CatalogJobJournalError::MissingSnapshot(id))?;
        let record = decode_job_record(&snapshot)?;
        if record.id != id {
            return Err(CatalogJobJournalError::SnapshotIdMismatch {
                key: id,
                record: record.id,
            });
        }
        Ok(record)
    }

    /// Persists a newly enqueued job into the catalog only after the local
    /// record has been atomically published.
    pub fn enqueue(
        &mut self,
        store: &JobStore,
        kind: impl AsRef<[u8]>,
        payload: impl AsRef<[u8]>,
    ) -> Result<JobRecord, CatalogJobJournalError> {
        let record = store.enqueue(kind, payload)?;
        self.mirror_record(&record)?;
        Ok(record)
    }

    /// Equivalent to [`Self::enqueue`] with a higher-level caller-owned job
    /// identity.
    pub fn enqueue_with_id(
        &mut self,
        store: &JobStore,
        id: JobId,
        kind: impl AsRef<[u8]>,
        payload: impl AsRef<[u8]>,
    ) -> Result<JobRecord, CatalogJobJournalError> {
        let record = store.enqueue_with_id(id, kind, payload)?;
        self.mirror_record(&record)?;
        Ok(record)
    }

    pub fn start(
        &mut self,
        store: &JobStore,
        id: JobId,
    ) -> Result<JobRecord, CatalogJobJournalError> {
        let record = store.start(id)?;
        self.mirror_record(&record)?;
        Ok(record)
    }

    pub fn succeed(
        &mut self,
        store: &JobStore,
        id: JobId,
    ) -> Result<JobRecord, CatalogJobJournalError> {
        let record = store.succeed(id)?;
        self.mirror_record(&record)?;
        Ok(record)
    }

    pub fn fail(
        &mut self,
        store: &JobStore,
        id: JobId,
        error: impl AsRef<[u8]>,
    ) -> Result<JobRecord, CatalogJobJournalError> {
        let record = store.fail(id, error)?;
        self.mirror_record(&record)?;
        Ok(record)
    }

    pub fn retry(
        &mut self,
        store: &JobStore,
        id: JobId,
    ) -> Result<JobRecord, CatalogJobJournalError> {
        let record = store.retry(id)?;
        self.mirror_record(&record)?;
        Ok(record)
    }
}

#[derive(Debug)]
pub enum CatalogJobJournalError {
    Job(JobError),
    Catalog(CatalogError),
    MissingSnapshot(JobId),
    SnapshotIdMismatch { key: JobId, record: JobId },
}

impl std::fmt::Display for CatalogJobJournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Job(error) => write!(formatter, "catalog job snapshot is invalid: {error}"),
            Self::Catalog(error) => write!(formatter, "catalog job publication failed: {error:?}"),
            Self::MissingSnapshot(id) => write!(formatter, "catalog has no job snapshot for {id}"),
            Self::SnapshotIdMismatch { key, record } => write!(
                formatter,
                "catalog job snapshot key {key} contains record {record}"
            ),
        }
    }
}
impl std::error::Error for CatalogJobJournalError {}
impl From<JobError> for CatalogJobJournalError {
    fn from(value: JobError) -> Self {
        Self::Job(value)
    }
}
impl From<CatalogError> for CatalogJobJournalError {
    fn from(value: CatalogError) -> Self {
        Self::Catalog(value)
    }
}

fn require_transition(
    record: &JobRecord,
    expected: JobState,
    target: JobState,
) -> Result<(), JobError> {
    if record.state == expected {
        Ok(())
    } else {
        Err(JobError::InvalidTransition {
            id: record.id,
            from: record.state,
            to: target,
        })
    }
}

fn lock_unpoisoned(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(parent) => sync_directory(parent),
        None => Ok(()),
    }
}

fn parse_job_filename(name: &str) -> Option<JobId> {
    name.strip_suffix(".job").and_then(JobId::parse_hex)
}

fn is_temporary_name(name: &str) -> bool {
    name.starts_with(JOB_TEMP_PREFIX) && name.ends_with(JOB_TEMP_SUFFIX)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_job_record(record: &JobRecord) -> Result<Vec<u8>, JobError> {
    record.validate()?;
    let kind_len = u32::try_from(record.kind.len())
        .map_err(|_| JobError::InvalidRecord("job kind length overflows format"))?;
    let payload_len = u64::try_from(record.payload.len())
        .map_err(|_| JobError::InvalidRecord("job payload length overflows format"))?;
    let error = record.last_error.as_deref().unwrap_or_default();
    let error_len = u32::try_from(error.len())
        .map_err(|_| JobError::InvalidRecord("job error length overflows format"))?;
    let total = JOB_HEADER_LEN
        .checked_add(record.kind.len())
        .and_then(|length| length.checked_add(record.payload.len()))
        .and_then(|length| length.checked_add(error.len()))
        .and_then(|length| length.checked_add(JOB_TRAILER_LEN))
        .filter(|length| *length <= MAX_JOB_RECORD_LEN)
        .ok_or(JobError::InvalidRecord("job record length is invalid"))?;
    let mut bytes = vec![0_u8; total];
    bytes[0] = JOB_RECORD_VERSION;
    bytes[1] = record.state as u8;
    bytes[2..10].copy_from_slice(&JOB_RECORD_MAGIC);
    bytes[10..26].copy_from_slice(record.id.as_bytes());
    put_u32(&mut bytes, 26, record.attempts);
    put_u32(&mut bytes, 30, kind_len);
    put_u64(&mut bytes, 34, payload_len);
    put_u32(&mut bytes, 42, error_len);
    let header_crc = crc32c(&bytes[..46]);
    put_u32(&mut bytes, 46, header_crc);
    let mut offset = JOB_HEADER_LEN;
    bytes[offset..offset + record.kind.len()].copy_from_slice(&record.kind);
    offset += record.kind.len();
    bytes[offset..offset + record.payload.len()].copy_from_slice(&record.payload);
    offset += record.payload.len();
    bytes[offset..offset + error.len()].copy_from_slice(error);
    offset += error.len();
    let body_crc = crc32c(&bytes[JOB_HEADER_LEN..offset]);
    put_u32(&mut bytes, offset, body_crc);
    Ok(bytes)
}

fn decode_job_record(bytes: &[u8]) -> Result<JobRecord, JobError> {
    if bytes.len() < JOB_HEADER_LEN + JOB_TRAILER_LEN {
        return Err(JobError::InvalidRecord("job record is truncated"));
    }
    if bytes.len() > MAX_JOB_RECORD_LEN {
        return Err(JobError::InvalidRecord("job record exceeds size limit"));
    }
    if bytes[0] != JOB_RECORD_VERSION {
        return Err(JobError::UnsupportedVersion(bytes[0]));
    }
    if bytes[2..10] != JOB_RECORD_MAGIC {
        return Err(JobError::InvalidRecord("job record magic is invalid"));
    }
    if read_u32(bytes, 46) != crc32c(&bytes[..46]) {
        return Err(JobError::InvalidRecord(
            "job record header checksum mismatch",
        ));
    }
    let state = JobState::from_tag(bytes[1])
        .ok_or(JobError::InvalidRecord("job record state is invalid"))?;
    let kind_len = usize::try_from(read_u32(bytes, 30))
        .map_err(|_| JobError::InvalidRecord("job kind length overflows"))?;
    let payload_len = usize::try_from(read_u64(bytes, 34))
        .map_err(|_| JobError::InvalidRecord("job payload length overflows"))?;
    let error_len = usize::try_from(read_u32(bytes, 42))
        .map_err(|_| JobError::InvalidRecord("job error length overflows"))?;
    let body_len = kind_len
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(error_len))
        .ok_or(JobError::InvalidRecord("job field lengths overflow"))?;
    let expected_len = JOB_HEADER_LEN
        .checked_add(body_len)
        .and_then(|length| length.checked_add(JOB_TRAILER_LEN))
        .ok_or(JobError::InvalidRecord("job record length overflows"))?;
    if bytes.len() != expected_len {
        return Err(JobError::InvalidRecord(
            "job record length does not match header",
        ));
    }
    let trailer_offset = bytes.len() - JOB_TRAILER_LEN;
    if read_u32(bytes, trailer_offset) != crc32c(&bytes[JOB_HEADER_LEN..trailer_offset]) {
        return Err(JobError::InvalidRecord("job record body checksum mismatch"));
    }
    let mut offset = JOB_HEADER_LEN;
    let kind = bytes[offset..offset + kind_len].to_vec();
    offset += kind_len;
    let payload = bytes[offset..offset + payload_len].to_vec();
    offset += payload_len;
    let last_error = match error_len {
        0 => None,
        _ => Some(bytes[offset..offset + error_len].to_vec()),
    };
    let record = JobRecord {
        id: JobId::from_bytes(
            bytes[10..26]
                .try_into()
                .expect("fixed job identifier length"),
        ),
        kind,
        payload,
        state,
        attempts: read_u32(bytes, 26),
        last_error,
    };
    record.validate()?;
    Ok(record)
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounds checked"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounds checked"),
    )
}

const LOCK_EX: std::ffi::c_int = 2;
const LOCK_NB: std::ffi::c_int = 4;
const LOCK_UN: std::ffi::c_int = 8;
const SOL_SOCKET: std::ffi::c_int = 1;
const SO_PEERCRED: std::ffi::c_int = 17;
const MAX_SOCKET_REQUEST_LEN: usize = 16 * 1024;
#[repr(C)]
struct UCred {
    pid: i32,
    uid: u32,
    gid: u32,
}
unsafe extern "C" {
    fn flock(fd: std::ffi::c_int, operation: std::ffi::c_int) -> std::ffi::c_int;
    fn getsockopt(
        fd: std::ffi::c_int,
        level: std::ffi::c_int,
        option_name: std::ffi::c_int,
        option_value: *mut std::ffi::c_void,
        option_len: *mut u32,
    ) -> std::ffi::c_int;
    fn getuid() -> u32;
}

#[derive(Debug)]
pub enum DaemonError {
    Io(io::Error),
    AlreadyRunning,
    UnauthorizedPeer,
    InvalidSocketPath,
}
impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "daemon I/O error: {error}"),
            Self::AlreadyRunning => write!(f, "daemon instance is already running"),
            Self::UnauthorizedPeer => write!(f, "socket peer has a different Unix UID"),
            Self::InvalidSocketPath => write!(f, "refusing to remove non-socket runtime path"),
        }
    }
}
impl std::error::Error for DaemonError {}
impl From<io::Error> for DaemonError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Typed local-daemon directory configuration. The runtime and durable state
/// roots are intentionally separate: deleting a stale socket must never be
/// able to affect authoritative job records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    runtime_dir: PathBuf,
    state_root: PathBuf,
}

impl DaemonConfig {
    pub fn new(runtime_dir: impl AsRef<Path>, state_root: impl AsRef<Path>) -> Self {
        Self {
            runtime_dir: runtime_dir.as_ref().to_path_buf(),
            state_root: state_root.as_ref().to_path_buf(),
        }
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// Validates already-created directories without changing their modes.
    pub fn validate(&self) -> Result<(), DaemonConfigError> {
        validate_owned_private_directory(&self.runtime_dir)?;
        validate_owned_private_directory(&self.state_root)?;
        Ok(())
    }

    /// Creates missing daemon roots with mode 0700, then validates ownership,
    /// type, and permissions before use.
    pub fn prepare(&self) -> Result<(), DaemonConfigError> {
        create_owned_private_directory(&self.runtime_dir)?;
        create_owned_private_directory(&self.state_root)?;
        self.validate()
    }
}

#[derive(Debug)]
pub enum DaemonConfigError {
    Io(io::Error),
    MissingDirectory(PathBuf),
    SymlinkDirectory(PathBuf),
    NotDirectory(PathBuf),
    WrongOwner {
        path: PathBuf,
        expected_uid: u32,
        actual_uid: u32,
    },
    UnsafePermissions {
        path: PathBuf,
        mode: u32,
    },
}

impl std::fmt::Display for DaemonConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "daemon configuration I/O error: {error}"),
            Self::MissingDirectory(path) => {
                write!(formatter, "daemon directory is missing: {}", path.display())
            }
            Self::SymlinkDirectory(path) => {
                write!(
                    formatter,
                    "daemon directory may not be a symlink: {}",
                    path.display()
                )
            }
            Self::NotDirectory(path) => {
                write!(
                    formatter,
                    "daemon path is not a directory: {}",
                    path.display()
                )
            }
            Self::WrongOwner {
                path,
                expected_uid,
                actual_uid,
            } => write!(
                formatter,
                "daemon directory {} belongs to uid {actual_uid}, expected uid {expected_uid}",
                path.display()
            ),
            Self::UnsafePermissions { path, mode } => write!(
                formatter,
                "daemon directory {} has unsafe mode {:o}",
                path.display(),
                mode & 0o777
            ),
        }
    }
}
impl std::error::Error for DaemonConfigError {}
impl From<io::Error> for DaemonConfigError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

fn create_owned_private_directory(path: &Path) -> Result<(), DaemonConfigError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Err(error) => return Err(error.into()),
    }
    validate_owned_private_directory(path)
}

fn validate_owned_private_directory(path: &Path) -> Result<(), DaemonConfigError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(DaemonConfigError::MissingDirectory(path.to_path_buf()))
        }
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(DaemonConfigError::SymlinkDirectory(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(DaemonConfigError::NotDirectory(path.to_path_buf()));
    }
    let expected_uid = current_uid();
    let actual_uid = metadata.uid();
    if actual_uid != expected_uid {
        return Err(DaemonConfigError::WrongOwner {
            path: path.to_path_buf(),
            expected_uid,
            actual_uid,
        });
    }
    let mode = metadata.mode();
    if mode & 0o077 != 0 || mode & 0o700 != 0o700 {
        return Err(DaemonConfigError::UnsafePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct InstanceLock {
    file: File,
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        unsafe {
            flock(self.file.as_raw_fd(), LOCK_UN);
        }
    }
}
pub fn acquire_lock(path: impl AsRef<Path>) -> Result<InstanceLock, DaemonError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(DaemonError::AlreadyRunning);
        }
        return Err(error.into());
    }
    Ok(InstanceLock { file })
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { getuid() }
}

/// A parsed local control command. Commands are deliberately limited to
/// durable job state transitions; no Git, mount, or workspace side effect can
/// be reached through this protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonCommand {
    Status,
    Enqueue { kind: Vec<u8>, payload: Vec<u8> },
    Get { id: JobId },
    Start { id: JobId },
    Succeed { id: JobId },
    Fail { id: JobId, error: Vec<u8> },
    Retry { id: JobId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonCommandParseError {
    Invalid,
    Unsupported,
}

impl std::fmt::Display for DaemonCommandParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(formatter, "invalid daemon command"),
            Self::Unsupported => write!(formatter, "unsupported daemon command"),
        }
    }
}
impl std::error::Error for DaemonCommandParseError {}

/// Parses the strict, one-line local socket protocol. Byte fields use lower
/// case hexadecimal so requests remain line-safe without treating job paths
/// or names as UTF-8.
pub fn parse_daemon_command(request: &str) -> Result<DaemonCommand, DaemonCommandParseError> {
    if request.is_empty()
        || request
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r' | b'\t'))
    {
        return Err(DaemonCommandParseError::Invalid);
    }
    let fields: Vec<_> = request.split(' ').collect();
    if fields.iter().any(|field| field.is_empty()) {
        return Err(DaemonCommandParseError::Invalid);
    }
    match fields.as_slice() {
        ["status"] => Ok(DaemonCommand::Status),
        ["job", "enqueue", kind, payload] => Ok(DaemonCommand::Enqueue {
            kind: parse_hex_bytes(kind, false)?,
            payload: parse_hex_bytes(payload, true)?,
        }),
        ["job", "get", id] => Ok(DaemonCommand::Get {
            id: parse_command_job_id(id)?,
        }),
        ["job", "start", id] => Ok(DaemonCommand::Start {
            id: parse_command_job_id(id)?,
        }),
        ["job", "succeed", id] => Ok(DaemonCommand::Succeed {
            id: parse_command_job_id(id)?,
        }),
        ["job", "fail", id, error] => Ok(DaemonCommand::Fail {
            id: parse_command_job_id(id)?,
            error: parse_hex_bytes(error, false)?,
        }),
        ["job", "retry", id] => Ok(DaemonCommand::Retry {
            id: parse_command_job_id(id)?,
        }),
        ["job", ..] => Err(DaemonCommandParseError::Unsupported),
        _ => Err(DaemonCommandParseError::Unsupported),
    }
}

fn parse_command_job_id(value: &str) -> Result<JobId, DaemonCommandParseError> {
    JobId::parse_hex(value).ok_or(DaemonCommandParseError::Invalid)
}

fn parse_hex_bytes(value: &str, allow_empty: bool) -> Result<Vec<u8>, DaemonCommandParseError> {
    if (!allow_empty && value.is_empty()) || value.len() % 2 != 0 {
        return Err(DaemonCommandParseError::Invalid);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or(DaemonCommandParseError::Invalid)?;
        let low = hex_nibble(pair[1]).ok_or(DaemonCommandParseError::Invalid)?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobStateCounts {
    pub queued: u64,
    pub running: u64,
    pub succeeded: u64,
    pub failed: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DaemonMetricsSnapshot {
    pub jobs: JobStateCounts,
    pub recovered_on_startup: u64,
    pub accepted_requests: u64,
    pub rejected_requests: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonStatus {
    pub runtime_dir: PathBuf,
    pub state_root: PathBuf,
    pub socket_path: PathBuf,
    pub metrics: DaemonMetricsSnapshot,
}

#[derive(Debug)]
pub enum DaemonServiceError {
    Config(DaemonConfigError),
    Daemon(DaemonError),
    Job(JobError),
    StoreAlreadyInUse(PathBuf),
}

impl std::fmt::Display for DaemonServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "daemon configuration failed: {error}"),
            Self::Daemon(error) => write!(formatter, "daemon startup failed: {error}"),
            Self::Job(error) => write!(formatter, "daemon job recovery failed: {error}"),
            Self::StoreAlreadyInUse(path) => write!(
                formatter,
                "daemon state root is already owned by another instance: {}",
                path.display()
            ),
        }
    }
}
impl std::error::Error for DaemonServiceError {}
impl From<DaemonConfigError> for DaemonServiceError {
    fn from(value: DaemonConfigError) -> Self {
        Self::Config(value)
    }
}
impl From<DaemonError> for DaemonServiceError {
    fn from(value: DaemonError) -> Self {
        Self::Daemon(value)
    }
}
impl From<JobError> for DaemonServiceError {
    fn from(value: JobError) -> Self {
        Self::Job(value)
    }
}

pub struct Daemon {
    listener: UnixListener,
    _lock: InstanceLock,
    socket: PathBuf,
}
impl Daemon {
    pub fn bind(runtime_dir: impl AsRef<Path>) -> Result<Self, DaemonError> {
        let runtime_dir = runtime_dir.as_ref();
        fs::create_dir_all(runtime_dir)?;
        fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o700))?;
        let lock = acquire_lock(runtime_dir.join("daemon.lock"))?;
        let socket = runtime_dir.join("daemon.sock");
        if socket.exists() {
            if !fs::symlink_metadata(&socket)?.file_type().is_socket() {
                return Err(DaemonError::InvalidSocketPath);
            }
            fs::remove_file(&socket)?;
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            listener,
            _lock: lock,
            socket,
        })
    }
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Handles one line-oriented diagnostic request. Protocol commands are
    /// deliberately small until an authenticated typed protocol replaces it.
    pub fn serve_one(&self) -> Result<(), DaemonError> {
        self.serve_one_with(|request| match request {
            "status" => "ok\n".to_owned(),
            _ => "error unsupported-request\n".to_owned(),
        })
    }

    fn serve_one_with<F>(&self, handler: F) -> Result<(), DaemonError>
    where
        F: FnOnce(&str) -> String,
    {
        let (stream, _) = self.listener.accept()?;
        ensure_same_uid(&stream)?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request = Vec::new();
        reader
            .by_ref()
            .take((MAX_SOCKET_REQUEST_LEN + 1) as u64)
            .read_until(b'\n', &mut request)?;
        let mut stream = stream;
        let response = match request.strip_suffix(b"\n") {
            Some(line)
                if line.len() <= MAX_SOCKET_REQUEST_LEN
                    && !line.contains(&b'\n')
                    && !line.contains(&b'\r') =>
            {
                match std::str::from_utf8(line) {
                    Ok(request) => handler(request),
                    Err(_) => "error invalid-request\n".to_owned(),
                }
            }
            _ => "error invalid-request\n".to_owned(),
        };
        stream.write_all(response.as_bytes())?;
        stream.flush()?;
        Ok(())
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
    }
}
fn ensure_same_uid(stream: &UnixStream) -> Result<(), DaemonError> {
    let mut credential = UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<UCred>() as u32;
    if unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credential as *mut UCred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if length != std::mem::size_of::<UCred>() as u32 || credential.uid != current_uid() {
        return Err(DaemonError::UnauthorizedPeer);
    }
    Ok(())
}

/// Owns a verified state root, durable job queue, and local control socket.
/// Startup takes the state-root lock and completes job recovery before the
/// listener is bound, so no request can observe unreconciled work.
pub struct DaemonService {
    config: DaemonConfig,
    daemon: Daemon,
    jobs: JobStore,
    _store_lock: InstanceLock,
    recovered_on_startup: u64,
    accepted_requests: AtomicU64,
    rejected_requests: AtomicU64,
}

impl DaemonService {
    pub fn start(config: DaemonConfig) -> Result<Self, DaemonServiceError> {
        config.prepare()?;
        let lock_path = config.state_root.join("instance.lock");
        let store_lock = match acquire_lock(&lock_path) {
            Ok(lock) => lock,
            Err(DaemonError::AlreadyRunning) => {
                return Err(DaemonServiceError::StoreAlreadyInUse(
                    config.state_root.clone(),
                ))
            }
            Err(error) => return Err(error.into()),
        };
        let (jobs, recovered) = JobStore::open_with_recovery(&config.state_root)?;
        let daemon = Daemon::bind(&config.runtime_dir)?;
        Ok(Self {
            config,
            daemon,
            jobs,
            _store_lock: store_lock,
            recovered_on_startup: recovered as u64,
            accepted_requests: AtomicU64::new(0),
            rejected_requests: AtomicU64::new(0),
        })
    }

    pub fn socket_path(&self) -> &Path {
        self.daemon.socket_path()
    }

    pub fn job_store(&self) -> &JobStore {
        &self.jobs
    }

    pub fn status(&self) -> Result<DaemonStatus, DaemonServiceError> {
        Ok(DaemonStatus {
            runtime_dir: self.config.runtime_dir.clone(),
            state_root: self.config.state_root.clone(),
            socket_path: self.socket_path().to_path_buf(),
            metrics: self.metrics_snapshot()?,
        })
    }

    pub fn metrics_snapshot(&self) -> Result<DaemonMetricsSnapshot, DaemonServiceError> {
        let mut jobs = JobStateCounts::default();
        for record in self.jobs.list()? {
            match record.state {
                JobState::Queued => jobs.queued += 1,
                JobState::Running => jobs.running += 1,
                JobState::Succeeded => jobs.succeeded += 1,
                JobState::Failed => jobs.failed += 1,
            }
        }
        Ok(DaemonMetricsSnapshot {
            jobs,
            recovered_on_startup: self.recovered_on_startup,
            accepted_requests: self.accepted_requests.load(Ordering::Relaxed),
            rejected_requests: self.rejected_requests.load(Ordering::Relaxed),
        })
    }

    /// Serves exactly one same-UID local control request.
    pub fn serve_one(&self) -> Result<(), DaemonError> {
        self.daemon
            .serve_one_with(|request| self.handle_socket_command(request))
    }

    fn handle_socket_command(&self, request: &str) -> String {
        match parse_daemon_command(request) {
            Ok(command) => match self.execute(command) {
                Ok(response) => {
                    self.accepted_requests.fetch_add(1, Ordering::Relaxed);
                    response
                }
                Err(error) => {
                    self.rejected_requests.fetch_add(1, Ordering::Relaxed);
                    job_error_response(&error)
                }
            },
            Err(DaemonCommandParseError::Unsupported) => {
                self.rejected_requests.fetch_add(1, Ordering::Relaxed);
                "error unsupported-request\n".to_owned()
            }
            Err(DaemonCommandParseError::Invalid) => {
                self.rejected_requests.fetch_add(1, Ordering::Relaxed);
                "error invalid-request\n".to_owned()
            }
        }
    }

    fn execute(&self, command: DaemonCommand) -> Result<String, JobError> {
        match command {
            DaemonCommand::Status => {
                let snapshot = self.metrics_snapshot().map_err(|error| match error {
                    DaemonServiceError::Job(error) => error,
                    _ => JobError::InvalidRecord("daemon metrics are unavailable"),
                })?;
                Ok(format!(
                    "ok status queued={} running={} succeeded={} failed={} recovered={} accepted={} rejected={}\n",
                    snapshot.jobs.queued,
                    snapshot.jobs.running,
                    snapshot.jobs.succeeded,
                    snapshot.jobs.failed,
                    snapshot.recovered_on_startup,
                    snapshot.accepted_requests,
                    snapshot.rejected_requests,
                ))
            }
            DaemonCommand::Enqueue { kind, payload } => {
                self.jobs.enqueue(kind, payload).map(render_job_response)
            }
            DaemonCommand::Get { id } => self.jobs.get(id).map(render_job_response),
            DaemonCommand::Start { id } => self.jobs.start(id).map(render_job_response),
            DaemonCommand::Succeed { id } => self.jobs.succeed(id).map(render_job_response),
            DaemonCommand::Fail { id, error } => self.jobs.fail(id, error).map(render_job_response),
            DaemonCommand::Retry { id } => self.jobs.retry(id).map(render_job_response),
        }
    }
}

fn render_job_response(record: JobRecord) -> String {
    format!(
        "ok job id={} state={} attempts={}\n",
        record.id,
        job_state_name(record.state),
        record.attempts
    )
}

const fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
    }
}

fn job_error_response(error: &JobError) -> String {
    match error {
        JobError::NotFound(_) => "error job-not-found\n",
        JobError::InvalidTransition { .. } => "error invalid-transition\n",
        JobError::InvalidRecord(_) | JobError::UnsupportedVersion(_) => "error invalid-job\n",
        JobError::Io(_)
        | JobError::AlreadyExists(_)
        | JobError::AttemptOverflow(_)
        | JobError::UnsafeJobDirectoryEntry(_) => "error job-store\n",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflink_forest_index::{Catalog, CatalogBatch, InMemoryCatalog};
    use std::{
        sync::Arc,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };
    fn dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "reflink-forest-daemon-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn service_config(root: &Path) -> DaemonConfig {
        DaemonConfig::new(root.join("runtime"), root.join("state"))
    }

    fn socket_request(socket: &Path, request: &str) -> String {
        let mut client = UnixStream::connect(socket).unwrap();
        client.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        BufReader::new(client).read_line(&mut response).unwrap();
        response
    }
    #[test]
    fn per_user_socket_and_lock_serve_status() {
        let dir = dir();
        let daemon = Daemon::bind(&dir).unwrap();
        assert!(matches!(
            Daemon::bind(&dir),
            Err(DaemonError::AlreadyRunning)
        ));
        let socket = daemon.socket_path().to_path_buf();
        let server = thread::spawn(move || daemon.serve_one().unwrap());
        let mut client = UnixStream::connect(socket).unwrap();
        client.write_all(b"status\n").unwrap();
        let mut result = String::new();
        BufReader::new(client).read_line(&mut result).unwrap();
        assert_eq!(result, "ok\n");
        server.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    fn job_id(value: u8) -> JobId {
        JobId::from_bytes([value; 16])
    }

    #[test]
    fn job_record_is_binary_versioned_and_round_trips() {
        let root = dir();
        let store = JobStore::open(&root).unwrap();
        let id = job_id(0x11);
        let queued = store
            .enqueue_with_id(id, b"import\x00git", b"source\xffpath")
            .unwrap();
        assert_eq!(queued.state, JobState::Queued);
        assert_eq!(store.get(id).unwrap(), queued);

        let path = store.directory().join(format!("{id}.job"));
        let bytes = fs::read(path).unwrap();
        assert_eq!(bytes[0], JOB_RECORD_VERSION);
        assert_eq!(&bytes[2..10], &JOB_RECORD_MAGIC);
        assert_ne!(&bytes[..1], b"{");
        assert_eq!(bytes[10..26], *id.as_bytes());
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_journal_mirrors_durable_job_state_transitions() {
        let root = dir();
        let store = JobStore::open(&root).unwrap();
        let id = job_id(0x12);
        let mut catalog = InMemoryCatalog::default();
        let mut journal = CatalogJobJournal::new(&mut catalog);

        let queued = journal
            .enqueue_with_id(&store, id, b"import", b"source\x00path")
            .unwrap();
        assert_eq!(queued.state, JobState::Queued);
        assert_eq!(journal.read_snapshot(id).unwrap(), queued);

        let running = journal.start(&store, id).unwrap();
        assert_eq!(running.state, JobState::Running);
        assert_eq!(journal.read_snapshot(id).unwrap(), running);

        let failed = journal.fail(&store, id, b"temporary failure").unwrap();
        assert_eq!(failed.state, JobState::Failed);
        assert_eq!(journal.read_snapshot(id).unwrap(), failed);

        let queued_again = journal.retry(&store, id).unwrap();
        assert_eq!(queued_again.state, JobState::Queued);
        assert_eq!(journal.read_snapshot(id).unwrap(), queued_again);
        assert!(catalog.job(id.as_bytes()).is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn catalog_journal_rejects_invalid_or_mismatched_snapshots() {
        let id = job_id(0x13);
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_job(id.as_bytes(), b"not a durable job record");
        catalog.apply(batch).unwrap();
        let journal = CatalogJobJournal::new(&mut catalog);
        assert!(matches!(
            journal.read_snapshot(id),
            Err(CatalogJobJournalError::Job(JobError::InvalidRecord(_)))
        ));
        let other = job_id(0x14);
        let record = JobRecord::queued(other, b"hydrate".to_vec(), b"payload".to_vec());
        let mut batch = CatalogBatch::new();
        batch.put_job(id.as_bytes(), encode_job_record(&record).unwrap());
        catalog.apply(batch).unwrap();
        let journal = CatalogJobJournal::new(&mut catalog);
        assert!(matches!(
            journal.read_snapshot(id),
            Err(CatalogJobJournalError::SnapshotIdMismatch { key, record: found })
                if key == id && found == other
        ));
    }

    #[test]
    fn transitions_are_durable_and_only_legal_edges_are_allowed() {
        let root = dir();
        let store = JobStore::open(&root).unwrap();
        let id = job_id(0x22);
        store.enqueue_with_id(id, b"hydrate", b"payload").unwrap();
        assert!(matches!(
            store.succeed(id),
            Err(JobError::InvalidTransition {
                from: JobState::Queued,
                to: JobState::Succeeded,
                ..
            })
        ));
        let running = store.start(id).unwrap();
        assert_eq!(running.state, JobState::Running);
        assert_eq!(running.attempts, 1);
        let failed = store.fail(id, b"temporary I/O failure").unwrap();
        assert_eq!(failed.state, JobState::Failed);
        assert_eq!(
            failed.last_error.as_deref(),
            Some(&b"temporary I/O failure"[..])
        );
        let queued = store.retry(id).unwrap();
        assert_eq!(queued.state, JobState::Queued);
        assert_eq!(queued.attempts, 1);
        let running = store.start(id).unwrap();
        assert_eq!(running.attempts, 2);
        let succeeded = store.succeed(id).unwrap();
        assert_eq!(succeeded.state, JobState::Succeeded);
        assert_eq!(succeeded.last_error, None);
        assert_eq!(store.get(id).unwrap(), succeeded);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_requeues_interrupted_running_jobs_and_cleans_temp_files() {
        let root = dir();
        let id = job_id(0x33);
        {
            let store = JobStore::open(&root).unwrap();
            store.enqueue_with_id(id, b"checkout", b"payload").unwrap();
            store.start(id).unwrap();
            let temporary = store
                .directory()
                .join(format!("{JOB_TEMP_PREFIX}{id}-deadbeef{JOB_TEMP_SUFFIX}"));
            fs::write(temporary, b"partial state never published").unwrap();
        }

        let recovered = JobStore::open(&root).unwrap();
        let record = recovered.get(id).unwrap();
        assert_eq!(record.state, JobState::Queued);
        assert_eq!(record.attempts, 1);
        assert_eq!(recovered.recover_startup().unwrap(), 0);
        assert_eq!(fs::read_dir(recovered.directory()).unwrap().count(), 1);
        drop(recovered);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_or_unknown_version_job_records_fail_closed() {
        let root = dir();
        let store = JobStore::open(&root).unwrap();
        let id = job_id(0x44);
        store.enqueue_with_id(id, b"import", b"payload").unwrap();
        let path = store.directory().join(format!("{id}.job"));
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] = JOB_RECORD_VERSION + 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            store.get(id),
            Err(JobError::UnsupportedVersion(version)) if version == JOB_RECORD_VERSION + 1
        ));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_claims_have_one_winner() {
        let root = dir();
        let store = Arc::new(JobStore::open(&root).unwrap());
        let id = job_id(0x55);
        store.enqueue_with_id(id, b"compact", b"payload").unwrap();
        let mut workers = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            workers.push(thread::spawn(move || store.start(id).is_ok()));
        }
        let claims = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|claimed| *claimed)
            .count();
        assert_eq!(claims, 1);
        let record = store.get(id).unwrap();
        assert_eq!(record.state, JobState::Running);
        assert_eq!(record.attempts, 1);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_startup_recovers_jobs_and_locks_the_state_root() {
        let root = dir();
        let config = service_config(&root);
        let id;
        {
            let service = DaemonService::start(config.clone()).unwrap();
            assert_eq!(service.status().unwrap().metrics.recovered_on_startup, 0);
            let record = service
                .job_store()
                .enqueue_with_id(job_id(0x66), b"checkout", b"payload")
                .unwrap();
            id = record.id;
            service.job_store().start(id).unwrap();

            let competing = DaemonConfig::new(root.join("other-runtime"), root.join("state"));
            assert!(matches!(
                DaemonService::start(competing),
                Err(DaemonServiceError::StoreAlreadyInUse(_))
            ));
        }

        let restarted = DaemonService::start(config).unwrap();
        let status = restarted.status().unwrap();
        assert_eq!(status.metrics.recovered_on_startup, 1);
        assert_eq!(status.metrics.jobs.queued, 1);
        assert_eq!(
            restarted.job_store().get(id).unwrap().state,
            JobState::Queued
        );
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn typed_socket_commands_are_strict_and_report_structured_status() {
        let root = dir();
        let service = DaemonService::start(service_config(&root)).unwrap();
        let socket = service.socket_path().to_path_buf();
        let server = thread::spawn(move || {
            for _ in 0..4 {
                service.serve_one().unwrap();
            }
            service
        });

        let queued = socket_request(&socket, "job enqueue 696d706f7274 7061796c6f6164\n");
        assert!(queued.starts_with("ok job id="));
        let id = queued
            .split_whitespace()
            .find_map(|field| field.strip_prefix("id="))
            .unwrap();
        let running = socket_request(&socket, &format!("job start {id}\n"));
        assert!(running.contains("state=running"));
        let status = socket_request(&socket, "status\n");
        assert!(status.starts_with("ok status"));
        assert!(status.contains("running=1"));
        assert_eq!(
            socket_request(&socket, "job destroy everything\n"),
            "error unsupported-request\n"
        );

        let service = server.join().unwrap();
        let metrics = service.metrics_snapshot().unwrap();
        assert_eq!(metrics.jobs.running, 1);
        assert_eq!(metrics.accepted_requests, 3);
        assert_eq!(metrics.rejected_requests, 1);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn service_serializes_concurrent_same_uid_clients() {
        let root = dir();
        let service = DaemonService::start(service_config(&root)).unwrap();
        let socket = service.socket_path().to_path_buf();
        let server = thread::spawn(move || {
            for _ in 0..9 {
                service.serve_one().unwrap();
            }
            service
        });
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut clients = Vec::new();
        for _ in 0..8 {
            let socket = socket.clone();
            let barrier = Arc::clone(&barrier);
            clients.push(thread::spawn(move || {
                barrier.wait();
                socket_request(&socket, "job enqueue 68796472617465 7061796c6f6164\n")
            }));
        }
        for client in clients {
            assert!(client.join().unwrap().starts_with("ok job id="));
        }
        let status = socket_request(&socket, "status\n");
        assert!(status.contains("queued=8"));

        let service = server.join().unwrap();
        let metrics = service.metrics_snapshot().unwrap();
        assert_eq!(metrics.jobs.queued, 8);
        assert_eq!(metrics.accepted_requests, 9);
        assert_eq!(metrics.rejected_requests, 0);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn configuration_rejects_public_state_directory() {
        let root = dir();
        let runtime = root.join("runtime");
        let state = root.join("state");
        fs::create_dir_all(&runtime).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        let config = DaemonConfig::new(&runtime, &state);
        assert!(matches!(
            config.validate(),
            Err(DaemonConfigError::UnsafePermissions { path, .. }) if path == state
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
