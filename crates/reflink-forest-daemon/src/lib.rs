//! Per-user Unix-socket daemon foundations.
//!
//! The daemon has one owner per instance and accepts requests only from that
//! Unix UID. It intentionally exposes no mount or ownership-changing action;
//! those remain a fixed-purpose privileged-helper concern.

use reflink_forest_format::crc32c;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
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
        store.recover_startup()?;
        Ok(store)
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
        let (stream, _) = self.listener.accept()?;
        ensure_same_uid(&stream)?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request = String::new();
        reader.read_line(&mut request)?;
        let mut stream = stream;
        match request.trim_end() {
            "status" => stream.write_all(b"ok\n")?,
            _ => stream.write_all(b"error unsupported-request\n")?,
        }
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
    if length != std::mem::size_of::<UCred>() as u32 || credential.uid != unsafe { getuid() } {
        return Err(DaemonError::UnauthorizedPeer);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
