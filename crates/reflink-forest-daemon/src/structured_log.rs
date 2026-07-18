//! Durable, append-only NDJSON operation telemetry.
//!
//! This log is deliberately an observation stream, never an authority for
//! daemon recovery. Durable job, scrub, and migration records remain the
//! source of truth. Each successfully appended line is synchronized before
//! [`StructuredOperationLog::append`] returns, while a partial trailing line
//! after a process or media failure is harmless to consumers that process
//! complete newline-delimited JSON values only.

use crate::{
    JobState, MaintenanceOperationKind, MigrationState, OperationEvent, OperationEventFailure,
    OperationEventOutcome, OperationEventSink, ScrubRunState,
};
use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// Schema tag written at the start of every structured-log line.
pub const STRUCTURED_OPERATION_LOG_VERSION: u8 = 1;
/// Hard upper bound for one complete newline-delimited JSON event.
///
/// Events contain only fixed vocabulary plus opaque 128-bit daemon IDs and
/// integer counters. Keeping the bound explicit makes a future event-field
/// addition fail closed instead of introducing unbounded logging.
pub const MAX_STRUCTURED_OPERATION_EVENT_BYTES: usize = 1024;

/// Failure while opening or appending the derived operation log.
#[derive(Debug)]
pub enum StructuredOperationLogError {
    Io(io::Error),
    UnsafeLogDirectory(PathBuf),
    UnsafeLogFile(PathBuf),
    EventTooLarge { length: usize, maximum: usize },
}

impl std::fmt::Display for StructuredOperationLogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "structured operation log I/O failed: {error}"),
            Self::UnsafeLogDirectory(path) => write!(
                formatter,
                "structured operation log parent is not a real directory: {}",
                path.display()
            ),
            Self::UnsafeLogFile(path) => write!(
                formatter,
                "structured operation log target is not a regular file: {}",
                path.display()
            ),
            Self::EventTooLarge { length, maximum } => write!(
                formatter,
                "structured operation log event is {length} bytes, exceeding the {maximum}-byte bound"
            ),
        }
    }
}

impl std::error::Error for StructuredOperationLogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::UnsafeLogDirectory(_) | Self::UnsafeLogFile(_) | Self::EventTooLarge { .. } => {
                None
            }
        }
    }
}

impl From<io::Error> for StructuredOperationLogError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// An append-only, synchronized NDJSON backend for [`OperationEvent`].
///
/// The parent directory must already exist and be a real directory. This
/// avoids turning logging startup into recursive directory creation and keeps
/// the ownership boundary under the daemon's existing state-root setup.
pub struct StructuredOperationLog {
    path: PathBuf,
    file: File,
    events_written: u64,
}

impl StructuredOperationLog {
    /// Opens an existing log for append or creates a new 0600 log file.
    ///
    /// Existing bytes are never parsed, truncated, renamed, or otherwise
    /// rewritten. A reopen therefore resumes at the end of the same durable
    /// stream after daemon startup or restart.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StructuredOperationLogError> {
        let path = path.as_ref().to_path_buf();
        let parent = log_parent(&path)?;
        match fs::symlink_metadata(parent) {
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                return Err(StructuredOperationLogError::UnsafeLogDirectory(
                    parent.to_path_buf(),
                ));
            }
            Ok(_) => {}
            Err(error) => return Err(StructuredOperationLogError::Io(error)),
        }

        let existed = match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() =>
            {
                return Err(StructuredOperationLogError::UnsafeLogFile(path));
            }
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(StructuredOperationLogError::Io(error)),
        };
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path)?;
        if !existed {
            // Make the new log's inode and directory entry durable before a
            // caller can observe a successfully opened log backend.
            file.sync_all()?;
            File::open(parent)?.sync_all()?;
        }
        Ok(Self {
            path,
            file,
            events_written: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of events successfully appended through this open handle.
    ///
    /// This intentionally does not scan preexisting log data at startup: log
    /// contents are derived telemetry and must not delay or alter recovery.
    pub const fn events_written(&self) -> u64 {
        self.events_written
    }

    /// Encodes, appends, and synchronizes one event.
    pub fn append(&mut self, event: OperationEvent) -> Result<(), StructuredOperationLogError> {
        let encoded = encode_event(event)?;
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.events_written = self.events_written.saturating_add(1);
        Ok(())
    }
}

/// An [`OperationEventSink`] adapter for [`StructuredOperationLog`].
///
/// The trait cannot return an error because telemetry must not change a
/// completed durable operation. Call [`Self::record_event`] where the caller
/// wants the append failure; trait-based emission records failures in a
/// saturating counter and otherwise remains non-authoritative.
pub struct DurableOperationEventSink {
    log: StructuredOperationLog,
    append_failures: u64,
}

impl DurableOperationEventSink {
    pub fn new(log: StructuredOperationLog) -> Self {
        Self {
            log,
            append_failures: 0,
        }
    }

    pub fn log(&self) -> &StructuredOperationLog {
        &self.log
    }

    pub fn log_mut(&mut self) -> &mut StructuredOperationLog {
        &mut self.log
    }

    pub const fn append_failures(&self) -> u64 {
        self.append_failures
    }

    pub fn record_event(
        &mut self,
        event: OperationEvent,
    ) -> Result<(), StructuredOperationLogError> {
        self.log.append(event)
    }

    pub fn into_log(self) -> StructuredOperationLog {
        self.log
    }
}

impl OperationEventSink for DurableOperationEventSink {
    fn record(&mut self, event: OperationEvent) {
        if self.record_event(event).is_err() {
            self.append_failures = self.append_failures.saturating_add(1);
        }
    }
}

fn log_parent(path: &Path) -> Result<&Path, StructuredOperationLogError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(StructuredOperationLogError::UnsafeLogDirectory(
            PathBuf::new(),
        ));
    };
    Ok(parent)
}

fn encode_event(event: OperationEvent) -> Result<Vec<u8>, StructuredOperationLogError> {
    let mut output = String::with_capacity(384);
    write!(output, "{{\"version\":{STRUCTURED_OPERATION_LOG_VERSION}")
        .expect("writing to a string cannot fail");
    match event {
        OperationEvent::Job { job, outcome } => {
            output.push_str(",\"event\":\"job\",\"outcome\":\"");
            output.push_str(outcome_name(outcome));
            output.push_str("\",\"job\":");
            append_job_metadata(&mut output, job);
        }
        OperationEvent::Maintenance { job, kind, outcome } => {
            output.push_str(",\"event\":\"maintenance\",\"outcome\":\"");
            output.push_str(outcome_name(outcome));
            output.push_str("\",\"kind\":\"");
            output.push_str(maintenance_kind_name(kind));
            output.push_str("\",\"job\":");
            append_job_metadata(&mut output, job);
        }
        OperationEvent::Scrub { schedule, outcome } => {
            output.push_str(",\"event\":\"scrub\",\"outcome\":\"");
            output.push_str(outcome_name(outcome));
            output.push_str("\",\"schedule\":");
            match schedule {
                None => output.push_str("null"),
                Some(schedule) => {
                    write!(
                        output,
                        "{{\"interval_seconds\":{},\"next_due_unix_seconds\":{},\"run_state\":\"{}\",\"consecutive_failures\":{},\"recovered_interrupted_runs\":{}}}",
                        schedule.interval_seconds,
                        schedule.next_due_unix_seconds,
                        scrub_run_state_name(schedule.run_state),
                        schedule.consecutive_failures,
                        schedule.recovered_interrupted_runs,
                    )
                    .expect("writing to a string cannot fail");
                }
            }
        }
        OperationEvent::Migration { migration, outcome } => {
            output.push_str(",\"event\":\"migration\",\"outcome\":\"");
            output.push_str(outcome_name(outcome));
            output.push_str("\",\"migration\":");
            match migration {
                None => output.push_str("null"),
                Some(migration) => {
                    write!(
                        output,
                        "{{\"id\":\"{}\",\"from_format_version\":{},\"to_format_version\":{},\"state\":\"{}\",\"transition_count\":{}}}",
                        migration.id,
                        migration.from_format_version,
                        migration.to_format_version,
                        migration_state_name(migration.state),
                        migration.transition_count,
                    )
                    .expect("writing to a string cannot fail");
                }
            }
        }
    }
    output.push_str("}\n");
    let bytes = output.into_bytes();
    if bytes.len() > MAX_STRUCTURED_OPERATION_EVENT_BYTES {
        return Err(StructuredOperationLogError::EventTooLarge {
            length: bytes.len(),
            maximum: MAX_STRUCTURED_OPERATION_EVENT_BYTES,
        });
    }
    Ok(bytes)
}

fn append_job_metadata(output: &mut String, job: Option<crate::OperationJobMetadata>) {
    match job {
        None => output.push_str("null"),
        Some(job) => {
            write!(
                output,
                "{{\"id\":\"{}\",\"state\":\"{}\",\"attempts\":{}}}",
                job.id,
                job_state_name(job.state),
                job.attempts,
            )
            .expect("writing to a string cannot fail");
        }
    }
}

fn outcome_name(outcome: OperationEventOutcome) -> &'static str {
    match outcome {
        OperationEventOutcome::Idle => "idle",
        OperationEventOutcome::Succeeded => "succeeded",
        OperationEventOutcome::Failed(OperationEventFailure::HandlerError) => "handler_error",
        OperationEventOutcome::Failed(OperationEventFailure::HandlerPanic) => "handler_panic",
        OperationEventOutcome::PersistenceFailure => "persistence_failure",
    }
}

fn job_state_name(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Succeeded => "succeeded",
        JobState::Failed => "failed",
    }
}

fn maintenance_kind_name(kind: MaintenanceOperationKind) -> &'static str {
    match kind {
        MaintenanceOperationKind::CacheReconcile => "cache_reconcile",
        MaintenanceOperationKind::CacheEvict => "cache_evict",
        MaintenanceOperationKind::VerifyColdChunk => "verify_cold_chunk",
        MaintenanceOperationKind::Unsupported => "unsupported",
    }
}

fn scrub_run_state_name(state: ScrubRunState) -> &'static str {
    match state {
        ScrubRunState::Idle => "idle",
        ScrubRunState::Running => "running",
    }
}

fn migration_state_name(state: MigrationState) -> &'static str {
    match state {
        MigrationState::NotStarted => "not_started",
        MigrationState::Copying => "copying",
        MigrationState::Validating => "validating",
        MigrationState::Published => "published",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JobId, MigrationId, MigrationOperationMetadata, ScrubOperationMetadata};
    use std::{
        fs,
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEMPORARY_ID: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory(label: &str) -> PathBuf {
        let unique = NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "reflink-forest-structured-log-{label}-{}-{nanos}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create temporary test directory");
        directory
    }

    fn job_event() -> OperationEvent {
        OperationEvent::Job {
            job: Some(crate::OperationJobMetadata {
                id: JobId::from_bytes([0x1a; 16]),
                state: JobState::Failed,
                attempts: 7,
            }),
            outcome: OperationEventOutcome::Failed(OperationEventFailure::HandlerError),
        }
    }

    #[test]
    fn appends_bounded_safe_ndjson_without_client_payloads() {
        let root = temporary_directory("safe-fields");
        let path = root.join("operations.ndjson");
        let mut log = StructuredOperationLog::open(&path).expect("open log");
        log.append(job_event()).expect("append event");
        log.append(OperationEvent::Maintenance {
            job: None,
            kind: MaintenanceOperationKind::Unsupported,
            outcome: OperationEventOutcome::PersistenceFailure,
        })
        .expect("append maintenance event");
        log.append(OperationEvent::Scrub {
            schedule: Some(ScrubOperationMetadata {
                interval_seconds: 86_400,
                next_due_unix_seconds: 1_700_000_000,
                run_state: ScrubRunState::Running,
                consecutive_failures: 2,
                recovered_interrupted_runs: 3,
            }),
            outcome: OperationEventOutcome::Idle,
        })
        .expect("append scrub event");
        log.append(OperationEvent::Migration {
            migration: Some(MigrationOperationMetadata {
                id: MigrationId::from_bytes([0x2b; 16]),
                from_format_version: 1,
                to_format_version: 2,
                state: MigrationState::Validating,
                transition_count: 9,
            }),
            outcome: OperationEventOutcome::Succeeded,
        })
        .expect("append migration event");
        assert_eq!(log.events_written(), 4);
        drop(log);

        let bytes = fs::read(&path).expect("read synchronized log");
        assert!(bytes.ends_with(b"\n"));
        assert!(bytes.len() <= 4 * MAX_STRUCTURED_OPERATION_EVENT_BYTES);
        let lines: Vec<&str> = std::str::from_utf8(&bytes)
            .expect("log uses fixed ASCII vocabulary")
            .lines()
            .collect();
        assert_eq!(lines.len(), 4);
        assert_eq!(
            lines[0],
            "{\"version\":1,\"event\":\"job\",\"outcome\":\"handler_error\",\"job\":{\"id\":\"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a\",\"state\":\"failed\",\"attempts\":7}}"
        );
        assert!(lines[1].contains("\"kind\":\"unsupported\""));
        assert!(lines[2].contains("\"run_state\":\"running\""));
        assert!(lines[3].contains("\"state\":\"validating\""));
        for line in lines {
            assert!(line.len() < MAX_STRUCTURED_OPERATION_EVENT_BYTES);
            assert!(!line.contains("/client/private"));
            assert!(!line.contains("handler diagnostic"));
        }
        fs::remove_dir_all(root).expect("remove temporary test directory");
    }

    #[test]
    fn reopen_resumes_append_only_log_without_reading_or_truncating_history() {
        let root = temporary_directory("reopen");
        let path = root.join("operations.ndjson");
        let mut initial = StructuredOperationLog::open(&path).expect("create log");
        initial.append(job_event()).expect("append initial event");
        drop(initial);
        let before = fs::read(&path).expect("read initial durable line");

        let mut reopened = StructuredOperationLog::open(&path).expect("reopen existing log");
        assert_eq!(reopened.events_written(), 0);
        reopened
            .append(OperationEvent::Maintenance {
                job: None,
                kind: MaintenanceOperationKind::CacheReconcile,
                outcome: OperationEventOutcome::Succeeded,
            })
            .expect("append reopened event");
        assert_eq!(reopened.events_written(), 1);
        drop(reopened);

        let after = fs::read(&path).expect("read reopened log");
        assert!(after.starts_with(&before));
        assert_eq!(after.iter().filter(|byte| **byte == b'\n').count(), 2);
        fs::remove_dir_all(root).expect("remove temporary test directory");
    }

    #[test]
    fn event_sink_adapter_appends_telemetry_without_error_channel() {
        let root = temporary_directory("sink");
        let path = root.join("operations.ndjson");
        let log = StructuredOperationLog::open(&path).expect("open log");
        let mut sink = DurableOperationEventSink::new(log);

        OperationEventSink::record(&mut sink, job_event());
        assert_eq!(sink.append_failures(), 0);
        assert_eq!(sink.log().events_written(), 1);
        drop(sink);

        let text = fs::read_to_string(&path).expect("read adapter output");
        assert!(text.contains("\"event\":\"job\""));
        assert!(text.contains("\"outcome\":\"handler_error\""));
        fs::remove_dir_all(root).expect("remove temporary test directory");
    }

    #[test]
    fn open_rejects_symlink_log_target() {
        let root = temporary_directory("symlink");
        let target = root.join("outside.log");
        let log_path = root.join("operations.ndjson");
        fs::write(&target, b"outside\n").expect("write target");
        symlink(&target, &log_path).expect("create log symlink");

        assert!(matches!(
            StructuredOperationLog::open(&log_path),
            Err(StructuredOperationLogError::UnsafeLogFile(path)) if path == log_path
        ));
        assert_eq!(
            fs::read(&target).expect("read outside target"),
            b"outside\n"
        );
        fs::remove_dir_all(root).expect("remove temporary test directory");
    }
}
