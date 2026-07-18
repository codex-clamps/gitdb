use reflink_forest_cache::Cache;
use reflink_forest_daemon::{
    BoundedOperationEvents, ColdChunkTarget, InMemoryOperationTelemetry, JobExecutionFailure,
    JobExecutionOutcome, JobId, JobRecord, JobState, JobStore, MaintenanceJobHandler,
    MaintenanceOperationKind, MigrationHandler, MigrationId, MigrationOperationMetadata,
    MigrationState, MigrationStore, OperationEvent, OperationEventBufferError,
    OperationEventFailure, OperationEventMetrics, OperationEventOutcome, OperationEventSink,
    ScrubOperationMetadata, ScrubScheduleStore, CACHE_RECONCILE_JOB_KIND,
    DEFAULT_OPERATION_EVENT_CAPACITY, MAX_OPERATION_EVENT_CAPACITY,
};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "reflink-forest-daemon-events-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

struct PanickingSink;

impl OperationEventSink for PanickingSink {
    fn record(&mut self, _event: OperationEvent) {
        panic!("telemetry sink must not affect durable work");
    }
}

#[test]
fn job_events_are_bounded_redacted_and_do_not_change_durable_outcomes() {
    let root = root();
    assert_eq!(
        BoundedOperationEvents::new(0),
        Err(OperationEventBufferError::ZeroCapacity)
    );
    assert_eq!(
        BoundedOperationEvents::new(MAX_OPERATION_EVENT_CAPACITY + 1),
        Err(OperationEventBufferError::CapacityTooLarge {
            requested: MAX_OPERATION_EVENT_CAPACITY + 1,
            maximum: MAX_OPERATION_EVENT_CAPACITY,
        })
    );
    let jobs = JobStore::open(root.join("state")).unwrap();
    let failed_id = JobId::from_bytes([0x11; 16]);
    jobs.enqueue_with_id(
        failed_id,
        b"import /client/private/kind",
        b"/client/private/payload",
    )
    .unwrap();
    let mut events = BoundedOperationEvents::new(1).unwrap();
    let mut handler = |_job: &JobRecord| -> Result<(), String> {
        Err("unbounded diagnostic mentioning /client/private/error".repeat(32))
    };
    let outcome = jobs
        .execute_next_with_events(&mut handler, &mut events)
        .unwrap();
    assert!(matches!(
        outcome,
        JobExecutionOutcome::Failed {
            ref job,
            failure: JobExecutionFailure::HandlerError,
        } if job.id == failed_id && job.state == JobState::Failed
    ));
    let event = *events.events().back().unwrap();
    assert!(matches!(
        event,
        OperationEvent::Job {
            job: Some(metadata),
            outcome: OperationEventOutcome::Failed(OperationEventFailure::HandlerError),
        } if metadata.id == failed_id && metadata.state == JobState::Failed && metadata.attempts == 1
    ));
    let rendered = format!("{event:?}");
    assert!(!rendered.contains("/client/private"));
    assert!(!rendered.contains("unbounded diagnostic"));

    // A panicking telemetry backend is ignored after the job transition, so
    // observers cannot turn a completed durable success into a daemon error.
    let succeeded_id = JobId::from_bytes([0x12; 16]);
    jobs.enqueue_with_id(succeeded_id, b"checkout", b"/private/workspace")
        .unwrap();
    let mut succeeding = |_job: &JobRecord| -> Result<(), &'static str> { Ok(()) };
    assert!(matches!(
        jobs.execute_next_with_events(&mut succeeding, &mut PanickingSink)
            .unwrap(),
        JobExecutionOutcome::Succeeded(ref job) if job.id == succeeded_id
    ));
    assert_eq!(jobs.get(succeeded_id).unwrap().state, JobState::Succeeded);

    // The single-entry sink retains only the newest event and records loss
    // explicitly rather than growing with job volume.
    let final_id = JobId::from_bytes([0x13; 16]);
    jobs.enqueue_with_id(final_id, b"checkout", b"payload")
        .unwrap();
    let mut succeeding = |_job: &JobRecord| -> Result<(), &'static str> { Ok(()) };
    jobs.execute_next_with_events(&mut succeeding, &mut events)
        .unwrap();
    assert_eq!(events.capacity(), 1);
    assert_eq!(events.events().len(), 1);
    assert_eq!(events.dropped_events(), 1);
    assert!(matches!(
        events.events().front(),
        Some(OperationEvent::Job {
            job: Some(metadata),
            outcome: OperationEventOutcome::Succeeded,
        }) if metadata.id == final_id
    ));
    assert_eq!(DEFAULT_OPERATION_EVENT_CAPACITY, 256);

    drop(jobs);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn maintenance_events_report_only_fixed_action_kinds() {
    let root = root();
    let cache = Cache::open(root.join("cache")).unwrap();
    let jobs = JobStore::open(root.join("state")).unwrap();
    let id = JobId::from_bytes([0x21; 16]);
    jobs.enqueue_with_id(id, CACHE_RECONCILE_JOB_KIND, b"")
        .unwrap();
    let mut handler =
        MaintenanceJobHandler::new(&cache, std::iter::empty::<ColdChunkTarget>()).unwrap();
    let mut telemetry = InMemoryOperationTelemetry::new(2).unwrap();
    let outcome = handler
        .execute_next_with_events(&jobs, &mut telemetry)
        .unwrap();
    assert!(matches!(
        outcome,
        JobExecutionOutcome::Succeeded(ref job) if job.id == id
    ));
    assert!(matches!(
        telemetry.events().events().back(),
        Some(OperationEvent::Maintenance {
            job: Some(metadata),
            kind: MaintenanceOperationKind::CacheReconcile,
            outcome: OperationEventOutcome::Succeeded,
        }) if metadata.id == id
    ));
    assert_eq!(
        telemetry.metrics(),
        reflink_forest_daemon::OperationEventMetricsSnapshot {
            total: 1,
            maintenance: 1,
            succeeded: 1,
            ..reflink_forest_daemon::OperationEventMetricsSnapshot::default()
        }
    );

    drop(telemetry);
    drop(handler);
    drop(jobs);
    drop(cache);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scrub_and_migration_events_are_safe_metric_inputs() {
    let root = root();
    let scrub_root = root.join("scrubs");
    let migration_root = root.join("migrations");
    fs::create_dir_all(&scrub_root).unwrap();
    fs::create_dir_all(&migration_root).unwrap();
    let scrubs = ScrubScheduleStore::open(&scrub_root, 100).unwrap();
    scrubs.configure_at(60, 100).unwrap();
    let mut scrub_handler = |_schedule: &reflink_forest_daemon::ScrubScheduleState| {
        Err::<(), _>("/private/scrub verifier diagnostic")
    };
    let mut events = BoundedOperationEvents::default();
    let scrub = scrubs
        .execute_if_due_at_with_events(160, &mut scrub_handler, &mut events)
        .unwrap();
    assert!(matches!(
        scrub,
        reflink_forest_daemon::ScrubExecutionOutcome::Failed { .. }
    ));
    let scrub_event = *events.events().back().unwrap();
    assert!(matches!(
        scrub_event,
        OperationEvent::Scrub {
            schedule: Some(ScrubOperationMetadata {
                consecutive_failures: 1,
                ..
            }),
            outcome: OperationEventOutcome::Failed(OperationEventFailure::HandlerError),
        }
    ));
    assert!(!format!("{scrub_event:?}").contains("/private"));

    let migrations = MigrationStore::open(&migration_root, 1).unwrap();
    migrations
        .begin_with_id(MigrationId::from_bytes([0x31; 16]), 2)
        .unwrap();
    let mut migration_handler = CopyingMigration;
    let migration = migrations
        .execute_once_with_events(&mut migration_handler, &mut events)
        .unwrap();
    assert!(matches!(
        migration,
        reflink_forest_daemon::MigrationExecutionOutcome::Advanced(_)
    ));
    let migration_event = *events.events().back().unwrap();
    assert!(matches!(
        migration_event,
        OperationEvent::Migration {
            migration: Some(MigrationOperationMetadata {
                state: MigrationState::Validating,
                from_format_version: 1,
                to_format_version: 2,
                transition_count: 2,
                ..
            }),
            outcome: OperationEventOutcome::Succeeded,
        }
    ));

    let mut metrics = OperationEventMetrics::default();
    metrics.record(scrub_event);
    metrics.record(migration_event);
    assert_eq!(
        metrics.snapshot(),
        reflink_forest_daemon::OperationEventMetricsSnapshot {
            total: 2,
            scrubs: 1,
            migrations: 1,
            handler_errors: 1,
            succeeded: 1,
            ..reflink_forest_daemon::OperationEventMetricsSnapshot::default()
        }
    );

    drop(events);
    drop(migrations);
    drop(scrubs);
    fs::remove_dir_all(root).unwrap();
}

struct CopyingMigration;

impl MigrationHandler for CopyingMigration {
    type Error = &'static str;

    fn copy(
        &mut self,
        _migration: &reflink_forest_daemon::MigrationRecord,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_and_publish(
        &mut self,
        _migration: &reflink_forest_daemon::MigrationRecord,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
