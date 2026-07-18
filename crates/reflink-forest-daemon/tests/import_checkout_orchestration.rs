use reflink_forest_cache::{Cache, CapacityMeter, CapacitySnapshot, ReservePolicy};
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_daemon::{
    DaemonConfig, DaemonImportCheckoutOrchestrator, ImportCheckoutConfig, JobExecutionFailure,
    JobExecutionOutcome, JobId, JobState, TrustedImportCheckoutOperations, TrustedOperationId,
    CACHE_RECONCILE_JOB_KIND, TRUSTED_CHECKOUT_JOB_KIND, TRUSTED_IMPORT_JOB_KIND,
};
use reflink_forest_import::{
    begin_snapshot_publication, write_snapshot_manifest, ImportPolicy, ImportSummary,
    RepoSnapshotId, SnapshotManifest,
};
use reflink_forest_index::{Catalog, InMemoryCatalog, RepoId, SnapshotVisibility, WorkspaceId};
use reflink_forest_workspace::{persist_ready_workspace, WorkspaceManifest};
use std::{
    collections::BTreeSet,
    fmt, fs, io,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "reflink-forest-daemon-import-checkout-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[derive(Clone)]
struct Meter {
    snapshot: Arc<Mutex<CapacitySnapshot>>,
    calls: Arc<AtomicUsize>,
}

impl Meter {
    fn new(snapshot: CapacitySnapshot) -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(snapshot)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn set(&self, snapshot: CapacitySnapshot) {
        *self.snapshot.lock().unwrap() = snapshot;
    }
}

impl CapacityMeter for Meter {
    fn measure(&self) -> io::Result<CapacitySnapshot> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(*self.snapshot.lock().unwrap())
    }
}

#[derive(Debug)]
struct OperationError(&'static str);

impl fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for OperationError {}

struct TrustedOperations {
    registered: BTreeSet<JobId>,
    meter_calls: Arc<AtomicUsize>,
    recovered_workspaces: u64,
    imports: Vec<JobId>,
    projected: u64,
    materialized: Vec<JobId>,
}

impl TrustedOperations {
    fn new(
        registered: impl IntoIterator<Item = JobId>,
        meter_calls: Arc<AtomicUsize>,
        recovered_workspaces: u64,
        projected: u64,
    ) -> Self {
        Self {
            registered: registered.into_iter().collect(),
            meter_calls,
            recovered_workspaces,
            imports: Vec::new(),
            projected,
            materialized: Vec::new(),
        }
    }

    fn registered(&self, operation: TrustedOperationId) -> Result<JobId, OperationError> {
        let id = operation.job_id();
        self.registered
            .contains(&id)
            .then_some(id)
            .ok_or(OperationError(
                "operation is not in the trusted daemon registry",
            ))
    }
}

impl TrustedImportCheckoutOperations for TrustedOperations {
    type Error = OperationError;

    fn reconcile_incomplete_workspaces(&mut self) -> Result<u64, Self::Error> {
        Ok(self.recovered_workspaces)
    }

    fn import(&mut self, operation: TrustedOperationId) -> Result<(), Self::Error> {
        self.imports.push(self.registered(operation)?);
        Ok(())
    }

    fn checkout_cache_bytes(&mut self, operation: TrustedOperationId) -> Result<u64, Self::Error> {
        self.registered(operation)?;
        Ok(self.projected)
    }

    fn materialize_checkout(
        &mut self,
        operation: TrustedOperationId,
        cache: &Cache,
    ) -> Result<(), Self::Error> {
        let id = self.registered(operation)?;
        if self.meter_calls.load(Ordering::SeqCst) == 0 {
            return Err(OperationError(
                "checkout materialized before cache admission",
            ));
        }
        let bytes = id.as_bytes();
        cache
            .publish_blob(ContentId::for_object(ObjectKind::Blob, bytes), bytes)
            .map_err(|_| OperationError("test cache publication failed"))?;
        self.materialized.push(id);
        Ok(())
    }
}

fn incomplete_snapshot(root: &std::path::Path, catalog: &mut InMemoryCatalog) -> SnapshotManifest {
    fs::create_dir_all(root).unwrap();
    let manifest = SnapshotManifest {
        repository: RepoId([0x91; 16]),
        snapshot_id: RepoSnapshotId([0x92; 16]),
        native_object_format: HashAlgorithm::Sha1,
        import_policy: ImportPolicy::LocalBranchesAndTags,
        refs: Vec::new(),
        summary: ImportSummary::default(),
        imported_unix_secs: 1,
        tool_version: b"daemon-orchestration-test".to_vec(),
        optional_fields: Vec::new(),
    };
    begin_snapshot_publication(catalog, &manifest).unwrap();
    write_snapshot_manifest(root.join("snapshot-v1"), &manifest).unwrap();
    manifest
}

fn ready_workspace(root: &std::path::Path, catalog: &mut InMemoryCatalog) -> WorkspaceId {
    let id = WorkspaceId([0x93; 16]);
    let manifest = WorkspaceManifest {
        workspace_id: id,
        repository: RepoId([0x94; 16]),
        snapshot_id: [0x95; 16],
        commit: GitOid::for_object(HashAlgorithm::Sha1, ObjectKind::Commit, b"workspace"),
        generation: 7,
        name: b"trusted-workspace".to_vec(),
        created_unix_secs: 2,
        directories: 0,
        regular_files: 0,
        executable_files: 0,
        symlinks: 0,
        gitlinks: 0,
        reflinked_regular_files: 0,
        copied_regular_files: 0,
        optional_fields: Vec::new(),
    };
    persist_ready_workspace(catalog, root.join("workspace-manifests"), &manifest).unwrap();
    id
}

#[test]
fn restart_reconciles_public_state_then_replays_trusted_import_and_checkout() {
    let root = root();
    let daemon_config = DaemonConfig::new(root.join("runtime"), root.join("state"));
    let mut catalog = InMemoryCatalog::default();
    let snapshot = incomplete_snapshot(&root, &mut catalog);
    let workspace_id = ready_workspace(&root, &mut catalog);
    let mut config =
        ImportCheckoutConfig::new(root.join("cache"), root.join("workspace-manifests"));
    config
        .add_snapshot_manifest(root.join("snapshot-v1"))
        .unwrap();
    config.add_workspace(workspace_id).unwrap();
    let unrelated_id = JobId::from_bytes([0x10; 16]);
    let import_id = JobId::from_bytes([0x20; 16]);
    let checkout_id = JobId::from_bytes([0x30; 16]);

    {
        let daemon = reflink_forest_daemon::DaemonService::start(daemon_config.clone()).unwrap();
        daemon
            .job_store()
            .enqueue_with_id(unrelated_id, CACHE_RECONCILE_JOB_KIND, [])
            .unwrap();
        daemon
            .job_store()
            .enqueue_with_id(import_id, TRUSTED_IMPORT_JOB_KIND, [])
            .unwrap();
        daemon
            .job_store()
            .enqueue_with_id(checkout_id, TRUSTED_CHECKOUT_JOB_KIND, [])
            .unwrap();
        // Simulate a process stop after the durable claim but before the
        // injected import runs. Startup must requeue this exact opaque ID.
        assert_eq!(
            daemon
                .job_store()
                .claim_next_matching(|job| job.id == import_id)
                .unwrap()
                .unwrap()
                .id,
            import_id
        );
    }

    let daemon = reflink_forest_daemon::DaemonService::start(daemon_config).unwrap();
    assert_eq!(
        daemon.job_store().get(import_id).unwrap().state,
        JobState::Queued
    );
    let meter = Meter::new(CapacitySnapshot {
        host_available_bytes: 1_000,
        guest_available_bytes: 1_000,
    });
    let operations =
        TrustedOperations::new([import_id, checkout_id], Arc::clone(&meter.calls), 3, 64);
    let (mut orchestrator, startup) = DaemonImportCheckoutOrchestrator::open(
        &daemon,
        &mut catalog,
        &config,
        operations,
        meter,
        ReservePolicy::new(100, 100),
    )
    .unwrap();
    assert_eq!(startup.snapshots_published, 1);
    assert_eq!(startup.ready_workspaces, 1);
    assert_eq!(startup.incomplete_workspaces_recovered, 3);
    assert_eq!(
        catalog.repository_snapshot(snapshot.repository, snapshot.snapshot_id),
        Some(SnapshotVisibility::Ready)
    );

    assert!(matches!(
        orchestrator.execute_next().unwrap(),
        JobExecutionOutcome::Succeeded(ref job) if job.id == import_id && job.attempts == 2
    ));
    assert!(matches!(
        orchestrator.execute_next().unwrap(),
        JobExecutionOutcome::Succeeded(ref job) if job.id == checkout_id && job.attempts == 1
    ));
    assert_eq!(
        daemon.job_store().get(unrelated_id).unwrap().state,
        JobState::Queued
    );
    assert_eq!(orchestrator.operations().imports, vec![import_id]);
    assert_eq!(orchestrator.operations().materialized, vec![checkout_id]);
    assert!(orchestrator.operations().meter_calls.load(Ordering::SeqCst) >= 1);

    drop(orchestrator);
    drop(daemon);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn checkout_reserve_failure_retries_without_client_payload_authority() {
    let root = root();
    let daemon = reflink_forest_daemon::DaemonService::start(DaemonConfig::new(
        root.join("runtime"),
        root.join("state"),
    ))
    .unwrap();
    let mut catalog = InMemoryCatalog::default();
    let config = ImportCheckoutConfig::new(root.join("cache"), root.join("workspace-manifests"));
    let rejected_import = JobId::from_bytes([0x01; 16]);
    let checkout_id = JobId::from_bytes([0x02; 16]);
    let meter = Meter::new(CapacitySnapshot {
        host_available_bytes: 100,
        guest_available_bytes: 100,
    });
    let operations = TrustedOperations::new([checkout_id], Arc::clone(&meter.calls), 0, 10);
    let (mut orchestrator, _) = DaemonImportCheckoutOrchestrator::open(
        &daemon,
        &mut catalog,
        &config,
        operations,
        meter.clone(),
        ReservePolicy::new(95, 95),
    )
    .unwrap();
    daemon
        .job_store()
        .enqueue_with_id(
            rejected_import,
            TRUSTED_IMPORT_JOB_KIND,
            b"/client/private/repository",
        )
        .unwrap();
    daemon
        .job_store()
        .enqueue_with_id(checkout_id, TRUSTED_CHECKOUT_JOB_KIND, [])
        .unwrap();

    let payload_rejected = orchestrator.execute_next().unwrap();
    assert!(matches!(
        payload_rejected,
        JobExecutionOutcome::Failed {
            ref job,
            failure: JobExecutionFailure::HandlerError,
        } if job.id == rejected_import
    ));
    let persisted_error = daemon
        .job_store()
        .get(rejected_import)
        .unwrap()
        .last_error
        .unwrap();
    assert!(!String::from_utf8_lossy(&persisted_error).contains("/client/private"));
    assert!(orchestrator.operations().imports.is_empty());

    let reserve_rejected = orchestrator.execute_next().unwrap();
    assert!(matches!(
        reserve_rejected,
        JobExecutionOutcome::Failed {
            ref job,
            failure: JobExecutionFailure::HandlerError,
        } if job.id == checkout_id
    ));
    assert!(orchestrator.operations().materialized.is_empty());

    // The durable failed job can be retried after capacity is restored. The
    // materializer observes a capacity measurement before it receives cache
    // access, proving the admission boundary is ahead of cache publication.
    meter.set(CapacitySnapshot {
        host_available_bytes: 1_000,
        guest_available_bytes: 1_000,
    });
    daemon.job_store().retry(checkout_id).unwrap();
    assert!(matches!(
        orchestrator.execute_next().unwrap(),
        JobExecutionOutcome::Succeeded(ref job) if job.id == checkout_id && job.attempts == 2
    ));
    assert_eq!(orchestrator.operations().materialized, vec![checkout_id]);

    drop(orchestrator);
    drop(daemon);
    fs::remove_dir_all(root).unwrap();
}
