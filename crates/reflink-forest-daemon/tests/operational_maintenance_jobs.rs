use reflink_forest_cache::{CapacityMeter, CapacitySnapshot, ReservePolicy};
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_daemon::{
    CachePressureJobHandler, DaemonConfig, DaemonService, JobExecutionFailure, JobExecutionOutcome,
    JobState, OperationalGcJobHandler, OperationalMaintenanceConfig, RetainedObjectSource,
    CACHE_PRESSURE_JOB_KIND, OPERATIONAL_GC_JOB_KIND,
};
use reflink_forest_format::{Codec, ObjectRecord};
use reflink_forest_import::SnapshotManifest;
use reflink_forest_index::{Catalog, CatalogBatch, InMemoryCatalog, ObjectLocation, RepoId};
use reflink_forest_maintenance::{
    CompactionReader, CompactionWriter, MarkLimits, RetainedObjectRef, SnapshotManifestSource,
};
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "reflink-forest-daemon-operational-jobs-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn start_service(root: &Path) -> DaemonService {
    DaemonService::start(DaemonConfig::new(root.join("runtime"), root.join("state"))).unwrap()
}

fn maintenance_config(root: &Path) -> OperationalMaintenanceConfig {
    OperationalMaintenanceConfig::new(
        root.join("cache"),
        root.join("state").join("generation-state"),
        root.join("generations"),
        root.join("trash"),
    )
}

#[derive(Clone, Copy)]
struct FixedMeter(CapacitySnapshot);

impl CapacityMeter for FixedMeter {
    fn measure(&self) -> io::Result<CapacitySnapshot> {
        Ok(self.0)
    }
}

fn ample_meter() -> FixedMeter {
    FixedMeter(CapacitySnapshot {
        host_available_bytes: 1 << 30,
        guest_available_bytes: 1 << 30,
    })
}

struct EmptyManifests;

impl SnapshotManifestSource for EmptyManifests {
    type Error = String;

    fn load_snapshot_manifest(
        &self,
        _repository: RepoId,
        _snapshot: reflink_forest_index::SnapshotId,
    ) -> Result<SnapshotManifest, Self::Error> {
        Err("this test has no repository snapshot roots".to_owned())
    }
}

struct StaticRetained(Vec<RetainedObjectRef>);

impl RetainedObjectSource for StaticRetained {
    type Error = String;

    fn retained_objects(&self) -> Result<Vec<RetainedObjectRef>, Self::Error> {
        Ok(self.0.clone())
    }
}

struct TestReader {
    record: ObjectRecord,
}

impl CompactionReader for TestReader {
    type Error = String;

    fn read_verified(
        &mut self,
        _content_id: ContentId,
        _location: ObjectLocation,
    ) -> Result<ObjectRecord, Self::Error> {
        Ok(self.record.clone())
    }
}

struct TestWriter {
    target: ObjectLocation,
    synced: bool,
}

impl CompactionWriter for TestWriter {
    type Error = String;

    fn append(&mut self, _record: &ObjectRecord) -> Result<ObjectLocation, Self::Error> {
        Ok(self.target)
    }

    fn sync_data(&mut self) -> Result<(), Self::Error> {
        self.synced = true;
        Ok(())
    }

    fn verify(
        &mut self,
        _expected_content_id: ContentId,
        location: ObjectLocation,
    ) -> Result<(), Self::Error> {
        if !self.synced || location != self.target {
            return Err("target record was not durably written".to_owned());
        }
        Ok(())
    }
}

struct GcFixture {
    repository: RepoId,
    oid: GitOid,
    content_id: ContentId,
    source_location: ObjectLocation,
    target_location: ObjectLocation,
    record: ObjectRecord,
}

impl GcFixture {
    fn new() -> Self {
        let repository = RepoId([0x81; 16]);
        let payload = b"durable operational GC job";
        let content_id = ContentId::for_object(ObjectKind::Blob, payload);
        let oid = GitOid::for_object(HashAlgorithm::Sha1, ObjectKind::Blob, payload);
        let source_location = ObjectLocation {
            generation: 1,
            chunk_id: 1,
            offset: 0,
            record_length: payload.len() as u64,
            stored_length: payload.len() as u64,
            raw_length: payload.len() as u64,
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            payload_crc32c: 0,
        };
        let target_location = ObjectLocation {
            generation: 2,
            chunk_id: 2,
            offset: 0,
            ..source_location
        };
        let record = ObjectRecord {
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id,
            primary_oid: oid,
            payload: payload.to_vec(),
        };
        Self {
            repository,
            oid,
            content_id,
            source_location,
            target_location,
            record,
        }
    }

    fn catalog(&self) -> InMemoryCatalog {
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_current_generation(1);
        batch.put_oid_alias(self.repository, self.oid, self.content_id);
        batch.put_object_location(self.content_id, self.source_location);
        catalog.apply(batch).unwrap();
        catalog
    }

    fn retained(&self) -> StaticRetained {
        StaticRetained(vec![RetainedObjectRef {
            repository: self.repository,
            oid: self.oid,
        }])
    }
}

fn socket_request(socket: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    response
}

#[test]
fn fixed_socket_commands_enqueue_only_opaque_operational_payloads() {
    let root = root();
    let service = start_service(&root);
    let socket = service.socket_path().to_path_buf();
    let server = thread::spawn(move || {
        service.serve_one().unwrap();
        service.serve_one().unwrap();
        service
    });

    assert!(socket_request(&socket, "maintenance gc\n").starts_with("ok job"));
    assert!(socket_request(&socket, "maintenance cache-pressure 4096\n").starts_with("ok job"));
    let service = server.join().unwrap();
    let jobs = service.job_store().list().unwrap();
    assert_eq!(jobs.len(), 2);
    assert!(jobs
        .iter()
        .any(|job| job.kind == OPERATIONAL_GC_JOB_KIND && job.payload.is_empty()));
    assert!(jobs.iter().any(|job| {
        job.kind == CACHE_PRESSURE_JOB_KIND && job.payload == 4096_u64.to_be_bytes()
    }));

    drop(service);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn running_operational_gc_job_recovers_after_restart_and_replays() {
    let root = root();
    let config = maintenance_config(&root);
    fs::create_dir_all(config.generation_path(1)).unwrap();
    let fixture = GcFixture::new();
    let job_id;
    {
        let service = start_service(&root);
        job_id = service.enqueue_operational_gc().unwrap().id;
        assert_eq!(
            service.job_store().claim_next().unwrap().unwrap().id,
            job_id
        );
        assert_eq!(
            service.job_store().get(job_id).unwrap().state,
            JobState::Running
        );
        drop(service);
    }

    let service = start_service(&root);
    assert!(matches!(
        service.job_store().get(job_id).unwrap(),
        ref job if job.state == JobState::Queued && job.attempts == 1
    ));
    let (coordinator, _) = service
        .open_operational_maintenance(
            fixture.catalog(),
            config.clone(),
            ample_meter(),
            ReservePolicy::new(0, 0),
        )
        .unwrap();
    let retained = fixture.retained();
    let mut reader = TestReader {
        record: fixture.record.clone(),
    };
    let mut writer = TestWriter {
        target: fixture.target_location,
        synced: false,
    };
    let mut handler = OperationalGcJobHandler::new(
        &coordinator,
        &EmptyManifests,
        &mut reader,
        &mut writer,
        &retained,
        MarkLimits::default(),
    );
    let outcome = service.execute_next_operational_gc(&mut handler).unwrap();
    assert!(matches!(
        outcome,
        JobExecutionOutcome::Succeeded(ref job) if job.id == job_id && job.attempts == 2
    ));
    assert_eq!(
        service.job_store().get(job_id).unwrap().state,
        JobState::Succeeded
    );
    assert_eq!(
        coordinator.with_catalog(|catalog| catalog.current_generation()),
        Some(2)
    );
    assert_eq!(
        coordinator.with_catalog(|catalog| catalog.object_location(fixture.content_id)),
        Some(fixture.target_location)
    );
    assert!(!config.generation_path(1).exists());

    drop(coordinator);
    drop(service);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cache_pressure_failure_is_durable_and_explicit_retry_succeeds() {
    let root = root();
    let config = maintenance_config(&root);
    let service = start_service(&root);
    let job_id = service.enqueue_cache_pressure(20).unwrap().id;
    service
        .job_store()
        .enqueue_with_id(
            reflink_forest_daemon::JobId::from_bytes([0; 16]),
            b"unrelated-fixed-purpose-job",
            [],
        )
        .unwrap();
    let (constrained, _) = service
        .open_operational_maintenance(
            InMemoryCatalog::default(),
            config.clone(),
            FixedMeter(CapacitySnapshot {
                host_available_bytes: 100,
                guest_available_bytes: 100,
            }),
            ReservePolicy::new(100, 100),
        )
        .unwrap();
    let mut constrained_handler = CachePressureJobHandler::new(&constrained);
    let first = service
        .execute_next_cache_pressure(&mut constrained_handler)
        .unwrap();
    assert!(matches!(
        first,
        JobExecutionOutcome::Failed {
            ref job,
            failure: JobExecutionFailure::HandlerError,
        } if job.id == job_id
            && job.state == JobState::Failed
            && job.last_error.as_deref().is_some_and(|error| error.starts_with(b"operational maintenance failed: cache admission refused"))
    ));
    assert_eq!(
        service
            .job_store()
            .get(reflink_forest_daemon::JobId::from_bytes([0; 16]))
            .unwrap()
            .state,
        JobState::Queued
    );
    drop(constrained);

    assert_eq!(
        service.job_store().retry(job_id).unwrap().state,
        JobState::Queued
    );
    let (recovered, _) = service
        .open_operational_maintenance(
            InMemoryCatalog::default(),
            config,
            ample_meter(),
            ReservePolicy::new(100, 100),
        )
        .unwrap();
    let mut recovered_handler = CachePressureJobHandler::new(&recovered);
    let second = service
        .execute_next_cache_pressure(&mut recovered_handler)
        .unwrap();
    assert!(matches!(
        second,
        JobExecutionOutcome::Succeeded(ref job) if job.id == job_id && job.attempts == 2
    ));
    assert_eq!(
        service.job_store().get(job_id).unwrap().state,
        JobState::Succeeded
    );

    drop(recovered);
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
