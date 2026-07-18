use reflink_forest_cache::{CapacityMeter, CapacitySnapshot, ReservePolicy};
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_daemon::{
    DaemonConfig, DaemonService, GenerationRetirement, OperationalMaintenanceConfig,
    OperationalMaintenanceError,
};
use reflink_forest_format::{Codec, ObjectRecord};
use reflink_forest_import::SnapshotManifest;
use reflink_forest_index::{Catalog, CatalogBatch, InMemoryCatalog, ObjectLocation, RepoId};
use reflink_forest_maintenance::{
    CompactionReader, CompactionWriter, GenerationManager, MarkLimits, RetainedObjectRef,
    SnapshotManifestSource,
};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "reflink-forest-daemon-operational-maintenance-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
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

fn config(root: &std::path::Path) -> OperationalMaintenanceConfig {
    OperationalMaintenanceConfig::new(
        root.join("cache"),
        root.join("state").join("generation-state"),
        root.join("generations"),
        root.join("trash"),
    )
}

fn start_service(root: &std::path::Path) -> DaemonService {
    DaemonService::start(DaemonConfig::new(root.join("runtime"), root.join("state"))).unwrap()
}

#[test]
fn daemon_startup_reconciles_cache_leases_and_active_generation() {
    let root = root();
    let maintenance = config(&root);
    let corrupt_payload = b"expected cache blob";
    let content_id = ContentId::for_object(ObjectKind::Blob, corrupt_payload);
    let cache = reflink_forest_cache::Cache::open(maintenance.cache_root()).unwrap();
    let corrupt_path = cache.path_for(content_id);
    fs::create_dir_all(corrupt_path.parent().unwrap()).unwrap();
    fs::write(&corrupt_path, b"not the expected cache blob").unwrap();
    drop(cache);

    let stale_lease = {
        let manager = GenerationManager::open(maintenance.generation_state_root()).unwrap();
        let lease = manager.lease(3).unwrap();
        let path = lease.path().to_path_buf();
        std::mem::forget(lease);
        path
    };
    assert!(stale_lease.exists());
    fs::set_permissions(root.join("state"), fs::Permissions::from_mode(0o700)).unwrap();

    let mut catalog = InMemoryCatalog::default();
    let mut batch = CatalogBatch::new();
    batch.put_current_generation(7);
    catalog.apply(batch).unwrap();

    let service = start_service(&root);
    let (coordinator, startup) = service
        .open_operational_maintenance(
            catalog,
            maintenance,
            ample_meter(),
            ReservePolicy::new(0, 0),
        )
        .unwrap();

    assert_eq!(startup.cache.quarantined, 1);
    assert_eq!(startup.active_generation, Some(7));
    assert!(!stale_lease.exists());
    assert!(coordinator.generation_manager().may_reclaim(3).unwrap());
    assert_eq!(
        coordinator
            .generation_manager()
            .active_generation()
            .unwrap(),
        Some(7)
    );

    drop(coordinator);
    drop(service);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn daemon_cache_publication_is_admitted_or_refused_before_writing() {
    let root = root();
    let maintenance = config(&root);
    let payload = b"cache blob";
    let content_id = ContentId::for_object(ObjectKind::Blob, payload);
    let service = start_service(&root);
    let (coordinator, _) = service
        .open_operational_maintenance(
            InMemoryCatalog::default(),
            maintenance.clone(),
            ample_meter(),
            ReservePolicy::new(100, 100),
        )
        .unwrap();
    let (admission, path) = coordinator.publish_cache_blob(content_id, payload).unwrap();
    assert_eq!(admission.projected_allocation_bytes, payload.len() as u64);
    assert!(path.is_file());
    drop(coordinator);
    drop(service);

    let refused_root = root.join("refused");
    let refused_config = config(&refused_root);
    let refused_service = start_service(&refused_root);
    let (refused, _) = refused_service
        .open_operational_maintenance(
            InMemoryCatalog::default(),
            refused_config.clone(),
            FixedMeter(CapacitySnapshot {
                host_available_bytes: 100,
                guest_available_bytes: 100,
            }),
            ReservePolicy::new(100, 100),
        )
        .unwrap();
    let error = refused.publish_cache_blob(content_id, payload).unwrap_err();
    assert!(matches!(error, OperationalMaintenanceError::Capacity(_)));
    assert!(
        !reflink_forest_cache::Cache::open(refused_config.cache_root())
            .unwrap()
            .path_for(content_id)
            .exists()
    );

    drop(refused);
    drop(refused_service);
    fs::remove_dir_all(root).unwrap();
}

struct EmptyManifests;

impl SnapshotManifestSource for EmptyManifests {
    type Error = String;

    fn load_snapshot_manifest(
        &self,
        _repository: RepoId,
        _snapshot: reflink_forest_index::SnapshotId,
    ) -> Result<SnapshotManifest, Self::Error> {
        Err("no repository snapshots are configured in this test".to_owned())
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
    appended: Vec<ContentId>,
    synced: bool,
}

impl CompactionWriter for TestWriter {
    type Error = String;

    fn append(&mut self, record: &ObjectRecord) -> Result<ObjectLocation, Self::Error> {
        self.appended.push(record.content_id);
        Ok(self.target)
    }

    fn sync_data(&mut self) -> Result<(), Self::Error> {
        self.synced = true;
        Ok(())
    }

    fn verify(
        &mut self,
        expected_content_id: ContentId,
        location: ObjectLocation,
    ) -> Result<(), Self::Error> {
        if !self.synced
            || location != self.target
            || self.appended.as_slice() != [expected_content_id]
        {
            return Err("writer verification did not observe the durable target record".to_owned());
        }
        Ok(())
    }
}

#[test]
fn bounded_gc_marks_compacts_publishes_and_retires_trusted_generation() {
    let root = root();
    let maintenance = config(&root);
    fs::create_dir_all(maintenance.generation_path(1)).unwrap();

    let repository = RepoId([0x44; 16]);
    let payload = b"a retained blob";
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
    let mut catalog = InMemoryCatalog::default();
    let mut batch = CatalogBatch::new();
    batch.put_current_generation(1);
    batch.put_oid_alias(repository, oid, content_id);
    batch.put_object_location(content_id, source_location);
    catalog.apply(batch).unwrap();

    let service = start_service(&root);
    let (coordinator, _) = service
        .open_operational_maintenance(
            catalog,
            maintenance.clone(),
            ample_meter(),
            ReservePolicy::new(0, 0),
        )
        .unwrap();
    let mut reader = TestReader { record };
    let mut writer = TestWriter {
        target: target_location,
        appended: Vec::new(),
        synced: false,
    };
    let active_reader = coordinator.generation_manager().lease(1).unwrap();
    let outcome = coordinator
        .run_gc_once(
            &EmptyManifests,
            &mut reader,
            &mut writer,
            [RetainedObjectRef { repository, oid }],
            MarkLimits::default(),
        )
        .unwrap();

    assert_eq!(outcome.marked_objects, 1);
    assert_eq!(outcome.compaction.source_generation, 1);
    assert_eq!(outcome.compaction.target_generation, 2);
    assert_eq!(outcome.compaction.copied_records, 1);
    assert!(matches!(
        outcome.retirement,
        GenerationRetirement::DeferredByActiveReaders { generation: 1 }
    ));
    assert!(maintenance.generation_path(1).is_dir());
    assert_eq!(
        coordinator.with_catalog(|catalog| catalog.current_generation()),
        Some(2)
    );
    assert_eq!(
        coordinator.with_catalog(|catalog| catalog.object_location(content_id)),
        Some(target_location)
    );
    assert_eq!(
        coordinator
            .generation_manager()
            .active_generation()
            .unwrap(),
        Some(2)
    );

    drop(active_reader);
    assert!(matches!(
        coordinator.retry_generation_retirement(1, 2).unwrap(),
        GenerationRetirement::Retired(ref path) if path == &maintenance.trash_root().join("generation-1-retired")
    ));
    assert!(!maintenance.generation_path(1).exists());

    drop(coordinator);
    drop(service);
    fs::remove_dir_all(root).unwrap();
}
