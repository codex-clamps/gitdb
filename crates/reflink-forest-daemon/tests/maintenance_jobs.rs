use reflink_forest_cache::Cache;
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_daemon::{
    enqueue_cache_eviction, ColdChunkTarget, JobExecutionFailure, JobExecutionOutcome, JobId,
    JobState, JobStore, MaintenanceConfigurationError, MaintenanceJobHandler,
};
use reflink_forest_format::{ChunkHeader, Codec, ObjectRecord};
use reflink_forest_store::ChunkWriter;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "reflink-forest-daemon-maintenance-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn cache_blob(cache: &Cache, payload: &[u8]) {
    let id = ContentId::for_object(ObjectKind::Blob, payload);
    cache.publish_blob(id, payload).unwrap();
}

fn write_chunk(root: &Path, generation: u32, chunk_id: u64) -> PathBuf {
    let path = root.join("chunks").join("generation-7").join("chunk.open");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut writer = ChunkWriter::create(
        &path,
        ChunkHeader {
            generation,
            chunk_id,
            created_unix_secs: 0,
            flags: 0,
        },
    )
    .unwrap();
    let payload = b"verified by daemon job";
    writer
        .append(&ObjectRecord {
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: ContentId::for_object(ObjectKind::Blob, payload),
            primary_oid: GitOid::for_object(HashAlgorithm::Sha1, ObjectKind::Blob, payload),
            payload: payload.to_vec(),
        })
        .unwrap();
    writer.sync_data().unwrap();
    drop(writer);
    path
}

#[test]
fn recovered_cache_eviction_job_replays_after_restart() {
    let root = root();
    let cache = Cache::open(root.join("cache")).unwrap();
    cache_blob(&cache, b"first cached blob");
    cache_blob(&cache, b"second cached blob");
    assert_eq!(cache.usage().unwrap().entries, 2);

    let id;
    {
        let jobs = JobStore::open(root.join("state")).unwrap();
        id = enqueue_cache_eviction(&jobs, 0).unwrap().id;
        assert_eq!(jobs.claim_next().unwrap().unwrap().id, id);
        assert_eq!(jobs.get(id).unwrap().state, JobState::Running);
    }

    let (jobs, recovered) = JobStore::open_with_recovery(root.join("state")).unwrap();
    assert_eq!(recovered, 1);
    let mut handler = MaintenanceJobHandler::new(&cache, []).unwrap();
    let outcome = handler.execute_next(&jobs).unwrap();
    assert!(matches!(
        outcome,
        JobExecutionOutcome::Succeeded(ref job) if job.id == id && job.attempts == 2
    ));
    assert_eq!(jobs.get(id).unwrap().state, JobState::Succeeded);
    assert_eq!(cache.usage().unwrap().entries, 0);

    drop(handler);
    drop(jobs);
    drop(cache);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cold_chunk_job_uses_configured_inventory_and_persists_bad_identity_failure() {
    let root = root();
    let cache = Cache::open(root.join("cache")).unwrap();
    let chunk = write_chunk(&root, 7, 9);
    let jobs = JobStore::open(root.join("state")).unwrap();
    let verified = jobs
        .enqueue_with_id(
            JobId::from_bytes([0x01; 16]),
            b"verify-cold-chunk-v1",
            [
                7_u32.to_be_bytes().as_slice(),
                9_u64.to_be_bytes().as_slice(),
            ]
            .concat(),
        )
        .unwrap();
    let unconfigured = jobs
        .enqueue_with_id(
            JobId::from_bytes([0xff; 16]),
            b"verify-cold-chunk-v1",
            [
                7_u32.to_be_bytes().as_slice(),
                10_u64.to_be_bytes().as_slice(),
            ]
            .concat(),
        )
        .unwrap();
    let mut handler =
        MaintenanceJobHandler::new(&cache, [ColdChunkTarget::new(7, 9, &chunk)]).unwrap();

    let first = handler.execute_next(&jobs).unwrap();
    assert!(matches!(
        first,
        JobExecutionOutcome::Succeeded(ref job) if job.id == verified.id
    ));
    let second = handler.execute_next(&jobs).unwrap();
    assert!(matches!(
        second,
        JobExecutionOutcome::Failed {
            ref job,
            failure: JobExecutionFailure::HandlerError,
        } if job.id == unconfigured.id
            && job.last_error.as_deref().is_some_and(|error| error.starts_with(b"cold chunk generation 7, chunk 10 is not configured"))
    ));

    drop(handler);
    drop(jobs);
    drop(cache);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cold_chunk_inventory_rejects_duplicate_generation_chunk_identity() {
    let root = root();
    let cache = Cache::open(root.join("cache")).unwrap();
    let result = MaintenanceJobHandler::new(
        &cache,
        [
            ColdChunkTarget::new(2, 3, root.join("first.open")),
            ColdChunkTarget::new(2, 3, root.join("second.open")),
        ],
    );
    assert!(matches!(
        result,
        Err(MaintenanceConfigurationError::DuplicateColdChunk {
            generation: 2,
            chunk_id: 3,
        })
    ));

    drop(cache);
    fs::remove_dir_all(root).unwrap();
}
