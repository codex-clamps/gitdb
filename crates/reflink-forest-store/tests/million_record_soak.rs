//! Opt-in release soak for append, restart recovery, sealing, and full scan.
//!
//! This is deliberately an ignored integration test: it writes roughly 180
//! MiB across one million records and takes long enough to be unsuitable for
//! pull-request CI. The scheduled/main/release CI gate enables it explicitly.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_format::{ChunkHeader, Codec, ObjectRecord};
use reflink_forest_index::InMemoryCatalog;
use reflink_forest_store::{verify_sealed_chunk, ChunkWriter};

const RECORD_COUNT: u64 = 1_000_000;
const RESTART_BOUNDARIES: &[u64] = &[1, 97, 4_096, 65_537, 250_000, 500_000, 750_000, 999_999];
const SOAK_ENV: &str = "REFLINK_FOREST_RUN_MILLION_RECORD_SOAK";

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "reflink-forest-million-record-soak-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after the Unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create isolated soak directory");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn header() -> ChunkHeader {
    ChunkHeader {
        generation: 1,
        chunk_id: 1,
        created_unix_secs: 0,
        flags: 0,
    }
}

fn synthetic_record() -> ObjectRecord {
    let payload = b"deterministic million-record cold-store soak payload";
    ObjectRecord {
        kind: ObjectKind::Blob,
        codec: Codec::Raw,
        flags: 0,
        raw_length: payload.len() as u64,
        content_id: ContentId::for_object(ObjectKind::Blob, payload),
        primary_oid: GitOid::for_object(HashAlgorithm::Sha1, ObjectKind::Blob, payload),
        payload: payload.to_vec(),
    }
}

#[cfg(debug_assertions)]
fn require_release_profile() {
    panic!("run this soak in release mode: cargo test --release ... -- --ignored");
}

#[cfg(not(debug_assertions))]
fn require_release_profile() {}

/// Writes one million records, restarts at fixed durable boundaries, seals,
/// and performs the immutable chunk's full verification scan.
#[test]
#[ignore = "release-profile, explicit-env million-record soak gate"]
fn million_record_soak() {
    require_release_profile();
    assert_eq!(
        std::env::var(SOAK_ENV).ok().as_deref(),
        Some("1"),
        "set {SOAK_ENV}=1 to authorize the million-record disk/time budget"
    );

    let root = TempRoot::new();
    let open_path = root.path().join("0000000000000001.open");
    let mut catalog = InMemoryCatalog::default();
    let mut writer =
        ChunkWriter::create_and_publish(&open_path, header(), &mut catalog).expect("create chunk");
    let record = synthetic_record();
    let mut restart_index = 0_usize;

    for completed in 1..=RECORD_COUNT {
        writer.append(&record).expect("append deterministic record");
        if RESTART_BOUNDARIES.get(restart_index) == Some(&completed) {
            // A restart begins only after the record boundary has reached the
            // durable file. Dropping the writer models a process exit without
            // relying on its in-memory counters, and `open_recovered` must
            // reconstruct those counters from the persisted prefix.
            writer.sync_data().expect("synchronize restart boundary");
            drop(writer);
            let (reopened, recovery) =
                ChunkWriter::open_recovered(&open_path).expect("recover durable prefix");
            assert_eq!(recovery.valid_records, completed);
            assert_eq!(recovery.truncated_bytes, 0);
            writer = reopened;
            restart_index += 1;
        }
    }
    assert_eq!(restart_index, RESTART_BOUNDARIES.len());
    assert_eq!(writer.record_count(), RECORD_COUNT);
    writer.sync_data().expect("synchronize complete chunk");

    let sealed = writer
        .seal_and_publish(&mut catalog)
        .expect("seal million-record chunk");
    let verified = verify_sealed_chunk(sealed.path()).expect("fully verify sealed chunk");
    assert_eq!(verified.footer().record_count, RECORD_COUNT);
}
