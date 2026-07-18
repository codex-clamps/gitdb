#![no_main]

use std::{
    fs::{self, OpenOptions},
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use libfuzzer_sys::fuzz_target;
use reflink_forest_format::ChunkHeader;
use reflink_forest_store::{recover_open_chunk, verify_chunk};

const MAX_TAIL_BYTES: usize = 128 * 1024;
static CASE_NUMBER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let case = CASE_NUMBER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "reflink-forest-open-recovery-fuzz-{}-{case}.open",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("create unique bounded recovery fixture");
    file.write_all(
        &ChunkHeader {
            generation: 1,
            chunk_id: 1,
            created_unix_secs: 0,
            flags: 0,
        }
        .encode(),
    )
    .expect("write valid chunk header");
    file.write_all(&data[..data.len().min(MAX_TAIL_BYTES)])
        .expect("write bounded malformed tail");
    drop(file);

    // Recovery must either retain a structurally valid prefix or reject an
    // impossible fixture without panicking. A subsequent strict verify covers
    // the reconstructed on-disk state.
    let _ = recover_open_chunk(&path);
    let _ = verify_chunk(&path);
    fs::remove_file(path).expect("remove bounded recovery fixture");
});
