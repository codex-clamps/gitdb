#![no_main]

use libfuzzer_sys::fuzz_target;
use reflink_forest_import::decode_snapshot_manifest_bytes;

fuzz_target!(|data: &[u8]| {
    let _ = decode_snapshot_manifest_bytes(data);
});
