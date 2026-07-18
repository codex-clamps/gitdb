#![no_main]

use libfuzzer_sys::fuzz_target;
use reflink_forest_backup::{
    decode_backup_manifest_bytes, decode_cold_tier_checkpoint_descriptor_bytes,
};

fuzz_target!(|data: &[u8]| {
    let _ = decode_backup_manifest_bytes(data);
    let _ = decode_cold_tier_checkpoint_descriptor_bytes(data);
});
