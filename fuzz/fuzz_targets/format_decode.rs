#![no_main]

use libfuzzer_sys::fuzz_target;
use reflink_forest_format::{decode_record, decode_record_metadata, ChunkHeader};

fuzz_target!(|data: &[u8]| {
    let _ = ChunkHeader::decode(data);
    let _ = decode_record_metadata(data);
    let _ = decode_record(data);
});
