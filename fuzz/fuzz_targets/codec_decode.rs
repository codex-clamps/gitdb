#![no_main]

use libfuzzer_sys::fuzz_target;
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_format::{encode_object_payload, verify_object_record, Codec, ObjectRecord};

const MAX_STORED_BYTES: usize = 128 * 1024;
const MAX_SYNTHETIC_RAW_BYTES: usize = 64 * 1024;
const MAX_DECLARED_RAW_BYTES: u64 = 8 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let mode = data.first().copied().unwrap_or_default() & 0b11;
    let body = data.get(1..).unwrap_or_default();
    let oid = GitOid::new(HashAlgorithm::Sha1, &[0_u8; 20]).expect("fixed SHA-1 width");

    let record = match mode {
        // Feed an externally supplied, bounded byte stream directly to the
        // Zstd decoder. The declared length is also bounded so a valid but
        // adversarial frame cannot turn fuzzing into an unbounded write loop.
        0 => {
            let raw_length = body
                .get(..8)
                .and_then(|prefix| prefix.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or_default()
                .min(MAX_DECLARED_RAW_BYTES);
            ObjectRecord {
                kind: ObjectKind::Blob,
                codec: Codec::Zstd,
                flags: 0,
                raw_length,
                content_id: ContentId([0_u8; 32]),
                primary_oid: oid,
                payload: body[..body.len().min(MAX_STORED_BYTES)].to_vec(),
            }
        }
        // Generate a valid independent frame from fuzzer-controlled raw data
        // so the success path stays covered even when corpus mutation has not
        // yet discovered a complete Zstd frame.
        1 => generated_record(body, oid, false, false),
        // Truncate a known-valid frame to exercise decoder error handling.
        2 => generated_record(body, oid, true, false),
        // Add known trailing data to a valid frame; v1 must reject this.
        _ => generated_record(body, oid, false, true),
    };
    let _ = verify_object_record(&record);
});

fn generated_record(
    body: &[u8],
    primary_oid: GitOid,
    truncate: bool,
    add_trailing_bytes: bool,
) -> ObjectRecord {
    let raw = &body[..body.len().min(MAX_SYNTHETIC_RAW_BYTES)];
    let mut payload = encode_object_payload(Codec::Zstd, raw).expect("bounded Zstd encoding");
    if truncate && !payload.is_empty() {
        payload.pop();
    }
    if add_trailing_bytes {
        payload.extend_from_slice(b"fuzz-tail");
    }
    ObjectRecord {
        kind: ObjectKind::Blob,
        codec: Codec::Zstd,
        flags: 0,
        raw_length: raw.len() as u64,
        content_id: ContentId::for_object(ObjectKind::Blob, raw),
        primary_oid,
        payload,
    }
}
