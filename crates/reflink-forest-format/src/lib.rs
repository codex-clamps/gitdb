//! Explicit v1 encodings for cold-store chunk headers and object records.
//!
//! This crate is deliberately byte-oriented: it neither relies on Rust struct
//! layout nor silently accepts malformed tails.  Storage code can use
//! [`decode_record`] while scanning an open chunk and truncate at its first
//! error.

use core::fmt;
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};

pub const FORMAT_VERSION: u16 = 1;
pub const CHUNK_HEADER_LEN: usize = 64;
pub const RECORD_HEADER_LEN: usize = 128;
pub const RECORD_FOOTER_LEN: usize = 20;
pub const RECORD_ALIGNMENT: usize = 8;

const CHUNK_MAGIC: &[u8; 8] = b"RFSCHNK\0";
const RECORD_MAGIC: &[u8; 4] = b"ROBJ";
const RECORD_END_MAGIC: &[u8; 8] = b"RENDOBJ\0";
const CHUNK_CRC_OFFSET: usize = 36;
const RECORD_CRC_OFFSET: usize = 94;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkHeader {
    pub generation: u32,
    pub chunk_id: u64,
    pub created_unix_secs: u64,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Codec {
    Raw = 0,
    Zstd = 1,
}

impl Codec {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Raw),
            1 => Some(Self::Zstd),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectRecord {
    pub kind: ObjectKind,
    pub codec: Codec,
    pub flags: u16,
    /// Uncompressed Git object payload length.
    pub raw_length: u64,
    pub content_id: ContentId,
    pub primary_oid: GitOid,
    /// Either raw payload bytes or a single independent compressed frame.
    pub payload: Vec<u8>,
}

/// Fixed metadata parsed from an object record header without reading its
/// payload.  Cold-store readers use this to validate catalog-addressed
/// records before streaming their payloads instead of allocating an
/// attacker-controlled stored length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordMetadata {
    pub kind: ObjectKind,
    pub codec: Codec,
    pub flags: u16,
    pub raw_length: u64,
    pub stored_length: u64,
    pub content_id: ContentId,
    pub primary_oid: GitOid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FormatError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u16),
    InvalidHeaderLength { expected: usize, actual: usize },
    HeaderCrcMismatch,
    PayloadCrcMismatch,
    FooterMagicMismatch,
    InvalidObjectKind(u8),
    InvalidCodec(u8),
    InvalidHashAlgorithm(u8),
    InvalidOidLength,
    InvalidRecordLength,
    NonZeroReserved,
    NonZeroPadding,
    LengthOverflow,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid reflink forest format: {self:?}")
    }
}
impl std::error::Error for FormatError {}

impl ChunkHeader {
    pub fn encode(&self) -> [u8; CHUNK_HEADER_LEN] {
        let mut bytes = [0_u8; CHUNK_HEADER_LEN];
        bytes[..8].copy_from_slice(CHUNK_MAGIC);
        put_u16(&mut bytes, 8, FORMAT_VERSION);
        put_u16(&mut bytes, 10, CHUNK_HEADER_LEN as u16);
        put_u32(&mut bytes, 12, self.generation);
        put_u64(&mut bytes, 16, self.chunk_id);
        put_u64(&mut bytes, 24, self.created_unix_secs);
        put_u32(&mut bytes, 32, self.flags);
        let crc = crc32c_with_zeroed_field(&bytes, CHUNK_CRC_OFFSET, 4);
        put_u32(&mut bytes, CHUNK_CRC_OFFSET, crc);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < CHUNK_HEADER_LEN {
            return Err(FormatError::Truncated);
        }
        let bytes = &bytes[..CHUNK_HEADER_LEN];
        if &bytes[..8] != CHUNK_MAGIC {
            return Err(FormatError::BadMagic);
        }
        check_version(read_u16(bytes, 8))?;
        check_header_len(read_u16(bytes, 10) as usize, CHUNK_HEADER_LEN)?;
        if read_u32(bytes, CHUNK_CRC_OFFSET) != crc32c_with_zeroed_field(bytes, CHUNK_CRC_OFFSET, 4)
        {
            return Err(FormatError::HeaderCrcMismatch);
        }
        if bytes[40..].iter().any(|&byte| byte != 0) {
            return Err(FormatError::NonZeroReserved);
        }
        Ok(Self {
            generation: read_u32(bytes, 12),
            chunk_id: read_u64(bytes, 16),
            created_unix_secs: read_u64(bytes, 24),
            flags: read_u32(bytes, 32),
        })
    }
}

/// Encodes a complete record followed by zero padding through an 8-byte boundary.
pub fn encode_record(record: &ObjectRecord) -> Result<Vec<u8>, FormatError> {
    let stored_length =
        u64::try_from(record.payload.len()).map_err(|_| FormatError::LengthOverflow)?;
    let total = RECORD_HEADER_LEN
        .checked_add(record.payload.len())
        .and_then(|n| n.checked_add(RECORD_FOOTER_LEN))
        .ok_or(FormatError::LengthOverflow)?;
    let total_u64 = u64::try_from(total).map_err(|_| FormatError::LengthOverflow)?;
    let padded = align(total)?;
    let mut bytes = vec![0_u8; padded];
    bytes[..4].copy_from_slice(RECORD_MAGIC);
    put_u16(&mut bytes, 4, FORMAT_VERSION);
    put_u16(&mut bytes, 6, RECORD_HEADER_LEN as u16);
    bytes[8] = record.kind.tag();
    bytes[9] = record.codec as u8;
    put_u16(&mut bytes, 10, record.flags);
    put_u64(&mut bytes, 12, record.raw_length);
    put_u64(&mut bytes, 20, stored_length);
    bytes[28..60].copy_from_slice(record.content_id.as_bytes());
    encode_oid_fixed(&record.primary_oid, &mut bytes[60..94]);
    let header_crc = crc32c_with_zeroed_field(&bytes[..RECORD_HEADER_LEN], RECORD_CRC_OFFSET, 4);
    put_u32(&mut bytes, RECORD_CRC_OFFSET, header_crc);
    bytes[RECORD_HEADER_LEN..RECORD_HEADER_LEN + record.payload.len()]
        .copy_from_slice(&record.payload);
    let footer = RECORD_HEADER_LEN + record.payload.len();
    put_u32(&mut bytes, footer, crc32c(&record.payload));
    put_u64(&mut bytes, footer + 4, total_u64);
    bytes[footer + 12..footer + 20].copy_from_slice(RECORD_END_MAGIC);
    Ok(bytes)
}

/// Decodes one aligned record and returns it with the number of consumed bytes.
pub fn decode_record(bytes: &[u8]) -> Result<(ObjectRecord, usize), FormatError> {
    let metadata = decode_record_metadata(bytes)?;
    let stored =
        usize::try_from(metadata.stored_length).map_err(|_| FormatError::LengthOverflow)?;
    let total = RECORD_HEADER_LEN
        .checked_add(stored)
        .and_then(|n| n.checked_add(RECORD_FOOTER_LEN))
        .ok_or(FormatError::LengthOverflow)?;
    let total_footer = total
        .checked_sub(RECORD_FOOTER_LEN)
        .ok_or(FormatError::LengthOverflow)?;
    if bytes.len() < total {
        return Err(FormatError::Truncated);
    }
    if read_u64(bytes, total_footer + 4)
        != u64::try_from(total).map_err(|_| FormatError::LengthOverflow)?
    {
        return Err(FormatError::InvalidRecordLength);
    }
    if &bytes[total_footer + 12..total] != RECORD_END_MAGIC {
        return Err(FormatError::FooterMagicMismatch);
    }
    let payload = &bytes[RECORD_HEADER_LEN..RECORD_HEADER_LEN + stored];
    if read_u32(bytes, total_footer) != crc32c(payload) {
        return Err(FormatError::PayloadCrcMismatch);
    }
    let consumed = align(total)?;
    if bytes.len() < consumed {
        return Err(FormatError::Truncated);
    }
    if bytes[total..consumed].iter().any(|&byte| byte != 0) {
        return Err(FormatError::NonZeroPadding);
    }
    Ok((
        ObjectRecord {
            kind: metadata.kind,
            codec: metadata.codec,
            flags: metadata.flags,
            raw_length: metadata.raw_length,
            content_id: metadata.content_id,
            primary_oid: metadata.primary_oid,
            payload: payload.to_vec(),
        },
        consumed,
    ))
}

/// Decodes and validates a fixed record header without reading or allocating
/// its payload.  The returned `stored_length` is still untrusted until a
/// caller validates the complete record footer, padding, and payload CRC.
pub fn decode_record_metadata(bytes: &[u8]) -> Result<RecordMetadata, FormatError> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(FormatError::Truncated);
    }
    let header = &bytes[..RECORD_HEADER_LEN];
    if &header[..4] != RECORD_MAGIC {
        return Err(FormatError::BadMagic);
    }
    check_version(read_u16(header, 4))?;
    check_header_len(read_u16(header, 6) as usize, RECORD_HEADER_LEN)?;
    if read_u32(header, RECORD_CRC_OFFSET) != crc32c_with_zeroed_field(header, RECORD_CRC_OFFSET, 4)
    {
        return Err(FormatError::HeaderCrcMismatch);
    }
    if header[98..].iter().any(|&byte| byte != 0) {
        return Err(FormatError::NonZeroReserved);
    }
    Ok(RecordMetadata {
        kind: ObjectKind::from_tag(header[8]).ok_or(FormatError::InvalidObjectKind(header[8]))?,
        codec: Codec::from_tag(header[9]).ok_or(FormatError::InvalidCodec(header[9]))?,
        flags: read_u16(header, 10),
        raw_length: read_u64(header, 12),
        stored_length: read_u64(header, 20),
        content_id: ContentId(header[28..60].try_into().expect("fixed length")),
        primary_oid: decode_oid_fixed(&header[60..94])?,
    })
}

/// Determines the complete aligned record size from its fixed header without
/// allocating or inspecting its payload. Storage scanners use this before
/// reading an untrusted record length.
pub fn encoded_record_len_from_header(bytes: &[u8]) -> Result<usize, FormatError> {
    let metadata = decode_record_metadata(bytes)?;
    let stored =
        usize::try_from(metadata.stored_length).map_err(|_| FormatError::LengthOverflow)?;
    let total = RECORD_HEADER_LEN
        .checked_add(stored)
        .and_then(|length| length.checked_add(RECORD_FOOTER_LEN))
        .ok_or(FormatError::LengthOverflow)?;
    align(total)
}

/// Determines the complete aligned record size from validated metadata without
/// narrowing its stored length to `usize`.  Streaming readers use this so a
/// large but valid record is processed in fixed-size buffers.
pub fn encoded_record_len_from_metadata(metadata: RecordMetadata) -> Result<u64, FormatError> {
    let total = (RECORD_HEADER_LEN as u64)
        .checked_add(metadata.stored_length)
        .and_then(|length| length.checked_add(RECORD_FOOTER_LEN as u64))
        .ok_or(FormatError::LengthOverflow)?;
    align_u64(total)
}

/// Validates the fixed footer that terminates a streamed record payload.
/// `payload_crc32c` must be computed over precisely the stored payload bytes,
/// and `unpadded_record_length` includes the fixed header and footer.
pub fn validate_record_footer(
    bytes: &[u8],
    payload_crc32c: u32,
    unpadded_record_length: u64,
) -> Result<(), FormatError> {
    if bytes.len() < RECORD_FOOTER_LEN {
        return Err(FormatError::Truncated);
    }
    let footer = &bytes[..RECORD_FOOTER_LEN];
    if read_u32(footer, 0) != payload_crc32c {
        return Err(FormatError::PayloadCrcMismatch);
    }
    if read_u64(footer, 4) != unpadded_record_length {
        return Err(FormatError::InvalidRecordLength);
    }
    if &footer[12..20] != RECORD_END_MAGIC {
        return Err(FormatError::FooterMagicMismatch);
    }
    Ok(())
}

fn encode_oid_fixed(oid: &GitOid, output: &mut [u8]) {
    output[0] = oid.algorithm().tag();
    output[1] = oid.len();
    output[2..2 + oid.as_bytes().len()].copy_from_slice(oid.as_bytes());
}
fn decode_oid_fixed(bytes: &[u8]) -> Result<GitOid, FormatError> {
    let algorithm =
        HashAlgorithm::from_tag(bytes[0]).ok_or(FormatError::InvalidHashAlgorithm(bytes[0]))?;
    if bytes[1] != algorithm.oid_len()
        || bytes[2 + usize::from(bytes[1])..]
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(FormatError::InvalidOidLength);
    }
    GitOid::new(algorithm, &bytes[2..2 + usize::from(bytes[1])])
        .map_err(|_| FormatError::InvalidOidLength)
}
fn check_version(version: u16) -> Result<(), FormatError> {
    if version == FORMAT_VERSION {
        Ok(())
    } else {
        Err(FormatError::UnsupportedVersion(version))
    }
}
fn check_header_len(actual: usize, expected: usize) -> Result<(), FormatError> {
    if actual == expected {
        Ok(())
    } else {
        Err(FormatError::InvalidHeaderLength { expected, actual })
    }
}
fn align(value: usize) -> Result<usize, FormatError> {
    value
        .checked_add(RECORD_ALIGNMENT - 1)
        .map(|n| n & !(RECORD_ALIGNMENT - 1))
        .ok_or(FormatError::LengthOverflow)
}
fn align_u64(value: u64) -> Result<u64, FormatError> {
    value
        .checked_add((RECORD_ALIGNMENT - 1) as u64)
        .map(|n| n & !((RECORD_ALIGNMENT - 1) as u64))
        .ok_or(FormatError::LengthOverflow)
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("bounds checked"),
    )
}
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounds checked"),
    )
}
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounds checked"),
    )
}

/// Castagnoli CRC-32C, using the reflected polynomial mandated by iSCSI/SSE4.2.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finalize()
}

/// Incremental Castagnoli CRC-32C calculator for bounded streaming I/O.
#[derive(Clone, Copy, Debug)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    pub const fn new() -> Self {
        Self(!0_u32)
    }

    pub fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u32::from(byte);
            for _ in 0..8 {
                self.0 = (self.0 >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(self.0 & 1));
            }
        }
    }

    pub const fn finalize(self) -> u32 {
        !self.0
    }
}
fn crc32c_with_zeroed_field(bytes: &[u8], offset: usize, len: usize) -> u32 {
    let mut copy = bytes.to_vec();
    copy[offset..offset + len].fill(0);
    crc32c(&copy)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(payload: &[u8]) -> ObjectRecord {
        ObjectRecord {
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: ContentId::for_object(ObjectKind::Blob, payload),
            primary_oid: GitOid::new(HashAlgorithm::Sha1, &[0xA5; 20]).unwrap(),
            payload: payload.to_vec(),
        }
    }
    #[test]
    fn crc32c_matches_known_vector() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }
    #[test]
    fn chunk_header_round_trips_and_checks_crc() {
        let header = ChunkHeader {
            generation: 7,
            chunk_id: 9,
            created_unix_secs: 11,
            flags: 13,
        };
        let encoded = header.encode();
        assert_eq!(ChunkHeader::decode(&encoded).unwrap(), header);
        let mut corrupt = encoded;
        corrupt[12] ^= 1;
        assert_eq!(
            ChunkHeader::decode(&corrupt),
            Err(FormatError::HeaderCrcMismatch)
        );
    }
    #[test]
    fn record_round_trips_with_alignment() {
        let original = record(b"hello");
        let encoded = encode_record(&original).unwrap();
        assert_eq!(encoded.len() % 8, 0);
        let (decoded, consumed) = decode_record(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
    }
    #[test]
    fn record_rejects_corrupt_payload_footer_and_padding() {
        let mut encoded = encode_record(&record(b"hello")).unwrap();
        encoded[RECORD_HEADER_LEN] ^= 1;
        assert_eq!(
            decode_record(&encoded),
            Err(FormatError::PayloadCrcMismatch)
        );
        let mut encoded = encode_record(&record(b"hello")).unwrap();
        let last = encoded.len() - 1;
        encoded[last] = 1;
        assert_eq!(decode_record(&encoded), Err(FormatError::NonZeroPadding));
    }
    #[test]
    fn truncated_record_is_not_accepted() {
        let encoded = encode_record(&record(b"hello")).unwrap();
        assert_eq!(
            decode_record(&encoded[..encoded.len() - 1]),
            Err(FormatError::Truncated)
        );
    }

    fn corpus_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                // SplitMix64 makes this corpus reproducible without bringing a
                // fuzz-only dependency into ordinary CI.
                state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut value = state;
                value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                (value ^ (value >> 31)) as u8
            })
            .collect()
    }

    #[test]
    fn untrusted_decoder_fuzz_corpus_is_total_and_length_bounded() {
        let lengths = [0, 1, 2, 3, 7, 8, 63, 64, 127, 128, 129, 255, 1024];
        for seed in 0..64 {
            for len in lengths {
                let bytes = corpus_bytes(seed, len);
                assert!(std::panic::catch_unwind(|| {
                    let _ = ChunkHeader::decode(&bytes);
                    let _ = encoded_record_len_from_header(&bytes);
                    let _ = decode_record(&bytes);
                })
                .is_ok());
            }
        }

        // A CRC-valid header with a hostile length must be rejected before the
        // record decoder can copy a payload or derive an unchecked allocation.
        let mut oversized = encode_record(&record(b"")).unwrap();
        put_u64(&mut oversized, 20, u64::MAX);
        let crc = crc32c_with_zeroed_field(&oversized[..RECORD_HEADER_LEN], RECORD_CRC_OFFSET, 4);
        put_u32(&mut oversized, RECORD_CRC_OFFSET, crc);
        assert_eq!(
            encoded_record_len_from_header(&oversized),
            Err(FormatError::LengthOverflow)
        );
        assert_eq!(decode_record(&oversized), Err(FormatError::LengthOverflow));
    }
}
