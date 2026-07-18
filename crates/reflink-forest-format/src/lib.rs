//! Explicit v1 encodings for cold-store chunk headers and object records.
//!
//! This crate is deliberately byte-oriented: it neither relies on Rust struct
//! layout nor silently accepts malformed tails.  Storage code can use
//! [`decode_record`] while scanning an open chunk and truncate at its first
//! error.

use core::fmt;
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use std::io::{self, BufReader, Cursor, Read, Write};

pub const FORMAT_VERSION: u16 = 1;
pub const CHUNK_HEADER_LEN: usize = 64;
/// Fixed trailer appended only to an immutable `.sealed` chunk.
///
/// `final_length` includes this trailer. `records_crc32c` covers the exact
/// encoded record byte stream (including each record's alignment padding),
/// but excludes the chunk header and this footer.
pub const SEALED_CHUNK_FOOTER_LEN: usize = 64;
pub const RECORD_HEADER_LEN: usize = 128;
pub const RECORD_FOOTER_LEN: usize = 20;
pub const RECORD_ALIGNMENT: usize = 8;
/// Maximum decoded bytes processed in one codec I/O operation.
///
/// Object readers must stream through this buffer instead of materializing an
/// attacker-controlled decompressed payload in one allocation.
pub const CODEC_STREAM_BUFFER_BYTES: usize = 64 * 1024;
/// The bounded Zstd history window accepted and emitted by the v1 codec.
///
/// Keeping the encoder and decoder at the same ceiling prevents an otherwise
/// small stored frame from forcing an unbounded decoder window allocation.
pub const ZSTD_WINDOW_LOG_MAX: u32 = 23;
/// Fixed v1 Zstd compression level. The codec is self-describing; this is a
/// writer policy, not part of a record's persistent interpretation.
pub const ZSTD_COMPRESSION_LEVEL: i32 = 3;

const CHUNK_MAGIC: &[u8; 8] = b"RFSCHNK\0";
const SEALED_CHUNK_FOOTER_MAGIC: &[u8; 8] = b"RFSSEAL\0";
const RECORD_MAGIC: &[u8; 4] = b"ROBJ";
const RECORD_END_MAGIC: &[u8; 8] = b"RENDOBJ\0";
const CHUNK_CRC_OFFSET: usize = 36;
const SEALED_CHUNK_FOOTER_CRC_OFFSET: usize = 32;
const RECORD_CRC_OFFSET: usize = 94;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkHeader {
    pub generation: u32,
    pub chunk_id: u64,
    pub created_unix_secs: u64,
    pub flags: u32,
}

/// Durable footer of an immutable sealed chunk.
///
/// The footer is written and synchronized before an `.open` chunk is renamed
/// to `.sealed`; readers can therefore reject a stale footer or an
/// interrupted seal without guessing whether its bytes are object records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SealedChunkFooter {
    pub record_count: u64,
    /// Exact file length, including this footer.
    pub final_length: u64,
    pub records_crc32c: u32,
}

impl SealedChunkFooter {
    pub fn encode(&self) -> [u8; SEALED_CHUNK_FOOTER_LEN] {
        let mut bytes = [0_u8; SEALED_CHUNK_FOOTER_LEN];
        bytes[..8].copy_from_slice(SEALED_CHUNK_FOOTER_MAGIC);
        put_u16(&mut bytes, 8, FORMAT_VERSION);
        put_u16(&mut bytes, 10, SEALED_CHUNK_FOOTER_LEN as u16);
        put_u64(&mut bytes, 12, self.record_count);
        put_u64(&mut bytes, 20, self.final_length);
        put_u32(&mut bytes, 28, self.records_crc32c);
        let crc = crc32c_with_zeroed_field(&bytes, SEALED_CHUNK_FOOTER_CRC_OFFSET, 4);
        put_u32(&mut bytes, SEALED_CHUNK_FOOTER_CRC_OFFSET, crc);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < SEALED_CHUNK_FOOTER_LEN {
            return Err(FormatError::Truncated);
        }
        let bytes = &bytes[..SEALED_CHUNK_FOOTER_LEN];
        if &bytes[..8] != SEALED_CHUNK_FOOTER_MAGIC {
            return Err(FormatError::BadMagic);
        }
        check_version(read_u16(bytes, 8))?;
        check_header_len(read_u16(bytes, 10) as usize, SEALED_CHUNK_FOOTER_LEN)?;
        if read_u32(bytes, SEALED_CHUNK_FOOTER_CRC_OFFSET)
            != crc32c_with_zeroed_field(bytes, SEALED_CHUNK_FOOTER_CRC_OFFSET, 4)
        {
            return Err(FormatError::HeaderCrcMismatch);
        }
        if bytes[36..].iter().any(|&byte| byte != 0) {
            return Err(FormatError::NonZeroReserved);
        }
        Ok(Self {
            record_count: read_u64(bytes, 12),
            final_length: read_u64(bytes, 20),
            records_crc32c: read_u32(bytes, 28),
        })
    }
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

/// Failure while encoding, decoding, or fully verifying an object's stored
/// payload.  Structural record decoding intentionally does not perform this
/// work so open-chunk recovery can remain bounded; consumers that expose raw
/// object bytes must call one of the helpers below.
#[derive(Debug)]
pub enum CodecError {
    Io(io::Error),
    RawLengthMismatch {
        expected: u64,
        actual: u64,
    },
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    /// A v1 `Codec::Zstd` payload must contain exactly one independent frame.
    TrailingZstdData,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "object codec I/O failed: {error}"),
            Self::RawLengthMismatch { expected, actual } => write!(
                f,
                "object codec produced {actual} raw bytes, expected {expected}"
            ),
            Self::ContentMismatch { .. } => {
                write!(f, "decoded object bytes do not match their ContentId")
            }
            Self::TrailingZstdData => {
                write!(
                    f,
                    "zstd object payload contains bytes after its first frame"
                )
            }
        }
    }
}
impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for CodecError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
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

/// Encodes one raw object payload using the requested v1 storage codec.
///
/// Zstd frames are deliberately independent (no dictionaries) and have a
/// bounded history window, so any reader can decode exactly one record
/// without retaining another record's data or accepting an unbounded window.
pub fn encode_object_payload(codec: Codec, raw: &[u8]) -> Result<Vec<u8>, CodecError> {
    match codec {
        Codec::Raw => Ok(raw.to_vec()),
        Codec::Zstd => {
            let mut encoder =
                zstd::stream::write::Encoder::new(Vec::new(), ZSTD_COMPRESSION_LEVEL)?;
            encoder.window_log(ZSTD_WINDOW_LOG_MAX)?;
            // The frame checksum is redundant with the record CRC and
            // ContentId, but cheaply detects malformed compressed content
            // before it is exposed as raw object bytes.
            encoder.include_checksum(true)?;
            encoder.write_all(raw)?;
            encoder.finish().map_err(CodecError::Io)
        }
    }
}

/// Decodes a record's stored payload into `writer` in fixed-size buffers and
/// verifies its declared raw length and internal ContentId.
///
/// `source` must expose exactly the stored payload bytes for this one record.
/// For `Codec::Zstd`, this rejects concatenated frames and trailing data. The
/// output never exceeds `raw_length`, even if a malicious frame claims a much
/// larger size.
pub fn decode_object_payload_to_writer<R: Read, W: Write>(
    kind: ObjectKind,
    codec: Codec,
    raw_length: u64,
    expected_content_id: ContentId,
    source: &mut R,
    writer: &mut W,
) -> Result<(), CodecError> {
    let mut validated = ValidatingObjectWriter::new(writer, kind, raw_length);
    match codec {
        Codec::Raw => copy_decoded(source, &mut validated)?,
        Codec::Zstd => {
            // A one-byte buffer prevents a successful first frame from
            // hiding a second frame in a large internal read-ahead buffer.
            let buffered = BufReader::with_capacity(1, source);
            let mut decoder = zstd::stream::read::Decoder::with_buffer(buffered)?.single_frame();
            decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
            copy_decoded(&mut decoder, &mut validated)?;
            let buffered = decoder.finish();
            if !buffered.buffer().is_empty() {
                return Err(CodecError::TrailingZstdData);
            }
            let source = buffered.into_inner();
            let mut trailing = [0_u8; 1];
            if source.read(&mut trailing)? != 0 {
                return Err(CodecError::TrailingZstdData);
            }
        }
    }
    validated.finish(expected_content_id)
}

/// Decodes a complete in-memory record payload after enforcing all raw-object
/// invariants. Callers that need an owned Git object use this helper; cold
/// hydration should instead use [`decode_object_payload_to_writer`] directly.
pub fn decode_object_payload(record: &ObjectRecord) -> Result<Vec<u8>, CodecError> {
    let mut raw = Vec::new();
    decode_object_payload_to_writer(
        record.kind,
        record.codec,
        record.raw_length,
        record.content_id,
        &mut Cursor::new(&record.payload),
        &mut raw,
    )?;
    Ok(raw)
}

/// Fully validates a record's stored codec payload without retaining its raw
/// bytes. This is the required verification before compaction republishes a
/// stored record into a different cold generation.
pub fn verify_object_record(record: &ObjectRecord) -> Result<(), CodecError> {
    decode_object_payload_to_writer(
        record.kind,
        record.codec,
        record.raw_length,
        record.content_id,
        &mut Cursor::new(&record.payload),
        &mut io::sink(),
    )
}

fn copy_decoded<R: Read, W: Write>(source: &mut R, writer: &mut W) -> Result<(), CodecError> {
    let mut buffer = [0_u8; CODEC_STREAM_BUFFER_BYTES];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..count])?;
    }
}

struct ValidatingObjectWriter<'a, W> {
    writer: &'a mut W,
    expected_length: u64,
    written: u64,
    hasher: reflink_forest_core::ContentHasher,
}

impl<'a, W: Write> ValidatingObjectWriter<'a, W> {
    fn new(writer: &'a mut W, kind: ObjectKind, expected_length: u64) -> Self {
        Self {
            writer,
            expected_length,
            written: 0,
            hasher: reflink_forest_core::ContentHasher::new(kind, expected_length),
        }
    }

    fn finish(self, expected_content_id: ContentId) -> Result<(), CodecError> {
        if self.written != self.expected_length {
            return Err(CodecError::RawLengthMismatch {
                expected: self.expected_length,
                actual: self.written,
            });
        }
        let actual = self.hasher.finalize();
        if actual != expected_content_id {
            return Err(CodecError::ContentMismatch {
                expected: expected_content_id,
                actual,
            });
        }
        Ok(())
    }
}

impl<W: Write> Write for ValidatingObjectWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let additional = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded object write length does not fit in u64",
            )
        })?;
        let next = self.written.checked_add(additional).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded object length overflowed u64",
            )
        })?;
        if next > self.expected_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded object exceeds its declared raw length",
            ));
        }
        let written = self.writer.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    fn zstd_record(payload: &[u8]) -> ObjectRecord {
        let mut record = record(payload);
        record.codec = Codec::Zstd;
        record.payload = encode_object_payload(Codec::Zstd, payload).unwrap();
        record
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
    fn sealed_chunk_footer_round_trips_and_checks_crc() {
        let footer = SealedChunkFooter {
            record_count: 17,
            final_length: 4_096,
            records_crc32c: 0x1234_5678,
        };
        let encoded = footer.encode();
        assert_eq!(SealedChunkFooter::decode(&encoded).unwrap(), footer);
        let mut corrupt = encoded;
        corrupt[20] ^= 1;
        assert_eq!(
            SealedChunkFooter::decode(&corrupt),
            Err(FormatError::HeaderCrcMismatch)
        );
        assert_eq!(
            SealedChunkFooter::decode(&encoded[..SEALED_CHUNK_FOOTER_LEN - 1]),
            Err(FormatError::Truncated)
        );
    }
    #[test]
    fn record_round_trip_raw_and_zstd() {
        let raw = b"one canonical payload repeated one canonical payload repeated";
        for original in [record(raw), zstd_record(raw)] {
            let encoded = encode_record(&original).unwrap();
            assert_eq!(encoded.len() % 8, 0);
            let (decoded, consumed) = decode_record(&encoded).unwrap();
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded, original);
            assert_eq!(decode_object_payload(&decoded).unwrap(), raw);
            verify_object_record(&decoded).unwrap();
        }
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

    #[test]
    fn decompression_corruption_length_and_content_id_fail_closed() {
        let payload = b"zstd corruption must never become a cache blob";
        let mut corrupted = zstd_record(payload);
        let last = corrupted.payload.len() - 1;
        corrupted.payload[last] ^= 0x80;
        assert!(decode_object_payload(&corrupted).is_err());

        let mut wrong_length = zstd_record(payload);
        wrong_length.raw_length += 1;
        assert!(matches!(
            decode_object_payload(&wrong_length),
            Err(CodecError::RawLengthMismatch { .. })
        ));

        let mut wrong_id = zstd_record(payload);
        wrong_id.content_id = ContentId::for_object(ObjectKind::Blob, b"different payload");
        assert!(matches!(
            decode_object_payload(&wrong_id),
            Err(CodecError::ContentMismatch { .. })
        ));
    }

    #[test]
    fn unknown_codec_tag_is_rejected_before_decompression() {
        let mut encoded = encode_record(&record(b"unknown codec")).unwrap();
        encoded[9] = 0xff;
        let crc = crc32c_with_zeroed_field(&encoded[..RECORD_HEADER_LEN], RECORD_CRC_OFFSET, 4);
        put_u32(&mut encoded, RECORD_CRC_OFFSET, crc);
        assert_eq!(
            decode_record(&encoded),
            Err(FormatError::InvalidCodec(0xff))
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
