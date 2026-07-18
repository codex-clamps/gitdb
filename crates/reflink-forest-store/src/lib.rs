//! Append-only chunk files and conservative open-tail recovery.
//!
//! This layer intentionally has no catalog dependency: callers must append,
//! `sync_data`, then atomically publish their index locations. A location is
//! therefore never returned as durable until [`ChunkWriter::sync_data`] has
//! completed successfully.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use reflink_forest_format::{
    crc32c, decode_record, encode_record, encoded_record_len_from_header, ChunkHeader, FormatError,
    ObjectRecord, CHUNK_HEADER_LEN, RECORD_HEADER_LEN,
};
use reflink_forest_index::{Catalog, CatalogBatch, CatalogError, ObjectLocation, RepoId};

/// A conservative MVP ceiling that prevents recovery from allocating an
/// attacker-controlled length. Production configuration will make this a
/// store limit and route larger objects through a streaming/spool path.
pub const MAX_RECOVERY_RECORD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Format(FormatError),
    NotAnOpenChunk,
    OffsetOverflow,
    Catalog(CatalogError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cold-store I/O error: {error}"),
            Self::Format(error) => write!(f, "cold-store format error: {error}"),
            Self::NotAnOpenChunk => write!(f, "chunk path must use the .open suffix"),
            Self::OffsetOverflow => write!(f, "chunk offset does not fit in u64"),
            Self::Catalog(error) => write!(f, "cold-store catalog error: {error:?}"),
        }
    }
}
impl std::error::Error for StoreError {}
impl From<io::Error> for StoreError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<FormatError> for StoreError {
    fn from(value: FormatError) -> Self {
        Self::Format(value)
    }
}
impl From<CatalogError> for StoreError {
    fn from(value: CatalogError) -> Self {
        Self::Catalog(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordLocation {
    pub offset: u64,
    pub record_length: u64,
}

pub struct ChunkWriter {
    path: PathBuf,
    file: File,
    next_offset: u64,
}

impl ChunkWriter {
    /// Creates a new open chunk and durably publishes its header and directory entry.
    pub fn create(path: impl AsRef<Path>, header: ChunkHeader) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if path.extension().and_then(|extension| extension.to_str()) != Some("open") {
            return Err(StoreError::NotAnOpenChunk);
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "chunk has no parent"))?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&header.encode())?;
        file.sync_data()?;
        File::open(parent)?.sync_all()?;
        Ok(Self {
            path,
            file,
            next_offset: CHUNK_HEADER_LEN as u64,
        })
    }

    /// Opens an existing open chunk after validating and recovering its tail.
    pub fn open_recovered(path: impl AsRef<Path>) -> Result<(Self, Recovery), StoreError> {
        let path = path.as_ref().to_path_buf();
        if path.extension().and_then(|extension| extension.to_str()) != Some("open") {
            return Err(StoreError::NotAnOpenChunk);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        let recovery = recover_file(&mut file)?;
        let next_offset = file.metadata()?.len();
        Ok((
            Self {
                path,
                file,
                next_offset,
            },
            recovery,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends exactly one self-contained object record. The returned location
    /// is not durable until `sync_data` returns successfully.
    pub fn append(&mut self, record: &ObjectRecord) -> Result<RecordLocation, StoreError> {
        let encoded = encode_record(record)?;
        let offset = self.next_offset;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&encoded)?;
        let record_length = u64::try_from(encoded.len()).map_err(|_| StoreError::OffsetOverflow)?;
        self.next_offset = self
            .next_offset
            .checked_add(record_length)
            .ok_or(StoreError::OffsetOverflow)?;
        Ok(RecordLocation {
            offset,
            record_length,
        })
    }

    /// Durably persists appended bytes before a catalog transaction can publish them.
    pub fn sync_data(&self) -> Result<(), StoreError> {
        self.file.sync_data().map_err(StoreError::Io)
    }

    /// Makes one object visible in `catalog` using the required durable order:
    /// append, synchronize chunk bytes, then apply the complete catalog batch.
    ///
    /// If catalog publication rejects the alias, the synchronized record is an
    /// unindexed orphan. That is safe and recoverable; no catalog entry ever
    /// points at unsynchronized bytes.
    pub fn append_and_index<C: Catalog>(
        &mut self,
        catalog: &mut C,
        repo: RepoId,
        generation: u32,
        chunk_id: u64,
        record: &ObjectRecord,
    ) -> Result<Option<RecordLocation>, StoreError> {
        let mut batch = CatalogBatch::new();
        if catalog.object_location(record.content_id).is_none() {
            let location = self.append(record)?;
            self.sync_data()?;
            batch.put_object_location(
                record.content_id,
                ObjectLocation {
                    generation,
                    chunk_id,
                    offset: location.offset,
                    record_length: location.record_length,
                    stored_length: u64::try_from(record.payload.len())
                        .map_err(|_| StoreError::OffsetOverflow)?,
                    raw_length: record.raw_length,
                    kind: record.kind,
                    codec: record.codec,
                    flags: record.flags,
                    payload_crc32c: crc32c(&record.payload),
                },
            );
            batch.put_oid_alias(repo, record.primary_oid, record.content_id);
            catalog.apply(batch)?;
            Ok(Some(location))
        } else {
            batch.put_oid_alias(repo, record.primary_oid, record.content_id);
            catalog.apply(batch)?;
            Ok(None)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovery {
    pub valid_records: u64,
    pub retained_bytes: u64,
    pub truncated_bytes: u64,
}

/// Validates an open chunk and truncates from its first invalid or incomplete
/// record. The header is never repaired: a bad header is a hard failure.
pub fn recover_open_chunk(path: impl AsRef<Path>) -> Result<Recovery, StoreError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    recover_file(&mut file)
}

fn recover_file(file: &mut File) -> Result<Recovery, StoreError> {
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0_u8; CHUNK_HEADER_LEN];
    file.read_exact(&mut header)?;
    ChunkHeader::decode(&header)?;
    let original_len = file.metadata()?.len();
    let mut offset = CHUNK_HEADER_LEN as u64;
    let mut valid_records = 0_u64;
    loop {
        if offset == original_len {
            break;
        }
        let remaining = original_len
            .checked_sub(offset)
            .ok_or(StoreError::OffsetOverflow)?;
        if remaining < RECORD_HEADER_LEN as u64 {
            break;
        }
        let mut header = [0_u8; RECORD_HEADER_LEN];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut header)?;
        let encoded_len = match encoded_record_len_from_header(&header) {
            Ok(length) if length <= MAX_RECOVERY_RECORD_BYTES => length,
            _ => break,
        };
        if u64::try_from(encoded_len).map_err(|_| StoreError::OffsetOverflow)? > remaining {
            break;
        }
        let mut bytes = vec![0_u8; encoded_len];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut bytes)?;
        match decode_record(&bytes) {
            Ok((_, consumed)) => {
                let consumed = u64::try_from(consumed).map_err(|_| StoreError::OffsetOverflow)?;
                offset = offset
                    .checked_add(consumed)
                    .ok_or(StoreError::OffsetOverflow)?;
                valid_records = valid_records
                    .checked_add(1)
                    .ok_or(StoreError::OffsetOverflow)?;
            }
            Err(_) => break,
        }
    }
    if offset != original_len {
        file.set_len(offset)?;
        file.sync_data()?;
    }
    Ok(Recovery {
        valid_records,
        retained_bytes: offset,
        truncated_bytes: original_len - offset,
    })
}

/// Reads and validates every record in a chunk without modifying it.
pub fn verify_chunk(path: impl AsRef<Path>) -> Result<u64, StoreError> {
    let bytes = fs::read(path)?;
    if bytes.len() < CHUNK_HEADER_LEN {
        return Err(StoreError::Format(FormatError::Truncated));
    }
    ChunkHeader::decode(&bytes[..CHUNK_HEADER_LEN])?;
    let mut offset = CHUNK_HEADER_LEN;
    let mut count = 0_u64;
    while offset < bytes.len() {
        let (_, consumed) = decode_record(&bytes[offset..])?;
        offset = offset
            .checked_add(consumed)
            .ok_or(StoreError::OffsetOverflow)?;
        count = count.checked_add(1).ok_or(StoreError::OffsetOverflow)?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
    use reflink_forest_format::{Codec, ObjectRecord};
    use reflink_forest_index::{Catalog, InMemoryCatalog};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_chunk() -> (PathBuf, PathBuf) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("reflink-forest-store-{nonce}"));
        fs::create_dir(&directory).unwrap();
        let chunk = directory.join("0000000000000001.open");
        (directory, chunk)
    }
    fn record(payload: &[u8]) -> ObjectRecord {
        ObjectRecord {
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: ContentId::for_object(ObjectKind::Blob, payload),
            primary_oid: GitOid::new(HashAlgorithm::Sha1, &[7; 20]).unwrap(),
            payload: payload.to_vec(),
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

    #[test]
    fn appended_records_verify_after_sync() {
        let (directory, path) = temporary_chunk();
        let mut writer = ChunkWriter::create(&path, header()).unwrap();
        let location = writer.append(&record(b"one")).unwrap();
        writer.append(&record(b"two")).unwrap();
        writer.sync_data().unwrap();
        assert_eq!(location.offset, CHUNK_HEADER_LEN as u64);
        assert_eq!(verify_chunk(&path).unwrap(), 2);
        drop(writer);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn recovery_discards_incomplete_tail() {
        let (directory, path) = temporary_chunk();
        let mut writer = ChunkWriter::create(&path, header()).unwrap();
        writer.append(&record(b"complete")).unwrap();
        writer.sync_data().unwrap();
        let complete_len = fs::metadata(&path).unwrap().len();
        drop(writer);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"ROBJ\x00\x01").unwrap();
        file.sync_data().unwrap();
        let recovered = recover_open_chunk(&path).unwrap();
        assert_eq!(recovered.valid_records, 1);
        assert_eq!(recovered.retained_bytes, complete_len);
        assert_eq!(recovered.truncated_bytes, 6);
        assert_eq!(verify_chunk(&path).unwrap(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn append_sync_then_catalog_commit_deduplicates() {
        let (directory, path) = temporary_chunk();
        let mut writer = ChunkWriter::create(&path, header()).unwrap();
        let mut catalog = InMemoryCatalog::default();
        let repo = RepoId([3; 16]);
        let object = record(b"deduplicated");

        assert!(writer
            .append_and_index(&mut catalog, repo, 1, 1, &object)
            .unwrap()
            .is_some());
        assert!(catalog.object_location(object.content_id).is_some());
        assert!(writer
            .append_and_index(&mut catalog, repo, 1, 1, &object)
            .unwrap()
            .is_none());
        assert_eq!(verify_chunk(&path).unwrap(), 1);

        drop(writer);
        fs::remove_dir_all(directory).unwrap();
    }
}
