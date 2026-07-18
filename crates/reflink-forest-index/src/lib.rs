//! Catalog-v1 key/value encodings and an atomic in-memory catalog.
//!
//! The in-memory implementation models the commit boundary required of the
//! eventual RocksDB adapter: a batch either completely commits or leaves every
//! catalog map unchanged.

use std::collections::HashMap;

use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_format::Codec;

pub const CATALOG_VERSION: u8 = 1;
pub const REPO_ID_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RepoId(pub [u8; REPO_ID_LEN]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectLocation {
    pub generation: u32,
    pub chunk_id: u64,
    pub offset: u64,
    pub record_length: u64,
    pub stored_length: u64,
    pub raw_length: u64,
    pub kind: ObjectKind,
    pub codec: Codec,
    pub flags: u16,
    pub payload_crc32c: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChunkState {
    Open = 1,
    Sealed = 2,
    Retired = 3,
}

impl ChunkState {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Open),
            2 => Some(Self::Sealed),
            3 => Some(Self::Retired),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkMetadata {
    pub state: ChunkState,
    pub size: u64,
    pub record_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    InvalidEncoding,
    UnsupportedVersion(u8),
    AliasConflict {
        repo: RepoId,
        oid: GitOid,
        existing: ContentId,
        requested: ContentId,
    },
    Backend(String),
}

/// Versioned `object_locations` key: version then ContentId.
pub fn encode_object_location_key(id: ContentId) -> [u8; 33] {
    let mut result = [0_u8; 33];
    result[0] = CATALOG_VERSION;
    result[1..].copy_from_slice(id.as_bytes());
    result
}
pub fn decode_object_location_key(input: &[u8]) -> Result<ContentId, CatalogError> {
    if input.len() != 33 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok(ContentId(input[1..].try_into().expect("fixed length")))
}

/// Versioned `object_locations` value, with only explicit big-endian fields.
pub fn encode_object_location_value(value: ObjectLocation) -> [u8; 53] {
    let mut out = [0_u8; 53];
    out[0] = CATALOG_VERSION;
    put_u32(&mut out, 1, value.generation);
    put_u64(&mut out, 5, value.chunk_id);
    put_u64(&mut out, 13, value.offset);
    put_u64(&mut out, 21, value.record_length);
    put_u64(&mut out, 29, value.stored_length);
    put_u64(&mut out, 37, value.raw_length);
    out[45] = value.kind.tag();
    out[46] = value.codec as u8;
    put_u16(&mut out, 47, value.flags);
    put_u32(&mut out, 49, value.payload_crc32c);
    out
}
pub fn decode_object_location_value(input: &[u8]) -> Result<ObjectLocation, CatalogError> {
    if input.len() != 53 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok(ObjectLocation {
        generation: read_u32(input, 1),
        chunk_id: read_u64(input, 5),
        offset: read_u64(input, 13),
        record_length: read_u64(input, 21),
        stored_length: read_u64(input, 29),
        raw_length: read_u64(input, 37),
        kind: ObjectKind::from_tag(input[45]).ok_or(CatalogError::InvalidEncoding)?,
        codec: codec(input[46])?,
        flags: read_u16(input, 47),
        payload_crc32c: read_u32(input, 49),
    })
}

/// Versioned repo-scoped alias key: version, RepoId, algorithm, length, OID.
pub fn encode_oid_alias_key(repo: RepoId, oid: &GitOid) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + REPO_ID_LEN + 2 + usize::from(oid.len()));
    out.push(CATALOG_VERSION);
    out.extend_from_slice(&repo.0);
    out.push(oid.algorithm().tag());
    out.push(oid.len());
    out.extend_from_slice(oid.as_bytes());
    out
}
pub fn decode_oid_alias_key(input: &[u8]) -> Result<(RepoId, GitOid), CatalogError> {
    if input.len() < 1 + REPO_ID_LEN + 2 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    let repo = RepoId(input[1..17].try_into().expect("fixed length"));
    let algorithm = HashAlgorithm::from_tag(input[17]).ok_or(CatalogError::InvalidEncoding)?;
    let len = usize::from(input[18]);
    if len != usize::from(algorithm.oid_len()) || input.len() != 19 + len {
        return Err(CatalogError::InvalidEncoding);
    }
    Ok((
        repo,
        GitOid::new(algorithm, &input[19..]).map_err(|_| CatalogError::InvalidEncoding)?,
    ))
}
pub fn encode_content_id_value(id: ContentId) -> [u8; 33] {
    encode_object_location_key(id)
}
pub fn decode_content_id_value(input: &[u8]) -> Result<ContentId, CatalogError> {
    decode_object_location_key(input)
}

/// Versioned `chunks` key: version, generation, chunk ID.
pub fn encode_chunk_key(generation: u32, chunk_id: u64) -> [u8; 13] {
    let mut out = [0_u8; 13];
    out[0] = CATALOG_VERSION;
    put_u32(&mut out, 1, generation);
    put_u64(&mut out, 5, chunk_id);
    out
}
pub fn decode_chunk_key(input: &[u8]) -> Result<(u32, u64), CatalogError> {
    if input.len() != 13 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok((read_u32(input, 1), read_u64(input, 5)))
}
pub fn encode_chunk_value(value: ChunkMetadata) -> [u8; 18] {
    let mut out = [0_u8; 18];
    out[0] = CATALOG_VERSION;
    out[1] = value.state as u8;
    put_u64(&mut out, 2, value.size);
    put_u64(&mut out, 10, value.record_count);
    out
}
pub fn decode_chunk_value(input: &[u8]) -> Result<ChunkMetadata, CatalogError> {
    if input.len() != 18 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok(ChunkMetadata {
        state: ChunkState::from_tag(input[1]).ok_or(CatalogError::InvalidEncoding)?,
        size: read_u64(input, 2),
        record_count: read_u64(input, 10),
    })
}

#[derive(Clone, Debug, Default)]
pub struct CatalogBatch {
    operations: Vec<Operation>,
}
#[derive(Clone, Debug)]
enum Operation {
    ObjectLocation(ContentId, ObjectLocation),
    OidAlias(RepoId, GitOid, ContentId),
    ChunkMetadata(u32, u64, ChunkMetadata),
}
impl CatalogBatch {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put_object_location(&mut self, id: ContentId, location: ObjectLocation) {
        self.operations
            .push(Operation::ObjectLocation(id, location));
    }
    pub fn put_oid_alias(&mut self, repo: RepoId, oid: GitOid, id: ContentId) {
        self.operations.push(Operation::OidAlias(repo, oid, id));
    }
    pub fn put_chunk(&mut self, generation: u32, chunk_id: u64, metadata: ChunkMetadata) {
        self.operations
            .push(Operation::ChunkMetadata(generation, chunk_id, metadata));
    }
}

pub trait Catalog {
    fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError>;
    fn object_location(&self, id: ContentId) -> Option<ObjectLocation>;
    fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId>;
    fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryCatalog {
    objects: HashMap<ContentId, ObjectLocation>,
    aliases: HashMap<(RepoId, GitOid), ContentId>,
    chunks: HashMap<(u32, u64), ChunkMetadata>,
}
impl Catalog for InMemoryCatalog {
    fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
        // Apply to a clone: no error can expose a partially committed batch.
        let mut staged = self.clone();
        for operation in batch.operations {
            match operation {
                Operation::ObjectLocation(id, location) => {
                    staged.objects.insert(id, location);
                }
                Operation::ChunkMetadata(generation, chunk_id, metadata) => {
                    staged.chunks.insert((generation, chunk_id), metadata);
                }
                Operation::OidAlias(repo, oid, id) => match staged.aliases.get(&(repo, oid)) {
                    Some(&existing) if existing != id => {
                        return Err(CatalogError::AliasConflict {
                            repo,
                            oid,
                            existing,
                            requested: id,
                        })
                    }
                    _ => {
                        staged.aliases.insert((repo, oid), id);
                    }
                },
            }
        }
        *self = staged;
        Ok(())
    }
    fn object_location(&self, id: ContentId) -> Option<ObjectLocation> {
        self.objects.get(&id).copied()
    }
    fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId> {
        self.aliases.get(&(repo, *oid)).copied()
    }
    fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata> {
        self.chunks.get(&(generation, chunk_id)).copied()
    }
}

/// RocksDB column families used by the v1 catalog adapter.
#[cfg(feature = "rocksdb-backend")]
pub const ROCKSDB_COLUMN_FAMILIES: [&str; 3] = ["object_locations", "oid_aliases", "chunks"];

/// RocksDB-backed catalog with synchronous, atomic write batches.
///
/// Alias conflict detection assumes the store's single-writer daemon contract.
/// A multi-process writer implementation needs transaction/CAS semantics.
#[cfg(feature = "rocksdb-backend")]
pub struct RocksDbCatalog {
    db: rocksdb::DB,
}

#[cfg(feature = "rocksdb-backend")]
impl RocksDbCatalog {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, rocksdb::Error> {
        let mut options = rocksdb::Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let descriptors: Vec<_> = ROCKSDB_COLUMN_FAMILIES
            .into_iter()
            .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, rocksdb::Options::default()))
            .collect();
        Ok(Self {
            db: rocksdb::DB::open_cf_descriptors(&options, path, descriptors)?,
        })
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily, CatalogError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| CatalogError::Backend(format!("missing RocksDB column family {name}")))
    }
}

#[cfg(feature = "rocksdb-backend")]
impl Catalog for RocksDbCatalog {
    fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
        let object_cf = self.cf("object_locations")?;
        let alias_cf = self.cf("oid_aliases")?;
        let chunk_cf = self.cf("chunks")?;
        let mut pending_aliases = HashMap::new();

        // Validate all conflicts before the atomic write. A rejected batch has
        // no preceding writes committed.
        for operation in &batch.operations {
            if let Operation::OidAlias(repo, oid, requested) = operation {
                let key = encode_oid_alias_key(*repo, oid);
                let existing = match pending_aliases.get(&(*repo, *oid)) {
                    Some(id) => Some(*id),
                    None => self
                        .db
                        .get_cf(alias_cf, key)
                        .map_err(|error| CatalogError::Backend(error.to_string()))?
                        .map(|value| decode_content_id_value(&value))
                        .transpose()?,
                };
                if let Some(existing) = existing {
                    if existing != *requested {
                        return Err(CatalogError::AliasConflict {
                            repo: *repo,
                            oid: *oid,
                            existing,
                            requested: *requested,
                        });
                    }
                }
                pending_aliases.insert((*repo, *oid), *requested);
            }
        }

        let mut writes = rocksdb::WriteBatch::default();
        for operation in batch.operations {
            match operation {
                Operation::ObjectLocation(id, location) => writes.put_cf(
                    object_cf,
                    encode_object_location_key(id),
                    encode_object_location_value(location),
                ),
                Operation::OidAlias(repo, oid, id) => writes.put_cf(
                    alias_cf,
                    encode_oid_alias_key(repo, &oid),
                    encode_content_id_value(id),
                ),
                Operation::ChunkMetadata(generation, chunk_id, metadata) => writes.put_cf(
                    chunk_cf,
                    encode_chunk_key(generation, chunk_id),
                    encode_chunk_value(metadata),
                ),
            }
        }
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        self.db
            .write_opt(writes, &options)
            .map_err(|error| CatalogError::Backend(error.to_string()))
    }

    fn object_location(&self, id: ContentId) -> Option<ObjectLocation> {
        let value = self
            .db
            .get_cf(
                self.cf("object_locations").ok()?,
                encode_object_location_key(id),
            )
            .ok()??;
        decode_object_location_value(&value).ok()
    }
    fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId> {
        let value = self
            .db
            .get_cf(
                self.cf("oid_aliases").ok()?,
                encode_oid_alias_key(repo, oid),
            )
            .ok()??;
        decode_content_id_value(&value).ok()
    }
    fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata> {
        let value = self
            .db
            .get_cf(
                self.cf("chunks").ok()?,
                encode_chunk_key(generation, chunk_id),
            )
            .ok()??;
        decode_chunk_value(&value).ok()
    }
}

fn check_version(version: u8) -> Result<(), CatalogError> {
    if version == CATALOG_VERSION {
        Ok(())
    } else {
        Err(CatalogError::UnsupportedVersion(version))
    }
}
fn codec(tag: u8) -> Result<Codec, CatalogError> {
    match tag {
        0 => Ok(Codec::Raw),
        1 => Ok(Codec::Zstd),
        _ => Err(CatalogError::InvalidEncoding),
    }
}
fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}
fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(
        input[offset..offset + 2]
            .try_into()
            .expect("validated length"),
    )
}
fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("validated length"),
    )
}
fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(
        input[offset..offset + 8]
            .try_into()
            .expect("validated length"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(byte: u8) -> ContentId {
        ContentId([byte; 32])
    }
    fn oid() -> GitOid {
        GitOid::new(HashAlgorithm::Sha1, &[7; 20]).unwrap()
    }
    fn location() -> ObjectLocation {
        ObjectLocation {
            generation: 1,
            chunk_id: 2,
            offset: 3,
            record_length: 4,
            stored_length: 5,
            raw_length: 6,
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 7,
            payload_crc32c: 8,
        }
    }
    #[test]
    fn keys_and_values_are_versioned_and_round_trip() {
        let repo = RepoId([9; 16]);
        let object = location();
        assert_eq!(
            decode_object_location_key(&encode_object_location_key(id(1))).unwrap(),
            id(1)
        );
        assert_eq!(
            decode_object_location_value(&encode_object_location_value(object)).unwrap(),
            object
        );
        let alias = encode_oid_alias_key(repo, &oid());
        assert_eq!(decode_oid_alias_key(&alias).unwrap(), (repo, oid()));
        let chunk = ChunkMetadata {
            state: ChunkState::Sealed,
            size: 33,
            record_count: 44,
        };
        assert_eq!(
            decode_chunk_value(&encode_chunk_value(chunk)).unwrap(),
            chunk
        );
    }
    #[test]
    fn unknown_version_is_rejected() {
        assert_eq!(
            decode_object_location_key(&[2; 33]),
            Err(CatalogError::UnsupportedVersion(2))
        );
    }
    #[test]
    fn alias_conflict_is_rejected_without_partial_batch_commit() {
        let repo = RepoId([1; 16]);
        let mut catalog = InMemoryCatalog::default();
        let mut initial = CatalogBatch::new();
        initial.put_oid_alias(repo, oid(), id(1));
        catalog.apply(initial).unwrap();
        let mut conflicting = CatalogBatch::new();
        conflicting.put_object_location(id(2), location());
        conflicting.put_oid_alias(repo, oid(), id(2));
        assert!(matches!(
            catalog.apply(conflicting),
            Err(CatalogError::AliasConflict { .. })
        ));
        assert_eq!(catalog.oid_alias(repo, &oid()), Some(id(1)));
        assert_eq!(catalog.object_location(id(2)), None);
    }
    #[test]
    fn successful_batch_is_visible_as_one_commit() {
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_object_location(id(3), location());
        batch.put_chunk(
            1,
            2,
            ChunkMetadata {
                state: ChunkState::Open,
                size: 4,
                record_count: 5,
            },
        );
        catalog.apply(batch).unwrap();
        assert_eq!(catalog.object_location(id(3)), Some(location()));
        assert_eq!(
            catalog.chunk(1, 2),
            Some(ChunkMetadata {
                state: ChunkState::Open,
                size: 4,
                record_count: 5
            })
        );
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocksdb_batch_survives_reopen() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let path = std::env::temp_dir().join(format!(
            "reflink-forest-index-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let repo = RepoId([8; 16]);
        let object_id = id(4);
        {
            let mut catalog = RocksDbCatalog::open(&path).unwrap();
            let mut batch = CatalogBatch::new();
            batch.put_object_location(object_id, location());
            batch.put_oid_alias(repo, oid(), object_id);
            catalog.apply(batch).unwrap();
        }
        let catalog = RocksDbCatalog::open(&path).unwrap();
        assert_eq!(catalog.object_location(object_id), Some(location()));
        assert_eq!(catalog.oid_alias(repo, &oid()), Some(object_id));
        drop(catalog);
        std::fs::remove_dir_all(path).unwrap();
    }
}
