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
    PutObject(ContentId, ObjectLocation),
    PutAlias(RepoId, GitOid, ContentId),
    PutChunk(u32, u64, ChunkMetadata),
}
impl CatalogBatch {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put_object_location(&mut self, id: ContentId, location: ObjectLocation) {
        self.operations.push(Operation::PutObject(id, location));
    }
    pub fn put_oid_alias(&mut self, repo: RepoId, oid: GitOid, id: ContentId) {
        self.operations.push(Operation::PutAlias(repo, oid, id));
    }
    pub fn put_chunk(&mut self, generation: u32, chunk_id: u64, metadata: ChunkMetadata) {
        self.operations
            .push(Operation::PutChunk(generation, chunk_id, metadata));
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
                Operation::PutObject(id, location) => {
                    staged.objects.insert(id, location);
                }
                Operation::PutChunk(generation, chunk_id, metadata) => {
                    staged.chunks.insert((generation, chunk_id), metadata);
                }
                Operation::PutAlias(repo, oid, id) => match staged.aliases.get(&(repo, oid)) {
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
}
