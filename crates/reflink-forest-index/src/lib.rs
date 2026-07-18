//! Catalog-v1 key/value encodings and an atomic in-memory catalog.
//!
//! The in-memory implementation models the commit boundary required of the
//! eventual RocksDB adapter: a batch either completely commits or leaves every
//! catalog map unchanged.

use std::collections::{HashMap, HashSet};

use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_format::Codec;

pub const CATALOG_VERSION: u8 = 1;
pub const REPO_ID_LEN: usize = 16;
pub const SNAPSHOT_ID_LEN: usize = 16;
pub const WORKSPACE_ID_LEN: usize = 16;
pub const GC_PIN_ID_LEN: usize = 16;

/// The fixed metadata key that identifies the generation new readers should
/// use. Its value is an encoded unsigned 32-bit generation number.
pub const CURRENT_GENERATION_META_KEY: &[u8] = b"current_generation";

/// Metadata marker persisted while a locations-only catalog rebuild is in
/// progress. The marker is intentionally separate from the current-generation
/// metadata: an interrupted rebuild must fail closed even when the active
/// generation itself remains valid. It is reserved for
/// [`ObjectLocationRebuildCatalog`]; ordinary [`CatalogBatch`] metadata writes
/// cannot mutate it.
pub const OBJECT_LOCATION_REBUILD_META_KEY: &[u8] = b"object_location_rebuild_v1";
#[cfg(feature = "rocksdb-backend")]
const OBJECT_LOCATION_REBUILD_IN_PROGRESS_MARKER: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct RepoId(pub [u8; REPO_ID_LEN]);

/// Stable identity of one imported repository snapshot.
///
/// The import manifest owns the snapshot's descriptive fields. The catalog
/// records only whether that manifest is visible as a GC root, so a failed or
/// incomplete import cannot retain cold data accidentally.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct SnapshotId(pub [u8; SNAPSHOT_ID_LEN]);

/// Stable identifier for a published workspace.
///
/// As with repository IDs, the catalog stores this value as raw bytes rather
/// than a textual UUID so it is independent of any presentation format.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct WorkspaceId(pub [u8; WORKSPACE_ID_LEN]);

/// Stable identity for an explicit cold-generation retention pin.
///
/// These pins are for durable operations such as a checkpoint or an
/// in-progress compaction. Workspace pins intentionally use their workspace
/// identity instead, so deleting a workspace never risks deleting an
/// unrelated operational pin.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct GcPinId(pub [u8; GC_PIN_ID_LEN]);

/// Visibility of a repository snapshot in the catalog.
///
/// Only `Ready` snapshots are roots during the GC mark phase. `Incomplete`
/// is persisted so recovery can distinguish an unfinished import from a
/// snapshot that was intentionally deleted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SnapshotVisibility {
    Incomplete = 1,
    Ready = 2,
}
impl SnapshotVisibility {
    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Incomplete),
            2 => Some(Self::Ready),
            _ => None,
        }
    }
}

/// A repository snapshot record discovered during durable catalog scans.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepositorySnapshot {
    pub repository: RepoId,
    pub snapshot: SnapshotId,
    pub visibility: SnapshotVisibility,
}

/// A cold-generation retention pin discovered during durable catalog scans.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GcPin {
    pub id: GcPinId,
    pub generation: u32,
}

/// One durable starting point for the GC mark phase or an old-generation
/// retention decision.
///
/// A compactor resolves ready snapshot IDs to their durable manifests and
/// walks the referenced Git object graph. Generation pins are independent:
/// they keep an old generation available until a workspace or operation no
/// longer needs it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GcRoot {
    RepositorySnapshot {
        repository: RepoId,
        snapshot: SnapshotId,
    },
    WorkspacePin {
        workspace: WorkspaceId,
        generation: u32,
    },
    ExplicitPin {
        pin: GcPin,
    },
}

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

/// One object-location record discovered during a streaming catalog scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectLocationEntry {
    pub content_id: ContentId,
    pub location: ObjectLocation,
}

/// One Git-object alias record discovered during a streaming catalog scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OidAliasEntry {
    pub repository: RepoId,
    pub oid: GitOid,
    pub content_id: ContentId,
}

/// One chunk metadata record discovered during a streaming catalog scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkEntry {
    pub generation: u32,
    pub chunk_id: u64,
    pub metadata: ChunkMetadata,
}

/// Durable state of the locations-only rebuild protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectLocationRebuildState {
    Idle,
    InProgress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogError {
    InvalidEncoding,
    UnsupportedVersion(u8),
    UnsupportedOperation(&'static str),
    ObjectLocationRebuildInProgress,
    ObjectLocationRebuildNotInProgress,
    DuplicateRebuiltObjectLocation(ContentId),
    AliasConflict {
        repo: RepoId,
        oid: GitOid,
        existing: ContentId,
        requested: ContentId,
    },
    Backend(String),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding => write!(formatter, "invalid catalog-v1 encoding"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported catalog-v1 version {version}")
            }
            Self::UnsupportedOperation(operation) => {
                write!(formatter, "catalog backend does not support {operation}")
            }
            Self::ObjectLocationRebuildInProgress => {
                write!(formatter, "object-location rebuild is already in progress")
            }
            Self::ObjectLocationRebuildNotInProgress => {
                write!(formatter, "object-location rebuild is not in progress")
            }
            Self::DuplicateRebuiltObjectLocation(id) => {
                write!(
                    formatter,
                    "rebuilt object-location for {id:?} is duplicated"
                )
            }
            Self::AliasConflict {
                repo,
                oid,
                existing,
                requested,
            } => write!(
                formatter,
                "repository {:?} alias {:?} already names {:?}, not {:?}",
                repo, oid, existing, requested
            ),
            Self::Backend(error) => write!(formatter, "catalog backend error: {error}"),
        }
    }
}

impl std::error::Error for CatalogError {}

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

/// Versioned `repositories` key: version then RepoId.
pub fn encode_repository_key(id: RepoId) -> [u8; 17] {
    let mut out = [0_u8; 17];
    out[0] = CATALOG_VERSION;
    out[1..].copy_from_slice(&id.0);
    out
}

/// Decodes a versioned `repositories` key.
pub fn decode_repository_key(input: &[u8]) -> Result<RepoId, CatalogError> {
    if input.len() != 17 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok(RepoId(
        input[1..].try_into().expect("fixed repository ID length"),
    ))
}

/// Versioned `repo_snapshots` key: version, RepoId, then SnapshotId.
pub fn encode_repository_snapshot_key(repository: RepoId, snapshot: SnapshotId) -> [u8; 33] {
    let mut out = [0_u8; 33];
    out[0] = CATALOG_VERSION;
    out[1..17].copy_from_slice(&repository.0);
    out[17..].copy_from_slice(&snapshot.0);
    out
}

/// Decodes a versioned `repo_snapshots` key.
pub fn decode_repository_snapshot_key(input: &[u8]) -> Result<(RepoId, SnapshotId), CatalogError> {
    if input.len() != 33 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok((
        RepoId(input[1..17].try_into().expect("fixed repository ID length")),
        SnapshotId(input[17..].try_into().expect("fixed snapshot ID length")),
    ))
}

/// Versioned `repo_snapshots` visibility value.
pub fn encode_snapshot_visibility_value(value: SnapshotVisibility) -> [u8; 2] {
    [CATALOG_VERSION, value as u8]
}

/// Decodes a versioned `repo_snapshots` visibility value.
pub fn decode_snapshot_visibility_value(input: &[u8]) -> Result<SnapshotVisibility, CatalogError> {
    if input.len() != 2 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    SnapshotVisibility::from_tag(input[1]).ok_or(CatalogError::InvalidEncoding)
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

/// Encodes an arbitrary byte key for a versioned catalog column family.
///
/// Callers that need a different logical key space use a distinct column
/// family, so the byte sequence after the version is intentionally opaque and
/// need not be UTF-8.
pub fn encode_opaque_key(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + key.len());
    out.push(CATALOG_VERSION);
    out.extend_from_slice(key);
    out
}

/// Decodes a versioned opaque key, returning its original byte sequence.
pub fn decode_opaque_key(input: &[u8]) -> Result<Vec<u8>, CatalogError> {
    let (&version, value) = input.split_first().ok_or(CatalogError::InvalidEncoding)?;
    check_version(version)?;
    Ok(value.to_vec())
}

/// Encodes an opaque record value with its catalog-format version.
pub fn encode_opaque_value(value: &[u8]) -> Vec<u8> {
    encode_opaque_key(value)
}

/// Decodes an opaque record value after checking its catalog-format version.
pub fn decode_opaque_value(input: &[u8]) -> Result<Vec<u8>, CatalogError> {
    decode_opaque_key(input)
}

/// Versioned `meta` key encoding.
pub fn encode_meta_key(key: &[u8]) -> Vec<u8> {
    encode_opaque_key(key)
}

/// Decodes a versioned `meta` key.
pub fn decode_meta_key(input: &[u8]) -> Result<Vec<u8>, CatalogError> {
    decode_opaque_key(input)
}

/// Versioned encoding for the `current_generation` metadata value.
pub fn encode_current_generation_value(generation: u32) -> [u8; 5] {
    let mut out = [0_u8; 5];
    out[0] = CATALOG_VERSION;
    put_u32(&mut out, 1, generation);
    out
}

/// Decodes the `current_generation` metadata value.
pub fn decode_current_generation_value(input: &[u8]) -> Result<u32, CatalogError> {
    if input.len() != 5 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok(read_u32(input, 1))
}

#[cfg(feature = "rocksdb-backend")]
fn decode_object_location_rebuild_marker(
    input: &[u8],
) -> Result<ObjectLocationRebuildState, CatalogError> {
    match decode_opaque_value(input)?.as_slice() {
        [OBJECT_LOCATION_REBUILD_IN_PROGRESS_MARKER] => Ok(ObjectLocationRebuildState::InProgress),
        _ => Err(CatalogError::InvalidEncoding),
    }
}

/// Versioned `workspaces` key: version then WorkspaceId.
pub fn encode_workspace_key(id: WorkspaceId) -> [u8; 17] {
    let mut out = [0_u8; 17];
    out[0] = CATALOG_VERSION;
    out[1..].copy_from_slice(&id.0);
    out
}

/// Decodes a versioned `workspaces` key.
pub fn decode_workspace_key(input: &[u8]) -> Result<WorkspaceId, CatalogError> {
    if input.len() != 17 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    Ok(WorkspaceId(
        input[1..].try_into().expect("fixed workspace ID length"),
    ))
}

/// Versioned `workspace_names` key. Workspace names are raw bytes, not UTF-8.
pub fn encode_workspace_name_key(name: &[u8]) -> Vec<u8> {
    encode_opaque_key(name)
}

/// Decodes a versioned `workspace_names` key.
pub fn decode_workspace_name_key(input: &[u8]) -> Result<Vec<u8>, CatalogError> {
    decode_opaque_key(input)
}

/// Versioned workspace-ID value used by `workspace_names`.
pub fn encode_workspace_id_value(id: WorkspaceId) -> [u8; 17] {
    encode_workspace_key(id)
}

/// Decodes a workspace-ID value used by `workspace_names`.
pub fn decode_workspace_id_value(input: &[u8]) -> Result<WorkspaceId, CatalogError> {
    decode_workspace_key(input)
}

/// Versioned `pins` key: version then WorkspaceId.
pub fn encode_workspace_pin_key(id: WorkspaceId) -> [u8; 17] {
    encode_workspace_key(id)
}

/// Decodes a versioned `pins` key.
pub fn decode_workspace_pin_key(input: &[u8]) -> Result<WorkspaceId, CatalogError> {
    decode_workspace_key(input)
}

/// Versioned generation value used by `pins`.
pub fn encode_workspace_pin_value(generation: u32) -> [u8; 5] {
    encode_current_generation_value(generation)
}

/// Decodes the generation value used by `pins`.
pub fn decode_workspace_pin_value(input: &[u8]) -> Result<u32, CatalogError> {
    decode_current_generation_value(input)
}

// `pins` already contains the legacy-compatible workspace key shape
// `[version, workspace-id]`. Explicit operational pins use a different fixed
// length and a domain byte, so every decoded key remains unambiguous.
const EXPLICIT_GC_PIN_KEY_TAG: u8 = 1;

/// Versioned `pins` key for an explicit operational generation pin.
pub fn encode_gc_pin_key(id: GcPinId) -> [u8; 18] {
    let mut out = [0_u8; 18];
    out[0] = CATALOG_VERSION;
    out[1] = EXPLICIT_GC_PIN_KEY_TAG;
    out[2..].copy_from_slice(&id.0);
    out
}

/// Decodes a versioned explicit operational pin key.
pub fn decode_gc_pin_key(input: &[u8]) -> Result<GcPinId, CatalogError> {
    if input.len() != 18 {
        return Err(CatalogError::InvalidEncoding);
    }
    check_version(input[0])?;
    if input[1] != EXPLICIT_GC_PIN_KEY_TAG {
        return Err(CatalogError::InvalidEncoding);
    }
    Ok(GcPinId(
        input[2..].try_into().expect("fixed GC pin ID length"),
    ))
}

/// Versioned generation value used by explicit operational pins.
pub fn encode_gc_pin_value(generation: u32) -> [u8; 5] {
    encode_workspace_pin_value(generation)
}

/// Decodes the generation value used by explicit operational pins.
pub fn decode_gc_pin_value(input: &[u8]) -> Result<u32, CatalogError> {
    decode_workspace_pin_value(input)
}

/// Versioned `jobs` key. Job IDs are deliberately opaque to the catalog.
pub fn encode_job_key(job_id: &[u8]) -> Vec<u8> {
    encode_opaque_key(job_id)
}

/// Decodes a versioned `jobs` key.
pub fn decode_job_key(input: &[u8]) -> Result<Vec<u8>, CatalogError> {
    decode_opaque_key(input)
}

#[derive(Clone, Debug, Default)]
pub struct CatalogBatch {
    operations: Vec<Operation>,
}
#[derive(Clone, Debug)]
enum Operation {
    ObjectLocation(ContentId, ObjectLocation),
    OidAlias(RepoId, GitOid, ContentId),
    Repository(RepoId, Vec<u8>),
    DeleteRepository(RepoId),
    RepositorySnapshot(RepoId, SnapshotId, SnapshotVisibility),
    DeleteRepositorySnapshot(RepoId, SnapshotId),
    ChunkMetadata(u32, u64, ChunkMetadata),
    Meta(Vec<u8>, Vec<u8>),
    Workspace(WorkspaceId, Vec<u8>),
    WorkspaceName(Vec<u8>, WorkspaceId),
    WorkspacePin(WorkspaceId, u32),
    DeleteWorkspacePin(WorkspaceId),
    GcPin(GcPinId, u32),
    DeleteGcPin(GcPinId),
    Job(Vec<u8>, Vec<u8>),
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
    /// Stores opaque, versioned repository metadata. The import layer owns
    /// the record format; this entry is removed atomically with a repository's
    /// snapshot visibility records by [`Catalog::delete_repository`].
    pub fn put_repository(&mut self, id: RepoId, record: impl AsRef<[u8]>) {
        self.operations
            .push(Operation::Repository(id, record.as_ref().to_vec()));
    }
    /// Removes an opaque repository metadata record. Prefer
    /// [`Catalog::delete_repository`] for normal deletion so no visible
    /// snapshots are accidentally left behind.
    pub fn delete_repository(&mut self, id: RepoId) {
        self.operations.push(Operation::DeleteRepository(id));
    }
    /// Sets the durable visibility of one repository snapshot. The import
    /// manifest must be synchronized before callers publish `Ready`.
    pub fn put_repository_snapshot(
        &mut self,
        repository: RepoId,
        snapshot: SnapshotId,
        visibility: SnapshotVisibility,
    ) {
        self.operations.push(Operation::RepositorySnapshot(
            repository, snapshot, visibility,
        ));
    }
    /// Removes one snapshot from catalog visibility. It ceases to be a GC
    /// root in the same synchronous write that removes this record.
    pub fn delete_repository_snapshot(&mut self, repository: RepoId, snapshot: SnapshotId) {
        self.operations
            .push(Operation::DeleteRepositorySnapshot(repository, snapshot));
    }
    pub fn put_chunk(&mut self, generation: u32, chunk_id: u64, metadata: ChunkMetadata) {
        self.operations
            .push(Operation::ChunkMetadata(generation, chunk_id, metadata));
    }
    /// Stores an opaque, versioned metadata value under an opaque byte key.
    pub fn put_meta(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.operations.push(Operation::Meta(
            key.as_ref().to_vec(),
            value.as_ref().to_vec(),
        ));
    }
    /// Atomically selects the generation readers should use with the rest of
    /// this batch.
    pub fn put_current_generation(&mut self, generation: u32) {
        self.operations.push(Operation::Meta(
            CURRENT_GENERATION_META_KEY.to_vec(),
            generation.to_be_bytes().to_vec(),
        ));
    }
    /// Stores an opaque workspace record. The record format is owned by the
    /// workspace layer, while its enclosing catalog value remains versioned.
    pub fn put_workspace(&mut self, id: WorkspaceId, record: impl AsRef<[u8]>) {
        self.operations
            .push(Operation::Workspace(id, record.as_ref().to_vec()));
    }
    /// Maps an opaque workspace name to its stable ID.
    pub fn put_workspace_name(&mut self, name: impl AsRef<[u8]>, id: WorkspaceId) {
        self.operations
            .push(Operation::WorkspaceName(name.as_ref().to_vec(), id));
    }
    /// Pins a workspace to a cold-store generation, preventing that generation
    /// from being reclaimed until the workspace pin is removed or replaced.
    pub fn put_workspace_pin(&mut self, id: WorkspaceId, generation: u32) {
        self.operations
            .push(Operation::WorkspacePin(id, generation));
    }
    /// Removes a workspace's old-generation retention pin.
    pub fn delete_workspace_pin(&mut self, id: WorkspaceId) {
        self.operations.push(Operation::DeleteWorkspacePin(id));
    }
    /// Adds or replaces an explicit operational generation pin.
    pub fn put_gc_pin(&mut self, id: GcPinId, generation: u32) {
        self.operations.push(Operation::GcPin(id, generation));
    }
    /// Removes an explicit operational generation pin.
    pub fn delete_gc_pin(&mut self, id: GcPinId) {
        self.operations.push(Operation::DeleteGcPin(id));
    }
    /// Stores an opaque durable job record. Job-ID allocation and record
    /// contents are owned by the daemon layer.
    pub fn put_job(&mut self, job_id: impl AsRef<[u8]>, record: impl AsRef<[u8]>) {
        self.operations.push(Operation::Job(
            job_id.as_ref().to_vec(),
            record.as_ref().to_vec(),
        ));
    }
}

fn reject_direct_rebuild_marker_mutation(batch: &CatalogBatch) -> Result<(), CatalogError> {
    if batch.operations.iter().any(|operation| {
        matches!(
            operation,
            Operation::Meta(key, _) if key.as_slice() == OBJECT_LOCATION_REBUILD_META_KEY
        )
    }) {
        return Err(CatalogError::UnsupportedOperation(
            "direct object-location rebuild metadata mutation",
        ));
    }
    Ok(())
}

pub trait Catalog {
    fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError>;
    fn object_location(&self, id: ContentId) -> Option<ObjectLocation>;
    /// Returns the durable locations-only rebuild state.
    ///
    /// Backends that predate the rebuild protocol report `Idle`, preserving
    /// source compatibility while requiring rebuild callers to opt into
    /// [`ObjectLocationRebuildCatalog`] before mutating locations.
    fn object_location_rebuild_state(&self) -> Result<ObjectLocationRebuildState, CatalogError> {
        Ok(ObjectLocationRebuildState::Idle)
    }
    /// Visits every object location in deterministic key order.
    ///
    /// A verifier must complete this scan before starting a rebuild, because a
    /// rebuild intentionally clears this collection first.
    fn visit_object_locations(
        &self,
        _visitor: &mut dyn FnMut(ObjectLocationEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        Err(CatalogError::UnsupportedOperation(
            "object-location enumeration",
        ))
    }
    /// Visits every OID alias in deterministic key order.
    ///
    /// Alias records remain available while a locations-only rebuild is in
    /// progress so a recovery scan can verify the aliases that the rebuild
    /// deliberately preserves.
    fn visit_oid_aliases(
        &self,
        _visitor: &mut dyn FnMut(OidAliasEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        Err(CatalogError::UnsupportedOperation("OID-alias enumeration"))
    }
    /// Visits every chunk record in deterministic key order.
    fn visit_chunks(
        &self,
        _visitor: &mut dyn FnMut(ChunkEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        Err(CatalogError::UnsupportedOperation("chunk enumeration"))
    }
    fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId>;
    /// Returns opaque repository metadata after checking the catalog version.
    fn repository(&self, _id: RepoId) -> Option<Vec<u8>> {
        None
    }
    /// Reads one repository snapshot visibility record.
    fn repository_snapshot(
        &self,
        _repository: RepoId,
        _snapshot: SnapshotId,
    ) -> Option<SnapshotVisibility> {
        None
    }
    /// Enumerates snapshot visibility records in deterministic order.
    ///
    /// Implementations must return an error instead of silently skipping an
    /// invalid stored record: a compactor needs fail-closed root discovery.
    fn repository_snapshots(&self) -> Result<Vec<RepositorySnapshot>, CatalogError> {
        Ok(Vec::new())
    }
    /// Deletes repository metadata and every visible or incomplete snapshot
    /// record in a single synchronous catalog batch.
    ///
    /// Snapshot manifests are intentionally not deleted here. Once the
    /// catalog batch commits they are no longer visible roots and can be
    /// reclaimed asynchronously, just like retired chunk generations.
    fn delete_repository(&mut self, repository: RepoId) -> Result<(), CatalogError> {
        let snapshots = self.repository_snapshots()?;
        let mut batch = CatalogBatch::new();
        batch.delete_repository(repository);
        for snapshot in snapshots {
            if snapshot.repository == repository {
                batch.delete_repository_snapshot(repository, snapshot.snapshot);
            }
        }
        self.apply(batch)
    }
    fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata>;
    /// Returns an opaque metadata value after checking the catalog version.
    ///
    /// The default keeps pre-v1-expansion wrappers source-compatible. Catalog
    /// implementations that persist metadata override it.
    fn meta(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }
    /// Returns the catalog's atomically published active generation.
    fn current_generation(&self) -> Option<u32> {
        let value = self.meta(CURRENT_GENERATION_META_KEY)?;
        let bytes: [u8; 4] = value.as_slice().try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
    /// Returns an opaque workspace record after checking the catalog version.
    fn workspace(&self, _id: WorkspaceId) -> Option<Vec<u8>> {
        None
    }
    /// Resolves a raw workspace name to its stable workspace ID.
    fn workspace_name(&self, _name: &[u8]) -> Option<WorkspaceId> {
        None
    }
    /// Returns the cold-store generation pinned by a workspace.
    fn workspace_pin(&self, _id: WorkspaceId) -> Option<u32> {
        None
    }
    /// Enumerates workspace generation pins in deterministic order.
    fn workspace_pins(&self) -> Result<Vec<(WorkspaceId, u32)>, CatalogError> {
        Ok(Vec::new())
    }
    /// Enumerates explicit operational generation pins in deterministic order.
    fn gc_pins(&self) -> Result<Vec<GcPin>, CatalogError> {
        Ok(Vec::new())
    }
    /// Enumerates every durable root used by cold GC.
    ///
    /// Repository snapshots identify object-graph mark roots; workspace and
    /// operational pins retain old generations until they are released.
    fn gc_roots(&self) -> Result<Vec<GcRoot>, CatalogError> {
        let mut roots = Vec::new();
        for snapshot in self.repository_snapshots()? {
            if snapshot.visibility == SnapshotVisibility::Ready {
                roots.push(GcRoot::RepositorySnapshot {
                    repository: snapshot.repository,
                    snapshot: snapshot.snapshot,
                });
            }
        }
        roots.extend(
            self.workspace_pins()?
                .into_iter()
                .map(|(workspace, generation)| GcRoot::WorkspacePin {
                    workspace,
                    generation,
                }),
        );
        roots.extend(
            self.gc_pins()?
                .into_iter()
                .map(|pin| GcRoot::ExplicitPin { pin }),
        );
        roots.sort_unstable();
        Ok(roots)
    }
    /// Returns an opaque durable job record after checking the catalog version.
    fn job(&self, _job_id: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Atomic locations-only rebuild protocol for a catalog implementation.
///
/// Callers must hold the catalog's sole-writer lease for the full protocol
/// and should complete every verification scan before [`Self::begin_object_location_rebuild`].
/// Beginning a rebuild clears only `object_locations`; OID aliases and all
/// other catalog families remain intact. A crash leaves a durable
/// `InProgress` marker, so normal catalog writes and object-location reads
/// fail closed until the caller resumes with appends and finish, or explicitly
/// restarts the rebuild.
pub trait ObjectLocationRebuildCatalog: Catalog {
    /// Clears object locations and records a durable in-progress marker.
    fn begin_object_location_rebuild(&mut self) -> Result<(), CatalogError>;
    /// Discards partially rebuilt locations after an interrupted rebuild while
    /// retaining the in-progress marker.
    fn restart_object_location_rebuild(&mut self) -> Result<(), CatalogError>;
    /// Adds verified locations to an active rebuild. Entries must not repeat
    /// a content ID already added by this rebuild.
    fn append_rebuilt_object_locations(
        &mut self,
        entries: &[ObjectLocationEntry],
    ) -> Result<(), CatalogError>;
    /// Publishes the rebuilt locations by removing the durable marker.
    fn finish_object_location_rebuild(&mut self) -> Result<(), CatalogError>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryCatalog {
    objects: HashMap<ContentId, ObjectLocation>,
    object_location_rebuild_in_progress: bool,
    aliases: HashMap<(RepoId, GitOid), ContentId>,
    repositories: HashMap<RepoId, Vec<u8>>,
    repository_snapshots: HashMap<(RepoId, SnapshotId), SnapshotVisibility>,
    chunks: HashMap<(u32, u64), ChunkMetadata>,
    meta: HashMap<Vec<u8>, Vec<u8>>,
    workspaces: HashMap<WorkspaceId, Vec<u8>>,
    workspace_names: HashMap<Vec<u8>, WorkspaceId>,
    workspace_pins: HashMap<WorkspaceId, u32>,
    gc_pins: HashMap<GcPinId, u32>,
    jobs: HashMap<Vec<u8>, Vec<u8>>,
}
impl Catalog for InMemoryCatalog {
    fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
        if self.object_location_rebuild_in_progress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        reject_direct_rebuild_marker_mutation(&batch)?;
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
                Operation::Repository(id, record) => {
                    staged.repositories.insert(id, record);
                }
                Operation::DeleteRepository(id) => {
                    staged.repositories.remove(&id);
                }
                Operation::RepositorySnapshot(repository, snapshot, visibility) => {
                    staged
                        .repository_snapshots
                        .insert((repository, snapshot), visibility);
                }
                Operation::DeleteRepositorySnapshot(repository, snapshot) => {
                    staged.repository_snapshots.remove(&(repository, snapshot));
                }
                Operation::Meta(key, value) => {
                    staged.meta.insert(key, value);
                }
                Operation::Workspace(id, record) => {
                    staged.workspaces.insert(id, record);
                }
                Operation::WorkspaceName(name, id) => {
                    staged.workspace_names.insert(name, id);
                }
                Operation::WorkspacePin(id, generation) => {
                    staged.workspace_pins.insert(id, generation);
                }
                Operation::DeleteWorkspacePin(id) => {
                    staged.workspace_pins.remove(&id);
                }
                Operation::GcPin(id, generation) => {
                    staged.gc_pins.insert(id, generation);
                }
                Operation::DeleteGcPin(id) => {
                    staged.gc_pins.remove(&id);
                }
                Operation::Job(job_id, record) => {
                    staged.jobs.insert(job_id, record);
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
        if self.object_location_rebuild_in_progress {
            return None;
        }
        self.objects.get(&id).copied()
    }
    fn object_location_rebuild_state(&self) -> Result<ObjectLocationRebuildState, CatalogError> {
        Ok(if self.object_location_rebuild_in_progress {
            ObjectLocationRebuildState::InProgress
        } else {
            ObjectLocationRebuildState::Idle
        })
    }
    fn visit_object_locations(
        &self,
        visitor: &mut dyn FnMut(ObjectLocationEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        if self.object_location_rebuild_in_progress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        let mut entries: Vec<_> = self
            .objects
            .iter()
            .map(|(&content_id, &location)| ObjectLocationEntry {
                content_id,
                location,
            })
            .collect();
        entries.sort_unstable_by(|left, right| {
            left.content_id.as_bytes().cmp(right.content_id.as_bytes())
        });
        for entry in entries {
            visitor(entry)?;
        }
        Ok(())
    }
    fn visit_oid_aliases(
        &self,
        visitor: &mut dyn FnMut(OidAliasEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        let mut entries: Vec<_> = self
            .aliases
            .iter()
            .map(|(&(repository, oid), &content_id)| OidAliasEntry {
                repository,
                oid,
                content_id,
            })
            .collect();
        entries.sort_unstable_by(|left, right| {
            left.repository
                .cmp(&right.repository)
                .then_with(|| left.oid.algorithm().tag().cmp(&right.oid.algorithm().tag()))
                .then_with(|| left.oid.as_bytes().cmp(right.oid.as_bytes()))
        });
        for entry in entries {
            visitor(entry)?;
        }
        Ok(())
    }
    fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId> {
        self.aliases.get(&(repo, *oid)).copied()
    }
    fn repository(&self, id: RepoId) -> Option<Vec<u8>> {
        self.repositories.get(&id).cloned()
    }
    fn repository_snapshot(
        &self,
        repository: RepoId,
        snapshot: SnapshotId,
    ) -> Option<SnapshotVisibility> {
        self.repository_snapshots
            .get(&(repository, snapshot))
            .copied()
    }
    fn repository_snapshots(&self) -> Result<Vec<RepositorySnapshot>, CatalogError> {
        let mut snapshots: Vec<_> = self
            .repository_snapshots
            .iter()
            .map(
                |(&(repository, snapshot), &visibility)| RepositorySnapshot {
                    repository,
                    snapshot,
                    visibility,
                },
            )
            .collect();
        snapshots.sort_unstable();
        Ok(snapshots)
    }
    fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata> {
        self.chunks.get(&(generation, chunk_id)).copied()
    }
    fn visit_chunks(
        &self,
        visitor: &mut dyn FnMut(ChunkEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        if self.object_location_rebuild_in_progress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        let mut entries: Vec<_> = self
            .chunks
            .iter()
            .map(|(&(generation, chunk_id), &metadata)| ChunkEntry {
                generation,
                chunk_id,
                metadata,
            })
            .collect();
        entries.sort_unstable_by_key(|entry| (entry.generation, entry.chunk_id));
        for entry in entries {
            visitor(entry)?;
        }
        Ok(())
    }
    fn meta(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.meta.get(key).cloned()
    }
    fn workspace(&self, id: WorkspaceId) -> Option<Vec<u8>> {
        self.workspaces.get(&id).cloned()
    }
    fn workspace_name(&self, name: &[u8]) -> Option<WorkspaceId> {
        self.workspace_names.get(name).copied()
    }
    fn workspace_pin(&self, id: WorkspaceId) -> Option<u32> {
        self.workspace_pins.get(&id).copied()
    }
    fn workspace_pins(&self) -> Result<Vec<(WorkspaceId, u32)>, CatalogError> {
        let mut pins: Vec<_> = self
            .workspace_pins
            .iter()
            .map(|(&workspace, &generation)| (workspace, generation))
            .collect();
        pins.sort_unstable();
        Ok(pins)
    }
    fn gc_pins(&self) -> Result<Vec<GcPin>, CatalogError> {
        let mut pins: Vec<_> = self
            .gc_pins
            .iter()
            .map(|(&id, &generation)| GcPin { id, generation })
            .collect();
        pins.sort_unstable();
        Ok(pins)
    }
    fn job(&self, job_id: &[u8]) -> Option<Vec<u8>> {
        self.jobs.get(job_id).cloned()
    }
}

impl ObjectLocationRebuildCatalog for InMemoryCatalog {
    fn begin_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        if self.object_location_rebuild_in_progress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        self.objects.clear();
        self.object_location_rebuild_in_progress = true;
        Ok(())
    }

    fn restart_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        if !self.object_location_rebuild_in_progress {
            return Err(CatalogError::ObjectLocationRebuildNotInProgress);
        }
        self.objects.clear();
        Ok(())
    }

    fn append_rebuilt_object_locations(
        &mut self,
        entries: &[ObjectLocationEntry],
    ) -> Result<(), CatalogError> {
        if !self.object_location_rebuild_in_progress {
            return Err(CatalogError::ObjectLocationRebuildNotInProgress);
        }
        let mut seen = HashSet::with_capacity(entries.len());
        for entry in entries {
            if !seen.insert(entry.content_id) || self.objects.contains_key(&entry.content_id) {
                return Err(CatalogError::DuplicateRebuiltObjectLocation(
                    entry.content_id,
                ));
            }
        }
        for entry in entries {
            self.objects.insert(entry.content_id, entry.location);
        }
        Ok(())
    }

    fn finish_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        if !self.object_location_rebuild_in_progress {
            return Err(CatalogError::ObjectLocationRebuildNotInProgress);
        }
        self.object_location_rebuild_in_progress = false;
        Ok(())
    }
}

/// RocksDB column-family names defined by catalog format v1.
#[cfg(feature = "rocksdb-backend")]
pub const CF_OBJECT_LOCATIONS: &str = "object_locations";
#[cfg(feature = "rocksdb-backend")]
pub const CF_OID_ALIASES: &str = "oid_aliases";
#[cfg(feature = "rocksdb-backend")]
pub const CF_REPOSITORIES: &str = "repositories";
#[cfg(feature = "rocksdb-backend")]
pub const CF_REPO_SNAPSHOTS: &str = "repo_snapshots";
#[cfg(feature = "rocksdb-backend")]
pub const CF_REFS: &str = "refs";
#[cfg(feature = "rocksdb-backend")]
pub const CF_CHUNKS: &str = "chunks";
#[cfg(feature = "rocksdb-backend")]
pub const CF_CACHE_OBJECTS: &str = "cache_objects";
#[cfg(feature = "rocksdb-backend")]
pub const CF_WORKSPACES: &str = "workspaces";
#[cfg(feature = "rocksdb-backend")]
pub const CF_WORKSPACE_NAMES: &str = "workspace_names";
#[cfg(feature = "rocksdb-backend")]
pub const CF_PINS: &str = "pins";
#[cfg(feature = "rocksdb-backend")]
pub const CF_JOBS: &str = "jobs";
#[cfg(feature = "rocksdb-backend")]
pub const CF_META: &str = "meta";

/// Every RocksDB column family declared by the catalog-v1 contract.
#[cfg(feature = "rocksdb-backend")]
pub const ROCKSDB_COLUMN_FAMILIES: [&str; 12] = [
    CF_OBJECT_LOCATIONS,
    CF_OID_ALIASES,
    CF_REPOSITORIES,
    CF_REPO_SNAPSHOTS,
    CF_REFS,
    CF_CHUNKS,
    CF_CACHE_OBJECTS,
    CF_WORKSPACES,
    CF_WORKSPACE_NAMES,
    CF_PINS,
    CF_JOBS,
    CF_META,
];

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

    /// Opens an already-published catalog for normal read/write service use,
    /// without creating a missing database or column family.
    ///
    /// This can acquire RocksDB's normal writable database lock. Recovery
    /// validation must use [`Self::validate_checkpoint`] instead, which opens
    /// the checkpoint read-only and drops that handle before returning.
    pub fn open_existing(path: impl AsRef<std::path::Path>) -> Result<Self, rocksdb::Error> {
        let options = rocksdb::Options::default();
        let descriptors: Vec<_> = ROCKSDB_COLUMN_FAMILIES
            .into_iter()
            .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, rocksdb::Options::default()))
            .collect();
        Ok(Self {
            db: rocksdb::DB::open_cf_descriptors(&options, path, descriptors)?,
        })
    }

    fn open_read_only(path: impl AsRef<std::path::Path>) -> Result<Self, rocksdb::Error> {
        let options = rocksdb::Options::default();
        let descriptors: Vec<_> = ROCKSDB_COLUMN_FAMILIES
            .into_iter()
            .map(|name| rocksdb::ColumnFamilyDescriptor::new(name, rocksdb::Options::default()))
            .collect();
        Ok(Self {
            db: rocksdb::DB::open_cf_descriptors_read_only(&options, path, descriptors, false)?,
        })
    }

    /// Creates a RocksDB-engine-consistent checkpoint at a new destination.
    ///
    /// The checkpoint API captures a coherent set of manifest, table, and WAL
    /// files even when the database has files that are unsafe to copy as an
    /// arbitrary live directory. The caller is responsible for supplying a
    /// new, trusted destination below its checkpoint staging directory.
    pub fn create_checkpoint(
        &self,
        destination: impl AsRef<std::path::Path>,
    ) -> Result<(), rocksdb::Error> {
        rocksdb::checkpoint::Checkpoint::new(&self.db)?.create_checkpoint(destination)
    }

    /// Validates every v1 column family and entry in this open catalog.
    ///
    /// This performs schema decoding rather than merely opening RocksDB, which
    /// prevents an intact-looking but foreign or partially corrupt checkpoint
    /// from being accepted during restore.
    pub fn validate(&self) -> Result<(), CatalogError> {
        self.validate_entries(CF_OBJECT_LOCATIONS, |key, value| {
            decode_object_location_key(key)?;
            decode_object_location_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_OID_ALIASES, |key, value| {
            decode_oid_alias_key(key)?;
            decode_content_id_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_REPOSITORIES, |key, value| {
            decode_repository_key(key)?;
            decode_opaque_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_REPO_SNAPSHOTS, |key, value| {
            decode_repository_snapshot_key(key)?;
            decode_snapshot_visibility_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_REFS, |key, value| {
            decode_opaque_key(key)?;
            decode_opaque_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_CHUNKS, |key, value| {
            decode_chunk_key(key)?;
            decode_chunk_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_CACHE_OBJECTS, |key, value| {
            decode_opaque_key(key)?;
            decode_opaque_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_WORKSPACES, |key, value| {
            decode_workspace_key(key)?;
            decode_opaque_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_WORKSPACE_NAMES, |key, value| {
            decode_workspace_name_key(key)?;
            decode_workspace_id_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_PINS, |key, value| {
            match key.len() {
                17 => {
                    decode_workspace_pin_key(key)?;
                    decode_workspace_pin_value(value)?;
                }
                18 => {
                    decode_gc_pin_key(key)?;
                    decode_gc_pin_value(value)?;
                }
                _ => return Err(CatalogError::InvalidEncoding),
            }
            Ok(())
        })?;
        self.validate_entries(CF_JOBS, |key, value| {
            decode_job_key(key)?;
            decode_opaque_value(value)?;
            Ok(())
        })?;
        self.validate_entries(CF_META, |key, value| {
            let key = decode_meta_key(key)?;
            if key == CURRENT_GENERATION_META_KEY {
                decode_current_generation_value(value)?;
            } else if key == OBJECT_LOCATION_REBUILD_META_KEY {
                decode_object_location_rebuild_marker(value)?;
            } else {
                decode_opaque_value(value)?;
            }
            Ok(())
        })
    }

    /// Opens and schema-validates a checkpoint that must already exist.
    ///
    /// The returned generation is read only after every catalog-v1 entry has
    /// decoded successfully, so checkpoint consumers can bind it to their own
    /// generation descriptor without accepting an invalid metadata value.
    pub fn validate_checkpoint(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Option<u32>, CatalogError> {
        // Keep the read-only DB lifetime entirely within this block. In
        // particular, restore validation must release its handle before the
        // caller publishes the verified staging directory by rename.
        let generation = {
            let catalog = Self::open_read_only(path)
                .map_err(|error| CatalogError::Backend(error.to_string()))?;
            catalog.validate()?;
            catalog.current_generation()
        };
        Ok(generation)
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily, CatalogError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| CatalogError::Backend(format!("missing RocksDB column family {name}")))
    }

    fn validate_entries<F>(&self, column_family: &str, mut validate: F) -> Result<(), CatalogError>
    where
        F: FnMut(&[u8], &[u8]) -> Result<(), CatalogError>,
    {
        let column_family = self.cf(column_family)?;
        for entry in self
            .db
            .iterator_cf(column_family, rocksdb::IteratorMode::Start)
        {
            let (key, value) = entry.map_err(|error| CatalogError::Backend(error.to_string()))?;
            validate(key.as_ref(), value.as_ref())?;
        }
        Ok(())
    }

    fn read_object_location_rebuild_state(
        &self,
    ) -> Result<ObjectLocationRebuildState, CatalogError> {
        let meta_cf = self.cf(CF_META)?;
        let value = self
            .db
            .get_cf(meta_cf, encode_meta_key(OBJECT_LOCATION_REBUILD_META_KEY))
            .map_err(|error| CatalogError::Backend(error.to_string()))?;
        match value {
            None => Ok(ObjectLocationRebuildState::Idle),
            Some(value) => decode_object_location_rebuild_marker(&value),
        }
    }
}

#[cfg(feature = "rocksdb-backend")]
impl Catalog for RocksDbCatalog {
    fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
        if self.read_object_location_rebuild_state()? == ObjectLocationRebuildState::InProgress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        reject_direct_rebuild_marker_mutation(&batch)?;
        let object_cf = self.cf(CF_OBJECT_LOCATIONS)?;
        let alias_cf = self.cf(CF_OID_ALIASES)?;
        let repository_cf = self.cf(CF_REPOSITORIES)?;
        let snapshot_cf = self.cf(CF_REPO_SNAPSHOTS)?;
        let chunk_cf = self.cf(CF_CHUNKS)?;
        let meta_cf = self.cf(CF_META)?;
        let workspace_cf = self.cf(CF_WORKSPACES)?;
        let workspace_name_cf = self.cf(CF_WORKSPACE_NAMES)?;
        let pin_cf = self.cf(CF_PINS)?;
        let job_cf = self.cf(CF_JOBS)?;
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
                Operation::Repository(id, record) => writes.put_cf(
                    repository_cf,
                    encode_repository_key(id),
                    encode_opaque_value(&record),
                ),
                Operation::DeleteRepository(id) => {
                    writes.delete_cf(repository_cf, encode_repository_key(id))
                }
                Operation::RepositorySnapshot(repository, snapshot, visibility) => writes.put_cf(
                    snapshot_cf,
                    encode_repository_snapshot_key(repository, snapshot),
                    encode_snapshot_visibility_value(visibility),
                ),
                Operation::DeleteRepositorySnapshot(repository, snapshot) => writes.delete_cf(
                    snapshot_cf,
                    encode_repository_snapshot_key(repository, snapshot),
                ),
                Operation::ChunkMetadata(generation, chunk_id, metadata) => writes.put_cf(
                    chunk_cf,
                    encode_chunk_key(generation, chunk_id),
                    encode_chunk_value(metadata),
                ),
                Operation::Meta(key, value) => {
                    writes.put_cf(meta_cf, encode_meta_key(&key), encode_opaque_value(&value))
                }
                Operation::Workspace(id, record) => writes.put_cf(
                    workspace_cf,
                    encode_workspace_key(id),
                    encode_opaque_value(&record),
                ),
                Operation::WorkspaceName(name, id) => writes.put_cf(
                    workspace_name_cf,
                    encode_workspace_name_key(&name),
                    encode_workspace_id_value(id),
                ),
                Operation::WorkspacePin(id, generation) => writes.put_cf(
                    pin_cf,
                    encode_workspace_pin_key(id),
                    encode_workspace_pin_value(generation),
                ),
                Operation::DeleteWorkspacePin(id) => {
                    writes.delete_cf(pin_cf, encode_workspace_pin_key(id))
                }
                Operation::GcPin(id, generation) => writes.put_cf(
                    pin_cf,
                    encode_gc_pin_key(id),
                    encode_gc_pin_value(generation),
                ),
                Operation::DeleteGcPin(id) => writes.delete_cf(pin_cf, encode_gc_pin_key(id)),
                Operation::Job(job_id, record) => writes.put_cf(
                    job_cf,
                    encode_job_key(&job_id),
                    encode_opaque_value(&record),
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
        if self.read_object_location_rebuild_state().ok()? != ObjectLocationRebuildState::Idle {
            return None;
        }
        let value = self
            .db
            .get_cf(
                self.cf(CF_OBJECT_LOCATIONS).ok()?,
                encode_object_location_key(id),
            )
            .ok()??;
        decode_object_location_value(&value).ok()
    }
    fn object_location_rebuild_state(&self) -> Result<ObjectLocationRebuildState, CatalogError> {
        self.read_object_location_rebuild_state()
    }
    fn visit_object_locations(
        &self,
        visitor: &mut dyn FnMut(ObjectLocationEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        if self.read_object_location_rebuild_state()? == ObjectLocationRebuildState::InProgress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        let object_cf = self.cf(CF_OBJECT_LOCATIONS)?;
        for entry in self.db.iterator_cf(object_cf, rocksdb::IteratorMode::Start) {
            let (key, value) = entry.map_err(|error| CatalogError::Backend(error.to_string()))?;
            visitor(ObjectLocationEntry {
                content_id: decode_object_location_key(&key)?,
                location: decode_object_location_value(&value)?,
            })?;
        }
        Ok(())
    }
    fn visit_oid_aliases(
        &self,
        visitor: &mut dyn FnMut(OidAliasEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        let alias_cf = self.cf(CF_OID_ALIASES)?;
        for entry in self.db.iterator_cf(alias_cf, rocksdb::IteratorMode::Start) {
            let (key, value) = entry.map_err(|error| CatalogError::Backend(error.to_string()))?;
            let (repository, oid) = decode_oid_alias_key(&key)?;
            visitor(OidAliasEntry {
                repository,
                oid,
                content_id: decode_content_id_value(&value)?,
            })?;
        }
        Ok(())
    }
    fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId> {
        let value = self
            .db
            .get_cf(
                self.cf(CF_OID_ALIASES).ok()?,
                encode_oid_alias_key(repo, oid),
            )
            .ok()??;
        decode_content_id_value(&value).ok()
    }
    fn repository(&self, id: RepoId) -> Option<Vec<u8>> {
        let value = self
            .db
            .get_cf(self.cf(CF_REPOSITORIES).ok()?, encode_repository_key(id))
            .ok()??;
        decode_opaque_value(&value).ok()
    }
    fn repository_snapshot(
        &self,
        repository: RepoId,
        snapshot: SnapshotId,
    ) -> Option<SnapshotVisibility> {
        let value = self
            .db
            .get_cf(
                self.cf(CF_REPO_SNAPSHOTS).ok()?,
                encode_repository_snapshot_key(repository, snapshot),
            )
            .ok()??;
        decode_snapshot_visibility_value(&value).ok()
    }
    fn repository_snapshots(&self) -> Result<Vec<RepositorySnapshot>, CatalogError> {
        let snapshot_cf = self.cf(CF_REPO_SNAPSHOTS)?;
        let mut snapshots = Vec::new();
        for entry in self
            .db
            .iterator_cf(snapshot_cf, rocksdb::IteratorMode::Start)
        {
            let (key, value) = entry.map_err(|error| CatalogError::Backend(error.to_string()))?;
            let (repository, snapshot) = decode_repository_snapshot_key(&key)?;
            let visibility = decode_snapshot_visibility_value(&value)?;
            snapshots.push(RepositorySnapshot {
                repository,
                snapshot,
                visibility,
            });
        }
        snapshots.sort_unstable();
        Ok(snapshots)
    }
    fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata> {
        let value = self
            .db
            .get_cf(
                self.cf(CF_CHUNKS).ok()?,
                encode_chunk_key(generation, chunk_id),
            )
            .ok()??;
        decode_chunk_value(&value).ok()
    }
    fn visit_chunks(
        &self,
        visitor: &mut dyn FnMut(ChunkEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        if self.read_object_location_rebuild_state()? == ObjectLocationRebuildState::InProgress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        let chunk_cf = self.cf(CF_CHUNKS)?;
        for entry in self.db.iterator_cf(chunk_cf, rocksdb::IteratorMode::Start) {
            let (key, value) = entry.map_err(|error| CatalogError::Backend(error.to_string()))?;
            let (generation, chunk_id) = decode_chunk_key(&key)?;
            visitor(ChunkEntry {
                generation,
                chunk_id,
                metadata: decode_chunk_value(&value)?,
            })?;
        }
        Ok(())
    }
    fn meta(&self, key: &[u8]) -> Option<Vec<u8>> {
        if key == OBJECT_LOCATION_REBUILD_META_KEY {
            return None;
        }
        let value = self
            .db
            .get_cf(self.cf(CF_META).ok()?, encode_meta_key(key))
            .ok()??;
        decode_opaque_value(&value).ok()
    }
    fn workspace(&self, id: WorkspaceId) -> Option<Vec<u8>> {
        let value = self
            .db
            .get_cf(self.cf(CF_WORKSPACES).ok()?, encode_workspace_key(id))
            .ok()??;
        decode_opaque_value(&value).ok()
    }
    fn workspace_name(&self, name: &[u8]) -> Option<WorkspaceId> {
        let value = self
            .db
            .get_cf(
                self.cf(CF_WORKSPACE_NAMES).ok()?,
                encode_workspace_name_key(name),
            )
            .ok()??;
        decode_workspace_id_value(&value).ok()
    }
    fn workspace_pin(&self, id: WorkspaceId) -> Option<u32> {
        let value = self
            .db
            .get_cf(self.cf(CF_PINS).ok()?, encode_workspace_pin_key(id))
            .ok()??;
        decode_workspace_pin_value(&value).ok()
    }
    fn workspace_pins(&self) -> Result<Vec<(WorkspaceId, u32)>, CatalogError> {
        let pin_cf = self.cf(CF_PINS)?;
        let mut pins = Vec::new();
        for entry in self.db.iterator_cf(pin_cf, rocksdb::IteratorMode::Start) {
            let (key, value) = entry.map_err(|error| CatalogError::Backend(error.to_string()))?;
            if key.len() == 17 {
                pins.push((
                    decode_workspace_pin_key(&key)?,
                    decode_workspace_pin_value(&value)?,
                ));
            } else if key.len() != 18 {
                return Err(CatalogError::InvalidEncoding);
            }
        }
        pins.sort_unstable();
        Ok(pins)
    }
    fn gc_pins(&self) -> Result<Vec<GcPin>, CatalogError> {
        let pin_cf = self.cf(CF_PINS)?;
        let mut pins = Vec::new();
        for entry in self.db.iterator_cf(pin_cf, rocksdb::IteratorMode::Start) {
            let (key, value) = entry.map_err(|error| CatalogError::Backend(error.to_string()))?;
            if key.len() == 18 {
                pins.push(GcPin {
                    id: decode_gc_pin_key(&key)?,
                    generation: decode_gc_pin_value(&value)?,
                });
            } else if key.len() != 17 {
                return Err(CatalogError::InvalidEncoding);
            }
        }
        pins.sort_unstable();
        Ok(pins)
    }
    fn job(&self, job_id: &[u8]) -> Option<Vec<u8>> {
        let value = self
            .db
            .get_cf(self.cf(CF_JOBS).ok()?, encode_job_key(job_id))
            .ok()??;
        decode_opaque_value(&value).ok()
    }
}

#[cfg(feature = "rocksdb-backend")]
impl ObjectLocationRebuildCatalog for RocksDbCatalog {
    fn begin_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        if self.read_object_location_rebuild_state()? == ObjectLocationRebuildState::InProgress {
            return Err(CatalogError::ObjectLocationRebuildInProgress);
        }
        self.clear_object_locations_and_mark_rebuild()
    }

    fn restart_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        if self.read_object_location_rebuild_state()? != ObjectLocationRebuildState::InProgress {
            return Err(CatalogError::ObjectLocationRebuildNotInProgress);
        }
        self.clear_object_locations_and_mark_rebuild()
    }

    fn append_rebuilt_object_locations(
        &mut self,
        entries: &[ObjectLocationEntry],
    ) -> Result<(), CatalogError> {
        if self.read_object_location_rebuild_state()? != ObjectLocationRebuildState::InProgress {
            return Err(CatalogError::ObjectLocationRebuildNotInProgress);
        }
        let object_cf = self.cf(CF_OBJECT_LOCATIONS)?;
        let mut seen = HashSet::with_capacity(entries.len());
        for entry in entries {
            if !seen.insert(entry.content_id)
                || self
                    .db
                    .get_cf(object_cf, encode_object_location_key(entry.content_id))
                    .map_err(|error| CatalogError::Backend(error.to_string()))?
                    .is_some()
            {
                return Err(CatalogError::DuplicateRebuiltObjectLocation(
                    entry.content_id,
                ));
            }
        }
        let mut writes = rocksdb::WriteBatch::default();
        for entry in entries {
            writes.put_cf(
                object_cf,
                encode_object_location_key(entry.content_id),
                encode_object_location_value(entry.location),
            );
        }
        self.write_sync(writes)
    }

    fn finish_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        if self.read_object_location_rebuild_state()? != ObjectLocationRebuildState::InProgress {
            return Err(CatalogError::ObjectLocationRebuildNotInProgress);
        }
        let meta_cf = self.cf(CF_META)?;
        let mut writes = rocksdb::WriteBatch::default();
        writes.delete_cf(meta_cf, encode_meta_key(OBJECT_LOCATION_REBUILD_META_KEY));
        self.write_sync(writes)
    }
}

#[cfg(feature = "rocksdb-backend")]
impl RocksDbCatalog {
    fn clear_object_locations_and_mark_rebuild(&self) -> Result<(), CatalogError> {
        let object_cf = self.cf(CF_OBJECT_LOCATIONS)?;
        let meta_cf = self.cf(CF_META)?;
        let mut writes = rocksdb::WriteBatch::default();
        writes.delete_range_cf(object_cf, [CATALOG_VERSION], [CATALOG_VERSION + 1]);
        writes.put_cf(
            meta_cf,
            encode_meta_key(OBJECT_LOCATION_REBUILD_META_KEY),
            encode_opaque_value(&[OBJECT_LOCATION_REBUILD_IN_PROGRESS_MARKER]),
        );
        self.write_sync(writes)
    }

    fn write_sync(&self, writes: rocksdb::WriteBatch) -> Result<(), CatalogError> {
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        self.db
            .write_opt(writes, &options)
            .map_err(|error| CatalogError::Backend(error.to_string()))
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
    fn workspace_id(byte: u8) -> WorkspaceId {
        WorkspaceId([byte; WORKSPACE_ID_LEN])
    }
    fn snapshot_id(byte: u8) -> SnapshotId {
        SnapshotId([byte; SNAPSHOT_ID_LEN])
    }
    fn gc_pin_id(byte: u8) -> GcPinId {
        GcPinId([byte; GC_PIN_ID_LEN])
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
        let snapshot = snapshot_id(4);
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
        assert_eq!(
            decode_repository_key(&encode_repository_key(repo)).unwrap(),
            repo
        );
        assert_eq!(
            decode_repository_snapshot_key(&encode_repository_snapshot_key(repo, snapshot))
                .unwrap(),
            (repo, snapshot)
        );
        assert_eq!(
            decode_snapshot_visibility_value(&encode_snapshot_visibility_value(
                SnapshotVisibility::Ready
            ))
            .unwrap(),
            SnapshotVisibility::Ready
        );
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
        assert_eq!(
            decode_opaque_value(&[2, 7]),
            Err(CatalogError::UnsupportedVersion(2))
        );
        assert_eq!(
            decode_current_generation_value(&[2, 0, 0, 0, 1]),
            Err(CatalogError::UnsupportedVersion(2))
        );
    }
    #[test]
    fn catalog_v1_opaque_and_workspace_encodings_round_trip() {
        let workspace = workspace_id(6);
        let pin = gc_pin_id(7);
        assert_eq!(
            decode_opaque_key(&encode_opaque_key(b"meta\0key")).unwrap(),
            b"meta\0key"
        );
        assert_eq!(
            decode_opaque_value(&encode_opaque_value(&[0xff, 0])).unwrap(),
            vec![0xff, 0]
        );
        assert_eq!(
            decode_meta_key(&encode_meta_key(b"arbitrary\0metadata")).unwrap(),
            b"arbitrary\0metadata"
        );
        assert_eq!(
            decode_current_generation_value(&encode_current_generation_value(45)).unwrap(),
            45
        );
        assert_eq!(
            decode_workspace_key(&encode_workspace_key(workspace)).unwrap(),
            workspace
        );
        assert_eq!(
            decode_workspace_name_key(&encode_workspace_name_key(b"name\xff")).unwrap(),
            b"name\xff"
        );
        assert_eq!(
            decode_workspace_id_value(&encode_workspace_id_value(workspace)).unwrap(),
            workspace
        );
        assert_eq!(
            decode_workspace_pin_key(&encode_workspace_pin_key(workspace)).unwrap(),
            workspace
        );
        assert_eq!(
            decode_workspace_pin_value(&encode_workspace_pin_value(46)).unwrap(),
            46
        );
        assert_eq!(decode_gc_pin_key(&encode_gc_pin_key(pin)).unwrap(), pin);
        assert_eq!(decode_gc_pin_value(&encode_gc_pin_value(47)).unwrap(), 47);
        assert_eq!(
            decode_job_key(&encode_job_key(&[9, 0, 8])).unwrap(),
            vec![9, 0, 8]
        );
    }
    #[test]
    fn opaque_catalog_records_are_visible_after_one_batch() {
        let workspace = workspace_id(3);
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_meta(b"migration", b"prepared\0state");
        batch.put_current_generation(9);
        batch.put_workspace(workspace, b"workspace-record");
        batch.put_workspace_name(b"checked-out\xff", workspace);
        batch.put_workspace_pin(workspace, 9);
        batch.put_job([0, 1, 2, 3], b"job-record\0payload");
        catalog.apply(batch).unwrap();

        assert_eq!(
            catalog.meta(b"migration"),
            Some(b"prepared\0state".to_vec())
        );
        assert_eq!(catalog.current_generation(), Some(9));
        assert_eq!(
            catalog.workspace(workspace),
            Some(b"workspace-record".to_vec())
        );
        assert_eq!(catalog.workspace_name(b"checked-out\xff"), Some(workspace));
        assert_eq!(catalog.workspace_pin(workspace), Some(9));
        assert_eq!(
            catalog.job(&[0, 1, 2, 3]),
            Some(b"job-record\0payload".to_vec())
        );
    }
    #[test]
    fn gc_root_enumeration_is_complete_deterministic_and_excludes_incomplete_snapshots() {
        let repository = RepoId([0x31; REPO_ID_LEN]);
        let ready = snapshot_id(0x32);
        let incomplete = snapshot_id(0x33);
        let workspace = workspace_id(0x34);
        let pin = gc_pin_id(0x35);
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_repository(repository, b"repository metadata");
        batch.put_repository_snapshot(repository, incomplete, SnapshotVisibility::Incomplete);
        batch.put_repository_snapshot(repository, ready, SnapshotVisibility::Ready);
        batch.put_workspace_pin(workspace, 17);
        batch.put_gc_pin(pin, 18);
        catalog.apply(batch).unwrap();

        assert_eq!(
            catalog.repository_snapshots().unwrap(),
            vec![
                RepositorySnapshot {
                    repository,
                    snapshot: ready,
                    visibility: SnapshotVisibility::Ready,
                },
                RepositorySnapshot {
                    repository,
                    snapshot: incomplete,
                    visibility: SnapshotVisibility::Incomplete,
                },
            ]
        );
        assert_eq!(
            catalog.gc_roots().unwrap(),
            vec![
                GcRoot::RepositorySnapshot {
                    repository,
                    snapshot: ready,
                },
                GcRoot::WorkspacePin {
                    workspace,
                    generation: 17,
                },
                GcRoot::ExplicitPin {
                    pin: GcPin {
                        id: pin,
                        generation: 18,
                    },
                },
            ]
        );
    }
    #[test]
    fn repository_deletion_removes_every_snapshot_visibility_in_one_batch() {
        let repository = RepoId([0x41; REPO_ID_LEN]);
        let other_repository = RepoId([0x42; REPO_ID_LEN]);
        let first = snapshot_id(0x43);
        let second = snapshot_id(0x44);
        let retained = snapshot_id(0x45);
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_repository(repository, b"source metadata");
        batch.put_repository_snapshot(repository, first, SnapshotVisibility::Ready);
        batch.put_repository_snapshot(repository, second, SnapshotVisibility::Incomplete);
        batch.put_repository_snapshot(other_repository, retained, SnapshotVisibility::Ready);
        catalog.apply(batch).unwrap();

        catalog.delete_repository(repository).unwrap();
        assert_eq!(catalog.repository(repository), None);
        assert_eq!(catalog.repository_snapshot(repository, first), None);
        assert_eq!(catalog.repository_snapshot(repository, second), None);
        assert_eq!(
            catalog.repository_snapshot(other_repository, retained),
            Some(SnapshotVisibility::Ready)
        );
        assert_eq!(
            catalog.gc_roots().unwrap(),
            vec![GcRoot::RepositorySnapshot {
                repository: other_repository,
                snapshot: retained,
            }]
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
        conflicting.put_current_generation(99);
        conflicting.put_job(b"must-not-commit", b"because-alias-conflicts");
        assert!(matches!(
            catalog.apply(conflicting),
            Err(CatalogError::AliasConflict { .. })
        ));
        assert_eq!(catalog.oid_alias(repo, &oid()), Some(id(1)));
        assert_eq!(catalog.object_location(id(2)), None);
        assert_eq!(catalog.current_generation(), None);
        assert_eq!(catalog.job(b"must-not-commit"), None);
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

    #[test]
    fn locations_only_rebuild_preserves_aliases_and_blocks_normal_access() {
        let repository = RepoId([0x51; REPO_ID_LEN]);
        let original = id(0x52);
        let rebuilt = id(0x53);
        let mut rebuilt_location = location();
        rebuilt_location.generation = 2;
        let mut catalog = InMemoryCatalog::default();
        let mut initial = CatalogBatch::new();
        initial.put_object_location(original, location());
        initial.put_oid_alias(repository, oid(), original);
        initial.put_chunk(
            1,
            2,
            ChunkMetadata {
                state: ChunkState::Sealed,
                size: 3,
                record_count: 4,
            },
        );
        catalog.apply(initial).unwrap();

        catalog.begin_object_location_rebuild().unwrap();
        assert_eq!(
            catalog.object_location_rebuild_state().unwrap(),
            ObjectLocationRebuildState::InProgress
        );
        assert_eq!(catalog.object_location(original), None);
        assert_eq!(catalog.oid_alias(repository, &oid()), Some(original));
        let mut aliases = Vec::new();
        catalog
            .visit_oid_aliases(&mut |entry| {
                aliases.push(entry);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            aliases,
            vec![OidAliasEntry {
                repository,
                oid: oid(),
                content_id: original,
            }]
        );
        assert!(matches!(
            catalog.apply(CatalogBatch::new()),
            Err(CatalogError::ObjectLocationRebuildInProgress)
        ));
        assert!(matches!(
            catalog.visit_object_locations(&mut |_| Ok(())),
            Err(CatalogError::ObjectLocationRebuildInProgress)
        ));

        catalog
            .append_rebuilt_object_locations(&[ObjectLocationEntry {
                content_id: rebuilt,
                location: rebuilt_location,
            }])
            .unwrap();
        catalog.finish_object_location_rebuild().unwrap();

        assert_eq!(
            catalog.object_location_rebuild_state().unwrap(),
            ObjectLocationRebuildState::Idle
        );
        assert_eq!(catalog.object_location(original), None);
        assert_eq!(catalog.object_location(rebuilt), Some(rebuilt_location));
        assert_eq!(catalog.oid_alias(repository, &oid()), Some(original));
    }

    #[test]
    fn locations_only_rebuild_restarts_partial_output_and_rejects_duplicates() {
        let partial = id(0x61);
        let final_entry = id(0x62);
        let mut catalog = InMemoryCatalog::default();
        catalog.begin_object_location_rebuild().unwrap();
        let entry = ObjectLocationEntry {
            content_id: partial,
            location: location(),
        };
        catalog.append_rebuilt_object_locations(&[entry]).unwrap();
        assert_eq!(
            catalog.append_rebuilt_object_locations(&[entry]),
            Err(CatalogError::DuplicateRebuiltObjectLocation(partial))
        );

        catalog.restart_object_location_rebuild().unwrap();
        catalog
            .append_rebuilt_object_locations(&[ObjectLocationEntry {
                content_id: final_entry,
                location: location(),
            }])
            .unwrap();
        catalog.finish_object_location_rebuild().unwrap();

        assert_eq!(catalog.object_location(partial), None);
        assert_eq!(catalog.object_location(final_entry), Some(location()));
        assert_eq!(
            catalog.restart_object_location_rebuild(),
            Err(CatalogError::ObjectLocationRebuildNotInProgress)
        );
    }

    #[test]
    fn streaming_enumeration_uses_catalog_key_order() {
        let first_repository = RepoId([0x70; REPO_ID_LEN]);
        let second_repository = RepoId([0x71; REPO_ID_LEN]);
        let second_oid = GitOid::new(HashAlgorithm::Sha1, &[6; 20]).unwrap();
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_object_location(id(2), location());
        batch.put_object_location(id(1), location());
        batch.put_oid_alias(second_repository, oid(), id(2));
        batch.put_oid_alias(first_repository, second_oid, id(1));
        batch.put_chunk(
            2,
            1,
            ChunkMetadata {
                state: ChunkState::Open,
                size: 1,
                record_count: 2,
            },
        );
        batch.put_chunk(
            1,
            9,
            ChunkMetadata {
                state: ChunkState::Sealed,
                size: 3,
                record_count: 4,
            },
        );
        catalog.apply(batch).unwrap();

        let mut locations = Vec::new();
        catalog
            .visit_object_locations(&mut |entry| {
                locations.push(entry.content_id);
                Ok(())
            })
            .unwrap();
        assert_eq!(locations, vec![id(1), id(2)]);

        let mut aliases = Vec::new();
        catalog
            .visit_oid_aliases(&mut |entry| {
                aliases.push((entry.repository, entry.oid, entry.content_id));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            aliases,
            vec![
                (first_repository, second_oid, id(1)),
                (second_repository, oid(), id(2)),
            ]
        );

        let mut chunks = Vec::new();
        catalog
            .visit_chunks(&mut |entry| {
                chunks.push((entry.generation, entry.chunk_id));
                Ok(())
            })
            .unwrap();
        assert_eq!(chunks, vec![(1, 9), (2, 1)]);
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
        let workspace = workspace_id(7);
        let snapshot = snapshot_id(9);
        let pin = gc_pin_id(10);
        {
            let mut catalog = RocksDbCatalog::open(&path).unwrap();
            let mut batch = CatalogBatch::new();
            batch.put_object_location(object_id, location());
            batch.put_oid_alias(repo, oid(), object_id);
            batch.put_repository(repo, b"repository metadata");
            batch.put_repository_snapshot(repo, snapshot, SnapshotVisibility::Ready);
            batch.put_meta(b"migration", b"complete");
            batch.put_current_generation(12);
            batch.put_workspace(workspace, b"workspace manifest bytes");
            batch.put_workspace_name(b"demo\xff", workspace);
            batch.put_workspace_pin(workspace, 12);
            batch.put_gc_pin(pin, 13);
            batch.put_job([4, 5, 6], b"opaque job record");
            catalog.apply(batch).unwrap();
        }
        let catalog = RocksDbCatalog::open(&path).unwrap();
        assert_eq!(catalog.object_location(object_id), Some(location()));
        assert_eq!(catalog.oid_alias(repo, &oid()), Some(object_id));
        assert_eq!(
            catalog.repository(repo),
            Some(b"repository metadata".to_vec())
        );
        assert_eq!(
            catalog.repository_snapshot(repo, snapshot),
            Some(SnapshotVisibility::Ready)
        );
        assert_eq!(catalog.meta(b"migration"), Some(b"complete".to_vec()));
        assert_eq!(catalog.current_generation(), Some(12));
        assert_eq!(
            catalog.workspace(workspace),
            Some(b"workspace manifest bytes".to_vec())
        );
        assert_eq!(catalog.workspace_name(b"demo\xff"), Some(workspace));
        assert_eq!(catalog.workspace_pin(workspace), Some(12));
        assert_eq!(
            catalog.gc_roots().unwrap(),
            vec![
                GcRoot::RepositorySnapshot {
                    repository: repo,
                    snapshot,
                },
                GcRoot::WorkspacePin {
                    workspace,
                    generation: 12,
                },
                GcRoot::ExplicitPin {
                    pin: GcPin {
                        id: pin,
                        generation: 13,
                    },
                },
            ]
        );
        assert_eq!(catalog.job(&[4, 5, 6]), Some(b"opaque job record".to_vec()));
        // The pins family intentionally mixes 17-byte workspace keys with
        // 18-byte explicit-GC keys; schema validation must accept both.
        catalog.validate().unwrap();
        drop(catalog);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocksdb_locations_rebuild_recovers_interruption_and_preserves_aliases() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let path = std::env::temp_dir().join(format!(
            "reflink-forest-index-rebuild-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let repository = RepoId([0x81; REPO_ID_LEN]);
        let original = id(0x82);
        let partial = id(0x83);
        let final_entry = id(0x84);
        {
            let mut catalog = RocksDbCatalog::open(&path).unwrap();
            let mut batch = CatalogBatch::new();
            batch.put_object_location(original, location());
            batch.put_oid_alias(repository, oid(), original);
            catalog.apply(batch).unwrap();

            catalog.begin_object_location_rebuild().unwrap();
            assert_eq!(catalog.object_location(original), None);
            assert!(matches!(
                catalog.apply(CatalogBatch::new()),
                Err(CatalogError::ObjectLocationRebuildInProgress)
            ));
            let mut aliases = Vec::new();
            catalog
                .visit_oid_aliases(&mut |entry| {
                    aliases.push(entry);
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                aliases,
                vec![OidAliasEntry {
                    repository,
                    oid: oid(),
                    content_id: original,
                }]
            );
            catalog
                .append_rebuilt_object_locations(&[ObjectLocationEntry {
                    content_id: partial,
                    location: location(),
                }])
                .unwrap();
        }

        {
            let mut catalog = RocksDbCatalog::open_existing(&path).unwrap();
            assert_eq!(
                catalog.object_location_rebuild_state().unwrap(),
                ObjectLocationRebuildState::InProgress
            );
            assert_eq!(catalog.object_location(partial), None);
            assert_eq!(catalog.oid_alias(repository, &oid()), Some(original));
            catalog.validate().unwrap();

            catalog.restart_object_location_rebuild().unwrap();
            catalog
                .append_rebuilt_object_locations(&[ObjectLocationEntry {
                    content_id: final_entry,
                    location: location(),
                }])
                .unwrap();
            catalog.finish_object_location_rebuild().unwrap();

            assert_eq!(
                catalog.object_location_rebuild_state().unwrap(),
                ObjectLocationRebuildState::Idle
            );
            assert_eq!(catalog.object_location(partial), None);
            assert_eq!(catalog.object_location(final_entry), Some(location()));
            assert_eq!(catalog.oid_alias(repository, &oid()), Some(original));
            catalog.validate().unwrap();
        }
        std::fs::remove_dir_all(path).unwrap();
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocksdb_checkpoint_is_freshly_openable_and_excludes_later_writes() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let root = std::env::temp_dir().join(format!(
            "reflink-forest-index-checkpoint-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let live = root.join("live");
        let checkpoint = root.join("checkpoint");
        {
            let mut catalog = RocksDbCatalog::open(&live).unwrap();
            let mut before = CatalogBatch::new();
            before.put_meta(b"checkpointed", b"before");
            before.put_current_generation(17);
            catalog.apply(before).unwrap();
            catalog.create_checkpoint(&checkpoint).unwrap();

            let mut after = CatalogBatch::new();
            after.put_meta(b"after-checkpoint", b"not in snapshot");
            catalog.apply(after).unwrap();
            catalog.validate().unwrap();
        }

        RocksDbCatalog::validate_checkpoint(&checkpoint).unwrap();
        let restored = RocksDbCatalog::open_existing(&checkpoint).unwrap();
        assert_eq!(restored.meta(b"checkpointed"), Some(b"before".to_vec()));
        assert_eq!(restored.current_generation(), Some(17));
        assert_eq!(restored.meta(b"after-checkpoint"), None);
        drop(restored);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocksdb_declares_every_format_v1_column_family() {
        assert_eq!(
            ROCKSDB_COLUMN_FAMILIES,
            [
                "object_locations",
                "oid_aliases",
                "repositories",
                "repo_snapshots",
                "refs",
                "chunks",
                "cache_objects",
                "workspaces",
                "workspace_names",
                "pins",
                "jobs",
                "meta",
            ]
        );
    }
}
