//! Imports a fixed Git ref snapshot into the cold store.
//!
//! The backend resolves refs once, walks immutable OIDs, and feeds raw object
//! payloads to the serialized cold-store writer. The source repository can be
//! removed after callers persist the returned snapshot metadata.

use reflink_forest_core::ContentId;
use reflink_forest_format::{Codec, ObjectRecord};
use reflink_forest_git::{GitBackend, GitBackendError, RefSnapshot};
use reflink_forest_index::{Catalog, RepoId};
use reflink_forest_store::{ChunkWriter, StoreError};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportSummary {
    pub objects_seen: u64,
    pub objects_written: u64,
    pub objects_deduplicated: u64,
    pub raw_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportResult {
    pub snapshot: RefSnapshot,
    pub summary: ImportSummary,
}
#[derive(Debug)]
pub enum ImportError {
    Git(GitBackendError),
    Store(StoreError),
    LengthOverflow,
}
impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Git(error) => write!(f, "Git import error: {error}"),
            Self::Store(error) => write!(f, "cold-store import error: {error}"),
            Self::LengthOverflow => write!(f, "import counter overflow"),
        }
    }
}
impl std::error::Error for ImportError {}
impl From<GitBackendError> for ImportError {
    fn from(value: GitBackendError) -> Self {
        Self::Git(value)
    }
}
impl From<StoreError> for ImportError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// Imports local branch/tag closure. Publication of a repository `Ready`
/// snapshot is deliberately a separate durable manifest transaction after this
/// function completes without error.
pub fn import_local_refs<B: GitBackend, C: Catalog>(
    backend: &B,
    writer: &mut ChunkWriter,
    catalog: &mut C,
    repo: RepoId,
    generation: u32,
    chunk_id: u64,
) -> Result<ImportResult, ImportError> {
    let snapshot = backend.snapshot_local_refs()?;
    let objects = backend.reachable_objects(&snapshot.roots())?;
    let mut summary = ImportSummary::default();
    for object in objects {
        summary.objects_seen = summary
            .objects_seen
            .checked_add(1)
            .ok_or(ImportError::LengthOverflow)?;
        summary.raw_bytes = summary
            .raw_bytes
            .checked_add(u64::try_from(object.data.len()).map_err(|_| ImportError::LengthOverflow)?)
            .ok_or(ImportError::LengthOverflow)?;
        let content_id = ContentId::for_object(object.kind, &object.data);
        let record = ObjectRecord {
            kind: object.kind,
            codec: Codec::Raw,
            flags: 0,
            raw_length: u64::try_from(object.data.len())
                .map_err(|_| ImportError::LengthOverflow)?,
            content_id,
            primary_oid: object.oid,
            payload: object.data,
        };
        if writer
            .append_and_index(catalog, repo, generation, chunk_id, &record)?
            .is_some()
        {
            summary.objects_written = summary
                .objects_written
                .checked_add(1)
                .ok_or(ImportError::LengthOverflow)?;
        } else {
            summary.objects_deduplicated = summary
                .objects_deduplicated
                .checked_add(1)
                .ok_or(ImportError::LengthOverflow)?;
        }
    }
    Ok(ImportResult { snapshot, summary })
}
