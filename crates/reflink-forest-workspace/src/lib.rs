//! Bridges cold Git-object storage to raw workspace construction.
//!
//! This crate resolves only repo-scoped aliases, validates every catalog
//! location through the chunk reader, and uses the cache hydration path before
//! checkout requests a reflink. It never accesses the original Git repository.

use std::{collections::HashSet, path::PathBuf};

use reflink_forest_cache::{hydrate_raw_blob_from_chunk, Cache, HydrationError};
use reflink_forest_checkout::{
    CheckoutError, CheckoutLimits, CheckoutPlan, CheckoutPlanBuilder, RawCheckoutSource,
    RelativePath, TreeEntry, TreeName,
};
use reflink_forest_core::{ContentId, GitOid, ObjectKind};
use reflink_forest_format::{Codec, ObjectRecord};
use reflink_forest_git::{commit_tree_oid, parse_tree_entries, GitObject, GitTreeEntry};
use reflink_forest_index::{Catalog, RepoId};
use reflink_forest_store::{read_record_at, StoreError};

#[derive(Debug)]
pub enum WorkspaceError {
    MissingAlias(GitOid),
    MissingLocation(ContentId),
    Store(StoreError),
    Hydration(HydrationError),
    Checkout(CheckoutError),
    WrongKind {
        expected: ObjectKind,
        actual: ObjectKind,
    },
    UnsupportedCodec(Codec),
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    TreeDepthExceeded,
}
impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAlias(oid) => write!(f, "cold store has no repo-scoped alias for {oid:?}"),
            Self::MissingLocation(id) => {
                write!(f, "cold store has no location for content ID {id:?}")
            }
            Self::Store(error) => write!(f, "cold-store read failed: {error}"),
            Self::Hydration(error) => write!(f, "cache hydration failed: {error}"),
            Self::Checkout(error) => write!(f, "checkout plan failed: {error}"),
            Self::WrongKind { expected, actual } => {
                write!(f, "expected {expected:?} but found {actual:?}")
            }
            Self::UnsupportedCodec(codec) => {
                write!(f, "raw workspace requires raw objects, found {codec:?}")
            }
            Self::ContentMismatch { .. } => write!(f, "cold record did not match its content ID"),
            Self::TreeDepthExceeded => write!(f, "tree nesting exceeds checkout component limit"),
        }
    }
}
impl std::error::Error for WorkspaceError {}
impl From<StoreError> for WorkspaceError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<HydrationError> for WorkspaceError {
    fn from(value: HydrationError) -> Self {
        Self::Hydration(value)
    }
}
impl From<CheckoutError> for WorkspaceError {
    fn from(value: CheckoutError) -> Self {
        Self::Checkout(value)
    }
}

/// Resolves records for one repository using a repo-scoped catalog namespace.
/// `chunk_path` maps a persisted generation/chunk pair to its immutable file.
pub struct ColdWorkspaceSource<'a, C, F> {
    repository: RepoId,
    catalog: &'a C,
    cache: &'a Cache,
    chunk_path: F,
}

impl<'a, C: Catalog, F: Fn(u32, u64) -> PathBuf> ColdWorkspaceSource<'a, C, F> {
    pub fn new(repository: RepoId, catalog: &'a C, cache: &'a Cache, chunk_path: F) -> Self {
        Self {
            repository,
            catalog,
            cache,
            chunk_path,
        }
    }

    fn content_id(&self, oid: &GitOid) -> Result<ContentId, WorkspaceError> {
        self.catalog
            .oid_alias(self.repository, oid)
            .ok_or(WorkspaceError::MissingAlias(*oid))
    }

    fn record_for(&self, oid: &GitOid) -> Result<(ContentId, ObjectRecord), WorkspaceError> {
        let id = self.content_id(oid)?;
        let location = self
            .catalog
            .object_location(id)
            .ok_or(WorkspaceError::MissingLocation(id))?;
        let record = read_record_at(
            (self.chunk_path)(location.generation, location.chunk_id),
            location,
        )?;
        if record.codec != Codec::Raw {
            return Err(WorkspaceError::UnsupportedCodec(record.codec));
        }
        let actual = ContentId::for_object(record.kind, &record.payload);
        if actual != id || record.content_id != id {
            return Err(WorkspaceError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        Ok((id, record))
    }

    fn git_object(&self, oid: &GitOid) -> Result<GitObject, WorkspaceError> {
        let (_, record) = self.record_for(oid)?;
        Ok(GitObject {
            oid: *oid,
            kind: record.kind,
            data: record.payload,
        })
    }

    /// Builds the raw checkout plan for an imported commit entirely from cold
    /// records. Directory tree entries are expanded recursively; gitlinks are
    /// preserved as explicit planned entries for checkout policy to decide.
    pub fn plan_commit(
        &self,
        commit: GitOid,
        limits: CheckoutLimits,
    ) -> Result<CheckoutPlan, WorkspaceError> {
        let commit_object = self.git_object(&commit)?;
        if commit_object.kind != ObjectKind::Commit {
            return Err(WorkspaceError::WrongKind {
                expected: ObjectKind::Commit,
                actual: commit_object.kind,
            });
        }
        let root_tree = commit_tree_oid(&commit_object).map_err(|_| WorkspaceError::WrongKind {
            expected: ObjectKind::Commit,
            actual: commit_object.kind,
        })?;
        let mut builder = CheckoutPlanBuilder::new(limits);
        self.expand_tree(root_tree, None, limits, &mut builder, &mut HashSet::new())?;
        Ok(builder.finish())
    }

    fn expand_tree(
        &self,
        tree: GitOid,
        parent: Option<RelativePath>,
        limits: CheckoutLimits,
        builder: &mut CheckoutPlanBuilder,
        active: &mut HashSet<GitOid>,
    ) -> Result<(), WorkspaceError> {
        if !active.insert(tree) {
            return Err(WorkspaceError::TreeDepthExceeded);
        }
        let result = (|| {
            let object = self.git_object(&tree)?;
            if object.kind != ObjectKind::Tree {
                return Err(WorkspaceError::WrongKind {
                    expected: ObjectKind::Tree,
                    actual: object.kind,
                });
            }
            for entry in parse_tree_entries(&object).map_err(|_| WorkspaceError::WrongKind {
                expected: ObjectKind::Tree,
                actual: object.kind,
            })? {
                self.expand_tree_entry(entry, parent.as_ref(), limits, builder, active)?;
            }
            Ok(())
        })();
        active.remove(&tree);
        result
    }

    fn expand_tree_entry(
        &self,
        entry: GitTreeEntry,
        parent: Option<&RelativePath>,
        limits: CheckoutLimits,
        builder: &mut CheckoutPlanBuilder,
        active: &mut HashSet<GitOid>,
    ) -> Result<(), WorkspaceError> {
        if entry.mode == 0o040000 {
            let name = TreeName::new(entry.name, limits)?;
            let path = match parent {
                Some(parent) => parent.join(name, limits)?,
                None => RelativePath::from_components([name], limits)?,
            };
            if path.components().len() > limits.max_components {
                return Err(WorkspaceError::TreeDepthExceeded);
            }
            return self.expand_tree(entry.oid, Some(path), limits, builder, active);
        }
        let entry = TreeEntry::from_raw(entry.name, entry.mode, entry.oid, limits)?;
        builder.add_tree_entry(parent, entry)?;
        Ok(())
    }
}

impl<'a, C: Catalog, F: Fn(u32, u64) -> PathBuf> RawCheckoutSource
    for ColdWorkspaceSource<'a, C, F>
{
    type Error = WorkspaceError;
    fn blob_content_id(&self, oid: &GitOid) -> Result<ContentId, Self::Error> {
        let id = self.content_id(oid)?;
        let location = self
            .catalog
            .object_location(id)
            .ok_or(WorkspaceError::MissingLocation(id))?;
        hydrate_raw_blob_from_chunk(
            self.cache,
            self.catalog,
            id,
            (self.chunk_path)(location.generation, location.chunk_id),
        )?;
        Ok(id)
    }
    fn blob_bytes(&self, oid: &GitOid) -> Result<Vec<u8>, Self::Error> {
        let (_, record) = self.record_for(oid)?;
        if record.kind != ObjectKind::Blob {
            return Err(WorkspaceError::WrongKind {
                expected: ObjectKind::Blob,
                actual: record.kind,
            });
        }
        Ok(record.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflink_forest_format::{ChunkHeader, ObjectRecord};
    use reflink_forest_index::InMemoryCatalog;
    use reflink_forest_store::ChunkWriter;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn oid(byte: u8) -> GitOid {
        GitOid::new(reflink_forest_core::HashAlgorithm::Sha1, &[byte; 20]).unwrap()
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "reflink-forest-workspace-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn append(
        writer: &mut ChunkWriter,
        catalog: &mut InMemoryCatalog,
        repo: RepoId,
        oid: GitOid,
        kind: ObjectKind,
        payload: Vec<u8>,
    ) {
        let id = ContentId::for_object(kind, &payload);
        let record = ObjectRecord {
            kind,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: id,
            primary_oid: oid,
            payload,
        };
        writer
            .append_and_index(catalog, repo, 1, 1, &record)
            .unwrap();
    }

    #[test]
    fn plans_commit_and_reads_blob_without_a_source_repository() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let chunk = root.join("1.open");
        let cache = Cache::open(root.join("cache")).unwrap();
        let repo = RepoId([9; 16]);
        let commit_oid = oid(1);
        let tree_oid = oid(2);
        let blob_oid = oid(3);
        let mut writer = ChunkWriter::create(
            &chunk,
            ChunkHeader {
                generation: 1,
                chunk_id: 1,
                created_unix_secs: 0,
                flags: 0,
            },
        )
        .unwrap();
        let blob = b"from cold store\n".to_vec();
        let mut tree = b"100644 file.txt\0".to_vec();
        tree.extend_from_slice(blob_oid.as_bytes());
        let commit = format!(
            "tree {}\nauthor Test <t@example.invalid> 0 +0000\n\nmessage\n",
            oid_hex(&tree_oid)
        )
        .into_bytes();
        let mut catalog = InMemoryCatalog::default();
        append(
            &mut writer,
            &mut catalog,
            repo,
            blob_oid,
            ObjectKind::Blob,
            blob.clone(),
        );
        append(
            &mut writer,
            &mut catalog,
            repo,
            tree_oid,
            ObjectKind::Tree,
            tree,
        );
        append(
            &mut writer,
            &mut catalog,
            repo,
            commit_oid,
            ObjectKind::Commit,
            commit,
        );
        writer.sync_data().unwrap();
        drop(writer);

        let source = ColdWorkspaceSource::new(repo, &catalog, &cache, |_, _| chunk.clone());
        let plan = source
            .plan_commit(commit_oid, reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS)
            .unwrap();
        assert_eq!(plan.entries().len(), 1);
        assert_eq!(plan.entries()[0].path.as_bytes(), b"file.txt");
        assert_eq!(source.blob_bytes(&blob_oid).unwrap(), blob);
        fs::remove_dir_all(root).unwrap();
    }

    fn oid_hex(oid: &GitOid) -> String {
        let mut output = String::new();
        for byte in oid.as_bytes() {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }
}
