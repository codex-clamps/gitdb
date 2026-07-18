//! Bridges cold Git-object storage to raw workspace construction.
//!
//! This crate resolves only repo-scoped aliases, validates every catalog
//! location through the chunk reader, and uses the cache hydration path before
//! checkout requests a reflink. It never accesses the original Git repository.

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_cache::{hydrate_raw_blob_from_chunk, Cache, HydrationError};
use reflink_forest_checkout::{
    materialize_raw, publish_workspace, CheckoutError, CheckoutLimits, CheckoutPlan,
    CheckoutPlanBuilder, GitlinkPolicy, MaterializeError, RawCheckoutSource, RelativePath,
    ReplacePolicy, TreeEntry, TreeName, WorkspaceName, WorkspacePublishError,
};
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_format::{decode_object_payload, Codec, CodecError, ObjectRecord};
use reflink_forest_git::{commit_tree_oid, parse_tree_entries, GitObject, GitTreeEntry};
use reflink_forest_index::{Catalog, CatalogBatch, CatalogError, RepoId, WorkspaceId};
use reflink_forest_maintenance::{GenerationManager, MaintenanceError};
use reflink_forest_store::{read_record_at, StoreError};

/// Binary workspace-manifest format persisted independently of the catalog.
/// The manifest must be synchronized before the catalog is allowed to expose
/// the corresponding workspace as Ready.
pub const WORKSPACE_MANIFEST_VERSION: u16 = 1;
pub const WORKSPACE_MANIFEST_SUFFIX: &str = ".workspace-v1";
const WORKSPACE_MANIFEST_MAGIC: &[u8; 8] = b"RFWORK\0\0";
const MAX_WORKSPACE_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_WORKSPACE_OPTIONAL_FIELDS: usize = 128;
const MAX_WORKSPACE_OPTIONAL_FIELD_BYTES: usize = 16 * 1024;

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
    Codec(CodecError),
    UnsupportedCodec(Codec),
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    Maintenance(MaintenanceError),
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
            Self::Codec(error) => write!(f, "cold object codec failed: {error}"),
            Self::UnsupportedCodec(codec) => {
                write!(f, "raw workspace requires raw objects, found {codec:?}")
            }
            Self::ContentMismatch { .. } => write!(f, "cold record did not match its content ID"),
            Self::Maintenance(error) => write!(f, "generation lease failed: {error}"),
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
impl From<CodecError> for WorkspaceError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<MaintenanceError> for WorkspaceError {
    fn from(value: MaintenanceError) -> Self {
        Self::Maintenance(value)
    }
}
impl From<CheckoutError> for WorkspaceError {
    fn from(value: CheckoutError) -> Self {
        Self::Checkout(value)
    }
}

#[derive(Debug)]
pub enum WorkspaceCheckoutError {
    Planning(Box<WorkspaceError>),
    Materialize(Box<MaterializeError<WorkspaceError>>),
    Publish(Box<WorkspacePublishError>),
}
impl std::fmt::Display for WorkspaceCheckoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planning(error) => write!(f, "workspace planning failed: {error}"),
            Self::Materialize(error) => write!(f, "workspace materialization failed: {error}"),
            Self::Publish(error) => write!(f, "workspace publication failed: {error}"),
        }
    }
}
impl std::error::Error for WorkspaceCheckoutError {}

/// A future-compatible optional workspace-manifest field. Unknown fields are
/// retained on read and emitted again when the manifest is rewritten.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceOptionalField {
    pub tag: u16,
    pub value: Vec<u8>,
}

/// Durable metadata for one atomically published raw workspace. This record
/// retains the snapshot, commit, materialization counts, and cold generation
/// pin necessary for future GC decisions without consulting a source Git repo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceManifest {
    pub workspace_id: WorkspaceId,
    pub repository: RepoId,
    pub snapshot_id: [u8; 16],
    pub commit: GitOid,
    pub generation: u32,
    pub name: Vec<u8>,
    pub created_unix_secs: u64,
    pub directories: u64,
    pub regular_files: u64,
    pub executable_files: u64,
    pub symlinks: u64,
    pub gitlinks: u64,
    pub reflinked_regular_files: u64,
    pub copied_regular_files: u64,
    pub optional_fields: Vec<WorkspaceOptionalField>,
}

/// Stable inputs supplied by the daemon when publishing a workspace. Keeping
/// these together makes it difficult to accidentally omit the generation pin
/// or immutable snapshot identity from a manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceManifestInput {
    pub workspace_id: WorkspaceId,
    pub repository: RepoId,
    pub snapshot_id: [u8; 16],
    pub commit: GitOid,
    pub generation: u32,
    pub name: WorkspaceName,
    pub created_unix_secs: u64,
}

impl WorkspaceManifest {
    /// Builds a manifest directly from a validated raw checkout plan. Raw
    /// checkout has no copy fallback, so every materialized regular file is
    /// recorded as reflinked and the copied count is zero.
    pub fn from_plan(
        input: WorkspaceManifestInput,
        plan: &CheckoutPlan,
    ) -> Result<Self, WorkspaceManifestError> {
        let mut regular_files = 0_u64;
        let mut executable_files = 0_u64;
        let mut symlinks = 0_u64;
        let mut gitlinks = 0_u64;
        for entry in plan.entries() {
            match entry.object.mode {
                reflink_forest_checkout::TreeEntryMode::Regular => {
                    regular_files = regular_files
                        .checked_add(1)
                        .ok_or(WorkspaceManifestError::LengthOverflow)?;
                }
                reflink_forest_checkout::TreeEntryMode::Executable => {
                    executable_files = executable_files
                        .checked_add(1)
                        .ok_or(WorkspaceManifestError::LengthOverflow)?;
                }
                reflink_forest_checkout::TreeEntryMode::Symlink => {
                    symlinks = symlinks
                        .checked_add(1)
                        .ok_or(WorkspaceManifestError::LengthOverflow)?;
                }
                reflink_forest_checkout::TreeEntryMode::Gitlink => {
                    gitlinks = gitlinks
                        .checked_add(1)
                        .ok_or(WorkspaceManifestError::LengthOverflow)?;
                }
            }
        }
        let reflinked_regular_files = regular_files
            .checked_add(executable_files)
            .ok_or(WorkspaceManifestError::LengthOverflow)?;
        let manifest = Self {
            workspace_id: input.workspace_id,
            repository: input.repository,
            snapshot_id: input.snapshot_id,
            commit: input.commit,
            generation: input.generation,
            name: input.name.as_str().as_bytes().to_vec(),
            created_unix_secs: input.created_unix_secs,
            directories: u64::try_from(plan.directories().len())
                .map_err(|_| WorkspaceManifestError::LengthOverflow)?,
            regular_files,
            executable_files,
            symlinks,
            gitlinks,
            reflinked_regular_files,
            copied_regular_files: 0,
            optional_fields: Vec::new(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn add_optional_field(
        &mut self,
        field: WorkspaceOptionalField,
    ) -> Result<(), WorkspaceManifestError> {
        if field.tag == 0
            || field.value.len() > MAX_WORKSPACE_OPTIONAL_FIELD_BYTES
            || self
                .optional_fields
                .iter()
                .any(|existing| existing.tag == field.tag)
        {
            return Err(WorkspaceManifestError::Invalid);
        }
        self.optional_fields.push(field);
        self.validate()
    }

    fn validate(&self) -> Result<(), WorkspaceManifestError> {
        WorkspaceName::new(
            std::str::from_utf8(&self.name).map_err(|_| WorkspaceManifestError::Invalid)?,
        )
        .map_err(|_| WorkspaceManifestError::Invalid)?;
        let total_regular_files = self
            .regular_files
            .checked_add(self.executable_files)
            .ok_or(WorkspaceManifestError::LengthOverflow)?;
        if self.copied_regular_files > total_regular_files
            || self.reflinked_regular_files > total_regular_files
            || self
                .copied_regular_files
                .checked_add(self.reflinked_regular_files)
                != Some(total_regular_files)
            || self.optional_fields.len() > MAX_WORKSPACE_OPTIONAL_FIELDS
        {
            return Err(WorkspaceManifestError::Invalid);
        }
        for (index, field) in self.optional_fields.iter().enumerate() {
            if field.tag == 0
                || field.value.len() > MAX_WORKSPACE_OPTIONAL_FIELD_BYTES
                || self.optional_fields[..index]
                    .iter()
                    .any(|earlier| earlier.tag == field.tag)
            {
                return Err(WorkspaceManifestError::Invalid);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum WorkspaceManifestError {
    Io(io::Error),
    Invalid,
    UnsupportedVersion(u16),
    LengthOverflow,
    AlreadyExists,
}
impl std::fmt::Display for WorkspaceManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "workspace manifest I/O error: {error}"),
            Self::Invalid => write!(f, "invalid workspace manifest"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported workspace manifest version {version}")
            }
            Self::LengthOverflow => write!(f, "workspace manifest length overflow"),
            Self::AlreadyExists => write!(f, "workspace manifest already exists"),
        }
    }
}
impl std::error::Error for WorkspaceManifestError {}
impl From<io::Error> for WorkspaceManifestError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub enum WorkspacePersistenceError {
    Manifest(WorkspaceManifestError),
    Catalog(CatalogError),
    NameAlreadyPublished(WorkspaceId),
    ExistingWorkspaceMismatch,
    ExistingWorkspaceIncomplete,
}
impl std::fmt::Display for WorkspacePersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Manifest(error) => write!(f, "workspace manifest persistence failed: {error}"),
            Self::Catalog(error) => write!(f, "workspace catalog persistence failed: {error:?}"),
            Self::NameAlreadyPublished(id) => {
                write!(f, "workspace name is already associated with {id:?}")
            }
            Self::ExistingWorkspaceMismatch => {
                write!(
                    f,
                    "workspace ID is already associated with different durable metadata"
                )
            }
            Self::ExistingWorkspaceIncomplete => {
                write!(
                    f,
                    "workspace ID has an incomplete durable catalog publication"
                )
            }
        }
    }
}
impl std::error::Error for WorkspacePersistenceError {}
impl From<WorkspaceManifestError> for WorkspacePersistenceError {
    fn from(value: WorkspaceManifestError) -> Self {
        Self::Manifest(value)
    }
}

/// Returns the deterministic, non-client-supplied manifest path for an ID.
pub fn workspace_manifest_path(root: impl AsRef<Path>, id: WorkspaceId) -> PathBuf {
    let mut hex = String::with_capacity(32);
    for byte in id.0 {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    root.as_ref()
        .join(format!("{hex}{WORKSPACE_MANIFEST_SUFFIX}"))
}

/// Writes a complete manifest by synchronizing a create-new temporary file,
/// atomically renaming it, then synchronizing the manifest directory.
pub fn write_workspace_manifest(
    root: impl AsRef<Path>,
    manifest: &WorkspaceManifest,
) -> Result<PathBuf, WorkspaceManifestError> {
    manifest.validate()?;
    let root = root.as_ref();
    fs::create_dir_all(root)?;
    let destination = workspace_manifest_path(root, manifest.workspace_id);
    if destination.exists() {
        return Err(WorkspaceManifestError::AlreadyExists);
    }
    let bytes = encode_workspace_manifest(manifest)?;
    let temporary = temporary_manifest_path(root)?;
    let result = (|| -> Result<(), WorkspaceManifestError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(destination)
}

/// Ensures that the durable external manifest for `manifest` exists and is
/// byte-for-byte identical to the requested publication.
///
/// A crash after the manifest rename but before the catalog batch leaves this
/// exact reusable state. Reopening it rather than overwriting it makes retry
/// safe and prevents one workspace ID from silently changing checkout
/// identity, generation, or pin data.
pub fn ensure_workspace_manifest(
    root: impl AsRef<Path>,
    manifest: &WorkspaceManifest,
) -> Result<PathBuf, WorkspaceManifestError> {
    let root = root.as_ref();
    let path = workspace_manifest_path(root, manifest.workspace_id);
    match read_workspace_manifest(&path) {
        Ok(existing) if existing == *manifest => Ok(path),
        Ok(_) => Err(WorkspaceManifestError::Invalid),
        Err(WorkspaceManifestError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            write_workspace_manifest(root, manifest)
        }
        Err(error) => Err(error),
    }
}

/// Loads and completely validates a workspace manifest, retaining unknown
/// optional fields so a subsequent write does not silently discard them.
pub fn read_workspace_manifest(
    path: impl AsRef<Path>,
) -> Result<WorkspaceManifest, WorkspaceManifestError> {
    let metadata = fs::symlink_metadata(path.as_ref())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_WORKSPACE_MANIFEST_BYTES as u64
    {
        return Err(WorkspaceManifestError::Invalid);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| WorkspaceManifestError::LengthOverflow)?,
    );
    File::open(path)?.read_to_end(&mut bytes)?;
    decode_workspace_manifest(&bytes)
}

/// Publishes a workspace's durable Ready records only after its external
/// manifest exists. The workspace record, name mapping, and generation pin
/// share one catalog batch so GC never observes a Ready workspace without the
/// pin that retains its cold generation.
pub fn persist_ready_workspace<C: Catalog>(
    catalog: &mut C,
    manifests_root: impl AsRef<Path>,
    manifest: &WorkspaceManifest,
) -> Result<PathBuf, WorkspacePersistenceError> {
    if let Some(existing) = catalog.workspace_name(&manifest.name) {
        if existing != manifest.workspace_id {
            return Err(WorkspacePersistenceError::NameAlreadyPublished(existing));
        }
    }
    let path = ensure_workspace_manifest(manifests_root, manifest)?;
    let bytes = encode_workspace_manifest(manifest)?;
    if let Some(existing) = catalog.workspace(manifest.workspace_id) {
        if existing != bytes {
            return Err(WorkspacePersistenceError::ExistingWorkspaceMismatch);
        }
        if catalog.workspace_name(&manifest.name) != Some(manifest.workspace_id)
            || catalog.workspace_pin(manifest.workspace_id) != Some(manifest.generation)
        {
            return Err(WorkspacePersistenceError::ExistingWorkspaceIncomplete);
        }
        return Ok(path);
    }
    let mut batch = CatalogBatch::new();
    batch.put_workspace(manifest.workspace_id, bytes);
    batch.put_workspace_name(&manifest.name, manifest.workspace_id);
    batch.put_workspace_pin(manifest.workspace_id, manifest.generation);
    catalog
        .apply(batch)
        .map_err(WorkspacePersistenceError::Catalog)?;
    Ok(path)
}

/// Resolves a catalog-visible workspace only when its independent manifest is
/// present, valid, and byte-for-byte consistent with the catalog record.
pub fn load_ready_workspace<C: Catalog>(
    catalog: &C,
    manifests_root: impl AsRef<Path>,
    id: WorkspaceId,
) -> Result<Option<WorkspaceManifest>, WorkspaceManifestError> {
    let Some(record) = catalog.workspace(id) else {
        return Ok(None);
    };
    // A deletion releases this pin before removing the external manifest.
    // Treat that durable intermediate state as non-Ready so a crash in that
    // interval cannot make startup fail or re-expose a workspace. It also
    // means a malformed/partial catalog publication never counts as Ready.
    if catalog.workspace_pin(id).is_none() {
        return Ok(None);
    }
    let manifest = read_workspace_manifest(workspace_manifest_path(manifests_root, id))?;
    if manifest.workspace_id != id || encode_workspace_manifest(&manifest)? != record {
        return Err(WorkspaceManifestError::Invalid);
    }
    if catalog.workspace_name(&manifest.name) != Some(id)
        || catalog.workspace_pin(id) != Some(manifest.generation)
    {
        return Ok(None);
    }
    Ok(Some(manifest))
}

/// Maximum number of durable workspace manifests examined before startup
/// accepts new checkout work. The daemon controls these directories, but a
/// bounded scan keeps a corrupt or unexpectedly populated state root from
/// turning recovery into unbounded work.
pub const MAX_WORKSPACE_PUBLICATION_RECONCILIATION: usize = 4096;

/// Result of reconciling manifest-first workspace publications after a crash.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WorkspacePublicationReconciliation {
    /// Valid manifest files that were examined.
    pub manifests_examined: u64,
    /// Workspace directories whose manifest, catalog record, name map, and
    /// generation pin were all complete.
    pub ready_workspaces: u64,
    /// Visible workspace directories moved back to private trash because
    /// their manifest was never made Ready in the catalog.
    pub incomplete_workspaces_withdrawn: u64,
}

/// Failure while reconciling a physical workspace with its durable manifest
/// and catalog publication state.
#[derive(Debug)]
pub enum WorkspaceReconciliationError {
    Io(io::Error),
    Manifest(WorkspaceManifestError),
    TooManyManifests { maximum: usize },
    UnsafeWorkspacePath(PathBuf),
    ReadyWorkspaceMissing(PathBuf),
}

impl std::fmt::Display for WorkspaceReconciliationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "workspace reconciliation I/O error: {error}"),
            Self::Manifest(error) => write!(
                formatter,
                "workspace reconciliation manifest error: {error}"
            ),
            Self::TooManyManifests { maximum } => {
                write!(
                    formatter,
                    "workspace reconciliation exceeds manifest limit {maximum}"
                )
            }
            Self::UnsafeWorkspacePath(path) => {
                write!(
                    formatter,
                    "workspace path is not a real directory: {}",
                    path.display()
                )
            }
            Self::ReadyWorkspaceMissing(path) => {
                write!(formatter, "Ready workspace is missing: {}", path.display())
            }
        }
    }
}

impl std::error::Error for WorkspaceReconciliationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::TooManyManifests { .. }
            | Self::UnsafeWorkspacePath(_)
            | Self::ReadyWorkspaceMissing(_) => None,
        }
    }
}

impl From<io::Error> for WorkspaceReconciliationError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<WorkspaceManifestError> for WorkspaceReconciliationError {
    fn from(value: WorkspaceManifestError) -> Self {
        Self::Manifest(value)
    }
}

/// Moves an unready visible workspace out of the public namespace.
///
/// The caller provides an ID generated by the daemon rather than a path. The
/// destination is therefore a private, deterministic-prefix trash name and
/// the public workspace name becomes absent in one rename. A later cleaner
/// can remove the retired tree without weakening publication safety.
fn withdraw_workspace(
    workspaces: &Path,
    trash: &Path,
    manifest: &WorkspaceManifest,
) -> Result<Option<PathBuf>, WorkspaceReconciliationError> {
    let source = workspaces.join(
        std::str::from_utf8(&manifest.name)
            .map_err(|_| WorkspaceReconciliationError::UnsafeWorkspacePath(workspaces.into()))?,
    );
    let metadata = match fs::symlink_metadata(&source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(WorkspaceReconciliationError::UnsafeWorkspacePath(source));
    }
    fs::create_dir_all(trash)?;
    for attempt in 0..32_u32 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WorkspaceReconciliationError::UnsafeWorkspacePath(trash.into()))?
            .as_nanos();
        let destination = trash.join(format!(
            ".reflink-forest-withdrawn-{}-{timestamp}-{attempt}",
            workspace_id_hex(manifest.workspace_id)
        ));
        match fs::rename(&source, &destination) {
            Ok(()) => {
                File::open(workspaces)?.sync_all()?;
                File::open(trash)?.sync_all()?;
                return Ok(Some(destination));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(WorkspaceReconciliationError::UnsafeWorkspacePath(source))
}

fn workspace_id_hex(id: WorkspaceId) -> String {
    let mut hex = String::with_capacity(32);
    for byte in id.0 {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

/// Reconciles the manifest-first physical publication protocol.
///
/// A crash after the public workspace rename but before the synchronous
/// catalog batch leaves an external manifest without a Ready catalog state.
/// That workspace is withdrawn before new jobs are accepted. An existing
/// manifest is deliberately retained for an idempotent retry; no Ready
/// workspace may exist without the matching catalog record, name mapping, and
/// generation pin.
pub fn reconcile_workspace_publications<C: Catalog>(
    catalog: &C,
    manifests_root: impl AsRef<Path>,
    workspaces: impl AsRef<Path>,
    trash: impl AsRef<Path>,
) -> Result<WorkspacePublicationReconciliation, WorkspaceReconciliationError> {
    let manifests_root = manifests_root.as_ref();
    let workspaces = workspaces.as_ref();
    let trash = trash.as_ref();
    let entries = match fs::read_dir(manifests_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(WorkspacePublicationReconciliation::default())
        }
        Err(error) => return Err(error.into()),
    };
    let mut manifests = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(WORKSPACE_MANIFEST_SUFFIX))
        {
            manifests.push(path);
            if manifests.len() > MAX_WORKSPACE_PUBLICATION_RECONCILIATION {
                return Err(WorkspaceReconciliationError::TooManyManifests {
                    maximum: MAX_WORKSPACE_PUBLICATION_RECONCILIATION,
                });
            }
        }
    }
    manifests.sort_unstable();

    let mut result = WorkspacePublicationReconciliation::default();
    for path in manifests {
        let manifest = read_workspace_manifest(&path)?;
        result.manifests_examined = result.manifests_examined.checked_add(1).ok_or(
            WorkspaceReconciliationError::TooManyManifests {
                maximum: MAX_WORKSPACE_PUBLICATION_RECONCILIATION,
            },
        )?;
        match load_ready_workspace(catalog, manifests_root, manifest.workspace_id)? {
            Some(_) => {
                let workspace =
                    workspaces.join(std::str::from_utf8(&manifest.name).map_err(|_| {
                        WorkspaceReconciliationError::UnsafeWorkspacePath(workspaces.into())
                    })?);
                let metadata = fs::symlink_metadata(&workspace).map_err(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        WorkspaceReconciliationError::ReadyWorkspaceMissing(workspace.clone())
                    } else {
                        WorkspaceReconciliationError::Io(error)
                    }
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(WorkspaceReconciliationError::UnsafeWorkspacePath(workspace));
                }
                result.ready_workspaces = result.ready_workspaces.checked_add(1).ok_or(
                    WorkspaceReconciliationError::TooManyManifests {
                        maximum: MAX_WORKSPACE_PUBLICATION_RECONCILIATION,
                    },
                )?;
            }
            None => {
                if withdraw_workspace(workspaces, trash, &manifest)?.is_some() {
                    result.incomplete_workspaces_withdrawn = result
                        .incomplete_workspaces_withdrawn
                        .checked_add(1)
                        .ok_or(WorkspaceReconciliationError::TooManyManifests {
                            maximum: MAX_WORKSPACE_PUBLICATION_RECONCILIATION,
                        })?;
                }
            }
        }
    }
    Ok(result)
}

/// Failure while deleting a Ready workspace and releasing its GC retention.
#[derive(Debug)]
pub enum WorkspaceDeletionError {
    Io(io::Error),
    Manifest(WorkspaceManifestError),
    Reconciliation(WorkspaceReconciliationError),
    Catalog(CatalogError),
    NotReady(WorkspaceId),
}

impl std::fmt::Display for WorkspaceDeletionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "workspace deletion I/O error: {error}"),
            Self::Manifest(error) => {
                write!(formatter, "workspace deletion manifest error: {error}")
            }
            Self::Reconciliation(error) => {
                write!(formatter, "workspace deletion withdrawal error: {error}")
            }
            Self::Catalog(error) => {
                write!(formatter, "workspace deletion catalog error: {error:?}")
            }
            Self::NotReady(id) => write!(formatter, "workspace is not Ready: {id:?}"),
        }
    }
}

impl std::error::Error for WorkspaceDeletionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::Reconciliation(error) => Some(error),
            Self::Catalog(error) => Some(error),
            Self::NotReady(_) => None,
        }
    }
}

impl From<io::Error> for WorkspaceDeletionError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<WorkspaceManifestError> for WorkspaceDeletionError {
    fn from(value: WorkspaceManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl From<WorkspaceReconciliationError> for WorkspaceDeletionError {
    fn from(value: WorkspaceReconciliationError) -> Self {
        Self::Reconciliation(value)
    }
}

impl From<CatalogError> for WorkspaceDeletionError {
    fn from(value: CatalogError) -> Self {
        Self::Catalog(value)
    }
}

/// Removes a workspace from the public namespace before releasing its cold
/// generation pin. A crash before the catalog update leaks a pin but never
/// lets GC reclaim a still-visible workspace; a crash after the update leaves
/// only non-Ready derived metadata that startup can clean up.
pub fn delete_persisted_workspace<C: Catalog>(
    catalog: &mut C,
    manifests_root: impl AsRef<Path>,
    workspaces: impl AsRef<Path>,
    trash: impl AsRef<Path>,
    id: WorkspaceId,
) -> Result<(), WorkspaceDeletionError> {
    let manifests_root = manifests_root.as_ref();
    let manifest = load_ready_workspace(catalog, manifests_root, id)?
        .ok_or(WorkspaceDeletionError::NotReady(id))?;
    withdraw_workspace(workspaces.as_ref(), trash.as_ref(), &manifest)?;
    let mut batch = CatalogBatch::new();
    batch.delete_workspace_pin(id);
    catalog.apply(batch)?;
    let path = workspace_manifest_path(manifests_root, id);
    match fs::remove_file(&path) {
        Ok(()) => File::open(manifests_root)?.sync_all()?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn encode_workspace_manifest(
    manifest: &WorkspaceManifest,
) -> Result<Vec<u8>, WorkspaceManifestError> {
    manifest.validate()?;
    let name_len =
        u16::try_from(manifest.name.len()).map_err(|_| WorkspaceManifestError::LengthOverflow)?;
    let optional_count = u16::try_from(manifest.optional_fields.len())
        .map_err(|_| WorkspaceManifestError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(WORKSPACE_MANIFEST_MAGIC);
    put_u16(&mut bytes, WORKSPACE_MANIFEST_VERSION);
    bytes.extend_from_slice(&manifest.workspace_id.0);
    bytes.extend_from_slice(&manifest.repository.0);
    bytes.extend_from_slice(&manifest.snapshot_id);
    bytes.push(manifest.commit.algorithm().tag());
    bytes.push(manifest.commit.len());
    bytes.extend_from_slice(manifest.commit.as_bytes());
    bytes.resize(bytes.len() + (32 - manifest.commit.as_bytes().len()), 0);
    put_u32(&mut bytes, manifest.generation);
    put_u64(&mut bytes, manifest.created_unix_secs);
    put_u16(&mut bytes, name_len);
    bytes.extend_from_slice(&manifest.name);
    for count in [
        manifest.directories,
        manifest.regular_files,
        manifest.executable_files,
        manifest.symlinks,
        manifest.gitlinks,
        manifest.reflinked_regular_files,
        manifest.copied_regular_files,
    ] {
        put_u64(&mut bytes, count);
    }
    put_u16(&mut bytes, optional_count);
    for field in &manifest.optional_fields {
        put_u16(&mut bytes, field.tag);
        put_u32(
            &mut bytes,
            u32::try_from(field.value.len()).map_err(|_| WorkspaceManifestError::LengthOverflow)?,
        );
        bytes.extend_from_slice(&field.value);
    }
    if bytes.len() > MAX_WORKSPACE_MANIFEST_BYTES {
        return Err(WorkspaceManifestError::LengthOverflow);
    }
    Ok(bytes)
}

fn decode_workspace_manifest(bytes: &[u8]) -> Result<WorkspaceManifest, WorkspaceManifestError> {
    if bytes.len() > MAX_WORKSPACE_MANIFEST_BYTES || bytes.len() < 8 + 2 {
        return Err(WorkspaceManifestError::Invalid);
    }
    let mut reader = WorkspaceManifestReader::new(bytes);
    if reader.take(8)? != WORKSPACE_MANIFEST_MAGIC {
        return Err(WorkspaceManifestError::Invalid);
    }
    let version = reader.u16()?;
    if version != WORKSPACE_MANIFEST_VERSION {
        return Err(WorkspaceManifestError::UnsupportedVersion(version));
    }
    let workspace_id = WorkspaceId(reader.array()?);
    let repository = RepoId(reader.array()?);
    let snapshot_id = reader.array()?;
    let algorithm = HashAlgorithm::from_tag(reader.u8()?).ok_or(WorkspaceManifestError::Invalid)?;
    let oid_len = usize::from(reader.u8()?);
    if oid_len != usize::from(algorithm.oid_len()) {
        return Err(WorkspaceManifestError::Invalid);
    }
    let oid_bytes: [u8; 32] = reader.array()?;
    if oid_bytes[oid_len..].iter().any(|byte| *byte != 0) {
        return Err(WorkspaceManifestError::Invalid);
    }
    let commit = GitOid::new(algorithm, &oid_bytes[..oid_len])
        .map_err(|_| WorkspaceManifestError::Invalid)?;
    let generation = reader.u32()?;
    let created_unix_secs = reader.u64()?;
    let name_len = usize::from(reader.u16()?);
    if name_len > 128 {
        return Err(WorkspaceManifestError::Invalid);
    }
    let name = reader.take(name_len)?.to_vec();
    let directories = reader.u64()?;
    let regular_files = reader.u64()?;
    let executable_files = reader.u64()?;
    let symlinks = reader.u64()?;
    let gitlinks = reader.u64()?;
    let reflinked_regular_files = reader.u64()?;
    let copied_regular_files = reader.u64()?;
    let optional_count = usize::from(reader.u16()?);
    if optional_count > MAX_WORKSPACE_OPTIONAL_FIELDS {
        return Err(WorkspaceManifestError::Invalid);
    }
    let mut optional_fields = Vec::with_capacity(optional_count);
    for _ in 0..optional_count {
        let tag = reader.u16()?;
        let length = usize::try_from(reader.u32()?).map_err(|_| WorkspaceManifestError::Invalid)?;
        if tag == 0 || length > MAX_WORKSPACE_OPTIONAL_FIELD_BYTES {
            return Err(WorkspaceManifestError::Invalid);
        }
        let value = reader.take(length)?.to_vec();
        if optional_fields
            .iter()
            .any(|field: &WorkspaceOptionalField| field.tag == tag)
        {
            return Err(WorkspaceManifestError::Invalid);
        }
        optional_fields.push(WorkspaceOptionalField { tag, value });
    }
    if !reader.is_empty() {
        return Err(WorkspaceManifestError::Invalid);
    }
    let manifest = WorkspaceManifest {
        workspace_id,
        repository,
        snapshot_id,
        commit,
        generation,
        name,
        created_unix_secs,
        directories,
        regular_files,
        executable_files,
        symlinks,
        gitlinks,
        reflinked_regular_files,
        copied_regular_files,
        optional_fields,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn temporary_manifest_path(root: &Path) -> Result<PathBuf, WorkspaceManifestError> {
    for attempt in 0..32_u32 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WorkspaceManifestError::Invalid)?
            .as_nanos();
        let candidate = root.join(format!(
            ".workspace-manifest-{}-{timestamp}-{attempt}",
            process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(WorkspaceManifestError::AlreadyExists)
}

struct WorkspaceManifestReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> WorkspaceManifestReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], WorkspaceManifestError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(WorkspaceManifestError::LengthOverflow)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(WorkspaceManifestError::Invalid)?;
        self.offset = end;
        Ok(result)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WorkspaceManifestError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WorkspaceManifestError::Invalid)
    }
    fn u8(&mut self) -> Result<u8, WorkspaceManifestError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WorkspaceManifestError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, WorkspaceManifestError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, WorkspaceManifestError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

/// Paths and policies required for the publication half of one raw checkout.
pub struct WorkspaceCheckoutRequest<'a> {
    pub commit: GitOid,
    pub limits: CheckoutLimits,
    pub staging: &'a std::path::Path,
    pub workspaces: &'a std::path::Path,
    pub trash: &'a std::path::Path,
    pub name: &'a WorkspaceName,
    pub gitlink_policy: GitlinkPolicy,
    pub replace: ReplacePolicy,
}

/// Trusted inputs for a cold checkout that must become both physically
/// visible and durably Ready. `manifest` is daemon-owned metadata, including
/// the immutable snapshot identity and cold generation that the workspace
/// must retain for GC.
pub struct PersistedWorkspaceCheckoutRequest<'a> {
    pub checkout: WorkspaceCheckoutRequest<'a>,
    pub manifests_root: &'a Path,
    pub manifest: WorkspaceManifestInput,
}

/// Failure while publishing a cold checkout together with its durable
/// workspace manifest and catalog generation pin.
#[derive(Debug)]
pub enum PersistedWorkspaceCheckoutError {
    ManifestInputMismatch,
    ReplaceNotSupported,
    Planning(Box<WorkspaceError>),
    Materialize(Box<MaterializeError<WorkspaceError>>),
    Manifest(WorkspaceManifestError),
    Publish(WorkspacePublishError),
    Persistence(WorkspacePersistenceError),
    Rollback {
        persistence: Box<WorkspacePersistenceError>,
        rollback: Box<WorkspaceReconciliationError>,
    },
}

impl std::fmt::Display for PersistedWorkspaceCheckoutError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ManifestInputMismatch => {
                write!(formatter, "workspace manifest input does not match checkout request")
            }
            Self::ReplaceNotSupported => write!(
                formatter,
                "durable workspace publication requires a new workspace name; replacement is not supported"
            ),
            Self::Planning(error) => write!(formatter, "workspace planning failed: {error}"),
            Self::Materialize(error) => write!(formatter, "workspace materialization failed: {error}"),
            Self::Manifest(error) => write!(formatter, "workspace manifest preparation failed: {error}"),
            Self::Publish(error) => write!(formatter, "workspace publication failed: {error}"),
            Self::Persistence(error) => write!(formatter, "workspace Ready publication failed: {error}"),
            Self::Rollback {
                persistence,
                rollback,
            } => write!(
                formatter,
                "workspace Ready publication failed ({persistence}) and visible-workspace rollback failed ({rollback})"
            ),
        }
    }
}

impl std::error::Error for PersistedWorkspaceCheckoutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Planning(error) => Some(error),
            Self::Materialize(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::Publish(error) => Some(error),
            Self::Persistence(error) => Some(error),
            Self::Rollback { persistence, .. } => Some(persistence),
            Self::ManifestInputMismatch | Self::ReplaceNotSupported => None,
        }
    }
}

/// Resolves records for one repository using a repo-scoped catalog namespace.
/// `chunk_path` maps a persisted generation/chunk pair to its immutable file.
pub struct ColdWorkspaceSource<'a, C, F> {
    repository: RepoId,
    catalog: &'a C,
    cache: &'a Cache,
    chunk_path: F,
    leases: Option<&'a GenerationManager>,
}

impl<'a, C: Catalog, F: Fn(u32, u64) -> PathBuf> ColdWorkspaceSource<'a, C, F> {
    pub fn new(repository: RepoId, catalog: &'a C, cache: &'a Cache, chunk_path: F) -> Self {
        Self {
            repository,
            catalog,
            cache,
            chunk_path,
            leases: None,
        }
    }

    /// Constructs a source that holds a generation lease while opening and
    /// validating each cold record. This is the production path used when GC
    /// may concurrently retire old generations.
    pub fn new_with_leases(
        repository: RepoId,
        catalog: &'a C,
        cache: &'a Cache,
        chunk_path: F,
        leases: &'a GenerationManager,
    ) -> Self {
        Self {
            repository,
            catalog,
            cache,
            chunk_path,
            leases: Some(leases),
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
        let _lease = match self.leases {
            Some(leases) => Some(leases.lease(location.generation)?),
            None => None,
        };
        let record = read_record_at(
            (self.chunk_path)(location.generation, location.chunk_id),
            location,
        )?;
        let raw_payload = decode_object_payload(&record)?;
        let actual = ContentId::for_object(record.kind, &raw_payload);
        if actual != id || record.content_id != id {
            return Err(WorkspaceError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        Ok((
            id,
            ObjectRecord {
                codec: Codec::Raw,
                payload: raw_payload,
                ..record
            },
        ))
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

    /// Builds, privately materializes, and atomically publishes one raw
    /// workspace. If materialization fails, `staging` remains private and no
    /// workspace name becomes visible.
    pub fn checkout_commit(
        &self,
        request: WorkspaceCheckoutRequest<'_>,
    ) -> Result<PathBuf, WorkspaceCheckoutError> {
        let plan = self
            .plan_commit(request.commit, request.limits)
            .map_err(|error| WorkspaceCheckoutError::Planning(Box::new(error)))?;
        materialize_raw(
            &plan,
            self,
            self.cache,
            request.staging,
            request.gitlink_policy,
        )
        .map_err(|error| WorkspaceCheckoutError::Materialize(Box::new(error)))?;
        publish_workspace(
            request.staging,
            request.workspaces,
            request.trash,
            request.name,
            request.replace,
        )
        .map_err(|error| WorkspaceCheckoutError::Publish(Box::new(error)))
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

/// Builds, materializes, and publishes a real cold checkout with the
/// manifest-first Ready transaction required for workspace GC safety.
///
/// The API deliberately owns the mutable catalog borrow. It creates short
/// immutable reader borrows only while resolving cold objects, then releases
/// them before committing the workspace record/name/pin batch. This avoids an
/// unsafe split between the source catalog and a different persistence
/// catalog. Replacement is intentionally rejected: a new durable workspace
/// requires a fresh identity and name rather than risking an unpinned visible
/// tree while trying to roll back an old one.
pub fn checkout_cold_commit_and_persist<C, F>(
    repository: RepoId,
    catalog: &mut C,
    cache: &Cache,
    chunk_path: F,
    request: PersistedWorkspaceCheckoutRequest<'_>,
) -> Result<PathBuf, PersistedWorkspaceCheckoutError>
where
    C: Catalog,
    F: Fn(u32, u64) -> PathBuf,
{
    let PersistedWorkspaceCheckoutRequest {
        checkout,
        manifests_root,
        manifest: manifest_input,
    } = request;
    if manifest_input.repository != repository
        || manifest_input.commit != checkout.commit
        || manifest_input.name != *checkout.name
    {
        return Err(PersistedWorkspaceCheckoutError::ManifestInputMismatch);
    }
    if checkout.replace != ReplacePolicy::Reject {
        return Err(PersistedWorkspaceCheckoutError::ReplaceNotSupported);
    }
    if let Some(existing) = catalog.workspace_name(checkout.name.as_str().as_bytes()) {
        if existing != manifest_input.workspace_id {
            return Err(PersistedWorkspaceCheckoutError::Persistence(
                WorkspacePersistenceError::NameAlreadyPublished(existing),
            ));
        }
    }

    let plan = ColdWorkspaceSource::new(repository, &*catalog, cache, &chunk_path)
        .plan_commit(checkout.commit, checkout.limits)
        .map_err(|error| PersistedWorkspaceCheckoutError::Planning(Box::new(error)))?;
    let manifest = WorkspaceManifest::from_plan(manifest_input, &plan)
        .map_err(PersistedWorkspaceCheckoutError::Manifest)?;
    {
        let source = ColdWorkspaceSource::new(repository, &*catalog, cache, &chunk_path);
        materialize_raw(
            &plan,
            &source,
            cache,
            checkout.staging,
            checkout.gitlink_policy,
        )
        .map_err(|error| PersistedWorkspaceCheckoutError::Materialize(Box::new(error)))?;
    }
    ensure_workspace_manifest(manifests_root, &manifest)
        .map_err(PersistedWorkspaceCheckoutError::Manifest)?;
    let published = publish_workspace(
        checkout.staging,
        checkout.workspaces,
        checkout.trash,
        checkout.name,
        ReplacePolicy::Reject,
    )
    .map_err(PersistedWorkspaceCheckoutError::Publish)?;
    match persist_ready_workspace(catalog, manifests_root, &manifest) {
        Ok(_) => Ok(published),
        Err(persistence) => {
            match withdraw_workspace(checkout.workspaces, checkout.trash, &manifest) {
                Ok(Some(_)) | Ok(None) => {
                    Err(PersistedWorkspaceCheckoutError::Persistence(persistence))
                }
                Err(rollback) => Err(PersistedWorkspaceCheckoutError::Rollback {
                    persistence: Box::new(persistence),
                    rollback: Box::new(rollback),
                }),
            }
        }
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
        let _lease = match self.leases {
            Some(leases) => Some(leases.lease(location.generation)?),
            None => None,
        };
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
    use reflink_forest_index::{InMemoryCatalog, RocksDbCatalog};
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

    fn append<C: Catalog>(
        writer: &mut ChunkWriter,
        catalog: &mut C,
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

        let leases = GenerationManager::open(root.join("leases")).unwrap();
        let source = ColdWorkspaceSource::new_with_leases(
            repo,
            &catalog,
            &cache,
            |_, _| chunk.clone(),
            &leases,
        );
        let plan = source
            .plan_commit(commit_oid, reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS)
            .unwrap();
        assert_eq!(plan.entries().len(), 1);
        assert_eq!(plan.entries()[0].path.as_bytes(), b"file.txt");
        assert_eq!(source.blob_bytes(&blob_oid).unwrap(), blob);
        assert!(leases.may_reclaim(1).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlink_only_commit_is_materialized_privately_then_published() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let chunk = root.join("1.open");
        let cache = Cache::open(root.join("cache")).unwrap();
        let repo = RepoId([6; 16]);
        let commit_oid = oid(4);
        let tree_oid = oid(5);
        let target_oid = oid(6);
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
        let mut tree = b"120000 linked\0".to_vec();
        tree.extend_from_slice(target_oid.as_bytes());
        let commit = format!("tree {}\n\nmessage\n", oid_hex(&tree_oid)).into_bytes();
        let mut catalog = InMemoryCatalog::default();
        append(
            &mut writer,
            &mut catalog,
            repo,
            target_oid,
            ObjectKind::Blob,
            b"target/path".to_vec(),
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
        let staging = root.join("staging/workspace");
        let workspaces = root.join("workspaces");
        let trash = root.join("trash");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&workspaces).unwrap();
        let name = WorkspaceName::new("published").unwrap();
        let published = source
            .checkout_commit(WorkspaceCheckoutRequest {
                commit: commit_oid,
                limits: reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
                staging: &staging,
                workspaces: &workspaces,
                trash: &trash,
                name: &name,
                gitlink_policy: GitlinkPolicy::Reject,
                replace: ReplacePolicy::Reject,
            })
            .unwrap();
        assert_eq!(
            fs::read_link(published.join("linked")).unwrap(),
            PathBuf::from("target/path")
        );
        assert!(!staging.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn regular_file_checkout_reflinks_when_the_test_domain_supports_ficlone() {
        use reflink_forest_cache::CacheError;
        use reflink_forest_checkout::MaterializeError;

        // `current_dir` is inside the checked-out workspace. On the supported
        // developer/production setup it is Btrfs; generic CI may use a
        // different filesystem and is allowed to report unsupported FICLONE.
        let root = std::env::current_dir().unwrap().join(format!(
            ".reflink-forest-ficlone-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let chunk = root.join("1.open");
        let cache = Cache::open(root.join("cache")).unwrap();
        let repo = RepoId([7; 16]);
        let commit_oid = oid(7);
        let tree_oid = oid(8);
        let blob_oid = oid(9);
        let payload = b"shared extent bytes\n".to_vec();
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
        let mut tree = b"100644 data\0".to_vec();
        tree.extend_from_slice(blob_oid.as_bytes());
        let commit = format!("tree {}\n\nmessage\n", oid_hex(&tree_oid)).into_bytes();
        let mut catalog = InMemoryCatalog::default();
        append(
            &mut writer,
            &mut catalog,
            repo,
            blob_oid,
            ObjectKind::Blob,
            payload.clone(),
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
        let staging = root.join("staging/workspace");
        let workspaces = root.join("workspaces");
        let trash = root.join("trash");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&workspaces).unwrap();
        let name = WorkspaceName::new("regular").unwrap();
        let result = source.checkout_commit(WorkspaceCheckoutRequest {
            commit: commit_oid,
            limits: reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
            staging: &staging,
            workspaces: &workspaces,
            trash: &trash,
            name: &name,
            gitlink_policy: GitlinkPolicy::Reject,
            replace: ReplacePolicy::Reject,
        });
        match result {
            Ok(workspace) => {
                let destination = workspace.join("data");
                assert_eq!(fs::read(&destination).unwrap(), payload);
                fs::write(&destination, b"workspace mutation\n").unwrap();
                let id = ContentId::for_object(ObjectKind::Blob, &payload);
                assert_eq!(fs::read(cache.verified_path(id).unwrap()).unwrap(), payload);
            }
            Err(WorkspaceCheckoutError::Materialize(error))
                if matches!(
                    *error,
                    MaterializeError::Cache(CacheError::Io(ref io_error))
                        if matches!(io_error.raw_os_error(), Some(18) | Some(95))
                ) => {}
            Err(error) => panic!("regular-file checkout failed unexpectedly: {error}"),
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ready_workspace_requires_a_valid_manifest_and_generation_pin() {
        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let commit = oid(0x21);
        let mut builder =
            CheckoutPlanBuilder::new(reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS);
        builder
            .add_tree_entry(
                None,
                TreeEntry::from_raw(
                    b"program",
                    0o100755,
                    oid(0x22),
                    reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
                )
                .unwrap(),
            )
            .unwrap();
        builder
            .add_tree_entry(
                None,
                TreeEntry::from_raw(
                    b"link",
                    0o120000,
                    oid(0x23),
                    reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
                )
                .unwrap(),
            )
            .unwrap();
        let plan = builder.finish();
        let workspace_id = WorkspaceId([0x24; 16]);
        let name = WorkspaceName::new("pinned-workspace").unwrap();
        let manifest = WorkspaceManifest::from_plan(
            WorkspaceManifestInput {
                workspace_id,
                repository: RepoId([0x25; 16]),
                snapshot_id: [0x26; 16],
                commit,
                generation: 9,
                name: name.clone(),
                created_unix_secs: 123,
            },
            &plan,
        )
        .unwrap();
        assert_eq!(manifest.executable_files, 1);
        assert_eq!(manifest.symlinks, 1);
        assert_eq!(manifest.reflinked_regular_files, 1);

        let manifests = root.join("manifests");
        let mut catalog = InMemoryCatalog::default();
        let path = persist_ready_workspace(&mut catalog, &manifests, &manifest).unwrap();
        assert_eq!(catalog.workspace_pin(workspace_id), Some(9));
        assert_eq!(
            catalog.workspace_name(name.as_str().as_bytes()),
            Some(workspace_id)
        );
        assert_eq!(
            load_ready_workspace(&catalog, &manifests, workspace_id).unwrap(),
            Some(manifest.clone())
        );

        let mut corrupted = fs::read(&path).unwrap();
        corrupted[0] ^= 1;
        fs::write(path, corrupted).unwrap();
        assert!(matches!(
            load_ready_workspace(&catalog, &manifests, workspace_id),
            Err(WorkspaceManifestError::Invalid)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_ready_catalog_batch_leaves_a_non_ready_manifest_for_reconciliation() {
        #[derive(Default)]
        struct RejectingCatalog;
        impl Catalog for RejectingCatalog {
            fn apply(&mut self, _: CatalogBatch) -> Result<(), CatalogError> {
                Err(CatalogError::Backend("injected catalog failure".into()))
            }
            fn object_location(
                &self,
                _: ContentId,
            ) -> Option<reflink_forest_index::ObjectLocation> {
                None
            }
            fn oid_alias(&self, _: RepoId, _: &GitOid) -> Option<ContentId> {
                None
            }
            fn chunk(&self, _: u32, _: u64) -> Option<reflink_forest_index::ChunkMetadata> {
                None
            }
        }

        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let name = WorkspaceName::new("unready-workspace").unwrap();
        let plan =
            CheckoutPlanBuilder::new(reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS).finish();
        let workspace_id = WorkspaceId([0x31; 16]);
        let manifest = WorkspaceManifest::from_plan(
            WorkspaceManifestInput {
                workspace_id,
                repository: RepoId([0x32; 16]),
                snapshot_id: [0x33; 16],
                commit: oid(0x34),
                generation: 4,
                name,
                created_unix_secs: 0,
            },
            &plan,
        )
        .unwrap();
        let manifests = root.join("manifests");
        let mut catalog = RejectingCatalog;
        assert!(matches!(
            persist_ready_workspace(&mut catalog, &manifests, &manifest),
            Err(WorkspacePersistenceError::Catalog(_))
        ));
        assert!(workspace_manifest_path(&manifests, workspace_id).is_file());
        assert_eq!(
            load_ready_workspace(&catalog, &manifests, workspace_id).unwrap(),
            None
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persisted_cold_checkout_withdraws_on_catalog_failure_retries_and_pins_until_deletion() {
        #[derive(Default)]
        struct ToggleCatalog {
            inner: InMemoryCatalog,
            reject_next_apply: bool,
        }

        impl Catalog for ToggleCatalog {
            fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
                if self.reject_next_apply {
                    self.reject_next_apply = false;
                    return Err(CatalogError::Backend(
                        "injected Ready workspace catalog failure".into(),
                    ));
                }
                self.inner.apply(batch)
            }

            fn object_location(
                &self,
                id: ContentId,
            ) -> Option<reflink_forest_index::ObjectLocation> {
                self.inner.object_location(id)
            }

            fn oid_alias(&self, repository: RepoId, oid: &GitOid) -> Option<ContentId> {
                self.inner.oid_alias(repository, oid)
            }

            fn chunk(
                &self,
                generation: u32,
                chunk_id: u64,
            ) -> Option<reflink_forest_index::ChunkMetadata> {
                self.inner.chunk(generation, chunk_id)
            }

            fn workspace(&self, id: WorkspaceId) -> Option<Vec<u8>> {
                self.inner.workspace(id)
            }

            fn workspace_name(&self, name: &[u8]) -> Option<WorkspaceId> {
                self.inner.workspace_name(name)
            }

            fn workspace_pin(&self, id: WorkspaceId) -> Option<u32> {
                self.inner.workspace_pin(id)
            }

            fn workspace_pins(&self) -> Result<Vec<(WorkspaceId, u32)>, CatalogError> {
                self.inner.workspace_pins()
            }

            fn current_generation(&self) -> Option<u32> {
                self.inner.current_generation()
            }
        }

        let root = temp_root();
        fs::create_dir(&root).unwrap();
        let chunk = root.join("1.open");
        let cache = Cache::open(root.join("cache")).unwrap();
        let repository = RepoId([0x51; 16]);
        let commit = oid(0x52);
        let tree = oid(0x53);
        let target = oid(0x54);
        let workspace_id = WorkspaceId([0x55; 16]);
        let name = WorkspaceName::new("durable-workspace").unwrap();
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
        let mut catalog = ToggleCatalog::default();
        append(
            &mut writer,
            &mut catalog,
            repository,
            target,
            ObjectKind::Blob,
            b"private-target".to_vec(),
        );
        let mut tree_bytes = b"120000 linked\0".to_vec();
        tree_bytes.extend_from_slice(target.as_bytes());
        append(
            &mut writer,
            &mut catalog,
            repository,
            tree,
            ObjectKind::Tree,
            tree_bytes,
        );
        append(
            &mut writer,
            &mut catalog,
            repository,
            commit,
            ObjectKind::Commit,
            format!("tree {}\n\ndurable workspace\n", oid_hex(&tree)).into_bytes(),
        );
        writer.sync_data().unwrap();
        drop(writer);

        let manifests = root.join("manifests");
        let staging = root.join("staging/workspace");
        let workspaces = root.join("workspaces");
        let trash = root.join("trash");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&workspaces).unwrap();
        let request = || PersistedWorkspaceCheckoutRequest {
            checkout: WorkspaceCheckoutRequest {
                commit,
                limits: reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
                staging: &staging,
                workspaces: &workspaces,
                trash: &trash,
                name: &name,
                gitlink_policy: GitlinkPolicy::Reject,
                replace: ReplacePolicy::Reject,
            },
            manifests_root: &manifests,
            manifest: WorkspaceManifestInput {
                workspace_id,
                repository,
                snapshot_id: [0x56; 16],
                commit,
                generation: 1,
                name: name.clone(),
                created_unix_secs: 7,
            },
        };

        catalog.reject_next_apply = true;
        assert!(matches!(
            checkout_cold_commit_and_persist(
                repository,
                &mut catalog,
                &cache,
                |_, _| chunk.clone(),
                request(),
            ),
            Err(PersistedWorkspaceCheckoutError::Persistence(
                WorkspacePersistenceError::Catalog(_)
            ))
        ));
        assert!(!workspaces.join(name.as_str()).exists());
        assert!(workspace_manifest_path(&manifests, workspace_id).is_file());
        assert_eq!(catalog.workspace(workspace_id), None);
        assert_eq!(catalog.workspace_pin(workspace_id), None);
        assert_eq!(
            reconcile_workspace_publications(&catalog, &manifests, &workspaces, &trash).unwrap(),
            WorkspacePublicationReconciliation {
                manifests_examined: 1,
                ready_workspaces: 0,
                incomplete_workspaces_withdrawn: 0,
            }
        );

        fs::create_dir_all(&staging).unwrap();
        let workspace = checkout_cold_commit_and_persist(
            repository,
            &mut catalog,
            &cache,
            |_, _| chunk.clone(),
            request(),
        )
        .unwrap();
        assert_eq!(
            fs::read_link(workspace.join("linked")).unwrap(),
            PathBuf::from("private-target")
        );
        assert_eq!(catalog.workspace_pin(workspace_id), Some(1));
        assert!(load_ready_workspace(&catalog, &manifests, workspace_id)
            .unwrap()
            .is_some());

        let generations = GenerationManager::open(root.join("leases")).unwrap();
        let source_generation = root.join("generation-1");
        fs::create_dir(&source_generation).unwrap();
        let mut publish_generation = CatalogBatch::new();
        publish_generation.put_current_generation(2);
        catalog.apply(publish_generation).unwrap();
        assert!(matches!(
            reflink_forest_maintenance::retire_compacted_generation(
                &catalog,
                &generations,
                1,
                2,
                &source_generation,
                root.join("generation-trash"),
            ),
            Err(MaintenanceError::PinnedGeneration(1))
        ));

        delete_persisted_workspace(&mut catalog, &manifests, &workspaces, &trash, workspace_id)
            .unwrap();
        assert!(!workspaces.join(name.as_str()).exists());
        assert_eq!(catalog.workspace_pin(workspace_id), None);
        assert!(!workspace_manifest_path(&manifests, workspace_id).exists());
        assert!(reflink_forest_maintenance::retire_compacted_generation(
            &catalog,
            &generations,
            1,
            2,
            &source_generation,
            root.join("generation-trash"),
        )
        .is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restored_cold_tier_materializes_a_workspace_without_the_original_tree() {
        use reflink_forest_backup::{
            checkpoint_cold_tier, restore_cold_tier, BackupError, CheckpointGuard,
            ChunkClassification, ColdChunkDescriptor, ColdTierAuthoritativePaths,
            ColdTierCheckpointDescriptor, ColdTierChunkPath, ColdTierChunkPaths,
        };
        use reflink_forest_cache::CacheError;
        use reflink_forest_checkout::MaterializeError;

        // Keep the original cold tree outside the Btrfs checkout domain so
        // success proves checkout reads only the restored authoritative bytes.
        let original = temp_root();
        fs::create_dir(&original).unwrap();
        let chunk = original.join("1.open");
        let repository = RepoId([0x41; 16]);
        let commit_oid = oid(0x42);
        let tree_oid = oid(0x43);
        let blob_oid = oid(0x44);
        let payload = b"restored cold object\n".to_vec();
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
        let catalog_path = original.join("metadata/catalog");
        fs::create_dir_all(catalog_path.parent().unwrap()).unwrap();
        let mut catalog = RocksDbCatalog::open(&catalog_path).unwrap();
        append(
            &mut writer,
            &mut catalog,
            repository,
            blob_oid,
            ObjectKind::Blob,
            payload.clone(),
        );
        let mut tree = b"100644 restored.txt\0".to_vec();
        tree.extend_from_slice(blob_oid.as_bytes());
        append(
            &mut writer,
            &mut catalog,
            repository,
            tree_oid,
            ObjectKind::Tree,
            tree,
        );
        append(
            &mut writer,
            &mut catalog,
            repository,
            commit_oid,
            ObjectKind::Commit,
            format!("tree {}\n\nrestored\n", oid_hex(&tree_oid)).into_bytes(),
        );
        writer.sync_data().unwrap();
        drop(writer);
        // RocksDB owns a lock while open. Closing it before the checkpoint
        // models the daemon's quiesce/sync handoff and proves the restored
        // catalog is independently reopenable.
        drop(catalog);
        let authoritative_paths = ColdTierAuthoritativePaths::new(
            "metadata/catalog",
            "metadata/config.bin",
            "metadata/pins.bin",
        )
        .unwrap();
        fs::write(original.join(authoritative_paths.config()), b"config").unwrap();
        fs::write(
            original.join(authoritative_paths.pins_manifest()),
            b"workspace pins",
        )
        .unwrap();
        let authoritative_digests = authoritative_paths.digests(&original).unwrap();
        let chunk_paths = ColdTierChunkPaths::new(vec![ColdTierChunkPath {
            generation: 1,
            chunk_id: 1,
            classification: ChunkClassification::Open,
            relative: PathBuf::from("1.open"),
        }])
        .unwrap();

        let backup_parent = temp_root();
        fs::create_dir(&backup_parent).unwrap();
        let backup = backup_parent.join("checkpoint");
        struct Guard;
        impl CheckpointGuard for Guard {
            fn quiesce_and_sync(&self) -> Result<(), BackupError> {
                Ok(())
            }
        }
        let manifest = checkpoint_cold_tier(
            &Guard,
            &original,
            &backup,
            &ColdTierCheckpointDescriptor {
                catalog_schema_version: 1,
                active_generation: 1,
                chunks: vec![ColdChunkDescriptor {
                    generation: 1,
                    chunk_id: 1,
                    classification: ChunkClassification::Open,
                    valid_prefix: fs::metadata(&chunk).unwrap().len(),
                }],
                catalog_digest: authoritative_digests.catalog_digest,
                config_digest: authoritative_digests.config_digest,
                pins_manifest_digest: authoritative_digests.pins_manifest_digest,
            },
            &authoritative_paths,
            &chunk_paths,
        )
        .unwrap();
        fs::remove_dir_all(&original).unwrap();
        assert!(!original.exists());

        // The workspace root is inside this checkout's Btrfs filesystem on
        // supported hosts, so the final regular file exercises restored
        // cold-record hydration and FICLONE in one path.
        let restored = std::env::current_dir().unwrap().join(format!(
            ".reflink-forest-restored-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        restore_cold_tier(
            &backup,
            &manifest,
            &restored,
            &authoritative_paths,
            &chunk_paths,
        )
        .unwrap();
        let cache = Cache::open(restored.join("cache")).unwrap();
        let catalog = RocksDbCatalog::open(restored.join(authoritative_paths.catalog())).unwrap();
        assert!(catalog.oid_alias(repository, &commit_oid).is_some());
        let source =
            ColdWorkspaceSource::new(repository, &catalog, &cache, |_, _| restored.join("1.open"));
        assert_eq!(source.blob_bytes(&blob_oid).unwrap(), payload);
        let staging = restored.join("staging/workspace");
        let workspaces = restored.join("workspaces");
        let trash = restored.join("trash");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&workspaces).unwrap();
        let result = source.checkout_commit(WorkspaceCheckoutRequest {
            commit: commit_oid,
            limits: reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
            staging: &staging,
            workspaces: &workspaces,
            trash: &trash,
            name: &WorkspaceName::new("restored").unwrap(),
            gitlink_policy: GitlinkPolicy::Reject,
            replace: ReplacePolicy::Reject,
        });
        match result {
            Ok(workspace) => {
                assert_eq!(fs::read(workspace.join("restored.txt")).unwrap(), payload);
            }
            Err(WorkspaceCheckoutError::Materialize(error))
                if matches!(
                    *error,
                    MaterializeError::Cache(CacheError::Io(ref io_error))
                        if matches!(io_error.raw_os_error(), Some(18) | Some(95))
                ) => {}
            Err(error) => panic!("restored checkout failed unexpectedly: {error}"),
        }
        fs::remove_dir_all(backup_parent).unwrap();
        fs::remove_dir_all(restored).unwrap();
    }

    fn oid_hex(oid: &GitOid) -> String {
        let mut output = String::new();
        for byte in oid.as_bytes() {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }
}
