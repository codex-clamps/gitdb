//! Cold-generation reader leases and durable generation publication.
//!
//! GC must not remove a retired generation while a reader can still resolve a
//! location in it. Leases make that dependency explicit and survive a process
//! crash as files that startup reconciliation can inspect.

use reflink_forest_core::{ContentId, GitOid};
use reflink_forest_format::{Codec, ObjectRecord};
use reflink_forest_git::{referenced_oids, GitObject};
use reflink_forest_import::SnapshotManifest;
use reflink_forest_index::{Catalog, CatalogBatch, GcRoot, ObjectLocation, RepoId, SnapshotId};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

const LOCK_EX: std::ffi::c_int = 2;
const LOCK_UN: std::ffi::c_int = 8;

unsafe extern "C" {
    fn flock(fd: std::ffi::c_int, operation: std::ffi::c_int) -> std::ffi::c_int;
}

#[derive(Debug)]
pub enum MaintenanceError {
    Io(io::Error),
    InvalidGenerationPointer,
    InvalidCompactionPlan(&'static str),
    CompactionSourceIsNotCurrent {
        source: u32,
        current: Option<u32>,
    },
    CompactionSourceLocation {
        expected_generation: u32,
        actual_generation: u32,
    },
    CompactionRecordIdMismatch(ContentId),
    CompactionShadowLocation {
        expected_generation: u32,
        actual_generation: u32,
    },
    CompactionRead(String),
    CompactionWrite(String),
    CompactionNotPublished {
        source: u32,
        target: u32,
        current: Option<u32>,
    },
    PinnedGeneration(u32),
    ActiveReaders(u32),
    RetiringGeneration(u32),
    CannotRetireActiveGeneration(u32),
    DestinationExists(PathBuf),
    UnsafeLeaseEntry(PathBuf),
    Catalog(String),
}
impl std::fmt::Display for MaintenanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "maintenance I/O error: {error}"),
            Self::InvalidGenerationPointer => write!(f, "invalid active-generation pointer"),
            Self::InvalidCompactionPlan(reason) => {
                write!(f, "invalid generation-compaction plan: {reason}")
            }
            Self::CompactionSourceIsNotCurrent { source, current } => write!(
                f,
                "cannot compact source generation {source}; catalog current generation is {current:?}"
            ),
            Self::CompactionSourceLocation {
                expected_generation,
                actual_generation,
            } => write!(
                f,
                "compaction source location is in generation {actual_generation}, expected {expected_generation}"
            ),
            Self::CompactionRecordIdMismatch(id) => write!(
                f,
                "compaction reader returned a record with a different content ID for {id:?}"
            ),
            Self::CompactionShadowLocation {
                expected_generation,
                actual_generation,
            } => write!(
                f,
                "compaction writer returned a location in generation {actual_generation}, expected {expected_generation}"
            ),
            Self::CompactionRead(error) => write!(f, "compaction source read failed: {error}"),
            Self::CompactionWrite(error) => write!(f, "compaction destination write failed: {error}"),
            Self::CompactionNotPublished {
                source,
                target,
                current,
            } => write!(
                f,
                "cannot retire compacted generation {source}; catalog current generation is {current:?}, not published target {target}"
            ),
            Self::PinnedGeneration(generation) => write!(
                f,
                "cannot retire generation {generation}; a durable workspace or operational pin still retains it"
            ),
            Self::ActiveReaders(generation) => {
                write!(f, "generation {generation} still has active readers")
            }
            Self::RetiringGeneration(generation) => {
                write!(f, "generation {generation} no longer admits new readers")
            }
            Self::CannotRetireActiveGeneration(generation) => {
                write!(f, "cannot retire the active generation {generation}")
            }
            Self::DestinationExists(path) => write!(
                f,
                "maintenance destination already exists: {}",
                path.display()
            ),
            Self::UnsafeLeaseEntry(path) => write!(
                f,
                "unsafe or unexpected generation lease entry: {}",
                path.display()
            ),
            Self::Catalog(error) => write!(f, "generation catalog error: {error}"),
        }
    }
}
impl std::error::Error for MaintenanceError {}
impl From<io::Error> for MaintenanceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Atomically commits all new object locations and the catalog's active
/// generation, then publishes the derived filesystem pointer. If the latter
/// fails, startup reconciliation repairs it from the catalog; it never rolls
/// back the authoritative catalog commit.
pub fn publish_generation<C: Catalog>(
    catalog: &mut C,
    manager: &GenerationManager,
    generation: u32,
    locations: impl IntoIterator<Item = (ContentId, ObjectLocation)>,
) -> Result<(), MaintenanceError> {
    let mut batch = CatalogBatch::new();
    for (id, location) in locations {
        batch.put_object_location(id, location);
    }
    batch.put_current_generation(generation);
    catalog
        .apply(batch)
        .map_err(|error| MaintenanceError::Catalog(format!("{error:?}")))?;
    manager.publish_active(generation)
}

/// Repairs the derived pointer after startup. The external pointer is never a
/// source of truth: absent catalog state yields `None`; a catalog generation
/// overwrites a stale, missing, or corrupt pointer.
pub fn reconcile_active_generation<C: Catalog>(
    catalog: &C,
    manager: &GenerationManager,
) -> Result<Option<u32>, MaintenanceError> {
    let generation = catalog.current_generation();
    if let Some(generation) = generation {
        manager.publish_active(generation)?;
    }
    Ok(generation)
}

/// A reader for the source side of generation compaction.
///
/// [`read_verified`](Self::read_verified) must validate the addressed source
/// record before returning it. In particular, a chunk-backed implementation
/// should validate the chunk header, complete record encoding, and every
/// catalog field duplicated in the record. The compaction core separately
/// checks the returned [`ObjectRecord::content_id`] against the requested ID.
pub trait CompactionReader {
    type Error: std::fmt::Display;

    fn read_verified(
        &mut self,
        content_id: ContentId,
        location: ObjectLocation,
    ) -> Result<ObjectRecord, Self::Error>;
}

/// A writer for the destination side of generation compaction.
///
/// The destination location returned by [`append`](Self::append) is kept
/// private until [`sync_data`](Self::sync_data) and
/// [`verify`](Self::verify) have succeeded for every copied object. A
/// chunk-backed verifier should use the same complete record/location checks
/// performed by normal cold-store reads.
pub trait CompactionWriter {
    type Error: std::fmt::Display;

    fn append(&mut self, record: &ObjectRecord) -> Result<ObjectLocation, Self::Error>;
    fn sync_data(&mut self) -> Result<(), Self::Error>;
    fn verify(
        &mut self,
        expected_content_id: ContentId,
        location: ObjectLocation,
    ) -> Result<(), Self::Error>;
}

/// Summary of a catalog-published generation compaction.
///
/// The values are intentionally enough to recover a crash between catalog
/// publication and old-generation retirement: callers can pass `source` and
/// `target` to [`retire_compacted_generation`] after reopening the catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionOutcome {
    pub source_generation: u32,
    pub target_generation: u32,
    pub copied_records: usize,
}

/// One repository-scoped native object reference retained outside a ready
/// repository snapshot, for example by an active job or boot-target manifest.
///
/// Generation pins are intentionally not represented here: they retain a
/// complete *old generation* until retirement and are enforced by the
/// retirement path. This type is for durable metadata that needs a particular
/// object copied into the next active generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RetainedObjectRef {
    pub repository: RepoId,
    pub oid: GitOid,
}

/// Bounded-work limits for [`completed_mark_set`].
///
/// Limits cover the durable root manifests, queued Git references, and unique
/// cold records. A limit failure returns no partial mark set, so callers can
/// leave the current generation authoritative and investigate or resume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarkLimits {
    pub max_snapshot_roots: usize,
    pub max_object_references: usize,
    pub max_objects: usize,
}

impl Default for MarkLimits {
    fn default() -> Self {
        Self {
            max_snapshot_roots: 4_096,
            max_object_references: 16 * 1024 * 1024,
            max_objects: 8 * 1024 * 1024,
        }
    }
}

/// Reads one completed snapshot manifest selected by a durable catalog root.
///
/// Implementations normally call
/// [`reflink_forest_import::read_snapshot_manifest`] against the instance's
/// private manifest directory. The mark phase validates the returned manifest
/// again, because [`SnapshotManifest`] has intentionally public fields for
/// format migration and inspection tooling.
pub trait SnapshotManifestSource {
    type Error: std::fmt::Display;

    fn load_snapshot_manifest(
        &self,
        repository: RepoId,
        snapshot: SnapshotId,
    ) -> Result<SnapshotManifest, Self::Error>;
}

impl<F, E> SnapshotManifestSource for F
where
    F: Fn(RepoId, SnapshotId) -> Result<SnapshotManifest, E>,
    E: std::fmt::Display,
{
    type Error = E;

    fn load_snapshot_manifest(
        &self,
        repository: RepoId,
        snapshot: SnapshotId,
    ) -> Result<SnapshotManifest, Self::Error> {
        self(repository, snapshot)
    }
}

/// Failure while deriving a complete mark set from durable roots.
#[derive(Debug)]
pub enum MarkError {
    Catalog(String),
    NoCurrentGeneration,
    TooManySnapshotRoots {
        limit: usize,
    },
    TooManyObjectReferences {
        limit: usize,
    },
    TooManyObjects {
        limit: usize,
    },
    Manifest(String),
    ManifestIdentity {
        expected_repository: RepoId,
        expected_snapshot: SnapshotId,
        actual_repository: RepoId,
        actual_snapshot: SnapshotId,
    },
    MissingAlias {
        repository: RepoId,
        oid: GitOid,
    },
    MissingLocation(ContentId),
    LocationOutsideCurrentGeneration {
        content_id: ContentId,
        expected_generation: u32,
        actual_generation: u32,
    },
    Read(String),
    UnsupportedCodec {
        content_id: ContentId,
        codec: Codec,
    },
    RawLengthMismatch {
        content_id: ContentId,
        expected: u64,
        actual: u64,
    },
    RecordContentIdMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    PayloadContentIdMismatch(ContentId),
    NativeOidMismatch {
        expected: GitOid,
        actual: GitOid,
    },
    InvalidGitObject(String),
}

impl std::fmt::Display for MarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Catalog(error) => write!(f, "GC mark catalog error: {error}"),
            Self::NoCurrentGeneration => write!(f, "GC mark requires a current cold generation"),
            Self::TooManySnapshotRoots { limit } => {
                write!(f, "GC mark exceeds its {limit} snapshot-root limit")
            }
            Self::TooManyObjectReferences { limit } => {
                write!(f, "GC mark exceeds its {limit} object-reference limit")
            }
            Self::TooManyObjects { limit } => {
                write!(f, "GC mark exceeds its {limit} object limit")
            }
            Self::Manifest(error) => write!(f, "GC mark manifest error: {error}"),
            Self::ManifestIdentity {
                expected_repository,
                expected_snapshot,
                actual_repository,
                actual_snapshot,
            } => write!(
                f,
                "GC mark manifest identity mismatch: expected {expected_repository:?}/{expected_snapshot:?}, got {actual_repository:?}/{actual_snapshot:?}"
            ),
            Self::MissingAlias { repository, oid } => {
                write!(f, "GC mark is missing an OID alias for {repository:?}/{oid:?}")
            }
            Self::MissingLocation(content_id) => {
                write!(f, "GC mark is missing the location for {content_id:?}")
            }
            Self::LocationOutsideCurrentGeneration {
                content_id,
                expected_generation,
                actual_generation,
            } => write!(
                f,
                "GC mark found {content_id:?} in generation {actual_generation}, not current generation {expected_generation}"
            ),
            Self::Read(error) => write!(f, "GC mark could not read a cold record: {error}"),
            Self::UnsupportedCodec { content_id, codec } => write!(
                f,
                "GC mark cannot inspect {content_id:?}: unsupported cold codec {codec:?}"
            ),
            Self::RawLengthMismatch {
                content_id,
                expected,
                actual,
            } => write!(
                f,
                "GC mark found raw-length mismatch for {content_id:?}: expected {expected}, got {actual}"
            ),
            Self::RecordContentIdMismatch { expected, actual } => write!(
                f,
                "GC mark found record ContentId {actual:?}, expected {expected:?}"
            ),
            Self::PayloadContentIdMismatch(content_id) => write!(
                f,
                "GC mark found payload bytes that do not hash to {content_id:?}"
            ),
            Self::NativeOidMismatch { expected, actual } => write!(
                f,
                "GC mark found native OID {actual:?}, expected {expected:?}"
            ),
            Self::InvalidGitObject(error) => write!(f, "GC mark found invalid Git object: {error}"),
        }
    }
}

impl std::error::Error for MarkError {}

struct MarkWalk {
    limits: MarkLimits,
    references_queued: usize,
    pending: VecDeque<RetainedObjectRef>,
    visited_references: HashSet<RetainedObjectRef>,
    locations: HashMap<ContentId, ObjectLocation>,
}

impl MarkWalk {
    fn new(limits: MarkLimits) -> Self {
        Self {
            limits,
            references_queued: 0,
            pending: VecDeque::new(),
            visited_references: HashSet::new(),
            locations: HashMap::new(),
        }
    }

    fn queue(&mut self, reference: RetainedObjectRef) -> Result<(), MarkError> {
        self.references_queued =
            self.references_queued
                .checked_add(1)
                .ok_or(MarkError::TooManyObjectReferences {
                    limit: self.limits.max_object_references,
                })?;
        if self.references_queued > self.limits.max_object_references {
            return Err(MarkError::TooManyObjectReferences {
                limit: self.limits.max_object_references,
            });
        }
        self.pending.push_back(reference);
        Ok(())
    }

    fn insert_location(
        &mut self,
        content_id: ContentId,
        location: ObjectLocation,
    ) -> Result<bool, MarkError> {
        if self.locations.contains_key(&content_id) {
            return Ok(false);
        }
        if self.locations.len() >= self.limits.max_objects {
            return Err(MarkError::TooManyObjects {
                limit: self.limits.max_objects,
            });
        }
        self.locations.insert(content_id, location);
        Ok(true)
    }

    fn into_sorted_locations(self) -> Vec<(ContentId, ObjectLocation)> {
        let mut locations: Vec<_> = self.locations.into_iter().collect();
        locations.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        locations
    }
}

/// Builds the complete, deterministic mark set for the current cold
/// generation.
///
/// The walk begins at all `Ready` repository snapshots returned by
/// [`Catalog::gc_roots`], plus exact retained object references supplied by
/// durable job/boot metadata. Every manifest identity, alias, location, raw
/// record, internal `ContentId`, native Git OID, and Git graph edge is checked
/// before any location is returned. Missing, corrupt, cross-generation, or
/// unsupported data therefore fails the whole mark phase rather than causing
/// GC to silently delete reachable objects.
///
/// Workspace and explicit generation pins are intentionally not expanded into
/// per-object entries: they keep their older generation from being retired.
/// They remain part of `gc_roots()` so a caller can enforce them during the
/// retirement decision; a pin alone cannot name a subset of current records.
/// The returned pairs are strictly sorted by raw `ContentId` bytes with no
/// duplicates and can be passed directly to [`compact_completed_mark_set`].
pub fn completed_mark_set<C, M, R, I>(
    catalog: &C,
    manifests: &M,
    reader: &mut R,
    retained: I,
    limits: MarkLimits,
) -> Result<Vec<(ContentId, ObjectLocation)>, MarkError>
where
    C: Catalog,
    M: SnapshotManifestSource,
    R: CompactionReader,
    I: IntoIterator<Item = RetainedObjectRef>,
{
    let current_generation = catalog
        .current_generation()
        .ok_or(MarkError::NoCurrentGeneration)?;
    let roots = catalog
        .gc_roots()
        .map_err(|error| MarkError::Catalog(format!("{error:?}")))?;
    let mut walk = MarkWalk::new(limits);
    let mut snapshot_roots = 0_usize;

    for root in roots {
        let GcRoot::RepositorySnapshot {
            repository,
            snapshot,
        } = root
        else {
            continue;
        };
        snapshot_roots = snapshot_roots
            .checked_add(1)
            .ok_or(MarkError::TooManySnapshotRoots {
                limit: limits.max_snapshot_roots,
            })?;
        if snapshot_roots > limits.max_snapshot_roots {
            return Err(MarkError::TooManySnapshotRoots {
                limit: limits.max_snapshot_roots,
            });
        }
        let manifest = manifests
            .load_snapshot_manifest(repository, snapshot)
            .map_err(|error| MarkError::Manifest(error.to_string()))?;
        manifest
            .validate()
            .map_err(|error| MarkError::Manifest(error.to_string()))?;
        if manifest.repository != repository || manifest.snapshot_id != snapshot {
            return Err(MarkError::ManifestIdentity {
                expected_repository: repository,
                expected_snapshot: snapshot,
                actual_repository: manifest.repository,
                actual_snapshot: manifest.snapshot_id,
            });
        }
        for reference in manifest.refs {
            walk.queue(RetainedObjectRef {
                repository,
                oid: reference.target,
            })?;
        }
    }

    let mut retained_roots = Vec::new();
    for reference in retained {
        if retained_roots.len() >= limits.max_object_references {
            return Err(MarkError::TooManyObjectReferences {
                limit: limits.max_object_references,
            });
        }
        retained_roots.push(reference);
    }
    retained_roots.sort_unstable_by(|left, right| {
        left.repository
            .0
            .cmp(&right.repository.0)
            .then_with(|| left.oid.algorithm().tag().cmp(&right.oid.algorithm().tag()))
            .then_with(|| left.oid.as_bytes().cmp(right.oid.as_bytes()))
    });
    for reference in retained_roots {
        walk.queue(reference)?;
    }

    while let Some(reference) = walk.pending.pop_front() {
        if !walk.visited_references.insert(reference) {
            continue;
        }
        let content_id = catalog
            .oid_alias(reference.repository, &reference.oid)
            .ok_or(MarkError::MissingAlias {
                repository: reference.repository,
                oid: reference.oid,
            })?;
        let location = catalog
            .object_location(content_id)
            .ok_or(MarkError::MissingLocation(content_id))?;
        if location.generation != current_generation {
            return Err(MarkError::LocationOutsideCurrentGeneration {
                content_id,
                expected_generation: current_generation,
                actual_generation: location.generation,
            });
        }
        let record = reader
            .read_verified(content_id, location)
            .map_err(|error| MarkError::Read(error.to_string()))?;
        if record.content_id != content_id {
            return Err(MarkError::RecordContentIdMismatch {
                expected: content_id,
                actual: record.content_id,
            });
        }
        if record.codec != Codec::Raw {
            return Err(MarkError::UnsupportedCodec {
                content_id,
                codec: record.codec,
            });
        }
        let raw_length =
            u64::try_from(record.payload.len()).map_err(|_| MarkError::RawLengthMismatch {
                content_id,
                expected: record.raw_length,
                actual: u64::MAX,
            })?;
        if record.raw_length != raw_length {
            return Err(MarkError::RawLengthMismatch {
                content_id,
                expected: record.raw_length,
                actual: raw_length,
            });
        }
        if ContentId::for_object(record.kind, &record.payload) != content_id {
            return Err(MarkError::PayloadContentIdMismatch(content_id));
        }
        let actual_oid =
            GitOid::for_object(reference.oid.algorithm(), record.kind, &record.payload);
        if actual_oid != reference.oid {
            return Err(MarkError::NativeOidMismatch {
                expected: reference.oid,
                actual: actual_oid,
            });
        }

        if !walk.insert_location(content_id, location)? {
            continue;
        }
        let object = GitObject {
            oid: reference.oid,
            kind: record.kind,
            data: record.payload,
        };
        for oid in referenced_oids(&object)
            .map_err(|error| MarkError::InvalidGitObject(error.to_string()))?
        {
            walk.queue(RetainedObjectRef {
                repository: reference.repository,
                oid,
            })?;
        }
    }

    Ok(walk.into_sorted_locations())
}

/// Copies a completed mark set into a new cold generation and atomically
/// publishes its shadow locations.
///
/// `live` is deliberately *not* a set of Git refs or manifests. It is the
/// completed output of the higher-level mark phase: `(ContentId,
/// ObjectLocation)` pairs, strictly ascending by raw ContentId bytes with no
/// duplicates. Separating marking from this operation keeps repository graph
/// traversal out of the critical copy-and-publish transaction.
///
/// No old generation is retired here. Before the catalog batch commits, the
/// source generation remains current and the target records are only safe
/// orphan data. Once the batch commits, recovery can repair the derived
/// generation pointer from the catalog and then call
/// [`retire_compacted_generation`].
pub fn compact_completed_mark_set<C, R, W>(
    catalog: &mut C,
    manager: &GenerationManager,
    source_generation: u32,
    target_generation: u32,
    live: &[(ContentId, ObjectLocation)],
    reader: &mut R,
    writer: &mut W,
) -> Result<CompactionOutcome, MaintenanceError>
where
    C: Catalog,
    R: CompactionReader,
    W: CompactionWriter,
{
    if target_generation <= source_generation {
        return Err(MaintenanceError::InvalidCompactionPlan(
            "target generation must be greater than the source generation",
        ));
    }
    let current = catalog.current_generation();
    if current != Some(source_generation) {
        return Err(MaintenanceError::CompactionSourceIsNotCurrent {
            source: source_generation,
            current,
        });
    }

    let mut previous = None::<ContentId>;
    for &(content_id, location) in live {
        if let Some(previous) = previous {
            if previous.as_bytes() >= content_id.as_bytes() {
                return Err(MaintenanceError::InvalidCompactionPlan(
                    "live objects must be strictly ascending by ContentId",
                ));
            }
        }
        if location.generation != source_generation {
            return Err(MaintenanceError::CompactionSourceLocation {
                expected_generation: source_generation,
                actual_generation: location.generation,
            });
        }
        previous = Some(content_id);
    }

    let mut shadow_locations = Vec::with_capacity(live.len());
    for &(content_id, source_location) in live {
        let record = reader
            .read_verified(content_id, source_location)
            .map_err(|error| MaintenanceError::CompactionRead(error.to_string()))?;
        if record.content_id != content_id {
            return Err(MaintenanceError::CompactionRecordIdMismatch(content_id));
        }
        let shadow_location = writer
            .append(&record)
            .map_err(|error| MaintenanceError::CompactionWrite(error.to_string()))?;
        if shadow_location.generation != target_generation {
            return Err(MaintenanceError::CompactionShadowLocation {
                expected_generation: target_generation,
                actual_generation: shadow_location.generation,
            });
        }
        shadow_locations.push((content_id, shadow_location));
    }

    // The publication order is deliberate: all target bytes must be durable
    // and independently readable before a catalog reader can resolve one of
    // the shadow locations.
    writer
        .sync_data()
        .map_err(|error| MaintenanceError::CompactionWrite(error.to_string()))?;
    for &(content_id, shadow_location) in &shadow_locations {
        writer
            .verify(content_id, shadow_location)
            .map_err(|error| MaintenanceError::CompactionWrite(error.to_string()))?;
    }

    publish_generation(
        catalog,
        manager,
        target_generation,
        shadow_locations.iter().copied(),
    )?;
    Ok(CompactionOutcome {
        source_generation,
        target_generation,
        copied_records: shadow_locations.len(),
    })
}

/// Retires a source generation only after the compaction catalog publication
/// is known to be durable.
///
/// This check is intentionally based on the catalog rather than an in-memory
/// [`CompactionOutcome`]. A daemon restarting after a catalog commit can
/// safely call this with the discovered old generation and published target;
/// a failed or interrupted compaction cannot pass the check. Reconciliation
/// repairs a stale derived pointer before the lease manager refuses new
/// readers and moves the old generation to trash.
pub fn retire_compacted_generation<C: Catalog>(
    catalog: &C,
    manager: &GenerationManager,
    source_generation: u32,
    target_generation: u32,
    generation_path: impl AsRef<Path>,
    trash_root: impl AsRef<Path>,
) -> Result<PathBuf, MaintenanceError> {
    if target_generation <= source_generation {
        return Err(MaintenanceError::InvalidCompactionPlan(
            "published target generation must be greater than the source generation",
        ));
    }
    let current = catalog.current_generation();
    if current != Some(target_generation) {
        return Err(MaintenanceError::CompactionNotPublished {
            source: source_generation,
            target: target_generation,
            current,
        });
    }
    let has_source_pin = catalog
        .gc_roots()
        .map_err(|error| MaintenanceError::Catalog(format!("{error:?}")))?
        .into_iter()
        .any(|root| match root {
            GcRoot::WorkspacePin { generation, .. } => generation == source_generation,
            GcRoot::ExplicitPin { pin } => pin.generation == source_generation,
            GcRoot::RepositorySnapshot { .. } => false,
        });
    if has_source_pin {
        return Err(MaintenanceError::PinnedGeneration(source_generation));
    }
    reconcile_active_generation(catalog, manager)?;
    manager.retire_generation(source_generation, generation_path, trash_root)
}

#[derive(Debug)]
pub struct GenerationLease {
    path: PathBuf,
}
impl GenerationLease {
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for GenerationLease {
    fn drop(&mut self) {
        if fs::remove_file(&self.path).is_ok() {
            if let Some(parent) = self.path.parent() {
                let _ = File::open(parent).and_then(|directory| directory.sync_all());
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct GenerationManager {
    root: PathBuf,
}
impl GenerationManager {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, MaintenanceError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("leases"))?;
        fs::create_dir_all(root.join("retiring"))?;
        let manager = Self { root };
        // The daemon holds the instance/store lock before opening maintenance
        // state. Every lease found at that point belongs to a dead daemon, so
        // it is safe to remove rather than guessing from reused process IDs.
        manager.reconcile_abandoned_leases()?;
        Ok(manager)
    }
    fn pointer_path(&self) -> PathBuf {
        self.root.join("active-generation")
    }
    fn generation_leases(&self, generation: u32) -> PathBuf {
        self.root.join("leases").join(generation.to_string())
    }
    fn retiring_marker(&self, generation: u32) -> PathBuf {
        self.root.join("retiring").join(generation.to_string())
    }
    fn state_lock_path(&self) -> PathBuf {
        self.root.join("generation-state.lock")
    }

    fn state_lock(&self) -> Result<StateLock, MaintenanceError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.state_lock_path())?;
        // SAFETY: `file` is a valid open descriptor for the lifetime of the
        // returned guard. `flock` does not retain the pointer.
        if unsafe { flock(file.as_raw_fd(), LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(StateLock { file })
    }

    /// Publishes a new active generation through a synchronized temp file and
    /// atomic rename. Catalog publication must occur first and remains the
    /// authoritative source during recovery.
    pub fn publish_active(&self, generation: u32) -> Result<(), MaintenanceError> {
        let _lock = self.state_lock()?;
        let temporary = self.root.join(format!(".active-generation.{}", nonce()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        writeln!(file, "{generation}")?;
        file.sync_all()?;
        fs::rename(&temporary, self.pointer_path())?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    pub fn active_generation(&self) -> Result<Option<u32>, MaintenanceError> {
        let _lock = self.state_lock()?;
        self.active_generation_locked()
    }
    fn active_generation_locked(&self) -> Result<Option<u32>, MaintenanceError> {
        let mut content = String::new();
        match File::open(self.pointer_path()) {
            Ok(mut file) => {
                file.read_to_string(&mut content)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let generation = content
            .trim()
            .parse()
            .map_err(|_| MaintenanceError::InvalidGenerationPointer)?;
        Ok(Some(generation))
    }
    /// Acquires a crash-visible lease before reading generation data.
    pub fn lease(&self, generation: u32) -> Result<GenerationLease, MaintenanceError> {
        let _lock = self.state_lock()?;
        if self.retiring_marker(generation).exists() {
            return Err(MaintenanceError::RetiringGeneration(generation));
        }
        let directory = self.generation_leases(generation);
        fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{}-{}", process::id(), nonce()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(file, "generation={generation}\npid={}", process::id())?;
        file.sync_all()?;
        File::open(&directory)?.sync_all()?;
        Ok(GenerationLease { path })
    }
    /// A retired generation may be reclaimed only when no leases remain.
    pub fn may_reclaim(&self, generation: u32) -> Result<bool, MaintenanceError> {
        let _lock = self.state_lock()?;
        self.may_reclaim_locked(generation)
    }
    fn may_reclaim_locked(&self, generation: u32) -> Result<bool, MaintenanceError> {
        let directory = self.generation_leases(generation);
        match fs::read_dir(directory) {
            Ok(entries) => {
                let mut active = false;
                for entry in entries {
                    let entry = entry?;
                    if !entry.file_type()?.is_file() {
                        return Err(MaintenanceError::UnsafeLeaseEntry(entry.path()));
                    }
                    active = true;
                }
                Ok(!active)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
        }
    }

    /// Removes leases left by a stopped daemon. Callers must own the instance
    /// lock; a live daemon must never have its leases reconciled underneath it.
    /// This method is also used by [`Self::open`] before request acceptance.
    pub fn reconcile_abandoned_leases(&self) -> Result<usize, MaintenanceError> {
        let _lock = self.state_lock()?;
        let mut removed = 0;
        for generation in fs::read_dir(self.root.join("leases"))? {
            let generation = generation?;
            if !generation.file_type()?.is_dir() {
                return Err(MaintenanceError::UnsafeLeaseEntry(generation.path()));
            }
            for lease in fs::read_dir(generation.path())? {
                let lease = lease?;
                if !lease.file_type()?.is_file() {
                    return Err(MaintenanceError::UnsafeLeaseEntry(lease.path()));
                }
                fs::remove_file(lease.path())?;
                removed += 1;
            }
            File::open(generation.path())?.sync_all()?;
        }
        Ok(removed)
    }

    /// Reopens admission for a generation only when a higher-level compaction
    /// aborts before publication. A successfully retired generation never
    /// calls this method.
    pub fn cancel_retirement(&self, generation: u32) -> Result<(), MaintenanceError> {
        let _lock = self.state_lock()?;
        let marker = self.retiring_marker(generation);
        match fs::remove_file(marker) {
            Ok(()) => File::open(self.root.join("retiring"))?
                .sync_all()
                .map_err(Into::into),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Moves an unleased retired generation out of the live chunk namespace.
    /// The caller may remove the returned trash path asynchronously; existing
    /// readers are protected because the operation refuses active leases.
    pub fn retire_generation(
        &self,
        generation: u32,
        generation_path: impl AsRef<Path>,
        trash_root: impl AsRef<Path>,
    ) -> Result<PathBuf, MaintenanceError> {
        let _lock = self.state_lock()?;
        if self.active_generation_locked()? == Some(generation) {
            return Err(MaintenanceError::CannotRetireActiveGeneration(generation));
        }
        self.stop_admitting_leases_locked(generation)?;
        if !self.may_reclaim_locked(generation)? {
            return Err(MaintenanceError::ActiveReaders(generation));
        }
        let generation_path = generation_path.as_ref();
        let trash_root = trash_root.as_ref();
        fs::create_dir_all(trash_root)?;
        let destination = trash_root.join(format!("generation-{generation}-retired"));
        if destination.exists() {
            return Err(MaintenanceError::DestinationExists(destination));
        }
        fs::rename(generation_path, &destination)?;
        File::open(trash_root)?.sync_all()?;
        Ok(destination)
    }

    fn stop_admitting_leases_locked(&self, generation: u32) -> Result<(), MaintenanceError> {
        let marker = self.retiring_marker(generation);
        if marker.exists() {
            return Ok(());
        }
        let temporary = self
            .root
            .join("retiring")
            .join(format!(".{generation}.{}", nonce()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        writeln!(file, "retiring={generation}")?;
        file.sync_all()?;
        fs::rename(temporary, marker)?;
        File::open(self.root.join("retiring"))?.sync_all()?;
        Ok(())
    }
}

#[derive(Debug)]
struct StateLock {
    file: File,
}
impl Drop for StateLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor is still live during Drop and unlock does not
        // retain it.
        unsafe {
            flock(self.file.as_raw_fd(), LOCK_UN);
        }
    }
}
fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflink_forest_core::{HashAlgorithm, ObjectKind};
    use reflink_forest_format::{crc32c, ChunkHeader, Codec, ObjectRecord};
    use reflink_forest_git::LocalRefKind;
    use reflink_forest_import::{ImportPolicy, ImportSummary, PersistedRef, RepoSnapshotId};
    use reflink_forest_index::{
        CatalogError, ChunkMetadata, GcPinId, InMemoryCatalog, RepoId, SnapshotVisibility,
        WorkspaceId,
    };
    use reflink_forest_store::{read_record_at, ChunkWriter, RecordLocation};
    use std::collections::{BTreeMap, HashMap};
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!("reflink-forest-maintenance-{}", nonce()))
    }
    #[test]
    fn generation_pointer_and_leases_are_durable_state() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        assert_eq!(manager.active_generation().unwrap(), None);
        manager.publish_active(7).unwrap();
        assert_eq!(manager.active_generation().unwrap(), Some(7));
        let lease = manager.lease(6).unwrap();
        assert!(!manager.may_reclaim(6).unwrap());
        drop(lease);
        assert!(manager.may_reclaim(6).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generations_move_to_trash_only_after_last_lease() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let generation = root.join("generation-4");
        let trash = root.join("trash");
        fs::create_dir(&generation).unwrap();
        let lease = manager.lease(4).unwrap();
        assert!(matches!(
            manager.retire_generation(4, &generation, &trash),
            Err(MaintenanceError::ActiveReaders(4))
        ));
        drop(lease);
        let retired = manager.retire_generation(4, &generation, &trash).unwrap();
        assert!(retired.is_dir());
        assert!(!generation.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retirement_closes_lease_admission_before_waiting_for_readers() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        manager.publish_active(2).unwrap();
        let generation = root.join("generation-1");
        let trash = root.join("trash");
        fs::create_dir(&generation).unwrap();
        let lease = manager.lease(1).unwrap();
        assert!(matches!(
            manager.retire_generation(1, &generation, &trash),
            Err(MaintenanceError::ActiveReaders(1))
        ));
        assert!(matches!(
            manager.lease(1),
            Err(MaintenanceError::RetiringGeneration(1))
        ));
        drop(lease);
        manager.retire_generation(1, &generation, &trash).unwrap();
        assert!(matches!(
            manager.retire_generation(2, root.join("generation-2"), &trash),
            Err(MaintenanceError::CannotRetireActiveGeneration(2))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn open_reconciles_abandoned_lease_files_after_daemon_restart() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let lease = manager.lease(7).unwrap();
        let lease_path = lease.path().to_path_buf();
        // Simulate a process crash: a stale file remains after its in-memory
        // guard disappears without running Drop.
        std::mem::forget(lease);
        drop(manager);
        let reopened = GenerationManager::open(&root).unwrap();
        assert!(!lease_path.exists());
        assert!(reopened.may_reclaim(7).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    fn location() -> ObjectLocation {
        ObjectLocation {
            generation: 8,
            chunk_id: 1,
            offset: 0,
            record_length: 128,
            stored_length: 16,
            raw_length: 16,
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            payload_crc32c: 4,
        }
    }

    #[test]
    fn publication_commits_locations_and_generation_before_derived_pointer() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let mut catalog = reflink_forest_index::InMemoryCatalog::default();
        let id = ContentId([7; 32]);
        publish_generation(&mut catalog, &manager, 8, [(id, location())]).unwrap();
        assert_eq!(catalog.current_generation(), Some(8));
        assert_eq!(catalog.object_location(id), Some(location()));
        assert_eq!(manager.active_generation().unwrap(), Some(8));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_reconciliation_repairs_pointer_from_catalog_and_catalog_survives_pointer_failure() {
        let root = root();
        let manager = GenerationManager::open(&root).unwrap();
        let mut catalog = reflink_forest_index::InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_current_generation(12);
        catalog.apply(batch).unwrap();
        fs::write(root.join("active-generation"), b"not-a-generation\n").unwrap();
        assert_eq!(
            reconcile_active_generation(&catalog, &manager).unwrap(),
            Some(12)
        );
        assert_eq!(manager.active_generation().unwrap(), Some(12));
        fs::remove_dir_all(&root).unwrap();
        assert!(publish_generation(&mut catalog, &manager, 13, []).is_err());
        assert_eq!(catalog.current_generation(), Some(13));
    }

    fn object_record(payload: &[u8], oid_byte: u8) -> ObjectRecord {
        ObjectRecord {
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: ContentId::for_object(ObjectKind::Blob, payload),
            primary_oid: reflink_forest_core::GitOid::new(
                reflink_forest_core::HashAlgorithm::Sha1,
                &[oid_byte; 20],
            )
            .unwrap(),
            payload: payload.to_vec(),
        }
    }

    fn chunk_header(generation: u32, chunk_id: u64) -> ChunkHeader {
        ChunkHeader {
            generation,
            chunk_id,
            created_unix_secs: 0,
            flags: 0,
        }
    }

    fn object_location(
        generation: u32,
        chunk_id: u64,
        record: &ObjectRecord,
        location: RecordLocation,
    ) -> ObjectLocation {
        ObjectLocation {
            generation,
            chunk_id,
            offset: location.offset,
            record_length: location.record_length,
            stored_length: record.payload.len() as u64,
            raw_length: record.raw_length,
            kind: record.kind,
            codec: record.codec,
            flags: record.flags,
            payload_crc32c: crc32c(&record.payload),
        }
    }

    struct ChunkSource {
        paths: BTreeMap<(u32, u64), PathBuf>,
    }
    impl CompactionReader for ChunkSource {
        type Error = io::Error;

        fn read_verified(
            &mut self,
            _content_id: ContentId,
            location: ObjectLocation,
        ) -> Result<ObjectRecord, Self::Error> {
            let path = self
                .paths
                .get(&(location.generation, location.chunk_id))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "source chunk was not registered")
                })?;
            read_record_at(path, location)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        }
    }

    struct ChunkDestination {
        writer: ChunkWriter,
        generation: u32,
        chunk_id: u64,
    }
    impl CompactionWriter for ChunkDestination {
        type Error = io::Error;

        fn append(&mut self, record: &ObjectRecord) -> Result<ObjectLocation, Self::Error> {
            let location = self
                .writer
                .append(record)
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
            Ok(object_location(
                self.generation,
                self.chunk_id,
                record,
                location,
            ))
        }

        fn sync_data(&mut self) -> Result<(), Self::Error> {
            self.writer
                .sync_data()
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))
        }

        fn verify(
            &mut self,
            expected_content_id: ContentId,
            location: ObjectLocation,
        ) -> Result<(), Self::Error> {
            let record = read_record_at(self.writer.path(), location)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            if record.content_id != expected_content_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "destination record content ID did not match the mark set",
                ));
            }
            Ok(())
        }
    }

    fn source_generation(root: &Path) -> (PathBuf, ChunkSource, Vec<(ContentId, ObjectLocation)>) {
        let path = root.join("generation-1").join("0000000000000001.open");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut writer = ChunkWriter::create(&path, chunk_header(1, 1)).unwrap();
        let first = object_record(b"live object one", 1);
        let second = object_record(b"live object two", 2);
        let first_location = object_location(1, 1, &first, writer.append(&first).unwrap());
        let second_location = object_location(1, 1, &second, writer.append(&second).unwrap());
        writer.sync_data().unwrap();
        drop(writer);

        let mut live = vec![
            (first.content_id, first_location),
            (second.content_id, second_location),
        ];
        live.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        let mut paths = BTreeMap::new();
        paths.insert((1, 1), path);
        (root.join("generation-1"), ChunkSource { paths }, live)
    }

    fn target_generation(root: &Path) -> ChunkDestination {
        let path = root.join("generation-2").join("0000000000000001.open");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        ChunkDestination {
            writer: ChunkWriter::create(&path, chunk_header(2, 1)).unwrap(),
            generation: 2,
            chunk_id: 1,
        }
    }

    fn seed_source_locations<C: Catalog>(catalog: &mut C, live: &[(ContentId, ObjectLocation)]) {
        let mut batch = CatalogBatch::new();
        for &(content_id, location) in live {
            batch.put_object_location(content_id, location);
        }
        batch.put_current_generation(1);
        catalog.apply(batch).unwrap();
    }

    #[test]
    fn compaction_copies_verified_mark_set_then_publishes_before_retirement() {
        let root = root();
        let manager = GenerationManager::open(root.join("maintenance")).unwrap();
        let (source_path, mut reader, live) = source_generation(&root);
        let mut writer = target_generation(&root);
        let mut catalog = InMemoryCatalog::default();
        seed_source_locations(&mut catalog, &live);
        manager.publish_active(1).unwrap();

        let outcome = compact_completed_mark_set(
            &mut catalog,
            &manager,
            1,
            2,
            &live,
            &mut reader,
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            outcome,
            CompactionOutcome {
                source_generation: 1,
                target_generation: 2,
                copied_records: 2,
            }
        );
        assert_eq!(catalog.current_generation(), Some(2));
        assert_eq!(manager.active_generation().unwrap(), Some(2));
        for &(content_id, _) in &live {
            let shadow = catalog.object_location(content_id).unwrap();
            assert_eq!(shadow.generation, 2);
            assert_eq!(
                read_record_at(writer.writer.path(), shadow)
                    .unwrap()
                    .content_id,
                content_id
            );
        }

        let lease = manager.lease(1).unwrap();
        assert!(matches!(
            retire_compacted_generation(&catalog, &manager, 1, 2, &source_path, root.join("trash")),
            Err(MaintenanceError::ActiveReaders(1))
        ));
        drop(lease);
        let workspace_pin = WorkspaceId([0x71; 16]);
        let operation_pin = GcPinId([0x72; 16]);
        let mut pins = CatalogBatch::new();
        pins.put_workspace_pin(workspace_pin, 1);
        pins.put_gc_pin(operation_pin, 1);
        catalog.apply(pins).unwrap();
        assert!(matches!(
            retire_compacted_generation(&catalog, &manager, 1, 2, &source_path, root.join("trash")),
            Err(MaintenanceError::PinnedGeneration(1))
        ));
        assert!(source_path.is_dir());
        let mut release_pins = CatalogBatch::new();
        release_pins.delete_workspace_pin(workspace_pin);
        release_pins.delete_gc_pin(operation_pin);
        catalog.apply(release_pins).unwrap();
        let retired =
            retire_compacted_generation(&catalog, &manager, 1, 2, &source_path, root.join("trash"))
                .unwrap();
        assert!(retired.is_dir());
        assert!(!source_path.exists());
        drop(writer);
        fs::remove_dir_all(root).unwrap();
    }

    struct RejectingCatalog {
        inner: InMemoryCatalog,
        reject_next_apply: bool,
    }
    impl Catalog for RejectingCatalog {
        fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
            if self.reject_next_apply {
                self.reject_next_apply = false;
                return Err(CatalogError::Backend(
                    "injected catalog commit failure".into(),
                ));
            }
            self.inner.apply(batch)
        }

        fn object_location(&self, id: ContentId) -> Option<ObjectLocation> {
            self.inner.object_location(id)
        }

        fn oid_alias(&self, repo: RepoId, oid: &reflink_forest_core::GitOid) -> Option<ContentId> {
            self.inner.oid_alias(repo, oid)
        }

        fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata> {
            self.inner.chunk(generation, chunk_id)
        }

        fn meta(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.inner.meta(key)
        }
    }

    #[test]
    fn failed_catalog_publication_keeps_source_current_and_non_retirable() {
        let root = root();
        let manager = GenerationManager::open(root.join("maintenance")).unwrap();
        let (source_path, mut reader, live) = source_generation(&root);
        let mut writer = target_generation(&root);
        let mut catalog = RejectingCatalog {
            inner: InMemoryCatalog::default(),
            reject_next_apply: false,
        };
        seed_source_locations(&mut catalog, &live);
        catalog.reject_next_apply = true;
        manager.publish_active(1).unwrap();

        assert!(matches!(
            compact_completed_mark_set(
                &mut catalog,
                &manager,
                1,
                2,
                &live,
                &mut reader,
                &mut writer,
            ),
            Err(MaintenanceError::Catalog(_))
        ));
        assert_eq!(catalog.current_generation(), Some(1));
        assert_eq!(manager.active_generation().unwrap(), Some(1));
        assert!(source_path.is_dir());
        assert!(matches!(
            retire_compacted_generation(&catalog, &manager, 1, 2, &source_path, root.join("trash")),
            Err(MaintenanceError::CompactionNotPublished { .. })
        ));
        // A failed publication never begins retirement, so source readers are
        // still admitted while the orphan target data awaits later cleanup.
        drop(manager.lease(1).unwrap());
        drop(writer);
        fs::remove_dir_all(root).unwrap();
    }

    #[derive(Default)]
    struct TestManifests {
        values: BTreeMap<(RepoId, SnapshotId), SnapshotManifest>,
    }
    impl SnapshotManifestSource for TestManifests {
        type Error = String;

        fn load_snapshot_manifest(
            &self,
            repository: RepoId,
            snapshot: SnapshotId,
        ) -> Result<SnapshotManifest, Self::Error> {
            self.values
                .get(&(repository, snapshot))
                .cloned()
                .ok_or_else(|| "test snapshot manifest is absent".to_owned())
        }
    }

    #[derive(Default)]
    struct TestMarkReader {
        records: HashMap<ContentId, ObjectRecord>,
    }
    impl CompactionReader for TestMarkReader {
        type Error = String;

        fn read_verified(
            &mut self,
            content_id: ContentId,
            _: ObjectLocation,
        ) -> Result<ObjectRecord, Self::Error> {
            self.records
                .get(&content_id)
                .cloned()
                .ok_or_else(|| "test cold record is absent".to_owned())
        }
    }

    fn native_oid(kind: ObjectKind, payload: &[u8]) -> GitOid {
        GitOid::for_object(HashAlgorithm::Sha1, kind, payload)
    }

    fn oid_hex(oid: GitOid) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = Vec::with_capacity(usize::from(oid.len()) * 2);
        for &byte in oid.as_bytes() {
            text.push(HEX[usize::from(byte >> 4)]);
            text.push(HEX[usize::from(byte & 0x0f)]);
        }
        text
    }

    fn marked_record(kind: ObjectKind, payload: Vec<u8>) -> ObjectRecord {
        ObjectRecord {
            kind,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: ContentId::for_object(kind, &payload),
            primary_oid: native_oid(kind, &payload),
            payload,
        }
    }

    fn mark_location(record: &ObjectRecord) -> ObjectLocation {
        ObjectLocation {
            generation: 7,
            chunk_id: 1,
            offset: 64,
            record_length: 128 + record.payload.len() as u64,
            stored_length: record.payload.len() as u64,
            raw_length: record.raw_length,
            kind: record.kind,
            codec: record.codec,
            flags: record.flags,
            payload_crc32c: crc32c(&record.payload),
        }
    }

    struct MarkFixture {
        catalog: InMemoryCatalog,
        manifests: TestManifests,
        reader: TestMarkReader,
        retained: RetainedObjectRef,
        ids: Vec<ContentId>,
    }

    fn mark_fixture() -> MarkFixture {
        let repository = RepoId([0x61; 16]);
        let snapshot = RepoSnapshotId([0x62; 16]);
        let tracked_blob = marked_record(ObjectKind::Blob, b"tracked\n".to_vec());
        let retained_blob = marked_record(ObjectKind::Blob, b"retained\n".to_vec());
        let mut tree_payload = b"100644 tracked.txt\0".to_vec();
        tree_payload.extend_from_slice(tracked_blob.primary_oid.as_bytes());
        let tree = marked_record(ObjectKind::Tree, tree_payload);
        let mut commit_payload = b"tree ".to_vec();
        commit_payload.extend_from_slice(&oid_hex(tree.primary_oid));
        commit_payload.extend_from_slice(
            b"\nauthor Mark <mark@example.invalid> 0 +0000\ncommitter Mark <mark@example.invalid> 0 +0000\n\nmark fixture\n",
        );
        let commit = marked_record(ObjectKind::Commit, commit_payload);

        let manifest = SnapshotManifest {
            repository,
            snapshot_id: snapshot,
            native_object_format: HashAlgorithm::Sha1,
            import_policy: ImportPolicy::LocalBranchesAndTags,
            refs: vec![PersistedRef {
                name: b"refs/heads/main".to_vec(),
                kind: LocalRefKind::Branch,
                target: commit.primary_oid,
            }],
            summary: ImportSummary {
                objects_seen: 3,
                objects_written: 3,
                objects_deduplicated: 0,
                raw_bytes: (commit.payload.len() + tree.payload.len() + tracked_blob.payload.len())
                    as u64,
            },
            imported_unix_secs: 0,
            tool_version: b"mark-test".to_vec(),
            optional_fields: Vec::new(),
        };
        manifest.validate().unwrap();

        let incomplete_snapshot = RepoSnapshotId([0x63; 16]);
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_current_generation(7);
        batch.put_repository_snapshot(repository, snapshot, SnapshotVisibility::Ready);
        // An incomplete snapshot must not trigger a manifest read or retain
        // its objects during this mark pass.
        batch.put_repository_snapshot(
            repository,
            incomplete_snapshot,
            SnapshotVisibility::Incomplete,
        );
        let mut reader = TestMarkReader::default();
        let mut ids = Vec::new();
        for record in [&commit, &tree, &tracked_blob, &retained_blob] {
            batch.put_oid_alias(repository, record.primary_oid, record.content_id);
            batch.put_object_location(record.content_id, mark_location(record));
            reader.records.insert(record.content_id, record.clone());
            ids.push(record.content_id);
        }
        catalog.apply(batch).unwrap();

        let mut manifests = TestManifests::default();
        manifests.values.insert((repository, snapshot), manifest);
        MarkFixture {
            catalog,
            manifests,
            reader,
            retained: RetainedObjectRef {
                repository,
                oid: retained_blob.primary_oid,
            },
            ids,
        }
    }

    #[test]
    fn completed_mark_set_preserves_ready_snapshot_graph_and_retained_objects() {
        let mut fixture = mark_fixture();
        let marked = completed_mark_set(
            &fixture.catalog,
            &fixture.manifests,
            &mut fixture.reader,
            [fixture.retained],
            MarkLimits {
                max_snapshot_roots: 1,
                max_object_references: 8,
                max_objects: 4,
            },
        )
        .unwrap();
        let marked_ids: Vec<_> = marked.iter().map(|(id, _)| *id).collect();
        let mut expected = fixture.ids;
        expected.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        assert_eq!(marked_ids, expected);
        assert!(marked
            .windows(2)
            .all(|pair| pair[0].0.as_bytes() < pair[1].0.as_bytes()));
        assert!(marked.iter().all(|(_, location)| location.generation == 7));
    }

    #[test]
    fn completed_mark_set_rejects_corrupt_reachable_record_and_bounded_walks() {
        let mut corrupt = mark_fixture();
        let corrupt_id = corrupt.ids[0];
        let record = corrupt.reader.records.get_mut(&corrupt_id).unwrap();
        record.payload = b"tampered cold record".to_vec();
        record.raw_length = record.payload.len() as u64;
        assert!(matches!(
            completed_mark_set(
                &corrupt.catalog,
                &corrupt.manifests,
                &mut corrupt.reader,
                [corrupt.retained],
                MarkLimits::default(),
            ),
            Err(MarkError::PayloadContentIdMismatch(id)) if id == corrupt_id
        ));

        let mut bounded = mark_fixture();
        assert!(matches!(
            completed_mark_set(
                &bounded.catalog,
                &bounded.manifests,
                &mut bounded.reader,
                [bounded.retained],
                MarkLimits {
                    max_snapshot_roots: 1,
                    max_object_references: 8,
                    max_objects: 1,
                },
            ),
            Err(MarkError::TooManyObjects { limit: 1 })
        ));
    }
}
