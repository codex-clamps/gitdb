//! Append-only chunk files and conservative open-tail recovery.
//!
//! This layer intentionally has no catalog dependency: callers must append,
//! `sync_data`, then atomically publish their index locations. A location is
//! therefore never returned as durable until [`ChunkWriter::sync_data`] has
//! completed successfully.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use reflink_forest_core::{ContentId, GitOid, GitOidHasher, HashAlgorithm};
use reflink_forest_format::{
    crc32c, decode_object_payload_to_writer, decode_record, decode_record_metadata, encode_record,
    encoded_record_len_from_header, encoded_record_len_from_metadata, validate_record_footer,
    verify_object_record, ChunkHeader, CodecError, Crc32c, FormatError, ObjectRecord,
    RecordMetadata, SealedChunkFooter, CHUNK_HEADER_LEN, RECORD_FOOTER_LEN, RECORD_HEADER_LEN,
    SEALED_CHUNK_FOOTER_LEN,
};
use reflink_forest_index::{
    Catalog, CatalogBatch, CatalogError, ChunkMetadata, ChunkState, ObjectLocation,
    ObjectLocationEntry, ObjectLocationRebuildCatalog, ObjectLocationRebuildState, OidAliasEntry,
    RepoId,
};

/// A conservative MVP ceiling that prevents recovery from allocating an
/// attacker-controlled length. Production configuration will make this a
/// store limit and route larger objects through a streaming/spool path.
pub const MAX_RECOVERY_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// Maximum payload bytes read or written by [`stream_record_at`] in one I/O
/// operation.  This bounds cold hydration memory independently of blob size.
pub const STREAM_COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Default upper bound for one synchronous catalog write during an
/// object-location rebuild. The scanner remains streaming at the chunk level;
/// this bound only limits how many already-verified locations are committed at
/// once.
pub const DEFAULT_LOCATION_REBUILD_BATCH_ENTRIES: usize = 1_024;

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Format(FormatError),
    Codec(CodecError),
    NotAnOpenChunk,
    NotASealedChunk,
    ConflictingChunkPaths(PathBuf),
    SealedFooterMissing,
    SealedFooterMismatch(&'static str),
    OpenChunkContainsSealedFooter,
    CatalogChunkStateConflict {
        generation: u32,
        chunk_id: u64,
        state: ChunkState,
    },
    RotationTargetTooSmall,
    InvalidLocationRebuildBatchSize,
    DuplicateRebuildChunkIdentity {
        generation: u32,
        chunk_id: u64,
    },
    PreservedAliasMissingContent {
        repository: RepoId,
        oid: GitOid,
        content_id: ContentId,
    },
    PreservedAliasContentMismatch {
        repository: RepoId,
        oid: GitOid,
        content_id: ContentId,
    },
    WriterGatePoisoned,
    OffsetOverflow,
    LocationMismatch(&'static str),
    Catalog(CatalogError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cold-store I/O error: {error}"),
            Self::Format(error) => write!(f, "cold-store format error: {error}"),
            Self::Codec(error) => write!(f, "cold-store codec error: {error}"),
            Self::NotAnOpenChunk => write!(f, "chunk path must use the .open suffix"),
            Self::NotASealedChunk => write!(f, "chunk path must use the .sealed suffix"),
            Self::ConflictingChunkPaths(path) => write!(
                f,
                "both open and sealed forms exist for chunk {}",
                path.display()
            ),
            Self::SealedFooterMissing => write!(f, "sealed chunk has no complete footer"),
            Self::SealedFooterMismatch(field) => {
                write!(f, "sealed chunk footer does not match {field}")
            }
            Self::OpenChunkContainsSealedFooter => write!(
                f,
                "open chunk contains a complete sealed footer and must be reconciled first"
            ),
            Self::CatalogChunkStateConflict {
                generation,
                chunk_id,
                state,
            } => write!(
                f,
                "catalog state {state:?} conflicts with writable chunk {generation}/{chunk_id}"
            ),
            Self::RotationTargetTooSmall => {
                write!(f, "chunk rotation target cannot represent a chunk footer")
            }
            Self::InvalidLocationRebuildBatchSize => {
                write!(f, "object-location rebuild batch size must be non-zero")
            }
            Self::DuplicateRebuildChunkIdentity {
                generation,
                chunk_id,
            } => write!(
                f,
                "multiple rebuild paths claim chunk {generation}/{chunk_id}"
            ),
            Self::PreservedAliasMissingContent {
                repository,
                oid,
                content_id,
            } => write!(
                f,
                "preserved alias {repository:?}/{oid:?} names absent content {content_id:?}"
            ),
            Self::PreservedAliasContentMismatch {
                repository,
                oid,
                content_id,
            } => write!(
                f,
                "preserved alias {repository:?}/{oid:?} does not match rebuilt content {content_id:?}"
            ),
            Self::WriterGatePoisoned => {
                write!(f, "cold-store writer/checkpoint gate was poisoned")
            }
            Self::OffsetOverflow => write!(f, "chunk offset does not fit in u64"),
            Self::LocationMismatch(field) => {
                write!(
                    f,
                    "catalog location does not match chunk record field {field}"
                )
            }
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
impl From<CodecError> for StoreError {
    fn from(value: CodecError) -> Self {
        Self::Codec(value)
    }
}
impl From<CatalogError> for StoreError {
    fn from(value: CatalogError) -> Self {
        Self::Catalog(value)
    }
}

/// Coordination point for every authoritative mutation of one cold tier.
///
/// A normal writer holds a shared [`ColdStoreWriterPermit`] for the complete
/// durable operation. A checkpoint obtains an exclusive
/// [`ColdStoreCheckpointGuard`], which waits for in-flight writers and keeps
/// subsequent writes paused until the checkpoint is published or fails. This
/// is deliberately a long-lived guard rather than an fsync callback: a
/// checkpoint must retain the exclusion for its entire copy/checkpoint
/// operation.
///
/// New production writers should use [`GatedChunkWriter`] or
/// [`GatedRotatingChunkWriter`], whose public mutators always acquire this
/// gate. Other authoritative mutations (for example pin or configuration
/// publication) must hold [`Self::acquire_writer`] over their complete
/// durable transition as well. The low-level [`ChunkWriter`] remains for
/// offline tooling and tests; it must not be used against a cold tier that is
/// checkpointed through this gate.
#[derive(Clone, Default)]
pub struct ColdStoreWriterGate {
    lock: Arc<RwLock<()>>,
}

impl ColdStoreWriterGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires the shared side of the cold-store gate for one complete
    /// authoritative write transition.
    pub fn acquire_writer(&self) -> Result<ColdStoreWriterPermit<'_>, StoreError> {
        let lock = self
            .lock
            .read()
            .map_err(|_| StoreError::WriterGatePoisoned)?;
        Ok(ColdStoreWriterPermit { _lock: lock })
    }

    /// Pauses all gate-aware cold-tier writers and waits for any already
    /// running operation to reach its durable boundary.
    ///
    /// The returned guard must be retained for the complete checkpoint. It is
    /// intentionally not possible to acquire it and immediately resume
    /// writers before a backup function has copied the authoritative state.
    pub fn freeze_for_checkpoint(&self) -> Result<ColdStoreCheckpointGuard<'_>, StoreError> {
        let lock = self
            .lock
            .write()
            .map_err(|_| StoreError::WriterGatePoisoned)?;
        Ok(ColdStoreCheckpointGuard { _lock: lock })
    }
}

/// Shared permit held by a writer while it changes authoritative cold-tier
/// state. Dropping it makes the writer visible to a pending checkpoint.
pub struct ColdStoreWriterPermit<'gate> {
    _lock: RwLockReadGuard<'gate, ()>,
}

/// Exclusive checkpoint freeze held from quiescence through checkpoint
/// publication. The writer wrappers synchronize their chunks before they
/// release their permits, so acquiring this guard establishes a durable
/// catalog/chunk boundary.
pub struct ColdStoreCheckpointGuard<'gate> {
    _lock: RwLockWriteGuard<'gate, ()>,
}

impl ColdStoreCheckpointGuard<'_> {
    /// Confirms that the exclusive guard is still retained. This is the hook
    /// used by the backup crate's `CheckpointGuard` adapter in the daemon.
    pub fn quiesce_and_sync(&self) -> Result<(), StoreError> {
        Ok(())
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
    header: ChunkHeader,
    next_offset: u64,
    record_count: u64,
    records_crc32c: Crc32c,
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
            header,
            next_offset: CHUNK_HEADER_LEN as u64,
            record_count: 0,
            records_crc32c: Crc32c::new(),
        })
    }

    /// Opens an existing open chunk after validating and recovering its tail.
    pub fn open_recovered(path: impl AsRef<Path>) -> Result<(Self, Recovery), StoreError> {
        let path = path.as_ref().to_path_buf();
        if path.extension().and_then(|extension| extension.to_str()) != Some("open") {
            return Err(StoreError::NotAnOpenChunk);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
        if verify_sealed_file(&mut file).is_ok() {
            return Err(StoreError::OpenChunkContainsSealedFooter);
        }
        let recovery = recover_file(&mut file)?;
        let next_offset = file.metadata()?.len();
        Ok((
            Self {
                path,
                file,
                header: recovery.header,
                next_offset,
                record_count: recovery.valid_records,
                records_crc32c: recovery.records_crc32c,
            },
            recovery,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The durable header established when this open chunk was created.
    pub const fn header(&self) -> ChunkHeader {
        self.header
    }

    /// Current valid record count, excluding any not-yet-written sealed footer.
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Current valid file length, excluding any not-yet-written sealed footer.
    pub const fn open_length(&self) -> u64 {
        self.next_offset
    }

    /// Durably records this chunk's writable state after its header has been
    /// synchronized.  Repeating the call is safe and updates a stale size or
    /// record count after open-tail recovery.
    pub fn publish_open<C: Catalog>(&self, catalog: &mut C) -> Result<(), StoreError> {
        ensure_catalog_writable(catalog, self.header)?;
        let mut batch = CatalogBatch::new();
        batch.put_chunk(
            self.header.generation,
            self.header.chunk_id,
            ChunkMetadata {
                state: ChunkState::Open,
                size: self.next_offset,
                record_count: self.record_count,
            },
        );
        catalog.apply(batch)?;
        Ok(())
    }

    /// Creates, synchronizes, directory-syncs, and then catalog-publishes a
    /// new empty open chunk.  A crash before catalog publication leaves an
    /// unreferenced header-only file; a later reconciliation can safely
    /// discover and publish it.
    pub fn create_and_publish<C: Catalog>(
        path: impl AsRef<Path>,
        header: ChunkHeader,
        catalog: &mut C,
    ) -> Result<Self, StoreError> {
        let writer = Self::create(path, header)?;
        writer.publish_open(catalog)?;
        Ok(writer)
    }

    /// Appends exactly one self-contained object record. The returned location
    /// is not durable until `sync_data` returns successfully.
    pub fn append(&mut self, record: &ObjectRecord) -> Result<RecordLocation, StoreError> {
        verify_object_record(record)?;
        let encoded = encode_record(record)?;
        let offset = self.next_offset;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&encoded)?;
        let record_length = u64::try_from(encoded.len()).map_err(|_| StoreError::OffsetOverflow)?;
        self.next_offset = self
            .next_offset
            .checked_add(record_length)
            .ok_or(StoreError::OffsetOverflow)?;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(StoreError::OffsetOverflow)?;
        self.records_crc32c.update(&encoded);
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
        if self.header.generation != generation {
            return Err(StoreError::LocationMismatch("generation"));
        }
        if self.header.chunk_id != chunk_id {
            return Err(StoreError::LocationMismatch("chunk_id"));
        }
        ensure_catalog_writable(catalog, self.header)?;
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
            batch.put_chunk(
                generation,
                chunk_id,
                ChunkMetadata {
                    state: ChunkState::Open,
                    size: self.next_offset,
                    record_count: self.record_count,
                },
            );
            catalog.apply(batch)?;
            Ok(Some(location))
        } else {
            batch.put_oid_alias(repo, record.primary_oid, record.content_id);
            catalog.apply(batch)?;
            Ok(None)
        }
    }

    /// Writes and synchronizes the sealed footer, renames `.open` to
    /// `.sealed`, synchronizes the parent directory, then publishes the
    /// matching catalog state.  Thus a crash before the catalog batch leaves
    /// a structurally valid sealed file that startup can publish idempotently.
    pub fn seal_and_publish<C: Catalog>(
        mut self,
        catalog: &mut C,
    ) -> Result<SealedChunk, StoreError> {
        ensure_catalog_writable(catalog, self.header)?;
        let sealed_path = sealed_path_for(&self.path)?;
        if sealed_path.exists() {
            return Err(StoreError::ConflictingChunkPaths(self.path.clone()));
        }
        let final_length = self
            .next_offset
            .checked_add(SEALED_CHUNK_FOOTER_LEN as u64)
            .ok_or(StoreError::OffsetOverflow)?;
        let footer = SealedChunkFooter {
            record_count: self.record_count,
            final_length,
            records_crc32c: self.records_crc32c.finalize(),
        };
        self.sync_data()?;
        self.file.seek(SeekFrom::Start(self.next_offset))?;
        self.file.write_all(&footer.encode())?;
        self.file.sync_data()?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "chunk has no parent"))?;
        drop(self.file);
        fs::rename(&self.path, &sealed_path)?;
        sync_directory(parent)?;
        publish_sealed_metadata(catalog, self.header, footer)?;
        Ok(SealedChunk {
            path: sealed_path,
            header: self.header,
            footer,
        })
    }
}

/// A production-facing chunk writer whose durable mutation methods all share
/// one [`ColdStoreWriterGate`].
///
/// Unlike the low-level [`ChunkWriter`], this type does not expose an
/// append-without-index operation. Each public write holds the shared gate
/// through its complete file/catalog transition, so a
/// [`ColdStoreCheckpointGuard`] cannot observe an in-between state.
pub struct GatedChunkWriter {
    gate: ColdStoreWriterGate,
    writer: ChunkWriter,
}

impl GatedChunkWriter {
    /// Creates and catalog-publishes a new open chunk while participating in
    /// the supplied cold-tier checkpoint gate.
    pub fn create_and_publish<C: Catalog>(
        gate: ColdStoreWriterGate,
        path: impl AsRef<Path>,
        header: ChunkHeader,
        catalog: &mut C,
    ) -> Result<Self, StoreError> {
        let permit = gate.acquire_writer()?;
        let writer = ChunkWriter::create_and_publish(path, header, catalog);
        drop(permit);
        Ok(Self {
            gate,
            writer: writer?,
        })
    }

    /// Opens and conservatively recovers an existing open chunk while holding
    /// the writer side of the checkpoint gate. Tail recovery can truncate, so
    /// it is an authoritative mutation rather than a read-only operation.
    pub fn open_recovered(
        gate: ColdStoreWriterGate,
        path: impl AsRef<Path>,
    ) -> Result<(Self, Recovery), StoreError> {
        let permit = gate.acquire_writer()?;
        let recovered = ChunkWriter::open_recovered(path);
        drop(permit);
        let (writer, recovery) = recovered?;
        Ok((Self { gate, writer }, recovery))
    }

    pub fn path(&self) -> &Path {
        self.writer.path()
    }

    pub const fn header(&self) -> ChunkHeader {
        self.writer.header()
    }

    pub const fn record_count(&self) -> u64 {
        self.writer.record_count()
    }

    pub const fn open_length(&self) -> u64 {
        self.writer.open_length()
    }

    /// Appends, synchronizes, and publishes one record as one gate-aware
    /// durable transition.
    pub fn append_and_index<C: Catalog>(
        &mut self,
        catalog: &mut C,
        repo: RepoId,
        generation: u32,
        chunk_id: u64,
        record: &ObjectRecord,
    ) -> Result<Option<RecordLocation>, StoreError> {
        let permit = self.gate.acquire_writer()?;
        let result = self
            .writer
            .append_and_index(catalog, repo, generation, chunk_id, record);
        drop(permit);
        result
    }

    /// Seals, renames, synchronizes, and catalog-publishes the chunk as one
    /// gate-aware durable transition.
    pub fn seal_and_publish<C: Catalog>(self, catalog: &mut C) -> Result<SealedChunk, StoreError> {
        let permit = self.gate.acquire_writer()?;
        let result = self.writer.seal_and_publish(catalog);
        drop(permit);
        result
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Recovery {
    /// Header independently validated before tail scanning began.
    pub header: ChunkHeader,
    pub valid_records: u64,
    pub retained_bytes: u64,
    pub truncated_bytes: u64,
    /// Rolling checksum of the retained complete encoded records.
    pub records_crc32c: Crc32c,
}

/// Verified durable identity of an immutable `.sealed` chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedChunk {
    path: PathBuf,
    header: ChunkHeader,
    footer: SealedChunkFooter,
}

impl SealedChunk {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn header(&self) -> ChunkHeader {
        self.header
    }

    pub const fn footer(&self) -> SealedChunkFooter {
        self.footer
    }
}

/// Result of reconciling one chunk across the footer, filesystem name, and
/// catalog state after a process crash.
#[derive(Clone, Debug)]
pub enum ChunkReconciliation {
    Open(Recovery),
    Sealed(SealedChunk),
}

struct RecordScan {
    records: u64,
    end: u64,
    checksum: Crc32c,
}

/// Validates an open chunk and truncates from its first invalid or incomplete
/// record. The header is never repaired: a bad header is a hard failure.
pub fn recover_open_chunk(path: impl AsRef<Path>) -> Result<Recovery, StoreError> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    if verify_sealed_file(&mut file).is_ok() {
        return Err(StoreError::OpenChunkContainsSealedFooter);
    }
    recover_file(&mut file)
}

fn recover_file(file: &mut File) -> Result<Recovery, StoreError> {
    let header = read_chunk_header(file)?;
    let original_len = file.metadata()?.len();
    let scan = scan_records(file, original_len, false)?;
    if scan.end != original_len {
        file.set_len(scan.end)?;
        file.sync_data()?;
    }
    Ok(Recovery {
        header,
        valid_records: scan.records,
        retained_bytes: scan.end,
        truncated_bytes: original_len - scan.end,
        records_crc32c: scan.checksum,
    })
}

/// Reads and validates every record in a chunk without modifying it.
pub fn verify_chunk(path: impl AsRef<Path>) -> Result<u64, StoreError> {
    let path = path.as_ref();
    if is_sealed_path(path) {
        return Ok(verify_sealed_chunk(path)?.footer.record_count);
    }
    if !is_open_path(path) {
        return Err(StoreError::NotAnOpenChunk);
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let length = file.metadata()?.len();
    read_chunk_header(&mut file)?;
    if let Ok(verified) = verify_sealed_file(&mut file) {
        return Ok(verified.footer.record_count);
    }
    Ok(scan_records(&mut file, length, true)?.records)
}

/// Reconciles an `.open`/`.sealed` pair after any lifecycle crash boundary.
///
/// A complete footer in an `.open` name means the crash happened after footer
/// synchronization but before rename.  Recovery verifies it, renames it,
/// syncs the directory, and then (re)publishes the sealed catalog entry.  A
/// partial or corrupt footer is merely an interrupted open-tail write and is
/// truncated with the rest of the uncommitted tail.
pub fn reconcile_chunk<C: Catalog>(
    catalog: &mut C,
    path: impl AsRef<Path>,
) -> Result<ChunkReconciliation, StoreError> {
    let path = path.as_ref();
    let (open_path, sealed_path) = chunk_path_pair(path)?;
    if open_path.exists() && sealed_path.exists() {
        return Err(StoreError::ConflictingChunkPaths(open_path));
    }
    if sealed_path.exists() {
        let sealed = verify_sealed_chunk(&sealed_path)?;
        publish_sealed_metadata(catalog, sealed.header, sealed.footer)?;
        return Ok(ChunkReconciliation::Sealed(sealed));
    }

    let mut file = OpenOptions::new().read(true).write(true).open(&open_path)?;
    if let Ok(verified) = verify_sealed_file(&mut file) {
        let header = verified.header;
        let footer = verified.footer;
        drop(file);
        let parent = open_path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "chunk has no parent"))?;
        fs::rename(&open_path, &sealed_path)?;
        sync_directory(parent)?;
        publish_sealed_metadata(catalog, header, footer)?;
        return Ok(ChunkReconciliation::Sealed(SealedChunk {
            path: sealed_path,
            header,
            footer,
        }));
    }

    // A catalog state of Sealed is never downgraded merely because a stale
    // `.open` name exists: that would make an acknowledged immutable chunk
    // writable again.  The operator must resolve the contradictory state.
    let header = read_chunk_header(&mut file)?;
    if let Some(metadata) = catalog.chunk(header.generation, header.chunk_id) {
        if metadata.state != ChunkState::Open {
            return Err(StoreError::CatalogChunkStateConflict {
                generation: header.generation,
                chunk_id: header.chunk_id,
                state: metadata.state,
            });
        }
    }
    let recovery = recover_file(&mut file)?;
    drop(file);
    let writer = ChunkWriter::open_recovered(&open_path)?.0;
    writer.publish_open(catalog)?;
    drop(writer);
    Ok(ChunkReconciliation::Open(recovery))
}

/// Reads and verifies a sealed chunk, including every record, footer count,
/// final length, and rolling record checksum.
pub fn verify_sealed_chunk(path: impl AsRef<Path>) -> Result<SealedChunk, StoreError> {
    let path = path.as_ref();
    if !is_sealed_path(path) {
        return Err(StoreError::NotASealedChunk);
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let verified = verify_sealed_file(&mut file)?;
    Ok(SealedChunk {
        path: path.to_path_buf(),
        header: verified.header,
        footer: verified.footer,
    })
}

/// Summary of a verified, locations-only catalog rebuild.
///
/// `scanned_records` counts every physical record. When the same ContentId is
/// present in more than one verified chunk, `selected_locations` counts it
/// once and `duplicate_records` records how many later physical copies were
/// deterministically discarded.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocationRebuildReport {
    pub chunk_files: u64,
    pub sealed_chunks: u64,
    pub open_chunks: u64,
    pub scanned_records: u64,
    pub selected_locations: u64,
    pub duplicate_records: u64,
    pub preserved_aliases_verified: u64,
    pub catalog_batches_written: u64,
}

/// A complete, immutable preflight result for an object-location rebuild.
///
/// The candidate locations are intentionally private. They can only be
/// committed by [`rebuild_object_locations`] after the full chunk and alias
/// verification has succeeded, preventing callers from accidentally indexing
/// a partially scanned set.
pub struct LocationRebuildPreflight {
    entries: Vec<RebuildCandidate>,
    report: LocationRebuildReport,
}

impl LocationRebuildPreflight {
    pub const fn report(&self) -> LocationRebuildReport {
        self.report
    }
}

#[derive(Clone, Debug)]
struct RebuildCandidate {
    entry: ObjectLocationEntry,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebuildChunkState {
    Open,
    Sealed,
}

struct RebuildChunkScan {
    header: ChunkHeader,
    state: RebuildChunkState,
    records: u64,
}

/// Fully scans every supplied chunk and verifies every preserved repository
/// alias before any catalog location is cleared.
///
/// Paths are normalized into lexical order for scanning, but winner selection
/// never depends on that order: duplicate ContentIds select the lowest
/// `(generation, chunk_id, offset)` location. Open chunks must end on a valid
/// record boundary. A complete sealed footer under an `.open` name is rejected
/// so callers must run lifecycle reconciliation before rebuilding locations.
///
/// The caller must hold the store writer freeze for the full preflight and
/// subsequent rebuild. This function does not repair chunks, alter aliases, or
/// mutate the catalog.
pub fn preflight_object_location_rebuild<C, I, P>(
    catalog: &C,
    paths: I,
) -> Result<LocationRebuildPreflight, StoreError>
where
    C: Catalog,
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut paths: Vec<PathBuf> = paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .collect();
    paths.sort_unstable();
    paths.dedup();

    let current_generation = catalog.current_generation();
    let mut report = LocationRebuildReport::default();
    let mut identities = BTreeSet::new();
    let mut selected: BTreeMap<[u8; 32], RebuildCandidate> = BTreeMap::new();
    for path in paths {
        let mut candidates = Vec::new();
        let chunk = scan_chunk_for_location_rebuild(&path, &mut candidates)?;
        if !identities.insert((chunk.header.generation, chunk.header.chunk_id)) {
            return Err(StoreError::DuplicateRebuildChunkIdentity {
                generation: chunk.header.generation,
                chunk_id: chunk.header.chunk_id,
            });
        }
        report.chunk_files = report
            .chunk_files
            .checked_add(1)
            .ok_or(StoreError::OffsetOverflow)?;
        match chunk.state {
            RebuildChunkState::Open => {
                report.open_chunks = report
                    .open_chunks
                    .checked_add(1)
                    .ok_or(StoreError::OffsetOverflow)?;
            }
            RebuildChunkState::Sealed => {
                report.sealed_chunks = report
                    .sealed_chunks
                    .checked_add(1)
                    .ok_or(StoreError::OffsetOverflow)?;
            }
        }
        report.scanned_records = report
            .scanned_records
            .checked_add(chunk.records)
            .ok_or(StoreError::OffsetOverflow)?;

        for candidate in candidates {
            let key = *candidate.entry.content_id.as_bytes();
            match selected.get_mut(&key) {
                None => {
                    selected.insert(key, candidate);
                }
                Some(current) => {
                    report.duplicate_records = report
                        .duplicate_records
                        .checked_add(1)
                        .ok_or(StoreError::OffsetOverflow)?;
                    if rebuild_location_precedes(
                        candidate.entry.location,
                        current.entry.location,
                        current_generation,
                    ) {
                        *current = candidate;
                    }
                }
            }
        }
    }

    verify_preserved_aliases(catalog, &selected, &mut report)?;
    report.selected_locations =
        u64::try_from(selected.len()).map_err(|_| StoreError::OffsetOverflow)?;
    Ok(LocationRebuildPreflight {
        entries: selected.into_values().collect(),
        report,
    })
}

/// Rebuilds only `object_locations` from a complete verified preflight.
///
/// Normal operation performs the full preflight before clearing locations. If
/// a previous attempt left the catalog's durable rebuild marker in progress,
/// the partial locations are first discarded, then the same full preflight is
/// repeated before any bounded append batch. OID aliases, chunk metadata, and
/// every other catalog family are never written by this operation.
///
/// A failure after `begin`/`restart` deliberately leaves the durable
/// in-progress marker set. Readers then fail closed until a later caller reruns
/// this function with the same writer freeze.
pub fn rebuild_object_locations<C, I, P>(
    catalog: &mut C,
    paths: I,
    maximum_batch_entries: usize,
) -> Result<LocationRebuildReport, StoreError>
where
    C: ObjectLocationRebuildCatalog,
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    if maximum_batch_entries == 0 {
        return Err(StoreError::InvalidLocationRebuildBatchSize);
    }
    let state = catalog.object_location_rebuild_state()?;
    if state == ObjectLocationRebuildState::InProgress {
        catalog.restart_object_location_rebuild()?;
    }

    let preflight = preflight_object_location_rebuild(&*catalog, paths)?;
    if state == ObjectLocationRebuildState::Idle {
        catalog.begin_object_location_rebuild()?;
    }

    let mut report = preflight.report();
    for batch in preflight.entries.chunks(maximum_batch_entries) {
        let entries: Vec<_> = batch.iter().map(|candidate| candidate.entry).collect();
        catalog.append_rebuilt_object_locations(&entries)?;
        report.catalog_batches_written = report
            .catalog_batches_written
            .checked_add(1)
            .ok_or(StoreError::OffsetOverflow)?;
    }
    catalog.finish_object_location_rebuild()?;
    Ok(report)
}

fn rebuild_location_order(location: ObjectLocation) -> (u32, u64, u64) {
    (location.generation, location.chunk_id, location.offset)
}

fn rebuild_location_precedes(
    candidate: ObjectLocation,
    existing: ObjectLocation,
    current_generation: Option<u32>,
) -> bool {
    match current_generation {
        Some(current) if candidate.generation == current && existing.generation != current => true,
        Some(current) if candidate.generation != current && existing.generation == current => false,
        _ => rebuild_location_order(candidate) < rebuild_location_order(existing),
    }
}

fn scan_chunk_for_location_rebuild(
    path: &Path,
    candidates: &mut Vec<RebuildCandidate>,
) -> Result<RebuildChunkScan, StoreError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let header = read_chunk_header(&mut file)?;
    let mut collect = |offset: u64, record: &ObjectRecord, record_length: u64| {
        let stored_length =
            u64::try_from(record.payload.len()).map_err(|_| StoreError::OffsetOverflow)?;
        candidates.push(RebuildCandidate {
            entry: ObjectLocationEntry {
                content_id: record.content_id,
                location: ObjectLocation {
                    generation: header.generation,
                    chunk_id: header.chunk_id,
                    offset,
                    record_length,
                    stored_length,
                    raw_length: record.raw_length,
                    kind: record.kind,
                    codec: record.codec,
                    flags: record.flags,
                    payload_crc32c: crc32c(&record.payload),
                },
            },
            path: path.to_path_buf(),
        });
        Ok(())
    };

    if is_sealed_path(path) {
        let verified = verify_sealed_file_with_visitor(&mut file, &mut collect)?;
        debug_assert_eq!(verified.header, header);
        return Ok(RebuildChunkScan {
            header,
            state: RebuildChunkState::Sealed,
            records: verified.footer.record_count,
        });
    }
    if !is_open_path(path) {
        return Err(StoreError::NotAnOpenChunk);
    }
    if verify_sealed_file(&mut file).is_ok() {
        return Err(StoreError::OpenChunkContainsSealedFooter);
    }
    let end = file.metadata()?.len();
    let scan = scan_records_with_visitor(&mut file, end, true, &mut collect)?;
    Ok(RebuildChunkScan {
        header,
        state: RebuildChunkState::Open,
        records: scan.records,
    })
}

fn verify_preserved_aliases<C: Catalog>(
    catalog: &C,
    selected: &BTreeMap<[u8; 32], RebuildCandidate>,
    report: &mut LocationRebuildReport,
) -> Result<(), StoreError> {
    let mut calculated = HashMap::new();
    let mut failure = None;
    catalog.visit_oid_aliases(&mut |alias| {
        if failure.is_none() {
            if let Err(error) = verify_preserved_alias(&alias, selected, &mut calculated) {
                failure = Some(error);
            } else {
                report.preserved_aliases_verified = report
                    .preserved_aliases_verified
                    .checked_add(1)
                    .ok_or_else(|| CatalogError::Backend("alias count overflow".into()))?;
            }
        }
        Ok(())
    })?;
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn verify_preserved_alias(
    alias: &OidAliasEntry,
    selected: &BTreeMap<[u8; 32], RebuildCandidate>,
    calculated: &mut HashMap<([u8; 32], HashAlgorithm), GitOid>,
) -> Result<(), StoreError> {
    let key = *alias.content_id.as_bytes();
    let Some(candidate) = selected.get(&key) else {
        return Err(StoreError::PreservedAliasMissingContent {
            repository: alias.repository,
            oid: alias.oid,
            content_id: alias.content_id,
        });
    };
    let algorithm = alias.oid.algorithm();
    let actual = match calculated.get(&(key, algorithm)) {
        Some(oid) => *oid,
        None => {
            let location = candidate.entry.location;
            let mut hasher = GitOidHasher::new(algorithm, location.kind, location.raw_length);
            stream_decoded_record_at(&candidate.path, location, &mut hasher)?;
            let oid = hasher.finish();
            calculated.insert((key, algorithm), oid);
            oid
        }
    };
    if actual != alias.oid {
        return Err(StoreError::PreservedAliasContentMismatch {
            repository: alias.repository,
            oid: alias.oid,
            content_id: alias.content_id,
        });
    }
    Ok(())
}

struct VerifiedSealedChunk {
    header: ChunkHeader,
    footer: SealedChunkFooter,
}

fn verify_sealed_file(file: &mut File) -> Result<VerifiedSealedChunk, StoreError> {
    verify_sealed_file_with_visitor(file, &mut |_, _, _| Ok(()))
}

/// Verifies an immutable chunk footer and every record while forwarding each
/// strict-verified record to `visitor`.
fn verify_sealed_file_with_visitor(
    file: &mut File,
    visitor: &mut dyn FnMut(u64, &ObjectRecord, u64) -> Result<(), StoreError>,
) -> Result<VerifiedSealedChunk, StoreError> {
    let header = read_chunk_header(file)?;
    let length = file.metadata()?.len();
    let minimum_length = (CHUNK_HEADER_LEN as u64)
        .checked_add(SEALED_CHUNK_FOOTER_LEN as u64)
        .ok_or(StoreError::OffsetOverflow)?;
    if length < minimum_length {
        return Err(StoreError::SealedFooterMissing);
    }
    let footer_offset = length
        .checked_sub(SEALED_CHUNK_FOOTER_LEN as u64)
        .ok_or(StoreError::OffsetOverflow)?;
    let mut footer_bytes = [0_u8; SEALED_CHUNK_FOOTER_LEN];
    file.seek(SeekFrom::Start(footer_offset))?;
    file.read_exact(&mut footer_bytes)?;
    let footer = SealedChunkFooter::decode(&footer_bytes)?;
    if footer.final_length != length {
        return Err(StoreError::SealedFooterMismatch("final length"));
    }
    let scan = scan_records_with_visitor(file, footer_offset, true, visitor)?;
    if scan.end != footer_offset {
        return Err(StoreError::SealedFooterMismatch("record boundary"));
    }
    if scan.records != footer.record_count {
        return Err(StoreError::SealedFooterMismatch("record count"));
    }
    if scan.checksum.finalize() != footer.records_crc32c {
        return Err(StoreError::SealedFooterMismatch("rolling record checksum"));
    }
    Ok(VerifiedSealedChunk { header, footer })
}

/// Scans records through exactly `end` bytes from the beginning of a chunk.
/// A recovery scan stops at its first malformed/incomplete record; a strict
/// scan returns that error, which is required before trusting a sealed footer.
fn scan_records(file: &mut File, end: u64, strict: bool) -> Result<RecordScan, StoreError> {
    scan_records_with_visitor(file, end, strict, &mut |_, _, _| Ok(()))
}

/// Equivalent to [`scan_records`], while exposing each fully decoded record
/// and its immutable byte range to an internal verifier. The visitor is
/// called only for complete records; strict scans additionally validate the
/// decoded object identity before exposing a record.
fn scan_records_with_visitor(
    file: &mut File,
    end: u64,
    strict: bool,
    visitor: &mut dyn FnMut(u64, &ObjectRecord, u64) -> Result<(), StoreError>,
) -> Result<RecordScan, StoreError> {
    let header_end = CHUNK_HEADER_LEN as u64;
    if end < header_end {
        return Err(StoreError::Format(FormatError::Truncated));
    }
    let mut offset = header_end;
    let mut records = 0_u64;
    let mut checksum = Crc32c::new();
    while offset < end {
        let remaining = end.checked_sub(offset).ok_or(StoreError::OffsetOverflow)?;
        if remaining < RECORD_HEADER_LEN as u64 {
            if strict {
                return Err(StoreError::Format(FormatError::Truncated));
            }
            break;
        }
        let mut record_header = [0_u8; RECORD_HEADER_LEN];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut record_header)?;
        let encoded_len = match encoded_record_len_from_header(&record_header) {
            Ok(length) if length <= MAX_RECOVERY_RECORD_BYTES => length,
            Ok(_) => {
                if strict {
                    return Err(StoreError::OffsetOverflow);
                }
                break;
            }
            Err(error) => {
                if strict {
                    return Err(error.into());
                }
                break;
            }
        };
        let encoded_len_u64 = u64::try_from(encoded_len).map_err(|_| StoreError::OffsetOverflow)?;
        if encoded_len_u64 > remaining {
            if strict {
                return Err(StoreError::Format(FormatError::Truncated));
            }
            break;
        }
        let mut encoded = vec![0_u8; encoded_len];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut encoded)?;
        match decode_record(&encoded) {
            Ok((record, consumed)) if consumed == encoded_len => {
                // A sealed footer authenticates the encoded record stream, but
                // not the relationship between a record's stored bytes and its
                // declared raw object identity.  Strict verification is the
                // trust boundary for immutable chunks, so validate that
                // relationship here.  Recovery deliberately stays structural
                // and bounded: it must be able to find a usable open tail
                // without decompressing untrusted records.
                if strict {
                    verify_object_record(&record)?;
                }
                visitor(offset, &record, encoded_len_u64)?;
                offset = offset
                    .checked_add(encoded_len_u64)
                    .ok_or(StoreError::OffsetOverflow)?;
                records = records.checked_add(1).ok_or(StoreError::OffsetOverflow)?;
                checksum.update(&encoded);
            }
            Ok(_) => {
                if strict {
                    return Err(StoreError::SealedFooterMismatch("record length"));
                }
                break;
            }
            Err(error) => {
                if strict {
                    return Err(error.into());
                }
                break;
            }
        }
    }
    Ok(RecordScan {
        records,
        end: offset,
        checksum,
    })
}

fn read_chunk_header(file: &mut File) -> Result<ChunkHeader, StoreError> {
    let mut bytes = [0_u8; CHUNK_HEADER_LEN];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    Ok(ChunkHeader::decode(&bytes)?)
}

fn is_open_path(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("open")
}

fn is_sealed_path(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("sealed")
}

fn sealed_path_for(open_path: &Path) -> Result<PathBuf, StoreError> {
    if !is_open_path(open_path) {
        return Err(StoreError::NotAnOpenChunk);
    }
    Ok(open_path.with_extension("sealed"))
}

fn chunk_path_pair(path: &Path) -> Result<(PathBuf, PathBuf), StoreError> {
    if is_open_path(path) {
        Ok((path.to_path_buf(), path.with_extension("sealed")))
    } else if is_sealed_path(path) {
        Ok((path.with_extension("open"), path.to_path_buf()))
    } else {
        Err(StoreError::NotAnOpenChunk)
    }
}

fn sync_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn ensure_catalog_writable<C: Catalog>(catalog: &C, header: ChunkHeader) -> Result<(), StoreError> {
    if let Some(metadata) = catalog.chunk(header.generation, header.chunk_id) {
        if metadata.state != ChunkState::Open {
            return Err(StoreError::CatalogChunkStateConflict {
                generation: header.generation,
                chunk_id: header.chunk_id,
                state: metadata.state,
            });
        }
    }
    Ok(())
}

fn publish_sealed_metadata<C: Catalog>(
    catalog: &mut C,
    header: ChunkHeader,
    footer: SealedChunkFooter,
) -> Result<(), StoreError> {
    if let Some(metadata) = catalog.chunk(header.generation, header.chunk_id) {
        if metadata.state == ChunkState::Retired {
            return Err(StoreError::CatalogChunkStateConflict {
                generation: header.generation,
                chunk_id: header.chunk_id,
                state: metadata.state,
            });
        }
    }
    let mut batch = CatalogBatch::new();
    batch.put_chunk(
        header.generation,
        header.chunk_id,
        ChunkMetadata {
            state: ChunkState::Sealed,
            size: footer.final_length,
            record_count: footer.record_count,
        },
    );
    catalog.apply(batch)?;
    Ok(())
}

/// Location returned by [`RotatingChunkWriter`].  `dedicated_oversized` is
/// true only when the record was larger than the configured target and was
/// therefore written to, and immediately sealed in, its own chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotatedRecordLocation {
    pub generation: u32,
    pub chunk_id: u64,
    pub location: RecordLocation,
    pub dedicated_oversized: bool,
}

/// Serialized cold-store writer that rotates only between complete records.
///
/// This deliberately has no background work: callers append through one
/// instance, and every rotation completes the same footer → sync → rename →
/// directory-sync → catalog-publication order as [`ChunkWriter`].
pub struct RotatingChunkWriter {
    directory: PathBuf,
    generation: u32,
    target_size: u64,
    created_unix_secs: u64,
    next_chunk_id: u64,
    active: Option<ChunkWriter>,
}

impl RotatingChunkWriter {
    /// Creates and catalog-publishes the first writable chunk.
    ///
    /// `target_size` includes the chunk header, all complete records, and the
    /// sealed footer.  A record larger than the remaining usable target is
    /// still accepted in a dedicated oversized chunk rather than split.
    pub fn create<C: Catalog>(
        directory: impl AsRef<Path>,
        generation: u32,
        first_chunk_id: u64,
        target_size: u64,
        created_unix_secs: u64,
        catalog: &mut C,
    ) -> Result<Self, StoreError> {
        let minimum = (CHUNK_HEADER_LEN as u64)
            .checked_add(SEALED_CHUNK_FOOTER_LEN as u64)
            .ok_or(StoreError::OffsetOverflow)?;
        if target_size < minimum {
            return Err(StoreError::RotationTargetTooSmall);
        }
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let mut writer = Self {
            directory,
            generation,
            target_size,
            created_unix_secs,
            next_chunk_id: first_chunk_id,
            active: None,
        };
        writer.create_next(catalog)?;
        Ok(writer)
    }

    pub const fn generation(&self) -> u32 {
        self.generation
    }

    pub const fn target_size(&self) -> u64 {
        self.target_size
    }

    pub fn active_path(&self) -> &Path {
        self.active
            .as_ref()
            .expect("rotating writer always has an active chunk outside a failed rotation")
            .path()
    }

    pub fn active_chunk_id(&self) -> u64 {
        self.active
            .as_ref()
            .expect("rotating writer always has an active chunk outside a failed rotation")
            .header()
            .chunk_id
    }

    /// Appends and indexes one record, rotating before the record when doing
    /// so preserves the target.  An oversized record gets an empty chunk of
    /// its own, which is sealed immediately before a fresh normal open chunk
    /// is created for subsequent records.
    pub fn append_and_index<C: Catalog>(
        &mut self,
        catalog: &mut C,
        repo: RepoId,
        record: &ObjectRecord,
    ) -> Result<Option<RotatedRecordLocation>, StoreError> {
        // A deduplicated record adds only a repository alias, so it must not
        // rotate an otherwise empty or target-sized chunk.
        if catalog.object_location(record.content_id).is_some() {
            let generation = self.generation;
            let active = self.active_mut();
            let chunk_id = active.header().chunk_id;
            let location = active.append_and_index(catalog, repo, generation, chunk_id, record)?;
            return Ok(location.map(|location| RotatedRecordLocation {
                generation,
                chunk_id,
                location,
                dedicated_oversized: false,
            }));
        }

        let encoded_len =
            u64::try_from(encode_record(record)?.len()).map_err(|_| StoreError::OffsetOverflow)?;
        let minimum_record_chunk = (CHUNK_HEADER_LEN as u64)
            .checked_add(encoded_len)
            .and_then(|length| length.checked_add(SEALED_CHUNK_FOOTER_LEN as u64))
            .ok_or(StoreError::OffsetOverflow)?;
        let oversized = minimum_record_chunk > self.target_size;
        let target_size = self.target_size;
        let would_exceed_target = {
            let active = self.active_mut();
            active
                .open_length()
                .checked_add(encoded_len)
                .and_then(|length| length.checked_add(SEALED_CHUNK_FOOTER_LEN as u64))
                .ok_or(StoreError::OffsetOverflow)?
                > target_size
                && active.record_count() != 0
        };
        if would_exceed_target {
            self.seal_current(catalog)?;
            self.create_next(catalog)?;
        }

        let generation = self.generation;
        let (chunk_id, location) = {
            let active = self.active_mut();
            let chunk_id = active.header().chunk_id;
            let location = active
                .append_and_index(catalog, repo, generation, chunk_id, record)?
                .expect("record was checked absent from the catalog before append");
            (chunk_id, location)
        };
        if oversized {
            self.seal_current(catalog)?;
            self.create_next(catalog)?;
        }
        Ok(Some(RotatedRecordLocation {
            generation,
            chunk_id,
            location,
            dedicated_oversized: oversized,
        }))
    }

    /// Seals the active chunk and leaves no writable chunk behind.  This is
    /// useful for a clean shutdown; reopening must use [`reconcile_chunk`] or
    /// construct a new rotating writer at the next chunk ID.
    pub fn finish<C: Catalog>(&mut self, catalog: &mut C) -> Result<SealedChunk, StoreError> {
        self.seal_current(catalog)
    }

    fn active_mut(&mut self) -> &mut ChunkWriter {
        self.active
            .as_mut()
            .expect("rotating writer always has an active chunk outside a failed rotation")
    }

    fn create_next<C: Catalog>(&mut self, catalog: &mut C) -> Result<(), StoreError> {
        let chunk_id = self.next_chunk_id;
        self.next_chunk_id = self
            .next_chunk_id
            .checked_add(1)
            .ok_or(StoreError::OffsetOverflow)?;
        let path = self.directory.join(format!("{chunk_id:016x}.open"));
        let writer = ChunkWriter::create_and_publish(
            path,
            ChunkHeader {
                generation: self.generation,
                chunk_id,
                created_unix_secs: self.created_unix_secs,
                flags: 0,
            },
            catalog,
        )?;
        self.active = Some(writer);
        Ok(())
    }

    fn seal_current<C: Catalog>(&mut self, catalog: &mut C) -> Result<SealedChunk, StoreError> {
        let writer = self
            .active
            .take()
            .expect("rotating writer always has an active chunk outside a failed rotation");
        writer.seal_and_publish(catalog)
    }
}

/// A production-facing rotating writer that cannot mutate its cold tier
/// without participating in its [`ColdStoreWriterGate`].
///
/// Each exported mutation holds a shared writer permit across any rotation,
/// chunk synchronization, rename, and catalog publication it performs.
pub struct GatedRotatingChunkWriter {
    gate: ColdStoreWriterGate,
    writer: RotatingChunkWriter,
}

impl GatedRotatingChunkWriter {
    pub fn create<C: Catalog>(
        gate: ColdStoreWriterGate,
        directory: impl AsRef<Path>,
        generation: u32,
        first_chunk_id: u64,
        target_size: u64,
        created_unix_secs: u64,
        catalog: &mut C,
    ) -> Result<Self, StoreError> {
        let permit = gate.acquire_writer()?;
        let writer = RotatingChunkWriter::create(
            directory,
            generation,
            first_chunk_id,
            target_size,
            created_unix_secs,
            catalog,
        );
        drop(permit);
        Ok(Self {
            gate,
            writer: writer?,
        })
    }

    pub const fn generation(&self) -> u32 {
        self.writer.generation()
    }

    pub const fn target_size(&self) -> u64 {
        self.writer.target_size()
    }

    pub fn active_path(&self) -> &Path {
        self.writer.active_path()
    }

    pub fn active_chunk_id(&self) -> u64 {
        self.writer.active_chunk_id()
    }

    pub fn append_and_index<C: Catalog>(
        &mut self,
        catalog: &mut C,
        repo: RepoId,
        record: &ObjectRecord,
    ) -> Result<Option<RotatedRecordLocation>, StoreError> {
        let permit = self.gate.acquire_writer()?;
        let result = self.writer.append_and_index(catalog, repo, record);
        drop(permit);
        result
    }

    pub fn finish<C: Catalog>(mut self, catalog: &mut C) -> Result<SealedChunk, StoreError> {
        let permit = self.gate.acquire_writer()?;
        let result = self.writer.finish(catalog);
        drop(permit);
        result
    }
}

/// Reads exactly one catalog-addressed record from a cold chunk.
///
/// The chunk header, byte range, complete record encoding, and every record
/// property duplicated in [`ObjectLocation`] are validated before the record
/// is returned.  This deliberately does not trust a path, offset, or length
/// merely because it came from the catalog.  Callers still need to verify the
/// returned record's `ContentId` against the key used to find `location`.
pub fn read_record_at(
    path: impl AsRef<Path>,
    location: ObjectLocation,
) -> Result<ObjectRecord, StoreError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let file_length = file.metadata()?.len();
    if location.offset < CHUNK_HEADER_LEN as u64 {
        return Err(StoreError::LocationMismatch("offset"));
    }
    let record_end = location
        .offset
        .checked_add(location.record_length)
        .ok_or(StoreError::OffsetOverflow)?;
    if record_end > file_length {
        return Err(StoreError::LocationMismatch("record_length"));
    }

    let mut chunk_header = [0_u8; CHUNK_HEADER_LEN];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut chunk_header)?;
    let chunk_header = ChunkHeader::decode(&chunk_header)?;
    if chunk_header.generation != location.generation {
        return Err(StoreError::LocationMismatch("generation"));
    }
    if chunk_header.chunk_id != location.chunk_id {
        return Err(StoreError::LocationMismatch("chunk_id"));
    }

    let mut record_header = [0_u8; RECORD_HEADER_LEN];
    file.seek(SeekFrom::Start(location.offset))?;
    file.read_exact(&mut record_header)?;
    let encoded_length = encoded_record_len_from_header(&record_header)?;
    // `read_record_at` materializes the complete encoded record, unlike the
    // streaming APIs below.  Keep its allocation ceiling identical to open
    // tail recovery before converting a catalog-provided length into a Vec.
    if encoded_length > MAX_RECOVERY_RECORD_BYTES {
        return Err(StoreError::OffsetOverflow);
    }
    let catalog_length = usize::try_from(location.record_length)
        .map_err(|_| StoreError::LocationMismatch("record_length"))?;
    if encoded_length != catalog_length {
        return Err(StoreError::LocationMismatch("record_length"));
    }

    let mut encoded = vec![0_u8; encoded_length];
    file.seek(SeekFrom::Start(location.offset))?;
    file.read_exact(&mut encoded)?;
    let (record, consumed) = decode_record(&encoded)?;
    if consumed != encoded_length {
        return Err(StoreError::LocationMismatch("record_length"));
    }
    if u64::try_from(record.payload.len()).map_err(|_| StoreError::OffsetOverflow)?
        != location.stored_length
    {
        return Err(StoreError::LocationMismatch("stored_length"));
    }
    if record.raw_length != location.raw_length {
        return Err(StoreError::LocationMismatch("raw_length"));
    }
    if record.kind != location.kind {
        return Err(StoreError::LocationMismatch("kind"));
    }
    if record.codec != location.codec {
        return Err(StoreError::LocationMismatch("codec"));
    }
    if record.flags != location.flags {
        return Err(StoreError::LocationMismatch("flags"));
    }
    if crc32c(&record.payload) != location.payload_crc32c {
        return Err(StoreError::LocationMismatch("payload_crc32c"));
    }
    verify_object_record(&record)?;
    Ok(record)
}

/// Streams exactly one catalog-addressed record payload into `writer` using a
/// fixed-size buffer and returns its fully validated fixed metadata.
///
/// Before the first payload byte is exposed, this verifies the chunk header,
/// record header, catalog-addressed byte range, and all metadata duplicated in
/// [`ObjectLocation`].  It then validates the payload CRC, record footer, and
/// alignment padding after streaming.  A caller must still compare the
/// returned `content_id` with the catalog key it requested.
pub fn stream_record_at<W: Write>(
    path: impl AsRef<Path>,
    location: ObjectLocation,
    writer: &mut W,
) -> Result<RecordMetadata, StoreError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let file_length = file.metadata()?.len();
    if location.offset < CHUNK_HEADER_LEN as u64 {
        return Err(StoreError::LocationMismatch("offset"));
    }
    let record_end = location
        .offset
        .checked_add(location.record_length)
        .ok_or(StoreError::OffsetOverflow)?;
    if record_end > file_length {
        return Err(StoreError::LocationMismatch("record_length"));
    }

    let mut chunk_header = [0_u8; CHUNK_HEADER_LEN];
    file.read_exact(&mut chunk_header)?;
    let chunk_header = ChunkHeader::decode(&chunk_header)?;
    if chunk_header.generation != location.generation {
        return Err(StoreError::LocationMismatch("generation"));
    }
    if chunk_header.chunk_id != location.chunk_id {
        return Err(StoreError::LocationMismatch("chunk_id"));
    }

    file.seek(SeekFrom::Start(location.offset))?;
    let mut record_header = [0_u8; RECORD_HEADER_LEN];
    file.read_exact(&mut record_header)?;
    let metadata = decode_record_metadata(&record_header)?;
    validate_stream_location(metadata, location)?;
    let expected_record_length = encoded_record_len_from_metadata(metadata)?;
    if expected_record_length != location.record_length {
        return Err(StoreError::LocationMismatch("record_length"));
    }

    let mut remaining = metadata.stored_length;
    let mut buffer = [0_u8; STREAM_COPY_BUFFER_BYTES];
    let mut payload_crc = Crc32c::new();
    while remaining != 0 {
        let chunk_length = usize::try_from(remaining.min(STREAM_COPY_BUFFER_BYTES as u64))
            .expect("a bounded stream buffer length fits usize");
        file.read_exact(&mut buffer[..chunk_length])?;
        writer.write_all(&buffer[..chunk_length])?;
        payload_crc.update(&buffer[..chunk_length]);
        remaining -= chunk_length as u64;
    }

    let mut footer = [0_u8; RECORD_FOOTER_LEN];
    file.read_exact(&mut footer)?;
    let unpadded_length = (RECORD_HEADER_LEN as u64)
        .checked_add(metadata.stored_length)
        .and_then(|length| length.checked_add(RECORD_FOOTER_LEN as u64))
        .ok_or(StoreError::OffsetOverflow)?;
    validate_record_footer(&footer, payload_crc.finalize(), unpadded_length)?;
    if payload_crc.finalize() != location.payload_crc32c {
        return Err(StoreError::LocationMismatch("payload_crc32c"));
    }

    let padding_length = expected_record_length
        .checked_sub(unpadded_length)
        .ok_or(StoreError::OffsetOverflow)?;
    let padding_length = usize::try_from(padding_length).map_err(|_| StoreError::OffsetOverflow)?;
    debug_assert!(padding_length < RECORD_HEADER_LEN);
    let mut padding = [0_u8; 8];
    file.read_exact(&mut padding[..padding_length])?;
    if padding[..padding_length].iter().any(|&byte| byte != 0) {
        return Err(StoreError::Format(FormatError::NonZeroPadding));
    }
    Ok(metadata)
}

/// Streams one catalog-addressed record through its declared codec into
/// `writer`, without materializing the stored or decompressed payload.
///
/// This is the hydration path for both raw and Zstd v1 records. It validates
/// the chunk and catalog metadata before decoding, limits codec output to the
/// declared raw length, recomputes the record ContentId, then validates the
/// stored-payload CRC, footer, and padding before success is returned.
pub fn stream_decoded_record_at<W: Write>(
    path: impl AsRef<Path>,
    location: ObjectLocation,
    writer: &mut W,
) -> Result<RecordMetadata, StoreError> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let file_length = file.metadata()?.len();
    if location.offset < CHUNK_HEADER_LEN as u64 {
        return Err(StoreError::LocationMismatch("offset"));
    }
    let record_end = location
        .offset
        .checked_add(location.record_length)
        .ok_or(StoreError::OffsetOverflow)?;
    if record_end > file_length {
        return Err(StoreError::LocationMismatch("record_length"));
    }

    let mut chunk_header = [0_u8; CHUNK_HEADER_LEN];
    file.read_exact(&mut chunk_header)?;
    let chunk_header = ChunkHeader::decode(&chunk_header)?;
    if chunk_header.generation != location.generation {
        return Err(StoreError::LocationMismatch("generation"));
    }
    if chunk_header.chunk_id != location.chunk_id {
        return Err(StoreError::LocationMismatch("chunk_id"));
    }

    file.seek(SeekFrom::Start(location.offset))?;
    let mut record_header = [0_u8; RECORD_HEADER_LEN];
    file.read_exact(&mut record_header)?;
    let metadata = decode_record_metadata(&record_header)?;
    validate_stream_location(metadata, location)?;
    let expected_record_length = encoded_record_len_from_metadata(metadata)?;
    if expected_record_length != location.record_length {
        return Err(StoreError::LocationMismatch("record_length"));
    }

    let payload_crc = {
        let mut payload = RecordPayloadReader::new(&mut file, metadata.stored_length);
        decode_object_payload_to_writer(
            metadata.kind,
            metadata.codec,
            metadata.raw_length,
            metadata.content_id,
            &mut payload,
            writer,
        )?;
        if payload.remaining != 0 {
            return Err(StoreError::Codec(CodecError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "codec did not consume the complete stored record payload",
            ))));
        }
        payload.crc.finalize()
    };

    let mut footer = [0_u8; RECORD_FOOTER_LEN];
    file.read_exact(&mut footer)?;
    let unpadded_length = (RECORD_HEADER_LEN as u64)
        .checked_add(metadata.stored_length)
        .and_then(|length| length.checked_add(RECORD_FOOTER_LEN as u64))
        .ok_or(StoreError::OffsetOverflow)?;
    validate_record_footer(&footer, payload_crc, unpadded_length)?;
    if payload_crc != location.payload_crc32c {
        return Err(StoreError::LocationMismatch("payload_crc32c"));
    }

    let padding_length = expected_record_length
        .checked_sub(unpadded_length)
        .ok_or(StoreError::OffsetOverflow)?;
    let padding_length = usize::try_from(padding_length).map_err(|_| StoreError::OffsetOverflow)?;
    let mut padding = [0_u8; 8];
    file.read_exact(&mut padding[..padding_length])?;
    if padding[..padding_length].iter().any(|&byte| byte != 0) {
        return Err(StoreError::Format(FormatError::NonZeroPadding));
    }
    Ok(metadata)
}

/// Exact bounded reader for one stored record payload. Its EOF boundary is
/// what lets the format codec reject concatenated Zstd frames without reading
/// into the following record footer.
struct RecordPayloadReader<'a> {
    file: &'a mut File,
    remaining: u64,
    crc: Crc32c,
}

impl<'a> RecordPayloadReader<'a> {
    fn new(file: &'a mut File, remaining: u64) -> Self {
        Self {
            file,
            remaining,
            crc: Crc32c::new(),
        }
    }
}

impl Read for RecordPayloadReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || bytes.is_empty() {
            return Ok(0);
        }
        let limit = usize::try_from(self.remaining.min(bytes.len() as u64))
            .expect("bounded record payload read length fits usize");
        let count = self.file.read(&mut bytes[..limit])?;
        self.crc.update(&bytes[..count]);
        self.remaining -= count as u64;
        Ok(count)
    }
}

fn validate_stream_location(
    metadata: RecordMetadata,
    location: ObjectLocation,
) -> Result<(), StoreError> {
    if metadata.stored_length != location.stored_length {
        return Err(StoreError::LocationMismatch("stored_length"));
    }
    if metadata.raw_length != location.raw_length {
        return Err(StoreError::LocationMismatch("raw_length"));
    }
    if metadata.kind != location.kind {
        return Err(StoreError::LocationMismatch("kind"));
    }
    if metadata.codec != location.codec {
        return Err(StoreError::LocationMismatch("codec"));
    }
    if metadata.flags != location.flags {
        return Err(StoreError::LocationMismatch("flags"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
    use reflink_forest_format::{Codec, CodecError, ObjectRecord};
    use reflink_forest_index::{Catalog, InMemoryCatalog};
    use std::{
        sync::mpsc,
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

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

    fn record_with_oid(payload: &[u8], oid_byte: u8) -> ObjectRecord {
        ObjectRecord {
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: ContentId::for_object(ObjectKind::Blob, payload),
            primary_oid: GitOid::new(HashAlgorithm::Sha1, &[oid_byte; 20]).unwrap(),
            payload: payload.to_vec(),
        }
    }

    fn append_complete_footer_without_rename(writer: &mut ChunkWriter) {
        let footer = SealedChunkFooter {
            record_count: writer.record_count,
            final_length: writer.open_length() + SEALED_CHUNK_FOOTER_LEN as u64,
            records_crc32c: writer.records_crc32c.finalize(),
        };
        writer.sync_data().unwrap();
        writer
            .file
            .seek(SeekFrom::Start(writer.open_length()))
            .unwrap();
        writer.file.write_all(&footer.encode()).unwrap();
        writer.file.sync_data().unwrap();
    }

    #[derive(Default)]
    struct ChunkObservingWriter {
        writes: usize,
        max_write: usize,
        total: usize,
    }

    impl Write for ChunkObservingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.max_write = self.max_write.max(bytes.len());
            self.total += bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
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
    fn checkpoint_freeze_waits_for_writer_permits_and_gated_writes_are_durable() {
        let (directory, path) = temporary_chunk();
        let gate = ColdStoreWriterGate::new();
        let mut catalog = InMemoryCatalog::default();
        let mut writer =
            GatedChunkWriter::create_and_publish(gate.clone(), &path, header(), &mut catalog)
                .unwrap();
        writer
            .append_and_index(
                &mut catalog,
                RepoId([29; 16]),
                1,
                1,
                &record(b"checkpointed record"),
            )
            .unwrap();

        // A permit is also available to the daemon's non-chunk authoritative
        // writers (pins/config). The exclusive checkpoint cannot begin until
        // that complete transition has finished.
        let outstanding_writer = gate.acquire_writer().unwrap();
        let checkpoint_gate = gate.clone();
        let (frozen_tx, frozen_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            let freeze = checkpoint_gate.freeze_for_checkpoint().unwrap();
            frozen_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            freeze.quiesce_and_sync().unwrap();
        });

        assert!(frozen_rx.recv_timeout(Duration::from_millis(30)).is_err());
        drop(outstanding_writer);
        frozen_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        release_tx.send(()).unwrap();
        waiter.join().unwrap();

        assert_eq!(verify_chunk(writer.path()).unwrap(), 1);
        writer.seal_and_publish(&mut catalog).unwrap();
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

    #[test]
    fn sealing_syncs_footer_renames_then_publishes_catalog_state() {
        let (directory, path) = temporary_chunk();
        let mut catalog = InMemoryCatalog::default();
        let mut writer = ChunkWriter::create_and_publish(&path, header(), &mut catalog).unwrap();
        let object = record(b"sealed object");
        writer
            .append_and_index(&mut catalog, RepoId([1; 16]), 1, 1, &object)
            .unwrap();
        let sealed = writer.seal_and_publish(&mut catalog).unwrap();

        assert!(!path.exists());
        assert!(sealed.path().is_file());
        assert_eq!(sealed.header(), header());
        assert_eq!(sealed.footer().record_count, 1);
        assert_eq!(
            sealed.footer().final_length,
            fs::metadata(sealed.path()).unwrap().len()
        );
        assert_eq!(verify_chunk(sealed.path()).unwrap(), 1);
        assert_eq!(
            catalog.chunk(1, 1),
            Some(ChunkMetadata {
                state: ChunkState::Sealed,
                size: sealed.footer().final_length,
                record_count: 1,
            })
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn sealed_verification_rejects_content_id_corruption_after_structural_crc_repair() {
        let (directory, path) = temporary_chunk();
        let mut catalog = InMemoryCatalog::default();
        let mut writer = ChunkWriter::create_and_publish(&path, header(), &mut catalog).unwrap();
        let original = record(b"sealed identity");
        let location = writer.append(&original).unwrap();
        let sealed = writer.seal_and_publish(&mut catalog).unwrap();
        let sealed_path = sealed.path().to_path_buf();

        // Re-encode a record with a false ContentId, then repair both the
        // record CRC and the sealed rolling checksum.  This remains fully
        // structural, so it proves sealed verification also checks decoded
        // object identity rather than only file framing.
        let mut corrupted = original;
        corrupted.content_id = ContentId::for_object(ObjectKind::Blob, b"other identity");
        let encoded = encode_record(&corrupted).unwrap();
        assert_eq!(encoded.len() as u64, location.record_length);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&sealed_path)
            .unwrap();
        file.seek(SeekFrom::Start(location.offset)).unwrap();
        file.write_all(&encoded).unwrap();
        file.sync_data().unwrap();

        let bytes = fs::read(&sealed_path).unwrap();
        let footer_offset = bytes.len() - SEALED_CHUNK_FOOTER_LEN;
        let repaired_footer = SealedChunkFooter {
            record_count: sealed.footer().record_count,
            final_length: bytes.len() as u64,
            records_crc32c: crc32c(&bytes[CHUNK_HEADER_LEN..footer_offset]),
        };
        file.seek(SeekFrom::Start(footer_offset as u64)).unwrap();
        file.write_all(&repaired_footer.encode()).unwrap();
        file.sync_data().unwrap();

        assert!(matches!(
            verify_sealed_chunk(&sealed_path),
            Err(StoreError::Codec(CodecError::ContentMismatch { .. }))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn read_record_at_rejects_over_ceiling_encoded_length_before_allocation() {
        let (directory, path) = temporary_chunk();
        let mut writer = ChunkWriter::create(&path, header()).unwrap();
        let original = record(b"small record");
        let record_location = writer.append(&original).unwrap();
        writer.sync_data().unwrap();
        drop(writer);
        let location = ObjectLocation {
            generation: 1,
            chunk_id: 1,
            offset: record_location.offset,
            record_length: record_location.record_length,
            stored_length: original.payload.len() as u64,
            raw_length: original.raw_length,
            kind: original.kind,
            codec: original.codec,
            flags: original.flags,
            payload_crc32c: crc32c(&original.payload),
        };

        // Preserve structural header validity while claiming a stored payload
        // larger than the materializing reader's fixed ceiling. The catalog
        // location remains in-file, so this specifically exercises the
        // post-header pre-allocation guard rather than the range check.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut record_header = [0_u8; RECORD_HEADER_LEN];
        file.seek(SeekFrom::Start(location.offset)).unwrap();
        file.read_exact(&mut record_header).unwrap();
        record_header[20..28]
            .copy_from_slice(&((MAX_RECOVERY_RECORD_BYTES as u64) + 1).to_be_bytes());
        record_header[94..98].fill(0);
        let header_crc = crc32c(&record_header);
        record_header[94..98].copy_from_slice(&header_crc.to_be_bytes());
        file.seek(SeekFrom::Start(location.offset)).unwrap();
        file.write_all(&record_header).unwrap();
        file.sync_data().unwrap();

        assert!(matches!(
            read_record_at(&path, location),
            Err(StoreError::OffsetOverflow)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reconciliation_finishes_footer_before_rename_and_rename_before_catalog_boundaries() {
        let (directory, path) = temporary_chunk();
        let mut catalog = InMemoryCatalog::default();
        let mut writer = ChunkWriter::create_and_publish(&path, header(), &mut catalog).unwrap();
        writer
            .append_and_index(&mut catalog, RepoId([2; 16]), 1, 1, &record(b"pre-rename"))
            .unwrap();

        // Model a crash after the footer's fdatasync but before `rename`.
        append_complete_footer_without_rename(&mut writer);
        drop(writer);
        let first = reconcile_chunk(&mut catalog, &path).unwrap();
        let sealed_path = path.with_extension("sealed");
        assert!(matches!(first, ChunkReconciliation::Sealed(_)));
        assert!(!path.exists());
        assert!(sealed_path.exists());
        assert_eq!(catalog.chunk(1, 1).unwrap().state, ChunkState::Sealed);

        // A crash after rename and directory sync but before its catalog batch
        // leaves a verified `.sealed` file beside stale Open metadata. Model
        // that separate boundary with a sibling chunk.
        let rename_only_path = directory.join("0000000000000002.open");
        let rename_only_header = ChunkHeader {
            chunk_id: 2,
            ..header()
        };
        let mut rename_only =
            ChunkWriter::create_and_publish(&rename_only_path, rename_only_header, &mut catalog)
                .unwrap();
        rename_only
            .append_and_index(
                &mut catalog,
                RepoId([2; 16]),
                1,
                2,
                &record_with_oid(b"pre-catalog", 8),
            )
            .unwrap();
        append_complete_footer_without_rename(&mut rename_only);
        drop(rename_only);
        let rename_only_sealed_path = rename_only_path.with_extension("sealed");
        fs::rename(&rename_only_path, &rename_only_sealed_path).unwrap();
        sync_directory(&directory).unwrap();
        assert_eq!(catalog.chunk(1, 2).unwrap().state, ChunkState::Open);

        let second = reconcile_chunk(&mut catalog, &rename_only_sealed_path).unwrap();
        assert!(matches!(second, ChunkReconciliation::Sealed(_)));
        assert_eq!(
            verify_sealed_chunk(&rename_only_sealed_path)
                .unwrap()
                .footer()
                .record_count,
            1
        );
        assert_eq!(catalog.chunk(1, 2).unwrap().state, ChunkState::Sealed);

        // Repeating the same recovery keeps the identity and metadata stable.
        let third = reconcile_chunk(&mut catalog, &rename_only_sealed_path).unwrap();
        assert!(matches!(third, ChunkReconciliation::Sealed(_)));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reconciliation_discards_partial_footer_and_preserves_complete_open_records() {
        let (directory, path) = temporary_chunk();
        let mut catalog = InMemoryCatalog::default();
        let mut writer = ChunkWriter::create_and_publish(&path, header(), &mut catalog).unwrap();
        writer
            .append_and_index(
                &mut catalog,
                RepoId([3; 16]),
                1,
                1,
                &record(b"keep complete record"),
            )
            .unwrap();
        let expected_length = writer.open_length();
        let footer = SealedChunkFooter {
            record_count: writer.record_count,
            final_length: expected_length + SEALED_CHUNK_FOOTER_LEN as u64,
            records_crc32c: writer.records_crc32c.finalize(),
        }
        .encode();
        writer.file.seek(SeekFrom::Start(expected_length)).unwrap();
        writer.file.write_all(&footer[..17]).unwrap();
        writer.file.sync_data().unwrap();
        drop(writer);

        let result = reconcile_chunk(&mut catalog, &path).unwrap();
        let recovery = match result {
            ChunkReconciliation::Open(recovery) => recovery,
            ChunkReconciliation::Sealed(_) => panic!("partial footer must remain an open chunk"),
        };
        assert_eq!(recovery.valid_records, 1);
        assert_eq!(recovery.retained_bytes, expected_length);
        assert_eq!(recovery.truncated_bytes, 17);
        assert_eq!(fs::metadata(&path).unwrap().len(), expected_length);
        assert_eq!(catalog.chunk(1, 1).unwrap().state, ChunkState::Open);
        assert_eq!(verify_chunk(&path).unwrap(), 1);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rotation_never_splits_records_and_seals_dedicated_oversized_chunks() {
        let directory = std::env::temp_dir().join(format!(
            "reflink-forest-store-rotation-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = record_with_oid(b"first target-sized record", 11);
        let second = record_with_oid(b"second target-sized record", 12);
        let first_len = encode_record(&first).unwrap().len() as u64;
        let second_len = encode_record(&second).unwrap().len() as u64;
        let target =
            CHUNK_HEADER_LEN as u64 + SEALED_CHUNK_FOOTER_LEN as u64 + first_len + second_len - 1;
        let mut catalog = InMemoryCatalog::default();
        let mut rotating =
            RotatingChunkWriter::create(&directory, 9, 10, target, 0, &mut catalog).unwrap();
        let first_location = rotating
            .append_and_index(&mut catalog, RepoId([4; 16]), &first)
            .unwrap()
            .unwrap();
        let second_location = rotating
            .append_and_index(&mut catalog, RepoId([4; 16]), &second)
            .unwrap()
            .unwrap();
        assert_eq!(first_location.chunk_id, 10);
        assert_eq!(second_location.chunk_id, 11);
        assert!(!first_location.dedicated_oversized);
        assert!(!second_location.dedicated_oversized);
        let first_path = directory.join("000000000000000a.sealed");
        let second_path = directory.join("000000000000000b.open");
        assert_eq!(verify_chunk(&first_path).unwrap(), 1);
        assert_eq!(verify_chunk(&second_path).unwrap(), 1);
        assert_eq!(catalog.chunk(9, 10).unwrap().state, ChunkState::Sealed);
        assert_eq!(catalog.chunk(9, 11).unwrap().state, ChunkState::Open);

        let oversized = record_with_oid(b"dedicated oversized record", 13);
        let oversized_target = CHUNK_HEADER_LEN as u64
            + SEALED_CHUNK_FOOTER_LEN as u64
            + encode_record(&oversized).unwrap().len() as u64
            - 1;
        let oversized_dir = directory.join("oversized");
        let mut oversized_writer =
            RotatingChunkWriter::create(&oversized_dir, 10, 20, oversized_target, 0, &mut catalog)
                .unwrap();
        let location = oversized_writer
            .append_and_index(&mut catalog, RepoId([5; 16]), &oversized)
            .unwrap()
            .unwrap();
        assert!(location.dedicated_oversized);
        assert_eq!(location.chunk_id, 20);
        assert_eq!(
            verify_chunk(oversized_dir.join("0000000000000014.sealed")).unwrap(),
            1
        );
        assert_eq!(oversized_writer.active_chunk_id(), 21);
        assert_eq!(catalog.chunk(10, 20).unwrap().state, ChunkState::Sealed);
        assert_eq!(catalog.chunk(10, 21).unwrap().state, ChunkState::Open);
        drop(rotating);
        drop(oversized_writer);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn stream_record_at_uses_a_bounded_copy_buffer_for_large_payloads() {
        let (directory, path) = temporary_chunk();
        let payload = vec![0x5a; STREAM_COPY_BUFFER_BYTES * 3 + 17];
        let object = record(&payload);
        let chunk_header = header();
        let mut chunk = ChunkWriter::create(&path, chunk_header).unwrap();
        let record_location = chunk.append(&object).unwrap();
        chunk.sync_data().unwrap();
        drop(chunk);
        let location = ObjectLocation {
            generation: chunk_header.generation,
            chunk_id: chunk_header.chunk_id,
            offset: record_location.offset,
            record_length: record_location.record_length,
            stored_length: payload.len() as u64,
            raw_length: payload.len() as u64,
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            payload_crc32c: crc32c(&payload),
        };
        let mut observed = ChunkObservingWriter::default();

        let metadata = stream_record_at(&path, location, &mut observed).unwrap();

        assert_eq!(metadata.content_id, object.content_id);
        assert_eq!(observed.total, payload.len());
        assert_eq!(observed.max_write, STREAM_COPY_BUFFER_BYTES);
        assert_eq!(observed.writes, 4);
        fs::remove_dir_all(directory).unwrap();
    }
}
