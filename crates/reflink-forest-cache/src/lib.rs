//! Derived, atomically published blob cache.
//!
//! Cache entries use internal content IDs, never Git paths. A caller can
//! discard the cache at any time because this crate has no authority over the
//! cold store; it only receives already-verified blob bytes.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_core::{ContentId, ObjectKind};
use reflink_forest_format::Codec;
use reflink_forest_index::{Catalog, ObjectLocation};
use reflink_forest_store::{read_record_at, StoreError};

const FICLONE: std::ffi::c_ulong = 0x4004_9409;

unsafe extern "C" {
    fn ioctl(fd: std::ffi::c_int, request: std::ffi::c_ulong, ...) -> std::ffi::c_int;
}

#[derive(Debug)]
pub enum CacheError {
    Io(io::Error),
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
    NotCached(ContentId),
}
impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "cache I/O error: {error}"),
            Self::ContentMismatch { .. } => {
                write!(f, "cache payload does not match its content ID")
            }
            Self::NotCached(_) => write!(f, "cache entry is missing"),
        }
    }
}
impl std::error::Error for CacheError {}
impl From<io::Error> for CacheError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Debug)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    /// Opens a service-owned cache root. The caller is responsible for placing
    /// it inside the verified Btrfs clone domain.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CacheError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    pub fn path_for(&self, id: ContentId) -> PathBuf {
        let hex = hex(id.as_bytes());
        self.root.join(&hex[..2]).join(&hex[2..4]).join(hex)
    }

    /// Returns an entry only after recomputing its blob content ID.
    pub fn verified_path(&self, id: ContentId) -> Result<PathBuf, CacheError> {
        let path = self.path_for(id);
        let bytes = fs::read(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CacheError::NotCached(id)
            } else {
                CacheError::Io(error)
            }
        })?;
        let actual = ContentId::for_object(ObjectKind::Blob, &bytes);
        if actual != id {
            return Err(CacheError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        Ok(path)
    }

    /// Removes a cache file only when it fails the cache's content-ID check.
    ///
    /// This is the recovery operation used by cold hydration after an
    /// interrupted or corrupt prior publication.  A concurrently repaired
    /// entry is retained: the content is checked again immediately before any
    /// removal.
    pub fn discard_invalid_blob(&self, id: ContentId) -> Result<bool, CacheError> {
        let path = self.path_for(id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(CacheError::Io(error)),
        };
        if ContentId::for_object(ObjectKind::Blob, &bytes) == id {
            return Ok(false);
        }
        fs::remove_file(&path)?;
        let parent = path.parent().expect("cache filename has parent");
        File::open(parent)?.sync_all()?;
        Ok(true)
    }

    /// Writes and verifies blob bytes before atomically publishing the cache
    /// entry. A racing publisher either wins with the same validated content
    /// or leaves the existing entry untouched.
    pub fn publish_blob(&self, id: ContentId, bytes: &[u8]) -> Result<PathBuf, CacheError> {
        let actual = ContentId::for_object(ObjectKind::Blob, bytes);
        if actual != id {
            return Err(CacheError::ContentMismatch {
                expected: id,
                actual,
            });
        }
        let destination = self.path_for(id);
        if destination.exists() {
            return self.verified_path(id);
        }
        let parent = destination.parent().expect("cache filename has parent");
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        let temporary = parent.join(format!(".{}.{}", process::id(), nonce()));
        let result = (|| -> Result<(), CacheError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {
                    fs::remove_file(&temporary)?;
                    File::open(parent)?.sync_all()?;
                    Ok(())
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary)?;
                    Ok(())
                }
                Err(error) => Err(CacheError::Io(error)),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
        self.verified_path(id)
    }

    /// Creates a Btrfs reflink at `destination`. It never falls back to a
    /// payload copy: that policy decision belongs to checkout orchestration.
    pub fn clone_blob(
        &self,
        id: ContentId,
        destination: impl AsRef<Path>,
    ) -> Result<(), CacheError> {
        let source_path = self.verified_path(id)?;
        let source = File::open(source_path)?;
        let destination = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(destination)?;
        // SAFETY: both FDs refer to regular files and FICLONE consumes the
        // source descriptor by value only for the duration of this syscall.
        if unsafe { ioctl(destination.as_raw_fd(), FICLONE, source.as_raw_fd()) } != 0 {
            return Err(CacheError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }
}

/// Failure while deriving a cache blob from its authoritative cold record.
#[derive(Debug)]
pub enum HydrationError {
    Cache(CacheError),
    Store(StoreError),
    MissingLocation(ContentId),
    NotBlob(ObjectKind),
    UnsupportedCodec(Codec),
    RawLengthMismatch {
        expected: u64,
        actual: u64,
    },
    ContentMismatch {
        expected: ContentId,
        actual: ContentId,
    },
}

impl std::fmt::Display for HydrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cache(error) => write!(f, "cache hydration failed: {error}"),
            Self::Store(error) => write!(f, "cold record validation failed: {error}"),
            Self::MissingLocation(_) => write!(f, "cold object location is missing"),
            Self::NotBlob(kind) => write!(f, "cold record is not a blob: {kind:?}"),
            Self::UnsupportedCodec(codec) => {
                write!(
                    f,
                    "cold blob codec is not supported by raw hydration: {codec:?}"
                )
            }
            Self::RawLengthMismatch { .. } => {
                write!(f, "raw cold blob length does not match its payload")
            }
            Self::ContentMismatch { .. } => {
                write!(f, "cold blob payload does not match its content ID")
            }
        }
    }
}
impl std::error::Error for HydrationError {}
impl From<CacheError> for HydrationError {
    fn from(value: CacheError) -> Self {
        Self::Cache(value)
    }
}
impl From<StoreError> for HydrationError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// Hydrates one raw blob addressed by `id` from its catalog location.
///
/// `chunk_path` is supplied by the caller's generation/manifest resolver.
/// The path cannot substitute a different chunk: its header's generation and
/// chunk ID must agree with the catalog location, and the record's duplicated
/// metadata and content ID are all revalidated before the cache atomically
/// publishes it.  A valid cache hit avoids opening the cold chunk.
pub fn hydrate_raw_blob_from_chunk<C: Catalog>(
    cache: &Cache,
    catalog: &C,
    id: ContentId,
    chunk_path: impl AsRef<Path>,
) -> Result<PathBuf, HydrationError> {
    match cache.verified_path(id) {
        Ok(path) => return Ok(path),
        Err(CacheError::NotCached(_)) => {}
        Err(CacheError::ContentMismatch { .. }) => {
            cache.discard_invalid_blob(id)?;
        }
        Err(error) => return Err(error.into()),
    }

    let location = catalog
        .object_location(id)
        .ok_or(HydrationError::MissingLocation(id))?;
    validate_raw_blob_location(location)?;
    let record = read_record_at(chunk_path, location)?;
    if record.kind != ObjectKind::Blob {
        return Err(HydrationError::NotBlob(record.kind));
    }
    if record.codec != Codec::Raw {
        return Err(HydrationError::UnsupportedCodec(record.codec));
    }
    let actual_length =
        u64::try_from(record.payload.len()).map_err(|_| HydrationError::RawLengthMismatch {
            expected: record.raw_length,
            actual: u64::MAX,
        })?;
    if record.raw_length != actual_length {
        return Err(HydrationError::RawLengthMismatch {
            expected: record.raw_length,
            actual: actual_length,
        });
    }
    let actual = ContentId::for_object(ObjectKind::Blob, &record.payload);
    if actual != id || record.content_id != id {
        return Err(HydrationError::ContentMismatch {
            expected: id,
            actual,
        });
    }

    // An existing corrupt cache file can only be derived state.  Remove it
    // after the authoritative cold record is fully validated, then retry the
    // atomic publication once.  If another hydrator won with valid content,
    // `publish_blob` returns that verified entry instead.
    match cache.publish_blob(id, &record.payload) {
        Ok(path) => Ok(path),
        Err(CacheError::ContentMismatch { .. }) => {
            cache.discard_invalid_blob(id)?;
            cache.publish_blob(id, &record.payload).map_err(Into::into)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_raw_blob_location(location: ObjectLocation) -> Result<(), HydrationError> {
    if location.kind != ObjectKind::Blob {
        return Err(HydrationError::NotBlob(location.kind));
    }
    if location.codec != Codec::Raw {
        return Err(HydrationError::UnsupportedCodec(location.codec));
    }
    Ok(())
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos()
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflink_forest_core::{GitOid, HashAlgorithm};
    use reflink_forest_format::{ChunkHeader, ObjectRecord, RECORD_HEADER_LEN};
    use reflink_forest_index::{Catalog, CatalogBatch, InMemoryCatalog};
    use reflink_forest_store::{ChunkWriter, RecordLocation};
    use std::{
        io::{Seek, SeekFrom},
        sync::Arc,
        thread,
    };

    fn directory() -> PathBuf {
        std::env::temp_dir().join(format!("reflink-forest-cache-{}", nonce()))
    }

    struct ColdBlobFixture {
        directory: PathBuf,
        chunk: PathBuf,
        cache: Cache,
        catalog: InMemoryCatalog,
        id: ContentId,
        location: ObjectLocation,
    }

    fn cold_blob_fixture(payload: &[u8]) -> ColdBlobFixture {
        cold_blob_fixture_with_id(payload, ContentId::for_object(ObjectKind::Blob, payload))
    }

    fn cold_blob_fixture_with_id(payload: &[u8], id: ContentId) -> ColdBlobFixture {
        let directory = directory();
        fs::create_dir(&directory).unwrap();
        let chunk = directory.join("0000000000000001.open");
        let record = ObjectRecord {
            kind: ObjectKind::Blob,
            codec: Codec::Raw,
            flags: 0,
            raw_length: payload.len() as u64,
            content_id: id,
            primary_oid: GitOid::new(HashAlgorithm::Sha1, &[7; 20]).unwrap(),
            payload: payload.to_vec(),
        };
        let header = ChunkHeader {
            generation: 3,
            chunk_id: 9,
            created_unix_secs: 0,
            flags: 0,
        };
        let mut writer = ChunkWriter::create(&chunk, header).unwrap();
        let record_location = writer.append(&record).unwrap();
        writer.sync_data().unwrap();
        drop(writer);

        let location = object_location(&record, record_location, header);
        let mut catalog = InMemoryCatalog::default();
        let mut batch = CatalogBatch::new();
        batch.put_object_location(id, location);
        catalog.apply(batch).unwrap();
        let cache = Cache::open(directory.join("cache")).unwrap();
        ColdBlobFixture {
            directory,
            chunk,
            cache,
            catalog,
            id,
            location,
        }
    }

    fn object_location(
        record: &ObjectRecord,
        record_location: RecordLocation,
        header: ChunkHeader,
    ) -> ObjectLocation {
        ObjectLocation {
            generation: header.generation,
            chunk_id: header.chunk_id,
            offset: record_location.offset,
            record_length: record_location.record_length,
            stored_length: record.payload.len() as u64,
            raw_length: record.raw_length,
            kind: record.kind,
            codec: record.codec,
            flags: record.flags,
            payload_crc32c: reflink_forest_format::crc32c(&record.payload),
        }
    }

    #[test]
    fn valid_blob_is_atomically_published_and_revalidated() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let id = ContentId::for_object(ObjectKind::Blob, b"cache bytes");
        let path = cache.publish_blob(id, b"cache bytes").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"cache bytes");
        assert_eq!(cache.verified_path(id).unwrap(), path);
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn incorrect_content_is_not_published() {
        let directory = directory();
        let cache = Cache::open(&directory).unwrap();
        let id = ContentId::for_object(ObjectKind::Blob, b"expected");
        assert!(matches!(
            cache.publish_blob(id, b"wrong"),
            Err(CacheError::ContentMismatch { .. })
        ));
        assert!(!cache.path_for(id).exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn hydration_reads_validated_cold_blob_and_atomically_publishes_cache() {
        let fixture = cold_blob_fixture(b"authoritative cold bytes");

        let path = hydrate_raw_blob_from_chunk(
            &fixture.cache,
            &fixture.catalog,
            fixture.id,
            &fixture.chunk,
        )
        .unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"authoritative cold bytes");
        assert_eq!(fixture.cache.verified_path(fixture.id).unwrap(), path);
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_rejects_corrupt_cold_record_without_publishing_cache() {
        let fixture = cold_blob_fixture(b"cold data to corrupt");
        let mut chunk = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fixture.chunk)
            .unwrap();
        chunk
            .seek(SeekFrom::Start(
                fixture.location.offset + RECORD_HEADER_LEN as u64,
            ))
            .unwrap();
        chunk.write_all(b"!").unwrap();
        chunk.sync_all().unwrap();

        assert!(matches!(
            hydrate_raw_blob_from_chunk(
                &fixture.cache,
                &fixture.catalog,
                fixture.id,
                &fixture.chunk,
            ),
            Err(HydrationError::Store(StoreError::Format(_)))
        ));
        assert!(!fixture.cache.path_for(fixture.id).exists());
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_rejects_a_record_whose_payload_does_not_match_its_content_id() {
        let expected_id = ContentId::for_object(ObjectKind::Blob, b"expected content");
        let fixture = cold_blob_fixture_with_id(b"different content", expected_id);

        assert!(matches!(
            hydrate_raw_blob_from_chunk(
                &fixture.cache,
                &fixture.catalog,
                fixture.id,
                &fixture.chunk,
            ),
            Err(HydrationError::ContentMismatch { expected, .. }) if expected == expected_id
        ));
        assert!(!fixture.cache.path_for(fixture.id).exists());
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_rejects_missing_cold_chunk_without_publishing_cache() {
        let fixture = cold_blob_fixture(b"missing cold bytes");
        fs::remove_file(&fixture.chunk).unwrap();

        assert!(matches!(
            hydrate_raw_blob_from_chunk(
                &fixture.cache,
                &fixture.catalog,
                fixture.id,
                &fixture.chunk,
            ),
            Err(HydrationError::Store(StoreError::Io(error)))
                if error.kind() == io::ErrorKind::NotFound
        ));
        assert!(!fixture.cache.path_for(fixture.id).exists());
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn hydration_recovers_an_invalid_cache_file_from_cold_data() {
        let fixture = cold_blob_fixture(b"recoverable cold bytes");
        let cache_path = fixture.cache.path_for(fixture.id);
        fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        fs::write(&cache_path, b"interrupted cache write").unwrap();

        let path = hydrate_raw_blob_from_chunk(
            &fixture.cache,
            &fixture.catalog,
            fixture.id,
            &fixture.chunk,
        )
        .unwrap();

        assert_eq!(path, cache_path);
        assert_eq!(fs::read(path).unwrap(), b"recoverable cold bytes");
        fs::remove_dir_all(fixture.directory).unwrap();
    }

    #[test]
    fn concurrent_hydration_publishes_one_verified_cache_entry() {
        let fixture = cold_blob_fixture(b"shared concurrent blob");
        let cache = Arc::new(fixture.cache);
        let catalog = Arc::new(fixture.catalog);
        let chunk = Arc::new(fixture.chunk);
        let mut workers = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let catalog = Arc::clone(&catalog);
            let chunk = Arc::clone(&chunk);
            let id = fixture.id;
            workers.push(thread::spawn(move || {
                hydrate_raw_blob_from_chunk(&cache, &*catalog, id, &*chunk).unwrap()
            }));
        }
        let paths: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(paths.iter().all(|path| path == &paths[0]));
        assert_eq!(
            fs::read(cache.verified_path(fixture.id).unwrap()).unwrap(),
            b"shared concurrent blob"
        );
        fs::remove_dir_all(fixture.directory).unwrap();
    }
}
