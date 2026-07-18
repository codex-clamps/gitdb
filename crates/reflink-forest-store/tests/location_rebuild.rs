//! Public rebuild harness for the locations-only catalog recovery protocol.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_format::{ChunkHeader, Codec, ObjectRecord};
use reflink_forest_index::{
    Catalog, CatalogBatch, CatalogError, ChunkMetadata, InMemoryCatalog, ObjectLocation,
    ObjectLocationEntry, ObjectLocationRebuildCatalog, ObjectLocationRebuildState, OidAliasEntry,
    RepoId,
};
use reflink_forest_store::{
    preflight_object_location_rebuild, rebuild_object_locations, ChunkWriter, StoreError,
};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "reflink-forest-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct TrackingCatalog {
    inner: InMemoryCatalog,
    rebuild_batch_lengths: Vec<usize>,
}

impl Catalog for TrackingCatalog {
    fn apply(&mut self, batch: CatalogBatch) -> Result<(), CatalogError> {
        self.inner.apply(batch)
    }

    fn object_location(&self, id: ContentId) -> Option<ObjectLocation> {
        self.inner.object_location(id)
    }

    fn object_location_rebuild_state(&self) -> Result<ObjectLocationRebuildState, CatalogError> {
        self.inner.object_location_rebuild_state()
    }

    fn visit_oid_aliases(
        &self,
        visitor: &mut dyn FnMut(OidAliasEntry) -> Result<(), CatalogError>,
    ) -> Result<(), CatalogError> {
        self.inner.visit_oid_aliases(visitor)
    }

    fn oid_alias(&self, repo: RepoId, oid: &GitOid) -> Option<ContentId> {
        self.inner.oid_alias(repo, oid)
    }

    fn chunk(&self, generation: u32, chunk_id: u64) -> Option<ChunkMetadata> {
        self.inner.chunk(generation, chunk_id)
    }

    fn current_generation(&self) -> Option<u32> {
        self.inner.current_generation()
    }
}

impl ObjectLocationRebuildCatalog for TrackingCatalog {
    fn begin_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        self.inner.begin_object_location_rebuild()
    }

    fn restart_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        self.inner.restart_object_location_rebuild()
    }

    fn append_rebuilt_object_locations(
        &mut self,
        entries: &[ObjectLocationEntry],
    ) -> Result<(), CatalogError> {
        self.rebuild_batch_lengths.push(entries.len());
        self.inner.append_rebuilt_object_locations(entries)
    }

    fn finish_object_location_rebuild(&mut self) -> Result<(), CatalogError> {
        self.inner.finish_object_location_rebuild()
    }
}

fn record(payload: &[u8], primary_oid: GitOid) -> ObjectRecord {
    ObjectRecord {
        kind: ObjectKind::Blob,
        codec: Codec::Raw,
        flags: 0,
        raw_length: payload.len() as u64,
        content_id: ContentId::for_object(ObjectKind::Blob, payload),
        primary_oid,
        payload: payload.to_vec(),
    }
}

fn header(generation: u32, chunk_id: u64) -> ChunkHeader {
    ChunkHeader {
        generation,
        chunk_id,
        created_unix_secs: 0,
        flags: 0,
    }
}

#[test]
fn locations_only_rebuild_preflights_aliases_selects_duplicates_and_batches() {
    let root = TempRoot::new("location-rebuild");
    let sealed_path = root.path().join("0000000000000001.open");
    let open_path = root.path().join("0000000000000002.open");
    let repository_a = RepoId([0x11; 16]);
    let repository_b = RepoId([0x12; 16]);
    let repository_c = RepoId([0x13; 16]);
    let same_payload = b"same object written twice";
    let first_payload = b"first unique object";
    let second_payload = b"second unique object";
    let same_sha1 = GitOid::for_object(HashAlgorithm::Sha1, ObjectKind::Blob, same_payload);
    let same_sha256 = GitOid::for_object(HashAlgorithm::Sha256, ObjectKind::Blob, same_payload);
    let first_sha1 = GitOid::for_object(HashAlgorithm::Sha1, ObjectKind::Blob, first_payload);
    let second_sha256 = GitOid::for_object(HashAlgorithm::Sha256, ObjectKind::Blob, second_payload);
    let same = record(same_payload, same_sha1);
    let first = record(first_payload, first_sha1);
    let second = record(second_payload, second_sha256);
    let mut catalog = TrackingCatalog::default();

    let mut sealed = ChunkWriter::create(&sealed_path, header(7, 1)).unwrap();
    sealed
        .append_and_index(&mut catalog, repository_a, 7, 1, &same)
        .unwrap();
    sealed
        .append_and_index(&mut catalog, repository_a, 7, 1, &first)
        .unwrap();
    let sealed = sealed.seal_and_publish(&mut catalog).unwrap();

    let mut open = ChunkWriter::create(&open_path, header(8, 2)).unwrap();
    open.append(&same).unwrap();
    open.append(&second).unwrap();
    open.sync_data().unwrap();
    drop(open);
    let mut aliases = CatalogBatch::new();
    // This cross-hash alias is deliberately different from `same.primary_oid`.
    // A rebuild that merely checks location existence or trusts primary_oid
    // would fail this public preflight contract.
    aliases.put_current_generation(8);
    aliases.put_oid_alias(repository_b, same_sha256, same.content_id);
    aliases.put_oid_alias(repository_c, second_sha256, second.content_id);
    catalog.apply(aliases).unwrap();

    let preflight = preflight_object_location_rebuild(
        &catalog,
        [open_path.clone(), sealed.path().to_path_buf()],
    )
    .unwrap();
    assert_eq!(
        preflight.report().scanned_records,
        4,
        "both physical copies are fully scanned"
    );
    assert_eq!(preflight.report().selected_locations, 3);
    assert_eq!(preflight.report().duplicate_records, 1);
    assert_eq!(preflight.report().sealed_chunks, 1);
    assert_eq!(preflight.report().open_chunks, 1);
    assert_eq!(preflight.report().preserved_aliases_verified, 4);

    let report = rebuild_object_locations(
        &mut catalog,
        [open_path.clone(), sealed.path().to_path_buf()],
        2,
    )
    .unwrap();
    assert_eq!(report.catalog_batches_written, 2);
    assert_eq!(catalog.rebuild_batch_lengths, vec![2, 1]);
    let same_location = catalog.inner.object_location(same.content_id).unwrap();
    assert_eq!(same_location.generation, 8);
    assert_eq!(
        same_location.chunk_id, 2,
        "the active generation wins over a stale lower-generation copy"
    );
    assert!(catalog.inner.object_location(first.content_id).is_some());
    assert_eq!(
        catalog
            .inner
            .object_location(second.content_id)
            .unwrap()
            .chunk_id,
        2
    );
    assert_eq!(
        catalog.inner.oid_alias(repository_b, &same_sha256),
        Some(same.content_id),
        "rebuild never rewrites preserved aliases"
    );
    assert_eq!(
        catalog.inner.oid_alias(repository_c, &second_sha256),
        Some(second.content_id)
    );
    assert_eq!(
        catalog.object_location_rebuild_state().unwrap(),
        ObjectLocationRebuildState::Idle
    );

    // Model a process crash after the durable rebuild marker and a partial
    // append. Restart must discard partial locations, re-run the full alias
    // preflight while the marker remains fail-closed, and finish cleanly.
    catalog.inner.begin_object_location_rebuild().unwrap();
    let resumed = rebuild_object_locations(
        &mut catalog,
        [sealed.path().to_path_buf(), open_path.clone()],
        2,
    )
    .unwrap();
    assert_eq!(resumed.catalog_batches_written, 2);
    assert_eq!(catalog.rebuild_batch_lengths, vec![2, 1, 2, 1]);
    assert_eq!(
        catalog.object_location_rebuild_state().unwrap(),
        ObjectLocationRebuildState::Idle
    );
    assert_eq!(
        catalog
            .inner
            .object_location(same.content_id)
            .unwrap()
            .generation,
        8
    );

    // A retained alias is not trusted merely because its ContentId was found.
    // Its native Git OID must hash the selected record's *raw* payload.
    let invalid_alias = GitOid::new(HashAlgorithm::Sha1, &[0x55; 20]).unwrap();
    let invalid_repository = RepoId([0x14; 16]);
    let mut invalid = CatalogBatch::new();
    invalid.put_oid_alias(invalid_repository, invalid_alias, same.content_id);
    catalog.apply(invalid).unwrap();
    assert!(matches!(
        preflight_object_location_rebuild(
            &catalog,
            [sealed.path().to_path_buf(), open_path],
        ),
        Err(StoreError::PreservedAliasContentMismatch {
            repository,
            oid,
            content_id,
        }) if repository == invalid_repository && oid == invalid_alias && content_id == same.content_id
    ));
}
