//! Feature-gated unprivileged production daemon startup.
//!
//! The production service deliberately verifies an *already mounted* Btrfs
//! domain. It never formats, attaches loop devices, mounts filesystems, or
//! changes ownership; those actions remain in the separately authorized
//! fixed-purpose helper. It retains the daemon instance lock while validating
//! the clone domain and authoritative RocksDB catalog, and binds the local
//! socket only after those checks and durable daemon recovery succeed.

use crate::{DaemonConfig, DaemonService, DaemonServiceError, DaemonServiceStartup};
use reflink_forest_backup::{
    checkpoint_cold_tier_rocksdb, restore_cold_tier_rocksdb, BackupError, BackupManifest,
    CheckpointGuard, ColdTierAuthoritativePaths, ColdTierCheckpoint, ColdTierCheckpointPlan,
    ColdTierChunkPaths,
};
use reflink_forest_btrfs::{
    native_layout, probe_clone_domain, verify_btrfs_mount, BtrfsError, CloneDomainProbe,
    NativeLayout,
};
use reflink_forest_index::{Catalog, CatalogError, ObjectLocationRebuildState, RocksDbCatalog};
use reflink_forest_store::{ColdStoreCheckpointGuard, ColdStoreWriterGate, StoreError};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Configuration for the feature-gated production service startup path.
///
/// `mount_root` must already be mounted by the privileged helper. The catalog
/// directory must already exist below that mount; production startup never
/// creates a new authoritative catalog implicitly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionDaemonConfig {
    daemon: DaemonConfig,
    mount_root: PathBuf,
    catalog_root: PathBuf,
}

impl ProductionDaemonConfig {
    pub fn new(
        daemon: DaemonConfig,
        mount_root: impl AsRef<Path>,
        catalog_root: impl AsRef<Path>,
    ) -> Self {
        Self {
            daemon,
            mount_root: mount_root.as_ref().to_path_buf(),
            catalog_root: catalog_root.as_ref().to_path_buf(),
        }
    }

    pub fn daemon_config(&self) -> &DaemonConfig {
        &self.daemon
    }

    pub fn mount_root(&self) -> &Path {
        &self.mount_root
    }

    pub fn catalog_root(&self) -> &Path {
        &self.catalog_root
    }
}

/// Successful production preflight data retained by the service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionStartup {
    pub layout: NativeLayout,
    pub clone_domain: CloneDomainProbe,
    pub current_generation: Option<u32>,
}

/// Failure while acquiring and validating production startup state.
#[derive(Debug)]
pub enum ProductionDaemonServiceError {
    Daemon(DaemonServiceError),
    Btrfs(BtrfsError),
    InvalidCatalogRoot(PathBuf),
    InvalidColdTierSource(PathBuf),
    CatalogOpen(String),
    Catalog(CatalogError),
    Store(StoreError),
    Backup(BackupError),
    ObjectLocationRebuildInProgress,
}

impl std::fmt::Display for ProductionDaemonServiceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Daemon(error) => write!(formatter, "daemon startup failed: {error}"),
            Self::Btrfs(error) => write!(formatter, "Btrfs startup preflight failed: {error}"),
            Self::InvalidCatalogRoot(path) => write!(
                formatter,
                "catalog root must be an existing non-symlink directory below the mounted instance: {}",
                path.display()
            ),
            Self::InvalidColdTierSource(path) => write!(
                formatter,
                "checkpoint source must be an existing non-symlink cold-tier root whose catalog is owned by this daemon: {}",
                path.display()
            ),
            Self::CatalogOpen(error) => write!(formatter, "opening production catalog failed: {error}"),
            Self::Catalog(error) => write!(formatter, "catalog startup reconciliation failed: {error}"),
            Self::Store(error) => write!(formatter, "cold-store checkpoint coordination failed: {error}"),
            Self::Backup(error) => write!(formatter, "cold-tier backup or restore failed: {error}"),
            Self::ObjectLocationRebuildInProgress => write!(
                formatter,
                "catalog has an interrupted object-location rebuild; resume or restart it before serving requests"
            ),
        }
    }
}

impl std::error::Error for ProductionDaemonServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Daemon(error) => Some(error),
            Self::Btrfs(error) => Some(error),
            Self::Catalog(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Backup(error) => Some(error),
            Self::InvalidCatalogRoot(_)
            | Self::InvalidColdTierSource(_)
            | Self::CatalogOpen(_)
            | Self::ObjectLocationRebuildInProgress => None,
        }
    }
}

impl From<DaemonServiceError> for ProductionDaemonServiceError {
    fn from(value: DaemonServiceError) -> Self {
        Self::Daemon(value)
    }
}

impl From<BtrfsError> for ProductionDaemonServiceError {
    fn from(value: BtrfsError) -> Self {
        Self::Btrfs(value)
    }
}

impl From<CatalogError> for ProductionDaemonServiceError {
    fn from(value: CatalogError) -> Self {
        Self::Catalog(value)
    }
}

impl From<StoreError> for ProductionDaemonServiceError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<BackupError> for ProductionDaemonServiceError {
    fn from(value: BackupError) -> Self {
        Self::Backup(value)
    }
}

/// A daemon instance that owns both the local control service and its
/// authoritative RocksDB catalog.
///
/// This type is only available with the `production` feature, which also
/// enables the catalog's RocksDB backend. It is intentionally unprivileged:
/// callers must arrange for a fixed-purpose helper to mount the configured
/// Btrfs instance before calling [`Self::start`].
pub struct ProductionDaemonService {
    daemon: DaemonService,
    catalog: RocksDbCatalog,
    catalog_root: PathBuf,
    cold_store_gate: ColdStoreWriterGate,
    startup: ProductionStartup,
}

impl ProductionDaemonService {
    /// Acquires the daemon's instance lock, runs Btrfs and clone-domain
    /// preflight, opens and reconciles the existing RocksDB catalog, then
    /// binds the local control socket.
    ///
    /// No helper action is performed here. A failed preflight or catalog
    /// reconciliation drops the still-unbound startup state, releasing its
    /// lock without exposing a control socket.
    pub fn start(config: ProductionDaemonConfig) -> Result<Self, ProductionDaemonServiceError> {
        Self::start_with_preflight(config, native_preflight)
    }

    fn start_with_preflight<F>(
        config: ProductionDaemonConfig,
        preflight: F,
    ) -> Result<Self, ProductionDaemonServiceError>
    where
        F: FnOnce(&Path) -> Result<(NativeLayout, CloneDomainProbe), BtrfsError>,
    {
        // This lock covers all subsequent preflight and recovery work. A
        // second daemon cannot race a first process between checking Btrfs and
        // opening RocksDB, and nothing has a listening socket yet.
        let startup = DaemonServiceStartup::acquire(config.daemon.clone())?;
        let (layout, clone_domain) = preflight(&config.mount_root)?;
        let catalog_root = checked_catalog_root(&layout, &config.catalog_root)?;
        let catalog = RocksDbCatalog::open_existing(&catalog_root)
            .map_err(|error| ProductionDaemonServiceError::CatalogOpen(error.to_string()))?;
        let current_generation = reconcile_catalog_startup(&catalog)?;

        // Binding is deliberately last: job/scrub/migration recovery occurred
        // in `DaemonServiceStartup::acquire`, and Btrfs plus catalog checks
        // completed above while the instance lock remained held.
        let daemon = startup.bind()?;
        Ok(Self {
            daemon,
            catalog,
            catalog_root,
            cold_store_gate: ColdStoreWriterGate::new(),
            startup: ProductionStartup {
                layout,
                clone_domain,
                current_generation,
            },
        })
    }

    pub fn daemon(&self) -> &DaemonService {
        &self.daemon
    }

    pub fn socket_path(&self) -> &Path {
        self.daemon.socket_path()
    }

    /// Returns the already validated production catalog.
    ///
    /// Future trusted workers should operate through daemon-owned APIs rather
    /// than a client socket; this accessor is read-only so it does not broaden
    /// the service's writer surface.
    pub fn catalog(&self) -> &RocksDbCatalog {
        &self.catalog
    }

    /// Returns the gate that production cold-tier writers must share with
    /// checkpointing. Construct [`reflink_forest_store::GatedChunkWriter`] or
    /// [`reflink_forest_store::GatedRotatingChunkWriter`] with this value, and
    /// hold its writer permit around every other authoritative mutation (such
    /// as pins or configuration publication).
    pub fn cold_store_writer_gate(&self) -> ColdStoreWriterGate {
        self.cold_store_gate.clone()
    }

    /// Creates an authenticated RocksDB checkpoint while retaining an
    /// exclusive cold-store writer freeze until backup publication completes.
    ///
    /// `external_writers` must retain every authoritative writer that this
    /// daemon does not itself own (currently trusted import, compaction, pins,
    /// and configuration publication) for the complete call. The daemon
    /// invokes it before freezing its own gate; it must therefore already be
    /// a held freeze after `quiesce_and_sync` returns. This explicit argument
    /// prevents a checkpoint from pretending that raw `ChunkWriter` users are
    /// covered by the daemon-local gate.
    ///
    /// `source` must be the cold-tier root currently owned by this daemon:
    /// the explicit catalog path has to resolve to the catalog opened during
    /// startup. The supplied plan and paths remain explicit because this
    /// service does not invent a deployment-specific chunk/config/pin layout.
    pub fn checkpoint_cold_tier<G: CheckpointGuard>(
        &self,
        external_writers: &G,
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        plan: &ColdTierCheckpointPlan,
        authoritative_paths: &ColdTierAuthoritativePaths,
        chunk_paths: &ColdTierChunkPaths,
    ) -> Result<ColdTierCheckpoint, ProductionDaemonServiceError> {
        // `CheckpointGuard` requires the caller to keep this exclusion held
        // for the enclosing checkpoint, not merely through this method call.
        // Do it before taking the daemon gate so an external quiesce which is
        // waiting for pre-existing writers cannot deadlock behind our freeze.
        external_writers
            .quiesce_and_sync()
            .map_err(ProductionDaemonServiceError::Backup)?;
        let source = self.checked_cold_tier_source(source.as_ref(), authoritative_paths)?;
        let freeze = self.cold_store_gate.freeze_for_checkpoint()?;
        let guard = ProductionCheckpointGuard { freeze };
        checkpoint_cold_tier_rocksdb(
            &guard,
            &self.catalog,
            source,
            destination,
            plan,
            authoritative_paths,
            chunk_paths,
        )
        .map_err(ProductionDaemonServiceError::Backup)
    }

    /// Verifies and restores a cold-tier checkpoint into a fresh destination.
    ///
    /// The backup layer refuses an existing destination and validates the
    /// manifest, descriptor, chunks, and newly-opened RocksDB catalog before
    /// publication. Restore intentionally returns a separate catalog handle;
    /// it never replaces the catalog owned by this running daemon.
    pub fn restore_cold_tier(
        &self,
        backup_root: impl AsRef<Path>,
        manifest: &BackupManifest,
        destination: impl AsRef<Path>,
        authoritative_paths: &ColdTierAuthoritativePaths,
        chunk_paths: &ColdTierChunkPaths,
    ) -> Result<RocksDbCatalog, ProductionDaemonServiceError> {
        restore_cold_tier_rocksdb(
            backup_root,
            manifest,
            destination,
            authoritative_paths,
            chunk_paths,
        )
        .map_err(ProductionDaemonServiceError::Backup)
    }

    pub fn startup(&self) -> &ProductionStartup {
        &self.startup
    }

    fn checked_cold_tier_source(
        &self,
        source: &Path,
        authoritative_paths: &ColdTierAuthoritativePaths,
    ) -> Result<PathBuf, ProductionDaemonServiceError> {
        let metadata = fs::symlink_metadata(source).map_err(|_| {
            ProductionDaemonServiceError::InvalidColdTierSource(source.to_path_buf())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProductionDaemonServiceError::InvalidColdTierSource(
                source.to_path_buf(),
            ));
        }
        let source = source.canonicalize().map_err(|_| {
            ProductionDaemonServiceError::InvalidColdTierSource(source.to_path_buf())
        })?;
        let catalog = source.join(authoritative_paths.catalog());
        let catalog_metadata = fs::symlink_metadata(&catalog).map_err(|_| {
            ProductionDaemonServiceError::InvalidColdTierSource(source.to_path_buf())
        })?;
        if catalog_metadata.file_type().is_symlink() || !catalog_metadata.is_dir() {
            return Err(ProductionDaemonServiceError::InvalidColdTierSource(source));
        }
        let catalog = catalog
            .canonicalize()
            .map_err(|_| ProductionDaemonServiceError::InvalidColdTierSource(source.clone()))?;
        if catalog != self.catalog_root {
            return Err(ProductionDaemonServiceError::InvalidColdTierSource(source));
        }
        Ok(source)
    }
}

/// Adapts the store's held exclusive guard to the backup contract. The store
/// guard is acquired before this adapter is constructed and lives until the
/// checkpoint function returns, so the backup crate cannot accidentally
/// resume writers between copying chunks and creating the RocksDB snapshot.
struct ProductionCheckpointGuard<'gate> {
    freeze: ColdStoreCheckpointGuard<'gate>,
}

impl CheckpointGuard for ProductionCheckpointGuard<'_> {
    fn quiesce_and_sync(&self) -> Result<(), BackupError> {
        self.freeze
            .quiesce_and_sync()
            .map_err(|error| BackupError::CatalogCheckpoint(error.to_string()))
    }
}

fn native_preflight(mount_root: &Path) -> Result<(NativeLayout, CloneDomainProbe), BtrfsError> {
    verify_btrfs_mount(mount_root)?;
    let layout = native_layout(mount_root)?;
    let clone_domain = probe_clone_domain(&layout.cache, &layout.staging)?;
    Ok((layout, clone_domain))
}

fn checked_catalog_root(
    layout: &NativeLayout,
    configured_catalog_root: &Path,
) -> Result<PathBuf, ProductionDaemonServiceError> {
    let metadata = fs::symlink_metadata(configured_catalog_root)
        .map_err(|error| ProductionDaemonServiceError::CatalogOpen(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ProductionDaemonServiceError::InvalidCatalogRoot(
            configured_catalog_root.to_path_buf(),
        ));
    }
    let mount_root = layout
        .mount_root
        .canonicalize()
        .map_err(|error| ProductionDaemonServiceError::CatalogOpen(error.to_string()))?;
    let catalog_root = configured_catalog_root
        .canonicalize()
        .map_err(|error| ProductionDaemonServiceError::CatalogOpen(error.to_string()))?;
    if !catalog_root.starts_with(&mount_root) {
        return Err(ProductionDaemonServiceError::InvalidCatalogRoot(
            configured_catalog_root.to_path_buf(),
        ));
    }
    Ok(catalog_root)
}

fn reconcile_catalog_startup(
    catalog: &RocksDbCatalog,
) -> Result<Option<u32>, ProductionDaemonServiceError> {
    // Decode every persisted catalog entry before a request can resolve an
    // object. This is intentionally fail-closed rather than silently ignoring
    // malformed metadata.
    catalog.validate()?;
    if catalog.object_location_rebuild_state()? == ObjectLocationRebuildState::InProgress {
        // Rebuilding requires a trusted cold-chunk scan, whose paths and
        // writer coordination are outside this narrow daemon bootstrap. Do
        // not clear or publish partial locations automatically.
        return Err(ProductionDaemonServiceError::ObjectLocationRebuildInProgress);
    }
    Ok(catalog.current_generation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{acquire_lock, DaemonError};
    use reflink_forest_backup::{
        CheckpointGuard, ChunkClassification, ColdChunkDescriptor, ColdTierChunkPath,
    };
    use reflink_forest_format::ChunkHeader;
    use reflink_forest_index::{
        CatalogBatch, ObjectLocationRebuildCatalog, ObjectLocationRebuildState, CATALOG_VERSION,
    };
    use std::{
        cell::{Cell, RefCell},
        os::unix::fs::{symlink, FileTypeExt},
        rc::Rc,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "reflink-forest-production-daemon-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn portable_layout(root: &Path) -> NativeLayout {
        let mount_root = root.join("mount");
        let layout = NativeLayout {
            cache: mount_root.join("internal/cache"),
            staging: mount_root.join("internal/staging"),
            trash: mount_root.join("internal/trash"),
            workspaces: mount_root.join("workspaces"),
            mount_root,
        };
        fs::create_dir_all(&layout.cache).unwrap();
        fs::create_dir_all(&layout.staging).unwrap();
        fs::create_dir_all(&layout.trash).unwrap();
        fs::create_dir_all(&layout.workspaces).unwrap();
        layout
    }

    fn portable_config(root: &Path, layout: &NativeLayout) -> ProductionDaemonConfig {
        ProductionDaemonConfig::new(
            DaemonConfig::new(root.join("runtime"), root.join("state")),
            &layout.mount_root,
            layout.mount_root.join("internal/catalog"),
        )
    }

    fn ready_catalog(config: &ProductionDaemonConfig, generation: u32) {
        fs::create_dir_all(config.catalog_root()).unwrap();
        let mut catalog = RocksDbCatalog::open(config.catalog_root()).unwrap();
        let mut batch = CatalogBatch::new();
        batch.put_current_generation(generation);
        catalog.apply(batch).unwrap();
    }

    fn portable_preflight(
        layout: NativeLayout,
    ) -> impl FnOnce(&Path) -> Result<(NativeLayout, CloneDomainProbe), BtrfsError> {
        move |_| {
            Ok((
                layout,
                CloneDomainProbe {
                    reflink_succeeded: true,
                    mutation_isolated: true,
                },
            ))
        }
    }

    struct RecordingExternalWriterGuard {
        calls: Cell<u32>,
    }

    impl RecordingExternalWriterGuard {
        fn new() -> Self {
            Self {
                calls: Cell::new(0),
            }
        }
    }

    impl CheckpointGuard for RecordingExternalWriterGuard {
        fn quiesce_and_sync(&self) -> Result<(), BackupError> {
            self.calls.set(self.calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn portable_startup_holds_instance_lock_reconciles_catalog_then_binds() {
        let root = temp_root("success");
        let layout = portable_layout(&root);
        let config = portable_config(&root, &layout);
        ready_catalog(&config, 41);
        let events = Rc::new(RefCell::new(Vec::new()));
        let observed_events = Rc::clone(&events);
        let state_lock = config.daemon_config().state_root().join("instance.lock");
        let runtime_socket = config.daemon_config().runtime_dir().join("daemon.sock");
        let expected_layout = layout.clone();

        let service = ProductionDaemonService::start_with_preflight(config.clone(), move |_| {
            assert!(matches!(
                acquire_lock(&state_lock),
                Err(DaemonError::AlreadyRunning)
            ));
            assert!(!runtime_socket.exists());
            observed_events.borrow_mut().push("preflight");
            Ok((
                expected_layout,
                CloneDomainProbe {
                    reflink_succeeded: true,
                    mutation_isolated: true,
                },
            ))
        })
        .unwrap();

        assert_eq!(events.borrow().as_slice(), ["preflight"]);
        assert!(fs::symlink_metadata(service.socket_path())
            .unwrap()
            .file_type()
            .is_socket());
        assert_eq!(service.startup().current_generation, Some(41));
        assert!(service.startup().clone_domain.reflink_succeeded);
        assert!(service.startup().clone_domain.mutation_isolated);
        assert_eq!(
            service.catalog().object_location_rebuild_state().unwrap(),
            ObjectLocationRebuildState::Idle
        );
        assert!(matches!(
            ProductionDaemonService::start_with_preflight(config, portable_preflight(layout)),
            Err(ProductionDaemonServiceError::Daemon(
                DaemonServiceError::StoreAlreadyInUse(_)
            ))
        ));

        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_and_restore_use_the_owned_catalog_and_explicit_writer_guard() {
        let root = temp_root("checkpoint-restore");
        let layout = portable_layout(&root);
        let config = portable_config(&root, &layout);
        ready_catalog(&config, 7);

        let source = layout.mount_root.clone();
        let authoritative_paths = ColdTierAuthoritativePaths::new(
            "internal/catalog",
            "metadata/config.bin",
            "metadata/pins.bin",
        )
        .unwrap();
        fs::create_dir_all(source.join("metadata")).unwrap();
        fs::write(source.join(authoritative_paths.config()), b"config v1").unwrap();
        fs::write(
            source.join(authoritative_paths.pins_manifest()),
            b"pins manifest v1",
        )
        .unwrap();
        let chunk_relative = PathBuf::from("chunks/generation-7/0000000000000001.open");
        let chunk = source.join(&chunk_relative);
        fs::create_dir_all(chunk.parent().unwrap()).unwrap();
        fs::write(
            &chunk,
            ChunkHeader {
                generation: 7,
                chunk_id: 1,
                created_unix_secs: 0,
                flags: 0,
            }
            .encode(),
        )
        .unwrap();
        let chunk_paths = ColdTierChunkPaths::new(vec![ColdTierChunkPath {
            generation: 7,
            chunk_id: 1,
            classification: ChunkClassification::Open,
            relative: chunk_relative,
        }])
        .unwrap();
        let plan = ColdTierCheckpointPlan {
            catalog_schema_version: u32::from(CATALOG_VERSION),
            active_generation: 7,
            chunks: vec![ColdChunkDescriptor {
                generation: 7,
                chunk_id: 1,
                classification: ChunkClassification::Open,
                valid_prefix: fs::metadata(&chunk).unwrap().len(),
            }],
        };

        let service =
            ProductionDaemonService::start_with_preflight(config, portable_preflight(layout))
                .unwrap();
        let parent = root.join("backup-parent");
        fs::create_dir(&parent).unwrap();
        let checkpoint_root = parent.join("checkpoint");
        let external_writers = RecordingExternalWriterGuard::new();
        let checkpoint = service
            .checkpoint_cold_tier(
                &external_writers,
                &source,
                &checkpoint_root,
                &plan,
                &authoritative_paths,
                &chunk_paths,
            )
            .unwrap();
        assert_eq!(external_writers.calls.get(), 1);
        assert_eq!(checkpoint.descriptor.active_generation, 7);
        assert_eq!(
            checkpoint.descriptor.catalog_schema_version,
            u32::from(CATALOG_VERSION)
        );

        let restore = parent.join("restore");
        let restored = service
            .restore_cold_tier(
                &checkpoint_root,
                &checkpoint.manifest,
                &restore,
                &authoritative_paths,
                &chunk_paths,
            )
            .unwrap();
        assert_eq!(restored.current_generation(), Some(7));
        restored.validate().unwrap();
        drop(restored);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_btrfs_preflight_never_opens_catalog_or_binds_socket() {
        let root = temp_root("preflight-failure");
        fs::create_dir_all(root.join("mount-target")).unwrap();
        symlink(root.join("mount-target"), root.join("mount-link")).unwrap();
        let config = ProductionDaemonConfig::new(
            DaemonConfig::new(root.join("runtime"), root.join("state")),
            root.join("mount-link"),
            root.join("catalog"),
        );

        assert!(matches!(
            ProductionDaemonService::start(config.clone()),
            Err(ProductionDaemonServiceError::Btrfs(
                BtrfsError::SymlinkMountRoot(_)
            ))
        ));
        assert!(!config.catalog_root().exists());
        assert!(!config
            .daemon_config()
            .runtime_dir()
            .join("daemon.sock")
            .exists());

        // The pre-bind failure dropped the startup guard, so retrying reaches
        // the same Btrfs error rather than falsely reporting an active daemon.
        assert!(matches!(
            ProductionDaemonService::start(config),
            Err(ProductionDaemonServiceError::Btrfs(
                BtrfsError::SymlinkMountRoot(_)
            ))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_or_rebuilding_catalog_blocks_socket_binding() {
        let root = temp_root("catalog-failure");
        let layout = portable_layout(&root);
        let config = portable_config(&root, &layout);
        assert!(matches!(
            ProductionDaemonService::start_with_preflight(
                config.clone(),
                portable_preflight(layout.clone())
            ),
            Err(ProductionDaemonServiceError::CatalogOpen(_))
        ));
        assert!(!config
            .daemon_config()
            .runtime_dir()
            .join("daemon.sock")
            .exists());

        ready_catalog(&config, 0);
        {
            let mut catalog = RocksDbCatalog::open_existing(config.catalog_root()).unwrap();
            catalog.begin_object_location_rebuild().unwrap();
        }
        assert!(matches!(
            ProductionDaemonService::start_with_preflight(
                config.clone(),
                portable_preflight(layout)
            ),
            Err(ProductionDaemonServiceError::ObjectLocationRebuildInProgress)
        ));
        assert!(!config
            .daemon_config()
            .runtime_dir()
            .join("daemon.sock")
            .exists());
        fs::remove_dir_all(root).unwrap();
    }
}
