//! Acceptance coverage for raw checkout through the public workspace API.
//!
//! These tests deliberately build only the cold chunk and catalog.  They do
//! not create or consult a source Git repository.

use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use reflink_forest_cache::{Cache, CacheError};
use reflink_forest_checkout::{
    materialize_raw, publish_workspace, GitlinkPolicy, MaterializeError, ReplacePolicy,
    WorkspaceName,
};
use reflink_forest_core::{ContentId, GitOid, HashAlgorithm, ObjectKind};
use reflink_forest_format::{ChunkHeader, Codec, ObjectRecord};
use reflink_forest_index::{Catalog, InMemoryCatalog, RepoId};
use reflink_forest_store::ChunkWriter;
use reflink_forest_workspace::{
    ColdWorkspaceSource, WorkspaceCheckoutError, WorkspaceCheckoutRequest, WorkspaceError,
};

struct TempRoot(PathBuf);

impl TempRoot {
    fn on_clone_domain(label: &str) -> Self {
        let root = std::env::current_dir().unwrap().join(format!(
            ".reflink-forest-{label}-{}-{}",
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

fn oid(byte: u8) -> GitOid {
    GitOid::new(HashAlgorithm::Sha1, &[byte; 20]).unwrap()
}

fn oid_hex(oid: &GitOid) -> String {
    oid.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn push_tree_entry(tree: &mut Vec<u8>, mode: &[u8], name: &[u8], object: GitOid) {
    tree.extend_from_slice(mode);
    tree.push(b' ');
    tree.extend_from_slice(name);
    tree.push(0);
    tree.extend_from_slice(object.as_bytes());
}

fn append<C: Catalog>(
    writer: &mut ChunkWriter,
    catalog: &mut C,
    repository: RepoId,
    object: GitOid,
    kind: ObjectKind,
    payload: impl Into<Vec<u8>>,
) {
    let payload = payload.into();
    let record = ObjectRecord {
        kind,
        codec: Codec::Raw,
        flags: 0,
        raw_length: payload.len() as u64,
        content_id: ContentId::for_object(kind, &payload),
        primary_oid: object,
        payload,
    };
    writer
        .append_and_index(catalog, repository, 1, 1, &record)
        .unwrap();
}

fn new_writer(path: &Path) -> ChunkWriter {
    ChunkWriter::create(
        path,
        ChunkHeader {
            generation: 1,
            chunk_id: 1,
            created_unix_secs: 0,
            flags: 0,
        },
    )
    .unwrap()
}

fn assert_mode(path: &Path, expected: u32) {
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        expected
    );
}

fn ficlone_is_unsupported(error: &MaterializeError<WorkspaceError>) -> bool {
    matches!(
        error,
        MaterializeError::Cache(CacheError::Io(io_error))
            if matches!(io_error.raw_os_error(), Some(18) | Some(95))
    )
}

#[test]
fn mixed_cold_tree_preserves_bytes_modes_symlinks_and_gitlink_policy() {
    // The regular files must be cloned from the cache, so place every path
    // within the clone domain. A generic CI filesystem can report FICLONE as
    // unsupported; the supported Btrfs test environment executes assertions.
    let root = TempRoot::on_clone_domain("checkout-mixed");
    let chunk = root.path().join("1.open");
    let cache = Cache::open(root.path().join("cache")).unwrap();
    let repository = RepoId([0x51; 16]);
    let commit = oid(0x52);
    let root_tree = oid(0x53);
    let bin_tree = oid(0x54);
    let regular = oid(0x55);
    let executable = oid(0x56);
    let symlink = oid(0x57);
    let gitlink = oid(0x58);
    let regular_bytes = b"ordinary file\0with exact bytes\n".to_vec();
    let executable_bytes = b"#!/bin/sh\nprintf executable\n".to_vec();
    let symlink_target = b"../plain.txt".to_vec();

    let mut writer = new_writer(&chunk);
    let mut catalog = InMemoryCatalog::default();
    append(
        &mut writer,
        &mut catalog,
        repository,
        regular,
        ObjectKind::Blob,
        regular_bytes.clone(),
    );
    append(
        &mut writer,
        &mut catalog,
        repository,
        executable,
        ObjectKind::Blob,
        executable_bytes.clone(),
    );
    append(
        &mut writer,
        &mut catalog,
        repository,
        symlink,
        ObjectKind::Blob,
        symlink_target.clone(),
    );
    let mut bin_payload = Vec::new();
    push_tree_entry(&mut bin_payload, b"100755", b"run", executable);
    append(
        &mut writer,
        &mut catalog,
        repository,
        bin_tree,
        ObjectKind::Tree,
        bin_payload,
    );
    let mut root_payload = Vec::new();
    push_tree_entry(&mut root_payload, b"40000", b"bin", bin_tree);
    push_tree_entry(&mut root_payload, b"120000", b"link", symlink);
    push_tree_entry(&mut root_payload, b"160000", b"module", gitlink);
    push_tree_entry(&mut root_payload, b"100644", b"plain.txt", regular);
    append(
        &mut writer,
        &mut catalog,
        repository,
        root_tree,
        ObjectKind::Tree,
        root_payload,
    );
    append(
        &mut writer,
        &mut catalog,
        repository,
        commit,
        ObjectKind::Commit,
        format!("tree {}\n\nmixed checkout\n", oid_hex(&root_tree)).into_bytes(),
    );
    writer.sync_data().unwrap();
    drop(writer);

    let source = ColdWorkspaceSource::new(repository, &catalog, &cache, |_, _| chunk.clone());
    let staging = root.path().join("staging/workspace");
    let workspaces = root.path().join("workspaces");
    let trash = root.path().join("trash");
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(&workspaces).unwrap();
    let result = source.checkout_commit(WorkspaceCheckoutRequest {
        commit,
        limits: reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
        staging: &staging,
        workspaces: &workspaces,
        trash: &trash,
        name: &WorkspaceName::new("mixed").unwrap(),
        gitlink_policy: GitlinkPolicy::EmptyDirectory,
        replace: ReplacePolicy::Reject,
    });

    let workspace = match result {
        Ok(workspace) => workspace,
        Err(WorkspaceCheckoutError::Materialize(error)) if ficlone_is_unsupported(&error) => {
            return;
        }
        Err(error) => panic!("mixed checkout failed unexpectedly: {error}"),
    };
    assert_eq!(
        fs::read(workspace.join("plain.txt")).unwrap(),
        regular_bytes
    );
    assert_eq!(
        fs::read(workspace.join("bin/run")).unwrap(),
        executable_bytes
    );
    assert_mode(&workspace.join("plain.txt"), 0o644);
    assert_mode(&workspace.join("bin/run"), 0o755);
    let target = fs::read_link(workspace.join("link")).unwrap();
    assert_eq!(target.as_os_str().as_bytes(), symlink_target);
    assert!(workspace.join("module").is_dir());
    assert_mode(&workspace.join("module"), 0o755);
    assert!(
        !staging.exists(),
        "only the published tree may become visible"
    );
}

#[test]
fn warm_cache_second_checkout_never_needs_the_removed_cold_chunk() {
    let root = TempRoot::on_clone_domain("checkout-warm-cache");
    let chunk = root.path().join("1.open");
    let retired_chunk = root.path().join("1.open.retired");
    let cache = Cache::open(root.path().join("cache")).unwrap();
    let repository = RepoId([0x61; 16]);
    let commit = oid(0x62);
    let tree = oid(0x63);
    let blob = oid(0x64);
    let bytes = b"cache hit avoids cold decode\n".to_vec();
    let mut writer = new_writer(&chunk);
    let mut catalog = InMemoryCatalog::default();
    append(
        &mut writer,
        &mut catalog,
        repository,
        blob,
        ObjectKind::Blob,
        bytes.clone(),
    );
    let mut tree_payload = Vec::new();
    push_tree_entry(&mut tree_payload, b"100644", b"cached.txt", blob);
    append(
        &mut writer,
        &mut catalog,
        repository,
        tree,
        ObjectKind::Tree,
        tree_payload,
    );
    append(
        &mut writer,
        &mut catalog,
        repository,
        commit,
        ObjectKind::Commit,
        format!("tree {}\n\ncache checkout\n", oid_hex(&tree)).into_bytes(),
    );
    writer.sync_data().unwrap();
    drop(writer);

    let source = ColdWorkspaceSource::new(repository, &catalog, &cache, |_, _| chunk.clone());
    let plan = source
        .plan_commit(commit, reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS)
        .unwrap();
    let first_staging = root.path().join("staging/first");
    let second_staging = root.path().join("staging/second");
    let workspaces = root.path().join("workspaces");
    let trash = root.path().join("trash");
    fs::create_dir_all(&first_staging).unwrap();
    fs::create_dir_all(&second_staging).unwrap();
    fs::create_dir_all(&workspaces).unwrap();

    match materialize_raw(
        &plan,
        &source,
        &cache,
        &first_staging,
        GitlinkPolicy::Reject,
    ) {
        Ok(()) => {}
        Err(error) if ficlone_is_unsupported(&error) => return,
        Err(error) => panic!("initial cache fill failed unexpectedly: {error}"),
    }
    publish_workspace(
        &first_staging,
        &workspaces,
        &trash,
        &WorkspaceName::new("first").unwrap(),
        ReplacePolicy::Reject,
    )
    .unwrap();
    assert!(cache
        .verified_path(ContentId::for_object(ObjectKind::Blob, &bytes))
        .is_ok());

    // Any cold record read or decode during the second materialization would
    // now fail. A cache hit may still look up the ContentId, but never opens
    // the retired chunk.
    fs::rename(&chunk, &retired_chunk).unwrap();
    materialize_raw(
        &plan,
        &source,
        &cache,
        &second_staging,
        GitlinkPolicy::Reject,
    )
    .unwrap();
    let second = publish_workspace(
        &second_staging,
        &workspaces,
        &trash,
        &WorkspaceName::new("second").unwrap(),
        ReplacePolicy::Reject,
    )
    .unwrap();
    assert_eq!(fs::read(second.join("cached.txt")).unwrap(), bytes);
}

#[test]
fn injected_mid_materialization_failure_never_publishes_a_workspace() {
    let root = TempRoot::on_clone_domain("checkout-failure");
    let chunk = root.path().join("1.open");
    let cache = Cache::open(root.path().join("cache")).unwrap();
    let repository = RepoId([0x71; 16]);
    let commit = oid(0x72);
    let tree = oid(0x73);
    let first_symlink = oid(0x74);
    let missing_symlink = oid(0x75);
    let mut writer = new_writer(&chunk);
    let mut catalog = InMemoryCatalog::default();
    append(
        &mut writer,
        &mut catalog,
        repository,
        first_symlink,
        ObjectKind::Blob,
        b"existing-target".to_vec(),
    );
    let mut tree_payload = Vec::new();
    push_tree_entry(&mut tree_payload, b"120000", b"a-good", first_symlink);
    // This object's alias is intentionally absent. Planning only reads trees;
    // materialization creates `a-good` and then fails while resolving this
    // second item, simulating a mid-checkout source/decode failure.
    push_tree_entry(
        &mut tree_payload,
        b"120000",
        b"z-injected-failure",
        missing_symlink,
    );
    append(
        &mut writer,
        &mut catalog,
        repository,
        tree,
        ObjectKind::Tree,
        tree_payload,
    );
    append(
        &mut writer,
        &mut catalog,
        repository,
        commit,
        ObjectKind::Commit,
        format!("tree {}\n\ninjected failure\n", oid_hex(&tree)).into_bytes(),
    );
    writer.sync_data().unwrap();
    drop(writer);

    let source = ColdWorkspaceSource::new(repository, &catalog, &cache, |_, _| chunk.clone());
    let staging = root.path().join("staging/private");
    let workspaces = root.path().join("workspaces");
    let trash = root.path().join("trash");
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(&workspaces).unwrap();
    let name = WorkspaceName::new("must-not-publish").unwrap();
    let result = source.checkout_commit(WorkspaceCheckoutRequest {
        commit,
        limits: reflink_forest_checkout::DEFAULT_CHECKOUT_LIMITS,
        staging: &staging,
        workspaces: &workspaces,
        trash: &trash,
        name: &name,
        gitlink_policy: GitlinkPolicy::Reject,
        replace: ReplacePolicy::Reject,
    });

    assert!(matches!(
        result,
        Err(WorkspaceCheckoutError::Materialize(error))
            if matches!(*error, MaterializeError::Source(WorkspaceError::MissingAlias(actual)) if actual == missing_symlink)
    ));
    assert!(staging.exists(), "the partially built tree remains private");
    assert_eq!(
        fs::read_link(staging.join("a-good"))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        b"existing-target"
    );
    assert!(
        !workspaces.join(name.as_str()).exists(),
        "failed materialization must not make a workspace name visible"
    );
}
