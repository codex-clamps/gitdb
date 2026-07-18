# Reflink Forest — Production-Grade Rust Engineering Roadmap

## 1. Executive architecture

The core idea is sound:

* The **Cold Tier** is the durable, content-addressed source of truth.
* The **Btrfs Tier** is a materialization domain where logically raw files can share physical extents.
* The **Hot Cache** is derived and disposable.
* A **Workspace** is a mutable checkout that initially shares extents with the cache and diverges through Btrfs copy-on-write when modified.

A more precise description is:

> Reflink Forest is a local, content-addressed Git object store backed by append-only compressed segments, with a Btrfs materialization layer that converts immutable Git blobs into reusable filesystem extents and publishes complete workspaces atomically.

The architecture should not call the Btrfs mount a security “sandbox.” It provides a reflink-compatible filesystem domain, but it does not isolate untrusted builds, processes, network access, or symlink traversal during execution.

---

# 2. Critical corrections to the original plan

## 2.1 FICLONE requires a shared clone domain

`FICLONE` requires the source and destination to be on the same filesystem. Linux reports `EXDEV` when they are not on the same mounted filesystem. On Btrfs, reflinking across two mount points of the same filesystem was unsupported before Linux 5.18 and is supported from Linux 5.18 onward. For maximum compatibility, keep the cache, staging area, and workspaces reachable through one root Btrfs mount rather than mounting each subvolume separately. ([man7.org][1])

Use this layout:

```text
/var/lib/yourfs/hot-mount/
├── internal/
│   ├── cache/
│   ├── staging/
│   └── trash/
└── workspaces/
```

Do not assume that comparing filesystem names, mount options, or path prefixes is sufficient. Run a real startup feature probe that creates two small files in the intended cache and workspace directories and attempts `FICLONE`.

---

## 2.2 Default `fallocate` is not sparse allocation

The original plan says that `fallocate` creates a 50 GiB sparse file while consuming no physical storage. Default `fallocate` actually allocates backing blocks and is specifically intended to reserve space so later writes do not fail from insufficient capacity. To create a sparse image, create a new file and extend its logical length with `ftruncate`, Rust’s `File::set_len`, or equivalent. ([Arch Manual Pages][2])

That creates a logical capacity, not a capacity guarantee. A sparse Btrfs image can later fail because the host filesystem runs out of space. The capacity manager must therefore monitor both:

1. Free space on the host filesystem.
2. Free and allocated space inside Btrfs.

Offer two initialization policies:

```text
--allocation sparse       # Low initial physical usage; may hit host ENOSPC later
--allocation reserved     # Preallocate the image with fallocate
```

---

## 2.3 Storing only blobs is not enough

A checkout by commit ID cannot be resolved after the source repository disappears unless the cold store also preserves the Git graph.

Git has four object types:

* Blob
* Tree
* Commit
* Tag

Trees describe directory hierarchy, commits reference root trees and parents, and annotated tags reference other objects. Therefore, import all reachable Git object types—not only blobs. Only blobs need to be hydrated into the hot cache. ([Git][3])

The revised invariant is:

> After a successful import, the source repository may be deleted and any imported revision must remain resolvable and check-outable.

---

## 2.4 Git OIDs and internal content IDs should be separate

Do not hardcode RocksDB keys as only 20-byte SHA-1 values.

Use:

```rust
enum GitHashAlgorithm {
    Sha1,
    Sha256,
}

struct GitOid {
    algorithm: GitHashAlgorithm,
    length: u8,
    bytes: [u8; 32],
}

struct ContentId([u8; 32]);
```

`GitOid` preserves the repository’s native identity.

`ContentId` is Reflink Forest’s internal, algorithm-independent identity and should be computed over a domain-separated canonical representation:

```text
SHA256(
    "yourfs-object-v1\0"
    || object_type
    || raw_length_be
    || raw_object_payload
)
```

This gives you:

* Deduplication across repositories.
* Blob deduplication across SHA-1 and SHA-256 repositories.
* Protection against object-type confusion.
* A stable hot-cache filename independent of the source repository’s hash algorithm.
* An additional integrity check beyond the native Git OID.

As of July 2026, libgit2 still labels SHA-256 support experimental. `gix` exposes SHA-1 and SHA-256 feature selection, while its maintainers describe basic SHA-256 object reading and writing as available but transport/protocol support as incomplete. Parameterize all formats from day one, but treat production SHA-256 support as a separately tested capability rather than assuming every Git library path is mature. ([GitHub][4])

---

## 2.5 Raw Git blobs are not always normal checkout bytes

A Git checkout may transform stored blob content through:

* End-of-line conversion.
* `text` and `eol` attributes.
* `ident`.
* `working-tree-encoding`.
* Clean/smudge filters.
* Git LFS filters.
* Repository, global, or system Git configuration.

Git’s documented checkout path applies text conversion, then `ident`, then configured filters. ([Git][5])

Define two explicit checkout modes:

### `raw` mode — MVP

Materialize exact blob bytes and apply only Git tree semantics:

* `100644`: regular non-executable file.
* `100755`: regular executable file.
* `120000`: symbolic link whose target is the blob content.
* `160000`: gitlink/submodule policy.
* `040000`: directory/tree.

Those are Git’s supported tree entry modes. ([Git][6])

### `git-compatible` mode — later phase

Apply attribute and filter transformations. The cache key can no longer be only the blob content ID because output may depend on path, attributes, Git configuration, filter definitions, and platform:

```text
TransformId = SHA256(
    "yourfs-transform-v1"
    || blob_content_id
    || repository_snapshot_id
    || path_bytes
    || attributes_digest
    || filter_configuration_digest
    || platform_policy
)
```

External filters execute programs and must be disabled by default for untrusted repositories.

---

## 2.6 RocksDB atomicity does not cover the chunk log

RocksDB `WriteBatch` provides atomicity for multiple database keys, and its WAL provides process-crash recovery. A durable RocksDB write can be requested with synchronous write options. However, RocksDB cannot atomically commit data stored in a separate append-only file. ([GitHub][7])

The required ordering is:

```text
1. Append one or more complete records to the open chunk.
2. fdatasync the chunk.
3. Commit all corresponding RocksDB keys in one WriteBatch.
4. Use RocksDB sync=true for durable mode.
5. Acknowledge the import batch.
```

Never commit a RocksDB location before the chunk data is durable.

A crash after step 2 but before step 3 leaves an orphaned but valid record. That is recoverable.

A crash after step 3 is safe because the record was synchronized first.

---

## 2.7 The Btrfs mount should be long-lived

Do not unmount the Btrfs filesystem at the end of every CLI invocation.

A production design should use:

* A long-running service.
* A single instance lock.
* A persistent loop attachment and mount.
* A recovery pass at service startup.
* A Unix socket used by the unprivileged CLI.

Repeated mount/unmount cycles complicate concurrency, background builds, open workspaces, cache hydration, and crash recovery.

---

## 2.8 Deleting cache files may not shrink the host image immediately

Deleting files releases space inside Btrfs, but physical host-file reclamation depends on discard propagation through every storage layer. Btrfs documentation explicitly notes that discard is useful for virtual-machine images and thin storage, but every layer must support it. Batch `fstrim` is an alternative to continuous discard. ([BTRFS Documentation][8])

During `yourfs doctor`, test reclamation:

1. Record the image file’s allocated block count.
2. Write a sufficiently large test file inside Btrfs.
3. Synchronize.
4. Delete it.
5. Run `fstrim` on the Btrfs mount.
6. Synchronize again.
7. Check whether the host image’s allocated block count decreased.

Report one of:

```text
discard-reclamation: supported
discard-reclamation: unsupported
discard-reclamation: inconclusive
```

Do not promise that cache eviction immediately reduces host disk usage.

---

# 3. Target architecture

```text
                    ┌──────────────────────────┐
                    │ Existing local Git repo  │
                    └─────────────┬────────────┘
                                  │
                            Git backend
                                  │
                    resolve refs + walk graph
                                  │
                                  ▼
                ┌──────────────────────────────────┐
                │ Import and canonicalization      │
                │                                  │
                │ Git OID verification             │
                │ Internal ContentId               │
                │ Deduplication                    │
                │ zstd compression                 │
                └───────────────┬──────────────────┘
                                │
              ┌─────────────────┴──────────────────┐
              ▼                                    ▼
┌────────────────────────────┐       ┌───────────────────────────┐
│ Cold append-only segments  │       │ RocksDB catalog/index     │
│                            │       │                           │
│ All Git object types       │       │ OID aliases               │
│ Independent records        │       │ Content locations         │
│ CRC + content digest       │       │ Repositories and refs      │
└──────────────┬─────────────┘       │ Workspaces and pins        │
               │                     └──────────────┬────────────┘
               │                                    │
               └──────────────────┬─────────────────┘
                                  │
                            checkout request
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │ Commit/tree resolver      │
                    │ Checkout plan             │
                    └─────────────┬─────────────┘
                                  │
                   missing blobs  │ cached blobs
                                  ▼
              ┌──────────────────────────────────┐
              │ Btrfs materialization domain     │
              │                                  │
              │ internal/cache/<ContentId>       │
              │ internal/staging/<UUID>          │
              │ workspaces/<name>                │
              └───────────────┬──────────────────┘
                              │
                  FICLONE each regular file
                              │
                    atomic workspace publish
```

---

# 4. Recommended filesystem layout

## 4.1 Host filesystem

```text
/var/lib/yourfs/
├── config.toml
├── instance.lock
├── catalog/
│   ├── repos/
│   │   └── <repo-id>/
│   │       ├── repository.toml
│   │       └── snapshots/
│   │           └── <snapshot-id>.manifest
│   └── workspaces/
│       └── <workspace-id>.manifest
├── rocksdb/
├── chunks/
│   ├── generation-000001/
│   │   ├── chunk-000000000001.sealed
│   │   ├── chunk-000000000002.sealed
│   │   └── chunk-000000000003.open
│   └── generation-000002/
├── temporary/
│   ├── compression/
│   └── gc/
├── hot/
│   └── hot.btrfs
├── run/
│   ├── daemon.sock
│   └── mount-state.json
└── backups/
```

Recommended permissions:

```text
/var/lib/yourfs                  0750 root:yourfs
/var/lib/yourfs/hot/hot.btrfs   0600 root:yourfs
/var/lib/yourfs/chunks           0750 yourfs:yourfs
/var/lib/yourfs/rocksdb          0750 yourfs:yourfs
```

---

## 4.2 Btrfs filesystem

```text
/var/lib/yourfs/hot-mount/
├── internal/                    0700 yourfs:yourfs
│   ├── cache/
│   │   └── objects/
│   │       ├── 00/
│   │       ├── 01/
│   │       └── ff/
│   ├── staging/
│   ├── trash/
│   └── manifests/
└── workspaces/
    ├── project-a/
    └── project-b/
```

Use a two-level or three-level fanout for cache objects:

```text
internal/cache/objects/ab/cd/abcdef...
```

Do not place millions of files directly in one directory.

Each workspace should be a Btrfs subvolume. This provides:

* Efficient recursive deletion.
* Optional snapshots.
* Optional quota-group accounting.
* A clear workspace lifecycle boundary.

Btrfs subvolume deletion is asynchronous: the directory entry can disappear before background cleaning has reclaimed all shared extents. Workspace deletion therefore needs `Deleting` and `Cleaned` states rather than assuming `rmdir` means immediate reclamation. ([BTRFS Documentation][9])

---

# 5. Product goals, non-goals, and invariants

## 5.1 Goals

1. Import selected Git history into an independent local object store.
2. Deduplicate identical objects across repositories.
3. Preserve repository refs and enough graph data to resolve revisions offline.
4. Hydrate a blob into Btrfs at most once per internal content ID.
5. Perform warm checkouts without decompressing or copying file payloads.
6. Publish only complete workspaces.
7. Recover automatically from interrupted imports, cache writes, checkouts, and mounts.
8. Safely handle malicious Git paths and object metadata.
9. Support cache eviction without invalidating existing workspaces.
10. Provide verifiable backup and restore of the cold tier.

---

## 5.2 Non-goals for the initial release

1. Acting as a full standard Git object database.
2. Supporting `git status`, `git commit`, or normal `.git` worktree semantics.
3. Fetching from remote repositories.
4. Executing clean/smudge filters.
5. Automatically downloading Git LFS content.
6. Recursively materializing submodules.
7. Providing process or build isolation.
8. Cold-tier Git-style delta compression.
9. Shrinking the Btrfs image in place.
10. Booting a system directly from arbitrary imported commits.

---

## 5.3 Core invariants

### Cold-store invariants

* Every indexed object location points to a complete record.
* Every complete record has a valid header, footer, length, checksum, and content digest.
* No object becomes visible until its chunk bytes are durable.
* Sealed chunks are immutable.
* Numeric offsets and lengths are 64-bit.
* A source repository is no longer required after an import is committed.

### Cache invariants

* Cache filenames are internal content IDs, not untrusted Git paths.
* A published cache file is complete and content-verified.
* Cache files are owned by the service and not writable by workspace users.
* Missing cache state is always recoverable from the cold tier.
* A cache DB entry is advisory; file existence and validation determine reality.

### Workspace invariants

* Workspace paths are never created through unchecked string concatenation.
* Users cannot access the staging directory while it is being populated.
* A workspace name becomes visible only after the complete tree is materialized.
* Every Ready workspace pins the repository snapshot or commit needed for cold GC.
* Mutating one workspace cannot mutate the cache or another workspace.

### Btrfs invariants

* Cache source and workspace destination files are under the same verified clone domain.
* Default COW and checksums remain enabled.
* `nodatacow` is not used for the cache or workspaces.
* FICLONE support is validated by an actual operation at startup.

---

# 6. Object identity and RocksDB schema

## 6.1 Core identifiers

```rust
#[repr(u8)]
pub enum ObjectKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

#[repr(u8)]
pub enum HashAlgorithm {
    Sha1 = 1,
    Sha256 = 2,
}

pub struct GitOid {
    pub algorithm: HashAlgorithm,
    pub len: u8,
    pub bytes: [u8; 32],
}

pub struct ContentId(pub [u8; 32]);

pub struct RepoId(pub [u8; 16]);
pub struct RepoSnapshotId(pub [u8; 16]);
pub struct WorkspaceId(pub [u8; 16]);
```

Do not use Rust’s in-memory struct representation as an on-disk format. Padding, enum representation, endianness, and crate changes make that unsafe for long-term storage.

Use one of:

* Explicit manually encoded fixed-endian records.
* A carefully versioned Protobuf schema.
* Another versioned schema with unknown-field compatibility.

All values should begin with a format version.

---

## 6.2 Recommended RocksDB column families

| Column family      | Key                           | Value                                                                      |
| ------------------ | ----------------------------- | -------------------------------------------------------------------------- |
| `object_locations` | `ContentId`                   | Chunk generation, chunk ID, offset, stored length, raw length, kind, codec |
| `oid_aliases`      | `RepoId + algorithm + GitOid` | `ContentId`                                                                |
| `repositories`     | `RepoId`                      | Name, source metadata, object format, policy                               |
| `repo_snapshots`   | `RepoSnapshotId`              | Repo ID, refs, import status, timestamp                                    |
| `refs`             | `RepoSnapshotId + refname`    | Native Git OID                                                             |
| `chunks`           | `generation + chunk_id`       | Open/sealed/retired state, size, record count                              |
| `cache_objects`    | `ContentId`                   | Size, last-access epoch, verification state                                |
| `workspaces`       | `WorkspaceId`                 | Name, snapshot, commit, state, owner, policy                               |
| `workspace_names`  | normalized workspace name     | Workspace ID                                                               |
| `pins`             | root identifier               | Snapshot or commit retained for GC                                         |
| `jobs`             | job UUID                      | Job type, progress, state, failure                                         |
| `meta`             | fixed key                     | Schema version, current generation, writer state                           |

### Why alias keys should include `RepoId`

A malicious or corrupted SHA-1 repository could present an OID collision. A global mapping from native OID to one content ID would then be ambiguous.

Use:

```text
RepoId || HashAlgorithm || OidLength || OidBytes
```

On import:

* If the repo-scoped alias already maps to the same `ContentId`, skip it.
* If it maps to a different `ContentId`, fail the import as corrupted or conflicting.
* Global deduplication still occurs through `object_locations[ContentId]`.

---

## 6.3 Example object-location value

```rust
pub struct ObjectLocationV1 {
    pub format_version: u8,
    pub chunk_generation: u32,
    pub chunk_id: u64,
    pub record_offset: u64,
    pub record_length: u64,
    pub stored_payload_length: u64,
    pub raw_payload_length: u64,
    pub object_kind: ObjectKind,
    pub codec: Codec,
    pub flags: u16,
    pub payload_crc32c: u32,
}
```

The original `Size(u32)` should become `u64`. A valid architecture should not silently fail for large Git blobs or future segment sizes.

---

# 7. Cold-tier chunk format

## 7.1 Design requirements

Each object record must be:

* Independently readable.
* Independently decompressible.
* Self-describing.
* Recoverable without RocksDB.
* Detectably incomplete after a crash.
* Verifiable through both CRC and `ContentId`.
* Skippable during sequential recovery scanning.

---

## 7.2 Chunk header

Example:

```text
Offset  Size  Field
0       8     Magic: "YFSCHNK\0"
8       2     Chunk format version
10      2     Header length
12      4     Generation
16      8     Chunk ID
24      8     Creation timestamp
32      4     Flags
36      4     Header CRC32C
40      24    Reserved
```

Keep the fixed header aligned to 64 bytes.

---

## 7.3 Object record

```text
RecordHeader
├── magic[4]                  = "YOBJ"
├── format_version: u16
├── header_length: u16
├── object_kind: u8
├── codec: u8                # raw or zstd
├── flags: u16
├── raw_length: u64
├── stored_length: u64
├── content_id[32]
├── primary_oid_algorithm: u8
├── primary_oid_length: u8
├── primary_oid[32]
├── header_crc32c: u32
└── reserved

Payload
└── stored_length bytes

RecordFooter
├── payload_crc32c: u32
├── total_record_length: u64
└── commit_magic[8]          = "YENDOBJ\0"

Padding
└── 0–7 bytes to 8-byte alignment
```

The final commit marker makes recovery straightforward:

* Missing footer: incomplete record.
* Invalid total length: damaged record.
* Invalid CRC: corrupt record.
* Valid CRC but wrong content digest after decompression: integrity failure.

---

## 7.4 Compression policy

Use one independent zstd frame per object.

Suggested policy:

```text
raw length < 256 bytes:
    store raw

otherwise:
    compress with configured zstd level

if compressed length >= raw length - minimum_savings:
    store raw
```

Start with a moderate cold-tier level such as 5 or 6 and benchmark. The optimal level depends on repository contents and import throughput.

Do not concatenate many blobs into one zstd stream. That would make random hydration require decompressing unrelated data.

For large objects, do not require the entire raw and compressed object to reside in memory. Use:

```text
Git object reader
    -> streaming ContentId hasher
    -> zstd encoder
    -> bounded in-memory spool
    -> spill file after memory threshold
    -> append writer
```

`git2` exposes an ODB reader API, but its documentation warns that many object backends do not support streaming reads because packed objects may be compressed or delta encoded. The importer therefore needs a bounded fallback for fully materialized objects and an optional system-Git backend for especially large objects. ([Docs.rs][10])

---

## 7.5 Rotation policy

Configuration:

```text
target_chunk_size = 1 GiB compressed
maximum_open_chunk_age = 30 minutes
```

Rules:

1. Never split one object record across chunks.
2. If an individual object exceeds the target, place it in an oversized dedicated chunk.
3. Check projected record size before appending.
4. Rotate only between records.
5. Allow only one active chunk writer per store generation.

Sealing protocol:

```text
1. Finish the last complete object record.
2. Append a chunk footer containing:
   - record count
   - final byte length
   - rolling metadata checksum
3. fdatasync the chunk.
4. Rename `.open` to `.sealed`.
5. fsync the chunks directory.
6. Mark the chunk Sealed in RocksDB.
7. Open the next `.open` chunk.
```

An `fsync` on the file does not necessarily persist the containing directory entry, so parent directories must also be synchronized after durable renames. ([man7.org][11])

---

## 7.6 Import transaction protocol

For a batch of records:

```text
Prepare stage
-------------
1. Read object.
2. Compute native identity metadata.
3. Compute ContentId.
4. Check object_locations.
5. Compress or select raw codec.
6. Produce complete record bytes or a spool file.

Commit stage — single writer
----------------------------
7. Recheck object_locations under writer serialization.
8. Append all new records.
9. fdatasync the open chunk.
10. Build one RocksDB WriteBatch:
    - object_locations
    - oid_aliases
    - chunk metadata
    - import counters
11. Commit RocksDB batch with sync=true in durable mode.
12. Report records committed.
```

The recheck at step 7 handles two concurrent import workers discovering the same object.

A simpler first implementation should use:

* Parallel readers/hashers/compressors.
* One append-and-index writer.
* Bounded channels and explicit backpressure.

That avoids complex cross-file write coordination while still using CPU parallelism.

---

# 8. Git repository import architecture

## 8.1 Git backend abstraction

Do not couple the entire store to `git2-rs`.

```rust
pub trait GitBackend {
    fn object_format(&self) -> Result<HashAlgorithm>;

    fn resolve_revision(
        &self,
        revision: &[u8],
    ) -> Result<GitOid>;

    fn list_refs(
        &self,
        selection: &RefSelection,
    ) -> Result<Vec<ResolvedRef>>;

    fn read_object_header(
        &self,
        oid: &GitOid,
    ) -> Result<ObjectHeader>;

    fn read_object(
        &self,
        oid: &GitOid,
    ) -> Result<GitObject>;

    fn read_object_stream(
        &self,
        oid: &GitOid,
    ) -> Result<Option<ObjectStream>>;
}
```

Initial implementations:

```text
Libgit2Backend
    Primary local-repository backend for validated object formats.

SystemGitBackend
    Optional compatibility backend using fixed Command arguments and
    batch-oriented Git plumbing.

GixBackend
    Experimental or future pure-Rust backend after repository-format,
    pack, and revision coverage has passed the compatibility suite.
```

Never invoke Git through a shell command string. Use `std::process::Command` with fixed arguments and separately supplied data.

---

## 8.2 Import scope

Recommended CLI policies:

```text
--all-refs
--branches
--tags
--ref refs/heads/main
--revision <rev>
--tree-only
--include-unreachable
```

Default:

```text
Import all objects reachable from local branches and tags.
```

For a source repository that is changing during import:

1. Resolve selected refs to immutable OIDs at the beginning.
2. Store that ref snapshot.
3. Walk from those OIDs.
4. Do not repeatedly reread moving ref names during traversal.
5. Publish the repository snapshot only after every reachable object has committed.

Git objects are immutable once addressed, so moving refs do not invalidate objects already read; they only affect which roots belong to the snapshot.

---

## 8.3 Graph traversal

Use a work queue and visited set.

```text
Annotated tag
    -> enqueue target object

Commit
    -> enqueue root tree
    -> optionally enqueue parent commits

Tree
    -> enqueue each child tree/blob/gitlink target as appropriate

Blob
    -> no children
```

A checkout-complete import needs:

* Commit object.
* Root tree and all descendant trees.
* Every referenced blob.

A history-complete import additionally needs:

* Parent commits.
* Annotated tags.
* Their reachable objects.

A gitlink points to a commit in another repository, so the corresponding object is generally not present in the superproject. Record it in the tree manifest but do not treat it as a missing local object.

---

## 8.4 Import flow

For each encountered object:

```text
1. Construct repo-scoped native alias key.
2. Check oid_aliases.
3. If present:
      mark visited and skip payload read where possible.

4. Read object type and payload.
5. Compute internal ContentId.
6. Check object_locations.

7. If ContentId exists:
      add only the new repo-scoped alias.

8. Otherwise:
      compress and append object record;
      add object location and alias atomically after chunk sync.
```

For trees and commits, store the exact raw Git payload. Do not store only a custom parsed form, because exact raw data enables:

* Reverification.
* Schema-independent recovery.
* Future parsing improvements.
* Native Git OID recomputation.
* Export into another Git-compatible representation.

A parsed tree/commit cache can be added as derived RocksDB data.

---

## 8.5 Repository snapshot publication

A repository should not appear usable while only partially imported.

Suggested states:

```text
Discovered
Scanning
Writing
Finalizing
Ready
Failed
Deleting
```

Publication sequence:

```text
1. Import all reachable objects.
2. Verify there are no unresolved required objects.
3. Write a versioned repo snapshot manifest to a temporary file.
4. fsync the manifest.
5. Atomically rename it to the final manifest name.
6. fsync the manifest directory.
7. Mark the repository snapshot Ready in RocksDB.
```

The manifest should contain:

```text
schema version
repository ID
snapshot ID
display name
source metadata
native object format
selected refs and resolved OIDs
import policy
object counts by type
raw and compressed bytes
timestamp
tool version
optional signature/attestation metadata
```

---

## 8.6 Partial, shallow, and promisor repositories

Explicitly detect and report:

* Missing parent commits in shallow repositories.
* Missing promised objects in partial clones.
* Broken alternates.
* Corrupt pack or loose objects.
* Unsupported object format.

Policies:

```text
strict:
    fail if any required reachable object is missing

checkout-complete:
    allow missing history outside the requested commit/tree closure

best-effort:
    publish only clearly marked incomplete snapshots
```

Do not silently publish an incomplete repository as Ready.

---

# 9. Btrfs materialization domain

## 9.1 Backend abstraction

Support two Btrfs deployment modes behind one trait:

```rust
pub trait MaterializationBackend {
    fn initialize(&self, options: &InitOptions) -> Result<()>;
    fn ensure_mounted(&self) -> Result<MountIdentity>;
    fn probe_reflink(&self) -> Result<ReflinkCapabilities>;
    fn create_staging_workspace(&self) -> Result<StagingWorkspace>;
    fn publish_workspace(&self, stage: &StagingWorkspace, name: &WorkspaceName)
        -> Result<WorkspaceHandle>;
    fn delete_workspace(&self, workspace: &WorkspaceHandle) -> Result<()>;
}
```

Implementations:

```text
LoopbackBtrfsBackend
    Btrfs filesystem inside a host file.

NativeBtrfsBackend
    Uses an existing Btrfs filesystem directly.
```

When the host is already Btrfs, native mode is usually simpler and avoids a nested filesystem and loop device. The loopback mode remains valuable for ext4 hosts and controlled deployment.

---

## 9.2 Sparse image creation

Rust skeleton:

```rust
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub fn create_sparse_image(path: &Path, logical_size: u64) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "image has no parent directory")
    })?;

    let image = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;

    image.set_len(logical_size)?;
    image.sync_all()?;

    // Make creation of the directory entry durable.
    File::open(parent)?.sync_all()?;

    Ok(())
}
```

Additional validation:

* Reject a symlink.
* Require `create_new`.
* Require a regular file.
* Refuse to overwrite a path containing an existing filesystem.
* Refuse destructive formatting unless the user explicitly ran `init`.
* Write a separate instance marker containing a generated instance UUID.

---

## 9.3 Loop-device setup

Recommended operational sequence:

```text
1. Hold an exclusive flock on the image or instance lock.
2. Search for an existing loop association for the canonical backing file.
3. Reuse the existing association if it is valid.
4. Otherwise run:
      losetup --find --show --nooverlap <image>
5. Verify the returned device’s backing file.
6. Format only during explicit initialization.
7. Mount by verified device/UUID.
```

Linux permits multiple loop devices to reference the same backing file, which can cause corruption. `losetup` recommends `--nooverlap`, and its find-and-attach flow needs external locking under concurrent setup. ([man7.org][12])

Do not persist `/dev/loop7` as the permanent identity. Loop numbering can change after reboot. Persist:

* Canonical image path.
* Filesystem UUID.
* YourFS instance UUID.
* Expected Btrfs label.
* Mountpoint.

---

## 9.4 Mount policy

Initial mount options:

```text
noatime,nodev,nosuid,compress=zstd:1
```

Do not set `noexec` when users need to compile and execute binaries from workspaces.

`noatime` avoids read-triggered inode updates in read-heavy Btrfs workloads. Btrfs supports transparent zstd compression; logically raw cache files can therefore remain byte-exact while their physical extents are compressed and subsequently shared through reflinks. Compression should still be benchmarked against CPU cost and build workloads. ([BTRFS Documentation][8])

Avoid:

```text
nodatacow
nodatacow on cache directories
autodefrag without dedicated reflink testing
nobarrier
```

Btrfs requires source and destination to have compatible COW/checksum status for reflinking. Default COW is the correct mode for this architecture. ([BTRFS Documentation][13])

---

## 9.5 Directory and subvolume setup

On first initialization:

```text
Create Btrfs subvolume: internal/cache
Create directory or subvolume: internal/staging
Create directory or subvolume: internal/trash
Create Btrfs subvolume: workspaces
```

Recommended approach:

* Cache as one subvolume.
* Every workspace as its own subvolume.
* Staging workspace created as its own temporary subvolume.
* Trash area holds exchanged or deleting workspaces.

Keep all paths reachable through the same top-level mount.

---

## 9.6 Reflink feature probe

At every daemon startup:

```text
1. Ensure mountpoint is Btrfs.
2. Create source under internal/cache/.probe/.
3. Write recognizable bytes and synchronize.
4. Create an empty destination under internal/staging/.probe/.
5. Call FICLONE.
6. Read and compare destination.
7. Modify destination.
8. Verify source remains unchanged.
9. Remove both files.
```

Report:

```text
FICLONE supported: yes/no
same clone domain: yes/no
mutation isolation: yes/no
copy fallback configured: yes/no
```

This probe is more reliable than inferring support from filesystem names.

---

## 9.7 Growing the image

Online grow sequence:

```text
1. Check host free-space policy.
2. Increase hot.btrfs logical length with set_len.
3. Run losetup --set-capacity <loopdev>.
4. Run btrfs filesystem resize max <mountpoint>.
5. Verify new device and filesystem sizes.
```

`losetup --set-capacity` asks the loop driver to reread the backing-file size, and Btrfs supports growing to the underlying device’s maximum size with `btrfs filesystem resize max`. ([man7.org][12])

Do not implement shrinking in the first production release. A safe shrink path requires relocation planning and failure handling. Prefer export/rebuild into a new image.

---

# 10. Hot-cache hydration engine

## 10.1 Cache key

Use:

```text
ContentId
```

not native Git OID.

Example path:

```text
internal/cache/objects/3a/7f/3a7f...
```

This allows the same cached blob to serve:

* Multiple repositories.
* Multiple branches.
* Multiple workspaces.
* SHA-1 and SHA-256 source repositories with identical blob content.

---

## 10.2 Cache object state

```text
Absent
Hydrating
Ready
Corrupt
Evicting
```

The filesystem remains the final authority:

* DB says Ready, file absent → mark missing and rehydrate.
* File exists, DB absent → inspect and adopt or delete.
* Temporary file exists → delete or resume according to validated state.
* Size mismatch → quarantine and rehydrate.
* Digest mismatch → quarantine, emit high-severity integrity event, rehydrate from cold tier.

---

## 10.3 Hydration algorithm

```text
hydrate(ContentId):
    1. Calculate final fanout path.
    2. If final file exists:
           verify expected size;
           return cache hit.

    3. Acquire a content-scoped singleflight lock.
    4. Recheck final path.

    5. Look up ObjectLocation in RocksDB.
    6. Open the appropriate sealed/open chunk read-only.
    7. pread the record header.
    8. Validate magic, version, lengths, kind, and header CRC.
    9. Create an O_EXCL temporary file in the cache directory.
   10. Decode zstd payload into the temporary file.
   11. While decoding:
           enforce expected raw length;
           compute ContentId;
           compute optional CRC.
   12. Reject early EOF, extra output, decompression failure, or hash mismatch.
   13. Set mode 0444.
   14. In durable mode, fdatasync the temporary file.
   15. Publish with renameat2(RENAME_NOREPLACE).
   16. fsync the parent cache directory in durable mode.
   17. If another process won the race:
           validate the winner;
           remove this temporary file.
   18. Update advisory cache metadata.
```

Use `pread` rather than shared file-position reads so multiple workers can safely read one chunk descriptor.

---

## 10.4 Hydration scheduling

For a checkout requiring many missing blobs:

1. Deduplicate required content IDs.
2. Query all locations.
3. Sort misses by:

```text
(chunk_generation, chunk_id, record_offset)
```

4. Process nearby records together.
5. Use a bounded decompression pool.
6. Cap:

   * concurrent open chunks,
   * concurrent large-object spools,
   * total temporary bytes,
   * total decompression output in flight.

This turns random log reads into mostly sequential chunk reads.

---

## 10.5 Cache immutability

Cache files should be:

```text
owner: yourfs service account
mode: 0444
parent directories: not writable by workspace users
```

Do not rely on `chattr +i` as the main correctness mechanism. Permissions and inaccessible parent directories are simpler to manage and recover.

Only the service creates and opens cache files.

---

## 10.6 Cache eviction

Eviction policy should use high and low watermarks:

```text
start eviction: 85% Btrfs usage
stop eviction: 70% Btrfs usage
emergency threshold: 95%
```

These must be configurable.

Eviction order can be approximate LRU:

```text
score =
    last_access_epoch
    + workspace_reference_hint
    + hydration_cost_hint
    + object_size_weight
```

Because `noatime` is enabled, maintain logical access information in RocksDB. Do not write an LRU update on every cache hit; sample or batch updates to avoid metadata write amplification.

Deleting a cache inode does not invalidate workspace files that already reflink its extents. The workspace has an independent inode referring to the shared blocks; physical blocks remain until all references are removed or diverged. That independence is the defining Btrfs reflink behavior. ([BTRFS Documentation][13])

---

# 11. Checkout planning and materialization

## 11.1 Revised CLI identity

A bare commit hash is ambiguous across imported repository snapshots and native hash algorithms.

Prefer:

```text
yourfs checkout <repository>@<revision> --workspace <name>
```

Examples:

```bash
yourfs checkout linux@v6.10 --workspace linux-build
yourfs checkout project-a@refs/heads/main --workspace project-a-main
yourfs checkout project-a@a71b... --workspace project-a-test
```

The resolver should:

1. Locate the repository.
2. Select a repository snapshot, defaulting to the latest committed snapshot.
3. Resolve the revision in that snapshot.
4. Peel annotated tags.
5. Require the result to be a commit unless an explicit tree checkout is requested.

---

## 11.2 Checkout plan structure

```rust
pub enum PlanEntryKind {
    Directory,
    RegularFile,
    ExecutableFile,
    Symlink,
    Gitlink,
}

pub struct CheckoutPlanEntry {
    pub path_components: Vec<Vec<u8>>,
    pub kind: PlanEntryKind,
    pub content_id: Option<ContentId>,
    pub native_blob_oid: Option<GitOid>,
    pub raw_length: u64,
}
```

Paths must remain byte sequences. Unix filenames are not guaranteed to be UTF-8.

Do not convert repository paths to Rust `String` merely for convenience.

---

## 11.3 Tree validation

Validate every component before creating anything:

```text
reject:
    empty component
    "."
    ".."
    embedded NUL
    embedded "/"
    absolute path
    component above configured byte limit
    total path above configured byte limit
```

Also enforce:

```text
maximum tree depth
maximum file count
maximum total logical bytes
maximum individual blob size
maximum symlink-target size
maximum directories
```

Detect:

* Duplicate entries.
* A path used as both file and directory.
* Invalid or unsupported Git modes.
* Unresolved required content IDs.
* Unsupported gitlink policy.

Git’s own canonical-path rules reject empty components, leading or trailing separators, and `.` or `..` components. ([Git][6])

---

## 11.4 Safe path operations

Do not create files with:

```rust
format!("{workspace}/{git_path}")
```

Instead:

* Hold a directory file descriptor for the inaccessible staging root.
* Split and validate components.
* Use `mkdirat`, `openat`, `symlinkat`, `renameat2`, and related fd-relative calls.
* Use `openat2` with resolution restrictions where supported.
* Avoid following symlinks while creating later entries.

`RESOLVE_BENEATH` prevents resolution outside the directory represented by the supplied fd, and `RESOLVE_NO_MAGICLINKS` explicitly blocks magic-link traversal. ([man7.org][14])

Create entries in this order:

```text
1. Directories
2. Regular and executable files
3. Gitlink placeholders, if enabled
4. Symbolic links last
```

The staging subvolume should remain mode `0700` and owned by the service until materialization is complete. That prevents an untrusted user from racing the service by replacing directories with symlinks.

---

## 11.5 File materialization

For every regular file:

```text
1. Ensure the content is hydrated.
2. Open cache source O_RDONLY | O_NOFOLLOW.
3. Create destination O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode 0600.
4. Verify both file descriptors are regular files.
5. Call FICLONE(destination_fd, source_fd).
6. Apply final mode:
      0644 for Git mode 100644
      0755 for Git mode 100755
7. Apply owner and group according to workspace policy.
8. Set timestamp policy if requested.
9. Close descriptors.
```

Rust’s `rustix` crate exposes `rustix::fs::ioctl_ficlone`, avoiding a handwritten unsafe ioctl wrapper for supported targets. ([Docs.rs][15])

Example:

```rust
use rustix::fs::ioctl_ficlone;
use std::fs::File;
use std::io;

pub fn reflink_file(source: &File, destination: &File) -> io::Result<()> {
    ioctl_ficlone(destination, source).map_err(io::Error::from)
}
```

`FICLONE` creates independent files sharing the underlying storage; later writes to a shared region are handled through copy-on-write. The clone itself is atomic with respect to concurrent source writes. ([man7.org][1])

For an empty blob, simply create an empty destination; a reflink operation is unnecessary.

---

## 11.6 FICLONE error policy

Classify errors:

```text
EXDEV
    Cache and workspace are not in the same usable clone domain.
    Treat as an architecture/configuration error.

EOPNOTSUPP / ENOTTY / EINVAL
    Filesystem, object type, or current configuration does not support clone.

ENOSPC
    Btrfs lacks data or metadata space.

EDQUOT
    Workspace or filesystem quota reached.

EPERM
    Permission or file-attribute conflict.

EIO
    Storage or filesystem error.
```

Default behavior:

```text
Fail checkout rather than silently copying.
```

Optional behavior:

```text
--copy-fallback
```

When enabled, record in the workspace manifest which files were copied rather than reflinked. Never describe such a checkout as fully reflinked.

---

## 11.7 Symbolic links

Git mode `120000` means:

```text
blob contents = symlink target bytes
```

Materialization:

```text
1. Read target bytes.
2. Reject embedded NUL.
3. Apply configured symlink policy.
4. Create with symlinkat.
5. Never follow the new link during checkout construction.
```

Policies:

```text
preserve
    Create any valid Linux symlink target.

workspace-contained
    Reject absolute targets and targets whose normalized traversal can escape.

reject
    Fail any checkout containing symlinks.
```

`workspace-contained` is useful for importing untrusted repositories, but it differs from normal Git semantics.

Even safe construction does not make subsequent build execution safe. A build process can intentionally follow repository symlinks. Use a separate execution sandbox for untrusted code.

---

## 11.8 Gitlinks/submodules

Policies:

```text
reject
    Fail when a gitlink is encountered.

empty-directory
    Create a directory and record the referenced submodule commit in metadata.

manifest-only
    Do not create a path; record it in the workspace manifest.

recursive
    Resolve a configured imported repository mapping and materialize it.
```

Recommended MVP default:

```text
empty-directory with a visible warning
```

Recursive submodules should be a later phase because they require URL-to-repository mapping, nested policy, cycle detection, and independent availability checks.

---

## 11.9 Timestamps and ownership

Git trees preserve only the executable bit, not:

* UID.
* GID.
* File timestamps.
* Extended attributes.
* ACLs.
* Hardlink relationships.
* Empty directories.

Offer explicit policies:

```text
mtime = checkout-time
mtime = commit-time
mtime = fixed:<unix-seconds>

owner = caller
owner = configured-service-user
```

A deterministic fixed or commit-derived timestamp can benefit reproducible build systems, but it is not normal Git metadata preservation.

---

## 11.10 Workspace publication

Use a staging subvolume:

```text
internal/staging/<workspace-uuid>
```

After all entries succeed:

```text
1. Write internal workspace manifest.
2. Verify expected file/dir counts.
3. In durable mode, synchronize Btrfs changes.
4. Change ownership and access policy.
5. Atomically publish:
      renameat2(RENAME_NOREPLACE)
6. fsync the workspaces parent directory.
7. Commit workspace Ready state and pin in RocksDB.
```

`RENAME_NOREPLACE` ensures an existing name is not overwritten. For `--replace`, use `RENAME_EXCHANGE` to atomically swap the completed staging workspace with the existing workspace, then move the old workspace through the asynchronous deletion path. Btrfs supports the relevant rename operation, and Linux documents the exchange operation as atomic. ([man7.org][16])

Workspace states:

```text
Creating
Ready
Replacing
Deleting
Failed
Orphaned
```

---

# 12. Durability modes

Offer explicit durability instead of one ambiguous behavior.

## 12.1 `durable`

For imports:

* `fdatasync` chunk before index commit.
* RocksDB `sync=true`.
* `fsync` directories after durable rename.

For cache hydration:

* `fdatasync` hydrated file.
* `fsync` cache parent after publication.

For workspace publication:

* Synchronize Btrfs before reporting success.
* Synchronize the final parent directory after rename.

Use for persistent workspaces and machine-reboot guarantees.

---

## 12.2 `balanced`

* Batch chunk synchronization.
* RocksDB WAL enabled but synchronous writes batched.
* Cache files may be reconstructed after crash.
* Workspace startup recovery verifies and repairs incomplete results.

This is likely the practical default.

---

## 12.3 `ephemeral`

* Minimal synchronization.
* Intended for disposable CI/build machines.
* A power loss may discard recent imports or workspaces.
* Process crashes should still be handled without memory-unsafety or uncontrolled corruption.

Never label this mode durable.

---

# 13. Daemon and privilege separation

## 13.1 Recommended process architecture

```text
yourfs-mount-helper
    Runs with root/CAP_SYS_ADMIN.
    Owns loop setup, mount, unmount, resize, and trim.
    Accepts a tiny fixed protocol.

yourfsd
    Runs as dedicated unprivileged `yourfs` user.
    Owns RocksDB, chunks, cache, checkout, and workspace metadata.
    Communicates with helper over a private Unix socket.

yourfs
    Unprivileged frontend CLI.
    Communicates with yourfsd over a public Unix socket.
```

Do not run Git parsing, zstd decompression, or general repository processing in a permanently privileged process.

The helper should permit only operations against the configured instance image and mountpoint—not arbitrary user-supplied devices and paths.

---

## 13.2 Daemon startup sequence

```text
1. Acquire instance flock.
2. Load and validate configuration.
3. Validate host paths and permissions.
4. Discover or attach loop device.
5. Verify Btrfs UUID and instance marker.
6. Mount through the helper.
7. Run FICLONE probe.
8. Open RocksDB.
9. Recover open chunk tail.
10. Reconcile cache temporary files.
11. Reconcile staging and published workspaces.
12. Reconcile job states.
13. Start background maintenance.
14. Begin accepting CLI requests.
```

Never automatically run `mkfs.btrfs` because mounting failed. Formatting must be possible only during explicit `yourfs init`.

---

## 13.3 Shutdown sequence

```text
1. Stop accepting new mutating jobs.
2. Allow active jobs to finish or cancel at safe checkpoints.
3. Flush the chunk writer.
4. Synchronize RocksDB according to durability policy.
5. Persist daemon state.
6. Stop background workers.
7. Unmount only if no workspaces or external users require the mount.
8. Detach the loop device.
```

For normal workstation use, systemd should keep the filesystem mounted for the lifetime of the service.

---

# 14. Crash recovery matrix

| Crash point                              | Expected state                      | Recovery                                                                |
| ---------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------- |
| During record header write               | Partial tail                        | Truncate open chunk to last valid committed record                      |
| During record payload write              | Header plus incomplete payload      | Truncate to prior valid record                                          |
| After complete record, before chunk sync | Record may or may not survive       | Scanner validates; unindexed record can be adopted or ignored           |
| After chunk sync, before RocksDB commit  | Valid orphan record                 | Rebuild `object_locations` or reclaim during GC                         |
| After RocksDB commit                     | Valid indexed record                | No action                                                               |
| During chunk sealing rename              | `.open` or `.sealed` exists         | Inspect footer and reconcile extension/state                            |
| During cache decompression               | Temporary file                      | Delete temp and rehydrate                                               |
| After cache rename, before DB update     | Valid cache file, DB missing        | Validate and adopt                                                      |
| DB says cache Ready, file missing        | Stale advisory metadata             | Mark missing and rehydrate                                              |
| During workspace tree creation           | `Creating` staging subvolume        | Resume only with a valid resumable manifest; otherwise delete           |
| After staging complete, before publish   | Complete staging workspace          | Publish or delete according to job state                                |
| After publish, before DB Ready           | Workspace visible, DB stale         | Validate manifest and repair DB                                         |
| During `RENAME_EXCHANGE` replacement     | Atomic old/new swap                 | Determine identities from manifests and continue old-workspace deletion |
| During workspace deletion                | Name removed, Btrfs cleaning active | Keep `Deleting` until cleaning completes or usage stabilizes            |
| Loop attached, mount missing             | Existing loop association           | Verify and remount                                                      |
| Mount exists, daemon stopped             | Persistent valid mount              | Reuse after identity check                                              |
| Duplicate startup                        | Second instance sees flock          | Exit with clear “instance already running” error                        |

---

# 15. Cold-store garbage collection

Append-only storage needs generation-based mark-and-compact GC.

## 15.1 GC roots

Mark from:

* Every Ready repository snapshot that is still retained.
* Every workspace-pinned commit.
* Explicit user pins.
* Boot-target manifests.
* Retention-policy snapshots.
* Active import and checkout jobs.

A branch update must not make a commit collectible while an existing workspace still depends on it.

---

## 15.2 Mark phase

For each root:

```text
tag -> target
commit -> tree and retained parents
tree -> child trees and blobs
blob -> leaf
gitlink -> external reference, not local traversal
```

Mark internal `ContentId`s, not only native OIDs.

Use a disk-backed mark set for very large stores rather than assuming the full graph fits in RAM.

---

## 15.3 Compact phase

```text
1. Create generation N+1.
2. Sequentially scan generation N chunks.
3. Copy live records into new chunks.
4. Build a shadow object-location index.
5. Synchronize new chunks.
6. Atomically switch the active-generation manifest.
7. Commit new location mappings.
8. Prevent new readers from entering generation N.
9. Wait for existing generation-N readers to release leases.
10. Retire and delete old chunks.
```

Never rewrite an active chunk in place.

Reader leases can be implemented with:

* In-process epoch counters.
* Generation reference counts.
* Open file-handle ownership plus DB generation state.

---

## 15.4 Object deletion semantics

Removing a repository should:

1. Mark its snapshot as Deleting.
2. Remove user-visible refs.
3. Remove its OID aliases.
4. Remove its pins.
5. Leave shared object records untouched.
6. Reclaim unreachable records only during GC.

This preserves cross-repository deduplication.

---

# 16. Capacity management

## 16.1 Two nested capacity domains

Because the cold store and sparse Btrfs image share the host filesystem, a single machine has at least three relevant measurements:

```text
Host filesystem free space
Cold-tier physical bytes
Btrfs guest free/allocated space
```

A fourth measurement is useful:

```text
Physical blocks allocated to hot.btrfs on the host
```

Do not rely only on `df` inside the Btrfs mount. `btrfs filesystem usage` reports internal allocated, unallocated, used, estimated-free, metadata, and global-reserve information that can differ from simple statfs output. ([BTRFS Documentation][17])

---

## 16.2 Reserve policy

Example:

```text
host_emergency_reserve_bytes = max(10 GiB, 5% of host volume)
btrfs_emergency_reserve_bytes = max(5 GiB, 5% of image)
cold_import_minimum_headroom = projected compressed bytes + safety margin
checkout_minimum_headroom = projected new hydration bytes + metadata margin
```

Before an import:

* Estimate incoming bytes from object headers where possible.
* Reject or pause if host headroom is unsafe.

Before a checkout:

* Sum missing raw blob sizes.
* Apply estimated Btrfs compression ratio conservatively.
* Include metadata overhead for file count.
* Evict cache if necessary.
* Reject before publishing partial work.

---

## 16.3 Quotas

Btrfs quota groups can track referenced and exclusive space and enforce limits. Exclusive space is especially useful for estimating what deletion would actually free. Qgroups should be optional because they add another accounting subsystem that needs operational testing. ([BTRFS Documentation][18])

Suggested modes:

```text
quotas = off
quotas = workspace-limits
quotas = full-accounting
```

---

# 17. Integrity and verification

## 17.1 Cold verification

`yourfs store verify` should support:

```text
--quick
    Verify chunk structure, headers, footers, and CRCs.

--sample <percentage>
    Decompress and rehash a sample.

--full
    Decompress every record and verify ContentId and native OID.

--rebuild-index
    Reconstruct object locations from chunk records.

--repair-open-tail
    Truncate incomplete tail records.
```

A native OID mismatch and an internal `ContentId` mismatch should be distinct diagnostics.

---

## 17.2 Hot verification

`yourfs cache verify`:

```text
1. Enumerate cache files by fanout.
2. Validate filename syntax.
3. Validate regular-file type.
4. Compare size with cold metadata.
5. Optionally hash content.
6. Remove or quarantine unrecognized files.
7. Repair advisory RocksDB state.
```

---

## 17.3 Btrfs verification

Run scheduled Btrfs scrub and surface results through `status`. Scrub detects checksum, metadata-header, superblock, and read errors. On a single-device loopback filesystem, it can detect corruption but generally has no redundant device copy from which to repair damaged data. ([BTRFS Documentation][19])

Because the hot cache is derived, damaged cache files can be deleted and rehydrated. Mutable workspace damage requires a separate recovery or backup policy.

---

# 18. Backup and restore

## 18.1 Authoritative data

Treat as authoritative:

* Sealed cold chunks.
* The valid prefix of the current open chunk.
* RocksDB or a consistent checkpoint.
* Repository snapshot manifests.
* Configuration and schema metadata.
* Workspace manifests and pins.

Treat as derived:

* Hot cache files.
* Parsed tree caches.
* Access timestamps.
* Temporary jobs.

Treat workspaces according to policy:

```text
ephemeral workspace:
    not backed up

persistent mutable workspace:
    snapshot/export separately
```

---

## 18.2 Consistent cold backup

```text
1. Pause the append writer.
2. Complete and synchronize the current object batch.
3. Record the current open-chunk valid length.
4. Create a RocksDB checkpoint.
5. Write a backup manifest containing:
      schema version
      chunk generations
      sealed chunk names and sizes
      open chunk valid prefix
      RocksDB checkpoint identity
      repository snapshot manifest digests
6. Synchronize the backup manifest.
7. Resume writes.
8. Copy immutable chunks incrementally.
```

---

## 18.3 Restore

```text
1. Restore chunks and catalog.
2. Restore or rebuild RocksDB.
3. Run full structural verification.
4. Recreate a fresh sparse Btrfs image.
5. Mount and initialize cache/workspace roots.
6. Lazily rehydrate cache during future checkouts.
7. Restore persistent workspaces separately if they were backed up.
```

This is one of the architecture’s strongest properties: the hot cache can be rebuilt from the cold tier.

---

# 19. Security model

## 19.1 Threats to handle

* Malicious Git tree paths.
* Symlink-based path escape.
* Decompression bombs.
* Huge objects.
* Deep or cyclic malformed graphs.
* SHA-1 collision attempts.
* Concurrent workspace-name races.
* Replacing the backing image with a symlink.
* Formatting the wrong path.
* Duplicate loop attachment.
* External filter command execution.
* Untrusted repository content executed during builds.
* Multi-user access to another user’s workspace.

---

## 19.2 Required controls

### Path controls

* Operate relative to directory file descriptors.
* Validate byte components.
* Use `openat2` restrictions where available.
* Never follow staging symlinks.
* Create symlinks last.
* Keep staging inaccessible to users.

### Resource controls

```text
max_blob_bytes
max_total_checkout_bytes
max_tree_depth
max_entries
max_decompression_ratio
max_concurrent_decompressions
max_import_memory
max_temp_spool_bytes
job timeout and cancellation
```

The decompressor must stop after the expected raw length rather than trusting zstd output indefinitely.

### Privilege controls

* Isolate mount privileges.
* Run import and checkout logic unprivileged.
* Restrict the helper to one configured image and mountpoint.
* Never interpolate user input into shell commands.
* Validate peer credentials on Unix-socket connections.

### Data controls

* Service-owned cache.
* Workspace ownership assigned only after complete construction.
* Repository IDs and workspace IDs generated internally.
* Display names mapped to IDs rather than used as unrestricted paths.
* Optional per-user authorization in RocksDB.

### Execution controls

A completed checkout is not a secure execution environment. Run untrusted builds through a separate mechanism such as namespaces, containers, a dedicated build user, or a VM.

---

# 20. Rust project structure

```text
reflink-forest/
├── Cargo.toml
├── crates/
│   ├── yourfs-core/
│   │   ├── identifiers
│   │   ├── errors
│   │   ├── limits
│   │   └── configuration
│   ├── yourfs-format/
│   │   ├── chunk encoding
│   │   ├── record encoding
│   │   ├── manifests
│   │   └── migrations
│   ├── yourfs-index/
│   │   ├── RocksDB column families
│   │   ├── key encoding
│   │   └── WriteBatch helpers
│   ├── yourfs-store/
│   │   ├── chunk writer
│   │   ├── chunk reader
│   │   ├── recovery scanner
│   │   ├── object verification
│   │   └── GC
│   ├── yourfs-git/
│   │   ├── backend trait
│   │   ├── libgit2 backend
│   │   ├── system Git backend
│   │   ├── graph traversal
│   │   └── tree parsing
│   ├── yourfs-btrfs/
│   │   ├── loop orchestration
│   │   ├── mount identity
│   │   ├── subvolumes
│   │   ├── reflink
│   │   ├── usage
│   │   └── trim/resize
│   ├── yourfs-cache/
│   │   ├── hydration
│   │   ├── singleflight
│   │   ├── verification
│   │   └── eviction
│   ├── yourfs-checkout/
│   │   ├── plan construction
│   │   ├── path validation
│   │   ├── materialization
│   │   └── publication
│   ├── yourfs-daemon/
│   │   ├── Unix socket protocol
│   │   ├── jobs
│   │   ├── recovery
│   │   └── background maintenance
│   ├── yourfs-mount-helper/
│   │   └── privileged fixed operation set
│   ├── yourfs-cli/
│   └── yourfs-test-support/
├── fuzz/
├── tests/
│   ├── integration/
│   ├── fault-injection/
│   └── compatibility/
└── docs/
    ├── architecture.md
    ├── format-v1.md
    ├── recovery.md
    ├── security.md
    └── adr/
```

---

## 20.1 Suggested dependencies

```text
clap
serde
toml
rocksdb
zstd
sha2
crc32c
rustix
libc or nix where rustix lacks an operation
uuid
tracing
tracing-subscriber
thiserror
anyhow for CLI/application boundaries
crossbeam-channel or equivalent bounded channels
rayon for CPU pools where useful
tempfile
proptest
```

Do not pin architecture documentation to specific crate versions. Pin versions in `Cargo.lock`, test updates through CI, and document the minimum supported Rust version separately.

---

## 20.2 Error model

Use typed internal errors:

```rust
pub enum YourFsError {
    Configuration(ConfigurationError),
    Git(GitError),
    Store(StoreError),
    Index(IndexError),
    Integrity(IntegrityError),
    Reflink(ReflinkError),
    Mount(MountError),
    Capacity(CapacityError),
    Security(SecurityError),
    Unsupported(UnsupportedError),
}
```

Expose stable CLI error codes:

```text
10 configuration
20 repository/import
30 object corruption
40 capacity
50 mount/loop
60 reflink unsupported
70 workspace conflict
80 permissions/security
90 internal
```

Every error should include contextual IDs:

```text
repo_id
snapshot_id
workspace_id
content_id
chunk_generation
chunk_id
offset
job_id
```

---

# 21. CLI design

```text
yourfs init
yourfs doctor
yourfs status
yourfs start
yourfs stop

yourfs repo import <path> --name <name>
yourfs repo update <name>
yourfs repo list
yourfs repo show <name>
yourfs repo remove <name>
yourfs repo snapshots <name>

yourfs checkout <repo>@<revision> --workspace <name>
yourfs checkout ... --mode raw
yourfs checkout ... --replace
yourfs checkout ... --copy-fallback
yourfs checkout ... --symlinks preserve|workspace-contained|reject
yourfs checkout ... --submodules reject|empty-directory|manifest-only

yourfs workspace list
yourfs workspace show <name>
yourfs workspace remove <name>
yourfs workspace snapshot <name>
yourfs workspace verify <name>

yourfs cache stats
yourfs cache verify
yourfs cache prune
yourfs cache drop-all

yourfs store stats
yourfs store verify
yourfs store gc
yourfs store checkpoint

yourfs fs usage
yourfs fs grow +50GiB
yourfs fs trim
yourfs fs scrub
```

All read commands should support:

```text
--json
```

Long jobs should expose:

```text
job ID
objects processed
objects deduplicated
raw bytes
compressed bytes
cache hits
cache misses
files cloned
files copied by fallback
current phase
cancellation status
```

---

# 22. Configuration example

```toml
schema_version = 1

[instance]
name = "default"
runtime_dir = "/run/yourfs"
socket = "/run/yourfs/daemon.sock"

[cold]
root = "/var/lib/yourfs"
rocksdb_path = "/var/lib/yourfs/rocksdb"
chunks_path = "/var/lib/yourfs/chunks"
temporary_path = "/var/lib/yourfs/temporary"
chunk_target_bytes = 1073741824
compression_level = 6
compression_memory_threshold_bytes = 16777216
durability = "balanced"

[hot]
backend = "loopback-btrfs"
image_path = "/var/lib/yourfs/hot/hot.btrfs"
logical_size_bytes = 53687091200
mountpoint = "/var/lib/yourfs/hot-mount"
mount_options = ["noatime", "nodev", "nosuid", "compress=zstd:1"]
cache_high_watermark_percent = 85
cache_low_watermark_percent = 70
discard_policy = "scheduled"

[checkout]
mode = "raw"
copy_fallback = false
symlink_policy = "preserve"
submodule_policy = "empty-directory"
default_file_owner = "caller"
timestamp_policy = "checkout-time"

[limits]
max_blob_bytes = 17179869184
max_checkout_logical_bytes = 1099511627776
max_entries = 5000000
max_tree_depth = 1024
max_path_bytes = 4096
max_component_bytes = 255
max_parallel_hydrations = 8
max_parallel_import_workers = 8
max_temp_bytes = 68719476736

[capacity]
host_emergency_reserve_bytes = 10737418240
btrfs_emergency_reserve_bytes = 5368709120

[maintenance]
cache_eviction_interval_seconds = 60
verification_sample_percent = 0.1
trim_interval_hours = 168
scrub_interval_days = 30
```

The default limits should be conservative and configurable rather than compiled assumptions.

---

# 23. Observability

## 23.1 Metrics

### Import

```text
yourfs_import_objects_total{kind}
yourfs_import_objects_deduplicated_total{kind}
yourfs_import_raw_bytes_total
yourfs_import_stored_bytes_total
yourfs_import_compression_ratio
yourfs_import_duration_seconds
yourfs_chunk_sync_duration_seconds
yourfs_rocksdb_write_duration_seconds
```

### Cache

```text
yourfs_cache_hits_total
yourfs_cache_misses_total
yourfs_cache_hydration_bytes_total
yourfs_cache_hydration_failures_total{reason}
yourfs_cache_logical_bytes
yourfs_cache_candidate_eviction_bytes
yourfs_cache_corrupt_objects_total
```

### Checkout

```text
yourfs_checkout_duration_seconds
yourfs_checkout_files_total
yourfs_checkout_reflinks_total
yourfs_checkout_copy_fallback_total
yourfs_checkout_symlinks_total
yourfs_checkout_failures_total{reason}
yourfs_checkout_decompressed_bytes_total
```

A warm checkout should report:

```text
decompressed bytes = 0
copy-fallback bytes = 0
```

### Storage

```text
yourfs_host_free_bytes
yourfs_hot_image_logical_bytes
yourfs_hot_image_allocated_host_bytes
yourfs_btrfs_free_estimated_bytes
yourfs_btrfs_metadata_used_bytes
yourfs_open_chunk_bytes
yourfs_orphan_records
yourfs_stale_staging_workspaces
```

---

## 23.2 Structured logs

Example event:

```json
{
  "level": "INFO",
  "event": "workspace_published",
  "job_id": "…",
  "workspace_id": "…",
  "workspace_name": "project-a-main",
  "repo_id": "…",
  "snapshot_id": "…",
  "commit_oid": "sha1:…",
  "files": 182341,
  "cache_hits": 181700,
  "cache_misses": 641,
  "reflinks": 182341,
  "copied_files": 0,
  "duration_ms": 1432
}
```

Avoid logging source file contents, symlink targets, credentials, or unbounded raw paths.

---

# 24. Testing strategy

## 24.1 Unit tests

Test:

* OID encoding and decoding.
* Content ID domain separation.
* Record header/footer encoding.
* CRC validation.
* Chunk rotation.
* Oversized records.
* Recovery scanner boundaries.
* RocksDB key ordering.
* Git mode mapping.
* Path-component validation.
* Symlink policy.
* Workspace state transitions.
* Capacity calculations.
* Size overflow and checked arithmetic.

---

## 24.2 Property tests

Properties:

```text
decode(encode(value)) == value

Any byte sequence passed to the record decoder:
    never panics
    never allocates based on unchecked lengths
    either rejects or returns a bounded record

Any accepted checkout path:
    cannot resolve above staging root

Any completed record:
    scanner finds the same next offset

Any interrupted record prefix:
    scanner never indexes it as complete
```

---

## 24.3 Fuzzing

Fuzz:

* Chunk scanner.
* Record decoder.
* Git tree parser.
* Commit parser.
* Tag parser.
* zstd metadata boundaries.
* Path planner.
* Manifest parser.
* Daemon protocol.
* Recovery-state reconciliation.

Use corpus samples containing real and deliberately corrupted Git objects.

---

## 24.4 Privileged integration tests

Run in a VM or privileged Linux CI job:

```text
1. Create sparse ext4-hosted image.
2. Attach loop.
3. Format Btrfs.
4. Mount.
5. Create cache source.
6. FICLONE into workspace.
7. Modify workspace.
8. Verify cache source unchanged.
9. Delete cache source.
10. Verify workspace remains readable.
11. Unmount/remount.
12. Verify workspace and cache state.
13. Grow image.
14. Verify new Btrfs capacity.
15. Trim and inspect host allocation.
```

Do not rely solely on mocked ioctl tests.

---

## 24.5 Fault-injection tests

Insert failure points after every persistence boundary:

```text
after record header
mid-payload
after footer
before fdatasync
after fdatasync
before RocksDB write
after RocksDB WAL write
before cache rename
after cache rename
before workspace publish
after workspace publish
during replacement exchange
during subvolume deletion
during chunk seal
during GC generation switch
```

Terminate with `SIGKILL` or VM power interruption, restart, and assert invariants.

---

## 24.6 Repository compatibility corpus

Include repositories with:

* Empty blob.
* Many duplicate blobs.
* Millions of small files.
* Large binary blobs.
* Deeply nested trees.
* Non-UTF-8 filenames.
* Executable files.
* Symlinks.
* Absolute symlink targets.
* Escaping symlink targets.
* Submodules.
* Annotated tags.
* Shallow history.
* Alternates.
* Packed and loose objects.
* `.gitattributes`.
* CRLF conversion rules.
* Required filters.
* LFS pointer blobs.
* SHA-256 object format.
* Corrupt tree entries.
* Corrupt object payloads.
* Deliberate duplicate or conflicting paths.

---

## 24.7 Correctness comparison

For `raw` mode, compare each output against:

```text
Git tree mode
+
exact blob payload from the Git object database
```

Do not blindly compare against `git checkout`, because Git checkout may apply worktree transformations.

Assertions:

```text
regular file bytes == raw blob bytes
executable bit matches tree mode
symlink target bytes == blob bytes
no unrequested entries
no missing entries
no path escapes
```

---

## 24.8 Performance benchmarks

Compare:

```text
git checkout
git worktree add
cp -a
cp --reflink=always
yourfs cold checkout
yourfs warm checkout
yourfs repeated multi-workspace checkout
```

Workloads:

```text
small repository
large monorepo
many tiny files
few huge files
100 similar repositories
100 revisions of one repository
high-dedup generated source trees
low-dedup binary assets
```

Measure:

```text
wall time
CPU time
peak RSS
cold bytes read
cold bytes written
Btrfs bytes written
metadata operations
physical host-space increase
cache hit rate
p50/p95/p99 checkout latency
```

The key warm-checkout success criterion is not an arbitrary millisecond target. It is:

```text
No blob decompression.
No userspace payload copying.
Only directory, inode, and reflink metadata work.
```

---

# 25. Implementation milestones

## Milestone 0 — Architecture contracts and probes

Deliver:

* Architecture decision records.
* On-disk format v1.
* OID and content-ID definitions.
* FICLONE probe tool.
* Sparse-image experiment.
* Host/Btrfs capacity experiment.
* Trim propagation experiment.
* Git compatibility corpus.

Exit criteria:

* Reflink works from intended cache to workspace.
* Workspace mutation leaves source unchanged.
* Sparse image behavior is measured on supported host filesystems.
* Recovery format is frozen for the MVP.

---

## Milestone 1 — Cold object store

Deliver:

* Chunk writer.
* Chunk reader.
* Record codec.
* zstd compression.
* CRC and content digest.
* Rotation and sealing.
* RocksDB schema.
* Durable append/index protocol.
* Open-tail recovery.
* `store verify`.

Exit criteria:

* One million synthetic records survive repeated kill/restart testing.
* No RocksDB location can point to a partial record.
* Duplicate content does not append a second record.
* Oversized length values do not overflow.

---

## Milestone 2 — Complete Git import

Deliver:

* Git backend trait.
* libgit2 backend.
* Ref snapshot.
* Reachability traversal.
* Import of blob/tree/commit/tag objects.
* Repository snapshot manifests.
* Source-independence test.
* Partial/shallow repository policy.

Exit criteria:

* Delete the original repository after import.
* Resolve an imported tag and commit.
* Traverse its tree entirely from the cold store.
* Retrieve every expected blob.

---

## Milestone 3 — Btrfs orchestration

Deliver:

* Explicit initialization.
* Sparse/reserved image modes.
* Loop discovery and attachment.
* UUID verification.
* Mount and unmount helper.
* Directory/subvolume scaffolding.
* FICLONE probe.
* Image grow.
* Usage and trim diagnostics.

Exit criteria:

* Reboot simulation reattaches and mounts the correct image.
* Duplicate loop attachment is prevented.
* The tool never formats an unmarked existing path.
* `doctor` produces actionable diagnostics.

---

## Milestone 4 — Hot cache

Deliver:

* Fanout paths.
* Content-scoped singleflight.
* Chunk-range reads.
* Streaming decompression.
* Temporary-file publication.
* Hash verification.
* Cache reconciliation.
* Cache stats and verification.

Exit criteria:

* Concurrent hydration of the same object creates one final file.
* Kill during hydration leaves no accepted partial file.
* Corrupt cache files are detected and repaired.
* Missing cache files are lazily reconstructed.

---

## Milestone 5 — Raw reflink checkout

Deliver:

* Commit/tree resolver.
* Byte-safe checkout plan.
* Path and resource limits.
* Directory creation.
* Regular/executable files.
* Symlinks.
* Gitlink policy.
* FICLONE.
* Atomic staging publication.
* Workspace manifest and pinning.

Exit criteria:

* Output bytes and modes match raw Git object semantics.
* Warm checkout performs zero decompression.
* Modifying workspace A does not affect cache or workspace B.
* No incomplete workspace name becomes visible.

---

## Milestone 6 — Daemon and lifecycle

Deliver:

* Unix-socket API.
* Job model.
* CLI frontend.
* Privileged mount helper.
* Startup recovery.
* Graceful shutdown.
* Structured logs.
* Metrics.
* systemd units.

Exit criteria:

* Multiple CLI clients can submit safe concurrent jobs.
* Only one daemon owns the store.
* Restart repairs all intentionally injected intermediate states.
* Unprivileged users cannot invoke arbitrary mount-helper operations.

---

## Milestone 7 — Capacity, eviction, and GC

Deliver:

* Host and guest headroom policies.
* Cache high/low watermark eviction.
* Optional qgroups.
* Cold mark-and-compact GC.
* Generation reader leases.
* Repository deletion.
* Trim diagnostics.

Exit criteria:

* Cache pressure cannot consume the configured host reserve.
* Deleting a cache source does not break workspaces.
* GC preserves every pinned and referenced checkout.
* Old generations are deleted only after readers finish.

---

## Milestone 8 — Backup and production hardening

Deliver:

* Consistent checkpoint.
* Backup manifest.
* Restore workflow.
* Full verification.
* Scheduled scrub.
* Security review.
* Fuzzing.
* Fault-injection matrix.
* Upgrade and schema-migration process.

Exit criteria:

* Restore to a fresh machine produces valid checkouts without the original repositories.
* A full store verification reports no unaccounted objects or invalid locations.
* Format upgrade can be interrupted and resumed safely.

---

## Milestone 9 — Git-compatible transformation mode

Deliver:

* Attribute evaluation.
* EOL and encoding policy.
* Controlled filter execution.
* Transform cache IDs.
* LFS integration policy.
* Compatibility comparison against native Git.

Exit criteria:

* Transformation output matches documented Git behavior for the supported policy.
* External filters are isolated and explicitly authorized.
* Raw mode remains available and unchanged.

---

## Milestone 10 — Boot-target integration

Treat this as a security-sensitive deployment project, not a simple extension.

A boot target should identify:

```text
repository snapshot
exact commit
root-tree digest
checkout policy
manifest digest
signing identity
required kernel/filesystem capabilities
rollback target
```

Safe sequence:

```text
1. Resolve immutable target manifest.
2. Verify signature or local allowlist.
3. Materialize into a staging workspace.
4. Verify manifest and expected binaries.
5. Convert or snapshot into a read-only deployment subvolume.
6. Atomically switch the active deployment pointer.
7. Preserve the previous deployment for rollback.
8. Reboot or transition only after all verification succeeds.
```

Do not boot from a mutable developer workspace. Do not treat an arbitrary imported commit as trusted system state.

---

# 26. Final definition of done

The first production release should not be declared complete until all of the following are true:

1. An imported source repository can be removed and checkout still succeeds.
2. Commits, trees, tags, and blobs are stored or reproducibly indexed.
3. SHA-1 versus SHA-256 is explicit in every API and persistent key.
4. Internal deduplication uses a strong domain-separated content ID.
5. RocksDB never exposes a record before its chunk data is durable.
6. An interrupted open chunk is recovered without guessing.
7. Sparse-image creation uses logical truncation, not default `fallocate`.
8. Duplicate loop attachment is prevented.
9. The daemon verifies the exact Btrfs instance before mounting.
10. A runtime FICLONE probe passes.
11. Cache and workspace paths share one verified clone domain.
12. Cache hydration is atomic and content-verified.
13. Checkout construction is fd-relative and symlink-safe.
14. Raw mode precisely defines what Git semantics it does and does not reproduce.
15. A workspace appears only after complete materialization.
16. Workspace mutation cannot alter cache content.
17. Existing workspaces survive cache-source eviction.
18. Host and guest ENOSPC conditions are tested.
19. Kill/restart tests cover every persistence transition.
20. Backup and restore work without preserving the hot cache.
21. Metrics distinguish cold hydration, cache hits, reflinks, and fallback copies.
22. The mount helper has a minimal privileged interface.
23. Untrusted build execution is documented as requiring separate isolation.
24. Cold GC cannot collect objects pinned by active workspaces.
25. Every persistent format has a version and migration policy.

This revised architecture preserves the original advantage—fast, extent-sharing workspaces—while giving it the durability, compatibility, recovery, and security boundaries required for a real system rather than a proof of concept.

[1]: https://man7.org/linux/man-pages/man2/ioctl_ficlone.2.html "https://man7.org/linux/man-pages/man2/ioctl_ficlone.2.html"
[2]: https://man.archlinux.org/man/fallocate.2.en "https://man.archlinux.org/man/fallocate.2.en"
[3]: https://git-scm.com/docs/user-manual "https://git-scm.com/docs/user-manual"
[4]: https://github.com/libgit2/libgit2 "https://github.com/libgit2/libgit2"
[5]: https://git-scm.com/docs/gitattributes "https://git-scm.com/docs/gitattributes"
[6]: https://git-scm.com/docs/git-fast-import/2.21.0 "https://git-scm.com/docs/git-fast-import/2.21.0"
[7]: https://github.com/facebook/rocksdb/wiki/Transactions "https://github.com/facebook/rocksdb/wiki/Transactions"
[8]: https://btrfs.readthedocs.io/en/latest/btrfs-man5.html "https://btrfs.readthedocs.io/en/latest/btrfs-man5.html"
[9]: https://btrfs.readthedocs.io/en/latest/Subvolumes.html "https://btrfs.readthedocs.io/en/latest/Subvolumes.html"
[10]: https://docs.rs/git2/latest/git2/struct.Odb.html "https://docs.rs/git2/latest/git2/struct.Odb.html"
[11]: https://man7.org/linux/man-pages/man2/fsync.2.html "https://man7.org/linux/man-pages/man2/fsync.2.html"
[12]: https://man7.org/linux/man-pages/man8/losetup.8.html "https://man7.org/linux/man-pages/man8/losetup.8.html"
[13]: https://btrfs.readthedocs.io/en/latest/Reflink.html "https://btrfs.readthedocs.io/en/latest/Reflink.html"
[14]: https://man7.org/linux/man-pages/man2/openat2.2.html "https://man7.org/linux/man-pages/man2/openat2.2.html"
[15]: https://docs.rs/rustix/latest/src/rustix/fs/ioctl.rs.html "https://docs.rs/rustix/latest/src/rustix/fs/ioctl.rs.html"
[16]: https://man7.org/linux/man-pages/man2/rename.2.html "https://man7.org/linux/man-pages/man2/rename.2.html"
[17]: https://btrfs.readthedocs.io/en/latest/btrfs-filesystem.html "https://btrfs.readthedocs.io/en/latest/btrfs-filesystem.html"
[18]: https://btrfs.readthedocs.io/en/latest/Qgroups.html "https://btrfs.readthedocs.io/en/latest/Qgroups.html"
[19]: https://btrfs.readthedocs.io/en/latest/Scrub.html "https://btrfs.readthedocs.io/en/latest/Scrub.html"
