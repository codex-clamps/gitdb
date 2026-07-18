# Reflink Forest implementation plan

This is the executable delivery order for the roadmap. Complete a phase only
when its acceptance tests pass in CI; do not begin a dependent phase with a
weaker durability or format contract.

## Working rules

* The public name is **Reflink Forest**; follow ADR 0001 for identifiers.
* Persistent data follows [format v1](format-v1.md). A format change requires
  a versioned migration design before implementation.
* Keep untrusted Git parsing, decompression, and checkout logic unprivileged.
* Each phase owns its tests and fault-injection points. Tests must exercise
  public crate APIs rather than private implementation details where possible.

## Phase M0 — contracts and environmental probes

**Goal:** remove environment and design uncertainty before durable storage is
implemented.

1. Keep the ADRs and format-v1 contract reviewed and version-controlled.
2. Implement the `reflink-forest-probe` checks for filesystem type, clone
   domain, FICLONE success, and copy-on-write isolation.
3. Run the sparse-image, Btrfs capacity, and trim-reclamation experiments on
   each supported host filesystem; save measured results as CI artifacts or
   operator documentation.
4. Create a compatibility corpus fixture layout, even if the Git importer is
   not yet implemented.

**Exit gate:** the probe proves that the intended cache and workspace paths can
reflink and that mutating the destination leaves the source unchanged. The
format, canonical name, and per-user ownership assumptions are accepted before
the first durable write.

## Phase M1 — cold object store

**Goal:** provide a crash-recoverable, content-addressed store independent of
Git repository traversal and Btrfs materialization.

### Build sequence

1. In `reflink-forest-core`, add bounded identifier, length, checksum, codec,
   and error primitives. Use checked arithmetic for every encoded length and
   offset.
2. Add a format crate/module with v1 chunk-header, record-header, footer, and
   sealed-chunk codec. Decoders must reject unknown required versions,
   malformed lengths, and invalid CRCs before allocation or decompression.
3. Add a catalog crate/module with the v1 column-family names and versioned key
   encoders. Implement `object_locations`, repo-scoped `oid_aliases`, chunk
   state, and `meta` first.
4. Implement one serialized append/index writer. Readers and compressors may
   be parallel later, but only the writer appends and performs the location
   recheck.
5. Implement append -> `fdatasync` -> synchronous RocksDB WriteBatch in
   durable mode. Expose balanced/ephemeral behavior only after durable mode is
   correct.
6. Implement rotation, sealing, and startup scanning. Recovery truncates an
   open chunk only to the last structurally complete record.
7. Implement `store verify` with quick, full, rebuild-index, and
   repair-open-tail modes. The first CLI surface may be a test-only harness;
   its semantics must match the final command.

### M1 acceptance tests

The M1 CI suite must include the following named cases. Each is deterministic
and uses temporary directories; crash tests restart a fresh store process or
store instance rather than reusing in-memory state.

| Test | Required assertion |
| --- | --- |
| `record_round_trip_raw_and_zstd` | Raw and zstd records decode to the exact input, kind, ContentId, and lengths. |
| `decoder_rejects_untrusted_lengths` | Truncated, overflowing, and oversized length fields return an error without panic or unbounded allocation. |
| `crc_and_content_id_detect_corruption` | Independent header, payload, footer, and decompressed-payload corruption are detected. |
| `dedupe_reuses_content_location` | Reimporting identical content creates one record/location while adding valid repo-scoped aliases. |
| `conflicting_repo_alias_fails` | One repo-scoped native OID mapping to different content is rejected. |
| `index_never_precedes_durable_record` | Injected failure before chunk sync or before catalog commit cannot leave a location pointing at a partial record after restart. |
| `open_tail_recovery` | A crash after each record-write boundary retains complete valid records and drops only the invalid tail. |
| `orphan_record_is_safe` | A crash after chunk sync but before catalog commit leaves an unindexed valid record; recovery either reports it or safely rebuilds its index. |
| `seal_recovery_is_idempotent` | Crashes before and after rename/directory sync reconcile `.open` and `.sealed` states without duplicate visibility. |
| `rotation_never_splits_record` | Target-size rotation and an oversized record preserve record boundaries and use a dedicated oversized chunk. |
| `verify_rebuilds_catalog` | Deleting the catalog's location data and scanning valid chunks reconstructs equivalent locations and passes full verification. |
| `million_record_soak` | A release-profile, opt-in CI job writes one million synthetic records, repeatedly interrupts/restarts at deterministic boundaries, then completes full verification. |

**M1 exit gate:** all normal tests run on every change; the soak test runs on
main/nightly or before a release. Full verification succeeds after every
fault-injection scenario. No catalog location references a partial, invalid, or
unsynchronized record.

The concrete soak gate is the ignored
`reflink-forest-store/tests/million_record_soak.rs` integration test. It only
runs in release mode with `REFLINK_FOREST_RUN_MILLION_RECORD_SOAK=1`; invoke it
locally with `cargo test --release -p reflink-forest-store --test
million_record_soak million_record_soak -- --ignored --exact`. CI enables that
environment only for protected `main` pushes, the nightly schedule, and
published releases.

## Phase M2 — Git import and immutable snapshots

Implement the backend trait, local libgit2 backend, ref snapshot, reachability
walk, and import of blobs, trees, commits, and tags. Publish only complete
snapshots; represent incomplete best-effort imports as `Incomplete`, never
`Ready`. Acceptance: delete the source repository, resolve a retained tag and
commit, traverse its tree from the cold store, and retrieve every required blob.

## Phase M3 — Btrfs materialization domain

Implement explicit initialization, loopback/native Btrfs backends, instance and
UUID checks, mount helper, directory/subvolume topology, image growth, and
doctor diagnostics. Run privileged integration tests in a VM. Acceptance:
reboot-style reattachment works, duplicate loop attachment is prevented, and
no existing unmarked path can be formatted.

## Phase M4 — derived hot cache

Implement fanout paths, content-scoped singleflight, chunk range reads,
streaming decode, temporary-file publication, verification, and reconciliation.
Acceptance: concurrent hydration publishes one valid final file; interrupted
or corrupt cache files are never accepted and are recoverable from cold data.

## Phase M5 — raw checkout

Implement byte-safe tree planning, fd-relative construction, resource limits,
regular files, executable bits, symlinks, explicit gitlink policy, FICLONE,
atomic staging publication, and workspace pins. Acceptance: raw bytes and
modes match Git-object semantics; warm checkout performs no decompression; no
partial workspace becomes visible.

## Phase M6 — daemon and operations

Add the per-user daemon/socket model from ADR 0002, jobs, startup recovery,
maintenance, metrics, structured logs, and the fixed-purpose mount helper.
Acceptance: concurrent clients are safe, only one instance owns its store, and
restart reconciles every injected intermediate state.

## Phase M7 — capacity and garbage collection

Add host/guest reserves, cache eviction, optional qgroups, mark-and-compact
cold GC, reader leases, repository deletion, and trim diagnostics. Commit new
locations and current generation together as specified by format v1.
Acceptance: GC preserves all pins, old generations wait for readers, and cache
pressure cannot consume the configured reserve.

## Phase M8 — backup and production hardening

Implement checkpoints, backup manifests, restore, scrub scheduling, fuzzing,
security review, full fault matrix, and resumable upgrades. Acceptance: restore
on a fresh machine produces valid checkouts without original repositories.

## Explicit deferrals

The following are not M1 work and must not expand its API or durability scope:

* Git graph traversal, local-repository import, SHA-256 production support,
  partial/shallow/promisor handling, and any network fetch.
* Loop devices, Btrfs images, FICLONE, cache hydration, checkout, workspaces,
  or a daemon/socket protocol.
* Git worktree transforms: attributes, EOL conversion, filters, LFS, and
  git-compatible checkout mode.
* Submodule recursion, boot-target deployment, process/build isolation,
  cross-user shared workspaces, delegated ownership, and arbitrary `chown`.
* Cold-store GC/compaction, backup/restore, quota enforcement, cache eviction,
  image shrinking, performance tuning, and automatic online migration.

These are deferred because they add independent persistence, privilege,
compatibility, or operational contracts. They may be prototyped only behind
test-only interfaces that do not alter the M1 durable format or acceptance
criteria.
