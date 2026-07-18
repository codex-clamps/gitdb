# Reflink Forest operational safety contracts

This document defines the operating constraints for phases M2–M8. It is a
safety contract, not a replacement for the phase-specific implementation and
test plans.

## Initialization and mount contract

`reflink-forest init` is the only operation allowed to create or format a
loopback Btrfs image. It must use create-new semantics, reject symlinks and
non-regular image files, write a generated instance marker, and record the
expected Btrfs UUID and label. A mount failure must never trigger formatting.

At startup, the mount helper must hold the instance lock, identify an existing
loop association by canonical backing file, or attach one with overlap
prevention. It verifies the backing file, Btrfs UUID, label, instance marker,
and configured mountpoint before use. Loop numbers are transient and are never
the persistent identity.

The cache, staging area, and workspaces must be reachable through one verified
Btrfs root mount. The daemon runs a real FICLONE probe between the intended
cache and staging paths at startup, verifies copy-on-write isolation, and fails
closed unless an explicitly requested copy-fallback policy permits operation.

The mount helper has a fixed protocol for its configured image and mountpoint.
It accepts no caller-supplied device, path, UID, GID, or shell command; it does
not parse Git data, decompress objects, or construct checkout paths.

## Per-user daemon contract

Multi-user deployments use one Reflink Forest instance per Unix user, as
defined in ADR 0002. Each instance has a user-owned state root, runtime socket,
cold catalog, Btrfs materialization root, cache, and workspaces. The socket
accepts only the owning user; no cross-user workspace visibility, ownership
delegation, or shared workspace API exists in the MVP.

The unprivileged daemon owns the store catalog, imports, hydration, checkout,
and workspace creation. Its workspace owner is the instance owner, never an
arbitrary socket peer. A root-owned helper, when needed for mounting, does not
grant ownership-changing capability to the daemon or client.

Startup is serialized by an instance lock and performs, in order: configuration
and permission validation; mount identity verification; FICLONE probe; catalog
open; open-chunk recovery; cache, staging, workspace, and job reconciliation;
then request acceptance. Shutdown first stops new mutating work, reaches safe
job checkpoints, synchronizes according to the selected durability mode, and
only unmounts when the instance has no required users.

## GC generation and reader-lease contract

Cold GC is generation based. It never rewrites an active chunk in place.

1. The compactor creates generation N+1 and scans N sequentially.
2. It copies and verifies live records into N+1 and builds shadow locations.
3. It synchronizes every new chunk.
4. It commits N+1 locations and `current_generation` in one synchronous
   catalog batch.
5. It writes or repairs the derived active-generation manifest after that
   catalog commit.
6. It stops admitting new leases for N, waits for current N leases to drain,
   marks N retired, and only then removes N's chunks.

A reader lease is acquired before opening a generation and released only after
the reader has closed all corresponding chunk descriptors. Lease ownership is
tracked in process and reconciled at daemon restart; a restarted daemon has no
live old-process leases. A failed or interrupted compaction leaves N
authoritative until the catalog switch is durable. An external manifest alone
can never select a generation.

All Ready repository snapshots, workspace pins, explicit pins, retained
snapshots, boot-target manifests, and active jobs are GC roots. Repository
deletion removes visibility and aliases first but leaves shared object records
for a later mark-and-compact pass.

## Checkpoint, backup, and restore contract

The authoritative backup set is sealed chunks, the valid prefix of the open
chunk, a consistent RocksDB checkpoint, repository/workspace manifests and
pins, configuration, and schema metadata. The hot cache, parsed metadata,
temporary jobs, and ephemeral workspaces are derived state and are not
required for restore.

A checkpoint pauses only the append writer long enough to finish and
synchronize its active batch, records the open chunk's valid length, creates a
RocksDB checkpoint, and writes a synchronized backup manifest. The manifest
names chunk generations, sealed chunk sizes, the open valid prefix, checkpoint
identity, schema version, and manifest digests. Writers may resume before
immutable chunks are copied.

Restore copies the recorded chunks and catalog/checkpoint, validates their
schema, performs full structural verification, and either restores the catalog
or rebuilds it from chunks. It initializes a fresh verified Btrfs image and
lazily recreates cache objects. Persistent mutable workspaces are restored only
from a separate workspace snapshot/export policy; they are never implied by a
cold-tier backup.

Any failed backup or restore leaves its target marked incomplete and unusable
until verification passes. Operators must test restoration on a separate
machine or isolated target before relying on a backup policy.

## Capacity, integrity, and incident handling

Before import, checkout, image growth, or GC compaction, the daemon checks both
host free space and Btrfs data/metadata headroom against configured reserves.
It reports ENOSPC, EDQUOT, I/O, and reflink-domain failures distinctly. Cache
eviction can reclaim cache inodes but cannot promise immediate host-image block
reclamation; trim capability is measured and reported by `doctor`.

`store verify --quick` checks structural data; a full verification additionally
decompresses every record and validates ContentIds and repository-scoped native
aliases. Cache corruption is quarantined or deleted and regenerated. Btrfs
scrub detects hot-tier corruption, but a single-device image may not repair it;
mutable workspace recovery requires its separate backup policy.

## Explicit non-goals

These contracts do not provide:

* Remote fetch, push, or full Git worktree behavior.
* Git filters, LFS download, attribute transformations, or arbitrary external
  command execution.
* A security sandbox for untrusted builds or repository code.
* Cross-user cache sharing, workspace sharing, arbitrary ownership changes, or
  a general privileged filesystem API.
* In-place Btrfs image shrinking, automatic formatting after errors, or a
  promise that cache deletion immediately returns host filesystem space.
* Booting arbitrary imported commits without a separately verified deployment
  and trust policy.

