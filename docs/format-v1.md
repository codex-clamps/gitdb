# Reflink Forest on-disk format v1

This document defines the durable-format contract for the MVP. It covers the
cold tier, its RocksDB catalog, and published manifests. The hot cache and
workspaces are derived state and are intentionally not part of the backup
format.

## Compatibility contract

Every persistent value begins with a format version. A v1 reader must reject
unknown required versions and preserve unknown optional fields when rewriting a
record. A writer must not emit a newer version unless the configured migration
has completed successfully.

Format migrations are resumable jobs. They write new files or generations,
validate them, durably publish a migration marker, then atomically make the new
catalog state active. Startup either resumes the recorded migration or uses the
last fully published state; it never guesses from partially written output.

## Identifiers and encodings

All integer fields use unsigned big-endian encoding unless a table says
otherwise. Strings used as paths or Git names are byte sequences, not UTF-8
strings. Fixed identifiers are encoded as their raw bytes.

* `ContentId`: 32 bytes, computed as
  `SHA-256("reflink-forest-object-v1\\0" || object_kind || raw_length_be || raw_payload)`.
* `GitOid`: algorithm byte, length byte, then 32 bytes with unused trailing
  bytes set to zero. Supported algorithms are SHA-1 (20 bytes) and SHA-256
  (32 bytes).
* `RepoId`, `RepoSnapshotId`, and `WorkspaceId`: 16-byte generated IDs.

`ContentId` is the global deduplication key. Native Git aliases are always
repo-scoped: `RepoId || algorithm || oid_length || oid_bytes`.

## Chunk files

Chunks live under `chunks/generation-<N>/`. At most one `.open` chunk has a
writer in a generation; `.sealed` chunks are immutable.

The 64-byte chunk header contains, in order:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 8 | magic `RFSCHNK\\0` |
| 8 | 2 | format version (v1) |
| 10 | 2 | header length |
| 12 | 4 | generation |
| 16 | 8 | chunk ID |
| 24 | 8 | creation timestamp |
| 32 | 4 | flags |
| 36 | 4 | header CRC32C |
| 40 | 24 | reserved, zero |

Each object record is independently readable and padded to an 8-byte boundary:

```text
RecordHeader: magic "ROBJ", version, header length, kind, codec, flags,
              raw length, stored length, ContentId, primary GitOid,
              header CRC32C, reserved bytes
Payload:      stored length bytes (raw or one independent zstd frame)
RecordFooter: payload CRC32C, total record length, magic "RENDOBJ\\0"
Padding:      zero to the next 8-byte boundary
```

Codec `0` is raw and codec `1` is one independent Zstd frame. V1 Zstd writers
use a bounded 2^23-byte history window and a frame checksum; readers reject a
larger window, concatenated frames, trailing compressed bytes, a decoded length
other than `raw length`, or raw bytes that do not recompute to the record's
`ContentId`. Unknown codec tags are required fields and fail closed before
decompression.

All lengths and offsets are `u64`. A scanner validates bounds, header CRC,
footer, total length, and payload CRC before accepting a record. A full
verification additionally decompresses the payload and recomputes its
`ContentId`. A primary OID is diagnostic metadata; alias verification is
performed from the catalog for every repository-scoped alias.

The only valid tail of an open chunk is a sequence of complete records. During
recovery, truncate at the first incomplete or invalid trailing record. A sealed
chunk ends with this fixed 64-byte footer:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 8 | magic `RFSSEAL\\0` |
| 8 | 2 | format version (v1) |
| 10 | 2 | footer length (64) |
| 12 | 8 | complete record count |
| 20 | 8 | final file length, including this footer |
| 28 | 4 | CRC32C of the exact encoded record stream |
| 32 | 4 | footer CRC32C, with this field zeroed while calculating |
| 36 | 28 | reserved, zero |

The record-stream CRC covers every complete encoded record, including its
alignment padding, and excludes both the chunk header and this footer. A sealed
reader validates the footer CRC, final length, every record boundary, the count,
and this rolling CRC before treating the chunk as immutable. A complete valid
footer under an `.open` name is an interrupted rename, not an open-tail record:
startup finishes the rename and publishes sealed metadata. A partial or invalid
footer is discarded as an invalid open tail.

## Commit and publication rules

For new records, append complete records, `fdatasync` the chunk, then write the
corresponding RocksDB `WriteBatch`. Durable mode uses synchronous RocksDB
writes. The catalog must never reference bytes that were not synchronized.

Creating an open chunk writes and synchronizes its header, synchronizes the
parent directory, and then publishes its `Open` metadata. Sealing writes and
synchronizes the chunk footer, renames `.open` to `.sealed`, synchronizes its
directory, then records the sealed state in RocksDB. Startup reconciles these
steps idempotently: a verified `.sealed` file republishes its sealed metadata,
and a complete footer in an `.open` file completes the rename before metadata is
published.

Rotation happens only before a complete record. The configured target includes
the header and sealed footer; a record that cannot fit in an otherwise empty
target-sized chunk is written to and immediately sealed in its own oversized
chunk.

Repository and workspace manifests are written to a temporary file, synced,
renamed into place, and followed by a parent-directory sync before their Ready
catalog state is committed. A visible manifest without a Ready entry is
reconciled at startup; a Ready entry without a valid manifest is not usable.

## RocksDB catalog v1

Column families are: `object_locations`, `oid_aliases`, `repositories`,
`repo_snapshots`, `refs`, `chunks`, `cache_objects`, `workspaces`,
`workspace_names`, `pins`, `jobs`, and `meta`.

All keys and values begin with a one-byte format version. `object_locations`
maps `ContentId` to generation, chunk ID, offset, record/stored/raw lengths,
object kind, codec, flags, and payload CRC. `meta` records the schema version,
current generation, writer state, and migration state.

Generation compaction creates a new generation and shadow locations first.
New chunks are synchronized, then the new locations and `current_generation`
are committed together in one synchronous RocksDB batch. Only after that batch
is durable may a generation manifest be published as active. Startup treats the
catalog batch as authoritative and can regenerate a missing manifest; it never
selects a generation solely because an external manifest exists.

## Manifest v1 minimum fields

A repository snapshot manifest includes schema version, repository and snapshot
IDs, native object format, selected refs and OIDs, import policy, object counts,
byte totals, timestamp, tool version, and optional attestation metadata.

A workspace manifest includes schema version, workspace and snapshot IDs,
commit or tree ID, checkout policy, creation timestamp, materialization counts,
reflink/copy-fallback results, and the pin needed by cold GC.

Unknown optional manifest fields must be preserved by tools that rewrite a
manifest. Unknown required fields or incompatible schema versions fail closed.
