# Reflink Forest security review

This review records the security boundaries enforced by the M2–M8 code. It is
updated with every persistent-format or privilege-boundary change.

## Trust boundaries

* Git object data, tree names, refs, snapshot manifests, cache leaves, backup
  manifests, and socket command fields are untrusted input.
* The cold-store writer, catalog, Btrfs mount root, cache, staging area, and
  workspace namespace are owned by one Unix user. They are not a sandbox for
  builds or imported repository code.
* A privileged loop/mount helper is restricted to a preconfigured backing
  image, mountpoint, UUID, label, and fixed command plans. It accepts no
  client-supplied device, path, UID/GID, shell text, Git data, or checkout
  path.

## Implemented controls

| Area | Control | Evidence |
| --- | --- | --- |
| Cold records | Versioned decoders validate lengths, CRCs, record boundaries, and ContentIds before use. | `reflink-forest-format`, `reflink-forest-store` tests |
| Git paths | Tree components reject NUL, `/`, `.`, `..`, and bounded-limit violations. | `reflink-forest-checkout` planning tests |
| Checkout construction | Materialization uses fd-relative `openat`/`mkdirat`/`symlinkat` with `O_NOFOLLOW`; a hostile symlink substitution test proves no escape from staging. | `reflink-forest-checkout` |
| Btrfs identity | Initialization is create-new; markers bind instance UUID, filesystem UUID, and label; roots and backing files reject symlinks. | `reflink-forest-btrfs` |
| Clone domain | Startup probe runs real FICLONE then verifies copy-on-write isolation. | `probe_clone_domain` test |
| Cache | Cache files are ContentId-addressed, verified, opened without following symlinks, atomically published, and safely quarantined/reconciled. | `reflink-forest-cache` |
| Daemon | Runtime/state roots require owner-only permissions; sockets check peer UID; command parsing is strict and byte fields are hex encoded. | `reflink-forest-daemon` |
| Durable metadata | Snapshot, workspace, job, backup, and catalog records are versioned and fail closed for malformed/unknown required data. | crate-level tests |
| Backup/restore | Manifests and cold-tier descriptors are checksummed; restoration verifies before publication and never overwrites a destination. | `reflink-forest-backup` |
| Decoder hardening | The record parser, Zstd codec, open-tail recovery, snapshot-manifest, backup-manifest, and cold-descriptor decoders run deterministic malformed-byte tests in normal CI. Bounded `cargo-fuzz` campaigns mutate checked-in seeds on nightly and published-release CI only: 120 seconds/target, 512 MiB RSS, and five seconds/input. Length/count fields are bounded before decoded collection allocation. | `untrusted_*_fuzz_corpus_*` tests; [`fuzz/`](../fuzz/README.md) |

## Residual risks and operational requirements

* Loop attachment, Btrfs formatting, mounting, subvolume operations, and
  image growth require a dedicated privileged VM test runner. Ordinary CI and
  developer processes must not receive those capabilities.
* FICLONE support is a runtime property. The daemon must perform the probe on
  its configured cache and staging roots at every startup and fail closed
  unless copy fallback is explicitly selected.
* Reflink Forest intentionally does not execute Git filters, LFS clients, or
  imported repository commands. Operators who execute builds in a workspace
  must provide their own process sandboxing and network policy.
* Backups protect the cold tier, manifests, pins, configuration, and catalog
  checkpoint. Mutable workspace content needs an explicit snapshot/export
  policy.
