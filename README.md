# Reflink Forest

Reflink Forest is a local, content-addressed Git object store designed to
publish complete raw Git workspaces that share Btrfs extents with a derived
cache. It is intentionally not a Git worktree implementation or a process
sandbox.

The project is in active construction. The durable cold-store foundation is
complete, and the current work covers the M2–M8 operational path: offline Git
snapshots, verified Btrfs materialization, cache hydration, raw workspaces,
daemon recovery, capacity controls, and cold-tier checkpoints. Privileged
loop/mount fault injection remains gated to a dedicated Btrfs VM.

## Project contracts

* [Architecture roadmap](description.md)
* [Format v1](docs/format-v1.md)
* [Implementation plan](docs/implementation-plan.md)
* [Naming decision](docs/adr/0001-canonical-product-name.md)
* [Workspace ownership decision](docs/adr/0002-multi-user-workspace-ownership.md)

## Build and test

```sh
cargo fmt --check
cargo test --workspace
cargo test -p reflink-forest-index --features rocksdb-backend
```

The runtime clone-domain probe must be run against the planned Btrfs cache and
workspace directories, not merely any two paths:

```sh
cargo run -p reflink-forest-probe -- /path/to/cache /path/to/workspaces
```

`ficlone: supported` means the probe successfully cloned a file and verified
that mutating the destination did not alter the source. Any error means that
pair of directories is not usable as a Reflink Forest clone domain.

The real loopback Btrfs lifecycle test is deliberately ignored. It creates and
formats a disposable image, so run it only on a dedicated VM as root with
`CAP_SYS_ADMIN` and loop-device support:

```sh
REFLINK_FOREST_RUN_PRIVILEGED_BTRFS_TESTS=1 \
  cargo test -p reflink-forest-btrfs --test privileged_loopback -- --ignored
```
