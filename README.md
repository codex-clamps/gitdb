# Reflink Forest

Reflink Forest is a local, content-addressed Git object store designed to
publish complete raw Git workspaces that share Btrfs extents with a derived
cache. It is intentionally not a Git worktree implementation or a process
sandbox.

The project is in active construction. The current focus is **M1: the durable
cold object store**. Git graph import, Btrfs orchestration, cache hydration,
and checkout remain staged behind the M1 durability gate.

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
```

The runtime clone-domain probe must be run against the planned Btrfs cache and
workspace directories, not merely any two paths:

```sh
cargo run -p reflink-forest-probe -- /path/to/cache /path/to/workspaces
```

`ficlone: supported` means the probe successfully cloned a file and verified
that mutating the destination did not alter the source. Any error means that
pair of directories is not usable as a Reflink Forest clone domain.
