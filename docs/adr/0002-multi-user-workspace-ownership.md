# ADR 0002: Per-user daemon instances own multi-user workspaces

Status: Accepted

## Context

Workspaces may be requested by different local users, but the main daemon is
intentionally unprivileged. An unprivileged shared daemon cannot safely `chown`
new files to arbitrary callers, and a shared mount exposes avoidable
name-discovery and authorization complexity.

## Decision

Reflink Forest uses **one daemon instance per Unix user** for multi-user
deployments. Each instance has a user-owned runtime socket, state directory,
cache, and Btrfs materialization root. Its workspaces are owned by that same
user; no cross-user workspace access is provided by the MVP.

A system-wide deployment may provide a root-owned mount helper only for the
fixed, configured image and mountpoint of an instance. The helper performs no
checkout, Git parsing, path handling, or arbitrary ownership changes. It does
not accept caller-supplied paths, devices, UIDs, or GIDs.

Shared-store or delegated-ownership deployments are deferred. They require a
separate ADR defining authorization, mount namespaces or equivalent isolation,
quota semantics, audit logging, and a narrowly validated ownership operation.

## Consequences

The workspace `owner = caller` policy means the instance owner, not an
arbitrary Unix-socket peer. The daemon can create all workspace files without
privilege escalation. Per-user instances duplicate hot-cache metadata and may
lose cross-user warm-cache sharing, but preserve the cold-tier architecture and
avoid a privileged ownership API in the MVP.

