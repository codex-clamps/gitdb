# ADR 0001: Canonical product name is Reflink Forest

Status: Accepted

## Context

The architecture material refers to both “Reflink Forest” and `yourfs`.
Using both as public names makes commands, configuration, file paths, and
support documentation ambiguous.

## Decision

The canonical public product name is **Reflink Forest**.

Use `reflink-forest` for package, service, configuration-root, and on-disk
branding where a stable identifier is required. Use `reflink-forest` as the
CLI name unless a platform packaging constraint requires an explicit alias.
`yourfs` is a historical placeholder and must not appear in new user-facing
documentation, examples, protocol names, or persistent-format magic values.

Internal Rust crate names may use a short `rf-*` prefix when that is clearer,
but must document their relationship to Reflink Forest.

## Consequences

Existing roadmap references require a coordinated rename before implementation.
Persistent v1 format identifiers use the `reflink-forest` namespace from their
first release; changing that namespace later requires a format migration.

