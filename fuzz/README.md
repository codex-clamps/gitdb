# Reflink Forest decoder fuzzing

This is a conventional, opt-in [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
project. It is excluded from the root Cargo workspace, so ordinary builds and
CI do not compile `libfuzzer-sys` or require a fuzzing toolchain.

Install a nightly toolchain and the runner once, then run a target from the
repository root:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo +nightly fuzz run format_decode -- -max_total_time=60
cargo +nightly fuzz run snapshot_manifest_decode -- -max_total_time=60
cargo +nightly fuzz run backup_decode -- -max_total_time=60
```

The checked-in `corpus/` files are deliberately malformed deterministic seeds.
They complement the ordinary deterministic decoder corpus tests; libFuzzer
mutates them into short headers, invalid lengths, count fields, checksums, and
trailing data. Keep minimized crash reproducers in the matching corpus
directory after confirming they contain no sensitive data. Generated crash
artifacts, coverage reports, target output, and the local fuzz lockfile are
ignored.

Targets exercise only in-memory decoders:

* `format_decode` covers v1 chunk headers and object records.
* `snapshot_manifest_decode` covers snapshot-manifest v1.
* `backup_decode` covers authenticated backup manifests and cold-tier
  checkpoint descriptors.
