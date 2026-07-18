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
cargo +nightly fuzz run codec_decode -- -max_total_time=60 -rss_limit_mb=512 -timeout=5
cargo +nightly fuzz run open_chunk_recovery -- -max_total_time=60 -rss_limit_mb=512 -timeout=5
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

Targets exercise bounded parser, codec, and recovery paths:

* `format_decode` covers v1 chunk headers and structural object-record parsing.
* `codec_decode` covers bounded Zstd frame decoding, decoded-length and
  ContentId validation, truncation, and trailing-data rejection.
* `open_chunk_recovery` writes a valid header plus a bounded arbitrary tail,
  then covers public open-tail recovery followed by strict verification.
* `snapshot_manifest_decode` covers snapshot-manifest v1.
* `backup_decode` covers authenticated backup manifests and cold-tier
  checkpoint descriptors.

The scheduled/release CI campaign runs every target for a fixed 120 seconds,
with a 512 MiB libFuzzer RSS cap and a five-second per-input timeout. It does
not run on pull requests; normal CI retains deterministic malformed-byte tests.
