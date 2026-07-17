# Changelog

All notable changes are documented here. The format follows Keep a Changelog,
and releases follow Semantic Versioning.

## [Unreleased]

### Added

- Initial RAP v1 specification, threat model and security model.
- Rust workspace quality and contribution policy.
- Bounded, portable RAP v1 protocol types and path validation.
- Canonical bounded RAP v1 binary and textual codec.
- Domain-separated incremental BLAKE3 integrity primitives.
- Bounded native and WebAssembly Zstandard decompression.
- Ed25519 verification with explicit publisher channel and key status policy.
- Deterministic artifact packager with canonical ordering and file digests.
- Typestate signing and verification pipeline with byte-exact reconstruction.
- Read-only `inspect`, `verify`, `diff`, `doctor` and completion CLI commands.
- Capability-confined, journaled and recoverable filesystem transactions.
- Confirmed/dry-run capsule application and transaction recovery CLI commands.
- Property tests, fuzz corpus and scheduled Miri, mutation and supply-chain checks.
- Browser-safe unsigned packing and structural inspection WebAssembly exports.
- Restricted deterministic and environment-backed development signing adapters.
- Cross-platform dist releases with checksums, SBOMs, attestations and complete usage documentation.
- Published LCOV and Criterion quality baselines for coverage and performance regression review.
