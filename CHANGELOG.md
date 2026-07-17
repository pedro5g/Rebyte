# Changelog

All notable changes are documented here. The format follows Keep a Changelog,
and releases follow Semantic Versioning.

## [Unreleased]

### Added

- Canonical `ra1_`/`.rba` unsigned artifacts for exact files and portable
  directory trees, including empty directories, executable bits and optional
  untrusted name/destination hints.
- Deterministic fast, balanced and maximum compression profiles.
- Optional bounded Zstandard dictionary training for similar multi-file
  artifacts, retained only after a complete-size comparison.
- Bounded streaming `.rba` encoding and transactional reconstruction for
  inputs up to the explicit large-artifact policy, without full-file memory
  allocation.
- `--limits large` support for binary `encode`, `decode` and streaming `hash`.

### Fixed

- Preserve extremely compressible payloads instead of rejecting them during
  encoding because their beneficial ratio exceeded a decoder policy.

## [1.1.0] - 2026-07-16

### Added

- Canonical `rf1_` unsigned single-file tokens with automatic bounded
  Zstandard compression, embedded RAP file digest and byte-exact decoding.
- Stable `encode_file_token` and `decode_file_token` Rust APIs through
  `rebyte-core`.
- `encode` and `decode` CLI workflows for files, stdin, token files and stable
  JSON reports without key management.
- `shell-env` generation for Fish, Bash, Zsh and PowerShell.
- Immutable vectors, property tests, large-text integration coverage and a
  dedicated file-token fuzz target.

### Fixed

- Close Windows transaction directory handles before cleanup and propagate
  cleanup failures, preventing partially removed journals from surfacing as
  `Io(NotFound)`.

## [1.0.0] - 2026-07-16

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
- Encrypted Argon2id/XChaCha20-Poly1305 local publisher-key documents.
- Production `key`, `pack` and domain-separated `hash` CLI workflows.
- External public trust documents, key rotation and explicit revocation status.
- Stable terminal help, version output, styled human reports and end-to-end CLI tests.
- Professional CLI, key-management and deployment use-case documentation.

### Fixed

- Avoid unsupported directory `sync_all` on Windows, which caused apply tests
  and transactions to fail with `PermissionDenied`.
