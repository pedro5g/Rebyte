# Changelog

All notable changes are documented here. The format follows Keep a Changelog,
and releases follow Semantic Versioning.

## [Unreleased]

### Added

- Self-custodied Chain identities with independent Ed25519 signing and X25519
  HPKE keys in passphrase-encrypted `.rbk` bundles.
- Unanimous group formation certificates and configurable `T-of-N` capsule
  approval policies bound to every original public identity.
- Canonical `.rbe` and `rbe2_` encrypted capsules with one authenticated
  payload and RFC 9180 HPKE content-key slots for multiple recipients.
- Canonical `rc1_` Access Contracts binding controllers, thresholds,
  recipients, capabilities, exact content and direct or quorum key release.
- Fail-closed Chain v2 contract integration; unsupported quorum, temporal and
  maximum-release policies cannot degrade into local clock/counter checks.
- Contract-gated `chain capsule diff` and recoverable `chain capsule apply`
  commands, sharing the RAP transaction engine and preserving explicit empty
  directories through journaled creation and rollback.
- Canonical Semantic Patch v1 as a first-class encrypted Chain content kind,
  with `chain capsule create --patch` and contract-gated `chain capsule patch`
  preview, confirmation, backup and atomic application.
- Complete `rebyte chain identity`, `chain group` and `chain capsule` CLI
  workflows, stable JSON reports and byte-exact file/directory integration
  coverage.
- A bounded Chain-envelope fuzz target and scheduled parser fuzzing.

### Fixed

- Avoid reopening a completed semantic-patch backup through a read-only Windows
  handle before `FlushFileBuffers`; backup bytes remain synchronized by their
  writable creation handle.
- Make transaction cleanup idempotent when Windows reports `NotFound` after the
  last recursively removed journal entry disappears.

### Documentation

- Specify the implemented Chain v2 and Access Contract v1 wire formats,
  security boundary, CLI, Rust API, modular layer diagram and multi-party flow;
  retain quorum release and the signed Merkle event history as explicit
  roadmap layers.

## [1.2.0] - 2026-07-17

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
- Strict Semantic Patch v1 documents with ordered `test`, `set` and `remove`
  operations for JSON and comment-preserving TOML.
- `patch create`, `patch inspect` and `patch apply` with digest preconditions,
  dry-run diffs, no-follow targets, exclusive backups, atomic replacement and
  post-write verification.

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
