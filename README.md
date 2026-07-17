# Rebyte

Rebyte Artifact Protocol (RAP) reconstructs exact file artifacts from bounded,
signed and self-contained capsules without executing commands or depending on
remote storage.

> Rebyte is under active development. The protocol specification is available
> in [`schemas/rap-v1.md`](schemas/rap-v1.md); no production key is trusted yet.

## Design promises

- byte-for-byte reconstruction verified with BLAKE3;
- Ed25519 publisher authentication and local trust policy;
- strictly relative, portable paths and bounded decompression;
- no shell commands, hooks, network access or generated-code execution;
- atomic replacement per file with recoverable multi-file transactions;
- native CLI targets for Linux, macOS and Windows plus a filesystem-free Wasm
  interface.

The detailed threat and security models live in [`docs/`](docs/). User-facing
installation, API and operations documentation will grow with each implemented
phase and be complete before the v1 release.

## Development

The repository uses Rust 1.97.1, Edition 2024 and a Cargo workspace. Once the
workspace dependencies are fetched:

```console
cargo xtask check
cargo xtask test
```

Adversarial inputs are exercised by always-on property tests and the targets in
`fuzz/`. Scheduled CI runs Miri over protocol primitives, bounded libFuzzer
jobs, dependency policy/audit checks and mutation sampling. Reproduce one fuzz
target with `cargo +nightly fuzz run decode_capsule` after installing
`cargo-fuzz`.

`rebyte-wasm` exports only `pack_unsigned`, `inspect` and `verify_structure`.
Browser packing is deterministic and uncompressed; a trusted server must
revalidate, choose production compression and sign it. The Wasm module contains
no private key, trust decision, network access or filesystem API.

Internal AI-assisted notes must stay below the ignored `.ai/` directory.

The `rebyte-format` crate is `no_std + alloc` compatible and exposes only
bounded protocol values. In particular, `RelativeArtifactPath` validates paths
with platform-independent rules before any filesystem crate receives them.

`rebyte-codec` implements the RAP v1 bytes directly rather than deriving a
serializer format. Its cursor validates every length before slicing, rejects
non-canonical manifests and supports unpadded `rb1_` Base64URL tokens.

`rebyte-integrity` exposes incremental BLAKE3 hashing with distinct RAP v1
domains for files, manifests, payloads, capsule roots and publisher key IDs.

`rebyte-compression` fixes native Zstandard level 3 and performs bounded
streaming decompression. Signed output size, absolute limits and compression
ratio are checked before and during expansion; the Wasm build uses a pure-Rust
decoder and intentionally cannot encode Zstandard.

`rebyte-signature` verifies Ed25519 signatures only after resolving the derived
key ID in a local keyring. Production is the default channel; staging and
development require explicit policy, while retired, revoked and unknown keys
are rejected.

`rebyte-pack` accepts only final bytes and validated relative paths. It sorts
files by canonical UTF-8 path bytes, rejects duplicates, builds contiguous
offsets, hashes each file and produces deterministic unsigned capsule material.

`rebyte-verify` makes trust transitions explicit in its types. The complete
pipeline is `Unverified → StructurallyValid → SignatureVerified →
PayloadVerified → FullyVerified`; only the last state exposes reconstructed
files to future diff and apply crates. `rebyte-core` re-exports the stable pack,
sign and verify facade.

The CLI provides bounded `inspect`, full `verify`, capability-confined `diff`
and `apply`, transaction recovery, `doctor` and shell `completions`. Input may
be an `rb1_` token, `-` for stdin, or `--file artifact.rbc`. The bundled
development public key is rejected unless `--trust-channel development` is
explicit.

```console
rebyte verify --file release.rbc
rebyte apply --file release.rbc --root ./app --dry-run
rebyte apply --file release.rbc --root ./app
rebyte apply --file release.rbc --root ./app --yes --backup
rebyte transactions --root ./app
rebyte resume TRANSACTION_ID --root ./app
rebyte rollback TRANSACTION_ID --root ./app
```

Interactive application defaults to no. `--yes` bypasses only the prompt and
never signature, trust, digest, limit, path or precondition checks. `--dry-run`
performs complete verification and diff without creating the Rebyte control
directory. Stable JSON is available through `--json`.

`rebyte-apply` accepts only `FullyVerifiedCapsule`, stages and re-hashes every
file, snapshots target preconditions, rejects symlinks, journals each state and
uses same-filesystem atomic renames. A multi-file operation may be partially
visible during a crash, but retained staging and backups support resume or
rollback; global multi-file atomicity is not claimed.

CLI exit codes are `0` for success/cancellation, `1` generic I/O, `2` malformed
input, `3` invalid signature, `4` unknown key, `5` digest/payload failure, `6`
unsupported protocol, `7` trust-policy rejection, `8` unsafe filesystem path,
`9` target/transaction conflict and `10` journal or transaction failure.

## License

Licensed under either Apache License, Version 2.0 or the MIT license, at your
option.
