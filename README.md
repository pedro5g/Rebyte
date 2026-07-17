# Rebyte

Rebyte Artifact Protocol (RAP) reconstructs exact file artifacts from bounded,
signed and self-contained capsules. It performs no network access, command
execution, lifecycle hooks or generated-code interpretation.

> Rebyte v0.1.0 is pre-release software. RAP v1 is specified, but no production
> publisher key ships with the CLI yet. Use the current development key only for
> local evaluation with explicit `--trust-channel development`.

## What it guarantees

- byte-for-byte reconstruction verified with domain-separated BLAKE3;
- Ed25519 publisher authentication under a caller-controlled keyring;
- fixed, canonical RAP v1 encoding with bounded parsing and decompression;
- portable relative paths, capability-confined filesystem access and symlink
  rejection;
- atomic replacement per file plus a durable multi-file recovery journal;
- deterministic native packing and an unsigned, filesystem-free browser API.

RAP does not encrypt content, delete files, preserve ownership/ACL/xattrs/
timestamps, or promise global atomicity across multiple files. Read the
[protocol](schemas/rap-v1.md), [threat model](docs/threat-model.md) and
[security model](docs/security-model.md) before production integration.

## Installation

Until the first release is published, build the CLI from a trusted checkout:

```console
git clone https://github.com/pedro5g/Rebyte.git
cd Rebyte
cargo install --locked --path crates/rebyte-cli
rebyte doctor
```

Tagged releases are configured to publish `rebyte` archives for Linux x64
glibc/musl, Linux ARM64 glibc, macOS Intel/Apple Silicon and Windows x64. Each
archive receives a SHA-256 file; releases also carry a `CycloneDX` SBOM,
embedded auditable dependency metadata and `GitHub` artifact attestations. Verify a
download before execution:

```console
sha256sum -c rebyte-cli-x86_64-unknown-linux-gnu.tar.xz.sha256
gh attestation verify rebyte-cli-x86_64-unknown-linux-gnu.tar.xz \
  --repo pedro5g/Rebyte
```

## CLI

Every capsule command accepts an `rb1_` token, `-` for a token on stdin, or
`--file release.rbc` for the binary envelope.

```console
rebyte inspect --file release.rbc
rebyte verify --file release.rbc
rebyte diff --file release.rbc --root ./app
rebyte apply --file release.rbc --root ./app --dry-run
rebyte apply --file release.rbc --root ./app
```

`apply` verifies limits, structure, trust policy, signature, decompression and
every file digest before showing the plan. The confirmation defaults to no.
`--yes` bypasses only that prompt; it never weakens verification. `--dry-run`
performs verification and diff without creating `.rebyte/`. `--backup` retains
the committed journal and original bytes. Machine-readable commands support
versioned `--json` output, and terminal output neutralizes control characters.

The current bundled key is development-only, so evaluation commands require:

```console
rebyte verify --file development.rbc --trust-channel development
```

### Recovery

Transactions live below `<root>/.rebyte/transactions/`. A crash may expose a
prefix of a multi-file change, but the persisted journal, staged bytes,
precondition digests and backups allow explicit recovery:

```console
rebyte transactions --root ./app
rebyte resume TRANSACTION_ID --root ./app
rebyte rollback TRANSACTION_ID --root ./app
```

`resume` re-hashes staged data and rechecks target preconditions. `rollback`
restores verified backups and removes files created by the transaction. A new
apply is rejected while an unfinished transaction exists. If either command
reports a conflict, preserve `.rebyte/` and investigate local concurrent
changes before retrying.

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | success or user cancellation before writes |
| 1 | generic CLI/input-output error |
| 2 | malformed or oversized input |
| 3 | invalid Ed25519 signature |
| 4 | unknown publisher key |
| 5 | digest, payload or decompression failure |
| 6 | unsupported RAP version |
| 7 | trust-policy rejection |
| 8 | unsafe path, symlink or non-file target |
| 9 | target or transaction conflict |
| 10 | journal, recovery or filesystem transaction failure |

## Rust API

`rebyte-core` exposes the stable facade. The important boundary is the return
type of `verify_capsule`: only `FullyVerifiedCapsule` can reach `diff_capsule`
or `apply_transaction`.

```rust,no_run
use std::path::Path;

use rebyte_core::{CapsuleInput, apply_transaction, verify_capsule};
use rebyte_core::{ApplyOptions, TrustedKeyring, VerificationPolicy};

# fn example(bytes: &[u8], keyring: &TrustedKeyring) -> Result<(), Box<dyn std::error::Error>> {
let policy = VerificationPolicy::default(); // production channel only
let verified = verify_capsule(CapsuleInput::Binary(bytes), &policy, keyring)?;
apply_transaction(
    &verified,
    Path::new("./application"),
    &ApplyOptions::default(),
)?;
# Ok(())
# }
```

The verification pipeline is encoded as typestates:
`Unverified → StructurallyValid → SignatureVerified → PayloadVerified →
FullyVerified`. `KeyId` is derived from the public key; publisher display names,
channel and active/retired/revoked state come from the local keyring.

Core crates are separated by responsibility:

- `rebyte-format`: `no_std + alloc` bounded values and portable paths;
- `rebyte-codec`: manual canonical binary and `rb1_` codecs;
- `rebyte-integrity`, `rebyte-compression`, `rebyte-signature`: cryptographic
  and bounded stream primitives;
- `rebyte-pack`, `rebyte-verify`: deterministic construction and typestates;
- `rebyte-diff`, `rebyte-apply`: read-only planning and recoverable writes;
- `rebyte-signer`: explicitly development-only signing adapters.

## WebAssembly

`rebyte-wasm` exports only `pack_unsigned`, `inspect` and `verify_structure`.
Browser packing always uses `CompressionAlgorithm::None`; a trusted server must
reparse semantic inputs, apply native compression and sign. The Wasm dependency
tree contains no private key, keyring, trust decision, filesystem or network
API.

Build `JavaScript` bindings with `wasm-pack`:

```console
wasm-pack build crates/rebyte-wasm --target web
```

Capsule input uses `{ kind: "binary", value: number[] }` or
`{ kind: "token", value: "rb1_..." }`. Inspection output is explicitly marked
`trust: "unverified"`.

## Security and trust

Production callers must provision their own `TrustedKeyring`. Production is
the default channel; staging and development are opt-in; retired, revoked and
unknown keys are rejected. RAP v1 has no timestamp or expiry field, so key
rotation/revocation is a local deployment responsibility.

`rebyte-signer` contains no private-key fixture. `DevelopmentSigner` requires
an explicit 32-byte seed, and `EnvironmentDevelopmentSigner` accepts unpadded
Base64URL while zeroizing copied buffers. Neither is a production KMS/HSM
adapter. Never put a production key in a capsule builder, browser bundle,
repository or ordinary process environment.

Report vulnerabilities according to [SECURITY.md](SECURITY.md). Error messages
do not include capsule content, tokens or secrets.

## Development and quality

The workspace uses Rust 1.97.1, Edition 2024 and resolver 3.

```console
cargo xtask check
cargo xtask test
cargo check -p rebyte-wasm --target wasm32-unknown-unknown
```

`check` enforces rustfmt, all-target Cargo check, strict Clippy and rustdoc with
warnings denied. Tests include unit, integration and property suites. Scheduled
CI runs RustSec/source/license checks, Miri, bounded fuzzing and mutation
sampling. Fuzz harnesses are in `fuzz/` and can be compiled or run with:

```console
cargo check --manifest-path fuzz/Cargo.toml --bins
cargo +nightly fuzz run decode_capsule
```

Internal AI-assisted notes, prompts and artifacts belong only in the ignored
`.ai/` directory. See [CONTRIBUTING.md](CONTRIBUTING.md) for commit and review
rules and [docs/release.md](docs/release.md) for the release procedure.

## Platforms and limitations

| Platform | CI | Release artifact |
|---|---|---|
| Linux x64 glibc | full quality gate | yes |
| Linux x64 musl | release build | yes |
| Linux ARM64 glibc | tests + release build | yes |
| macOS Intel | tests + release build | yes |
| macOS Apple Silicon | tests + release build | yes |
| Windows x64 | tests + release build | yes |
| `wasm32-unknown-unknown` | structural/pack build | Wasm package, no filesystem |

Filesystem behavior differs by platform. Rebyte promises atomic replacement
per file when the temporary and target are on the same filesystem; it does not
promise a globally atomic multi-file switch.

## Troubleshooting

- `unknown publisher key`: install the expected public key in the host keyring;
  the standalone CLI currently has no production key.
- `trust policy rejected publisher`: explicitly allow staging/development only
  when that environment is intended.
- `incomplete Rebyte transaction`: run `rebyte transactions`, then choose
  `resume` or `rollback`; do not delete the journal blindly.
- `target changed during the transaction`: another process or user modified a
  precondition; inspect the target and retained transaction before recovery.
- `symbolic links are forbidden`: choose a real directory tree below `--root`;
  Rebyte never follows symlinks in target paths.
- `invalid or truncated compression stream`: reacquire the capsule from a
  trusted channel and compare its published checksum.

## License

Copyright (c) 2026 Pedro Martins (pedro5g).

Licensed under either Apache License, Version 2.0 or the MIT license, at your
option.
