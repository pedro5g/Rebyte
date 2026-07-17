# Rebyte

[![CI](https://github.com/pedro5g/Rebyte/actions/workflows/ci.yml/badge.svg)](https://github.com/pedro5g/Rebyte/actions/workflows/ci.yml)
[![Security audit](https://github.com/pedro5g/Rebyte/actions/workflows/scheduled.yml/badge.svg)](https://github.com/pedro5g/Rebyte/actions/workflows/scheduled.yml)
[![License: MIT or Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Rebyte is an offline byte-exact reconstruction tool. Its simple mode turns a
file or portable directory into a compressed, integrity-checked `ra1_` token
or `.rba` binary artifact without keys. Its
authenticated mode packages a directory into a deterministic RAP v1 capsule,
signs it with Ed25519 and reconstructs files only after bounded parsing,
trust-policy verification, decompression and byte-level integrity checks.

Rebyte 1.1 provides a stable CLI and Rust API. It performs no network access,
command execution, lifecycle hooks or generated-code interpretation.

## Why Rebyte

- exact byte-for-byte reconstruction with domain-separated BLAKE3 digests;
- one-command unsigned file or directory artifacts for local transport;
- canonical binary encoding independent of `serde` or a language runtime;
- explicit publisher trust using production, staging and development channels;
- encrypted offline signing keys and distributable public trust documents;
- portable paths, bounded decompression and strict rejection of symlinks;
- dry-run diffs, per-file atomic replacement and recoverable transactions;
- Linux, macOS, Windows and browser-safe structural WebAssembly APIs.

RAP does not encrypt capsule contents, delete files, preserve ownership, ACLs,
xattrs or timestamps, and does not promise one globally atomic switch for a
multi-file update. Read the [protocol](schemas/rap-v1.md),
[threat model](docs/threat-model.md) and
[security model](docs/security-model.md) before deployment.

## Quick start

Build the CLI with Rust 1.97.1 or install a verified release archive:

```console
git clone https://github.com/pedro5g/Rebyte.git
cd Rebyte
cargo install --locked --path crates/rebyte-cli
rebyte --version
rebyte doctor
```

### Files and folders without keys

Use an unsigned Artifact Token when you only need portable bytes plus corruption
detection and do not need to authenticate who produced them:

```console
rebyte encode ./original.txt --output original.ra1
rebyte decode --file original.ra1 --output ./copy.txt
cmp ./original.txt ./copy.txt

rebyte encode ./project --format binary --output project.rba
rebyte decode --file project.rba --output ./project-copy
```

For short tokens, pass the string directly. In Fish:

```fish
rebyte shell-env fish | source
set TOKEN ($REBYTE encode ./original.txt)
$REBYTE decode "$TOKEN" --output ./copy.txt
```

`ra1_` is not a signature. Anyone can create a different internally valid
token. Use the signed workflow below for releases, deployments or any input
crossing a trust boundary. The complete format and verification order are in
[Artifact Token v1](schemas/artifact-token-v1.md). Legacy `rf1_` file tokens
remain decodable.

For inputs above the standard 64 `MiB` per-file limit, use the bounded streaming
binary mode. It never places the full source, compressed artifact or restored
file in memory:

```console
rebyte encode ./large.bin \
  --format binary --limits large --profile maximum --dictionary auto \
  --output large.rba

rebyte decode --file large.rba --limits large --output ./large-copy.bin
rebyte hash ./large.bin --limits large
rebyte hash ./large-copy.bin --limits large
```

`--limits large` is explicit, remains bounded, and is available only with
seekable binary artifact files. Inline tokens keep the smaller standard bounds
because shells and environment variables are unsuitable for very large data.

`--dictionary auto` samples multiple files in a folder and embeds a trained
Zstandard dictionary only when the complete artifact becomes smaller. Use
`--dictionary none` for the lowest encoding latency. A dictionary is normally
not useful for one giant file: the single Zstandard stream already learns
patterns as it advances, and `--profile maximum` adds bounded long-distance
matching. Rebyte reports embedded dictionary bytes in human and JSON output.

### Signed publisher workflow

Prepare a passphrase file outside the artifact tree. Interactive use may omit
`--passphrase-file`; Rebyte will prompt twice without echoing the passphrase.

```console
umask 077
printf '%s\n' 'replace-with-a-long-random-passphrase' > publisher.passphrase

rebyte key generate \
  --name "Example production publisher" \
  --private-key publisher.private.json \
  --public-key publisher.public.json \
  --passphrase-file publisher.passphrase
```

Keep `publisher.private.json` and the passphrase separate and offline. The
public document is the only key file copied to verifier machines.

Create and verify a signed capsule:

```console
rebyte pack \
  --root ./artifact \
  --private-key publisher.private.json \
  --passphrase-file publisher.passphrase \
  --output release.rbc \
  --producer "example-build" \
  --producer-version "1.0.0" \
  --name "Example release"

rebyte inspect --file release.rbc --trusted-key publisher.public.json
rebyte verify --file release.rbc --trusted-key publisher.public.json
```

Preview and apply it to a destination:

```console
rebyte diff \
  --file release.rbc \
  --trusted-key publisher.public.json \
  --root ./destination

rebyte apply \
  --file release.rbc \
  --trusted-key publisher.public.json \
  --root ./destination \
  --dry-run

rebyte apply \
  --file release.rbc \
  --trusted-key publisher.public.json \
  --root ./destination
```

`apply` defaults to an interactive “no”. `--yes` skips only the prompt and
never weakens verification. `--backup` retains verified original bytes and the
journal for a later explicit rollback.

## CLI overview

Run `rebyte -h`, `rebyte help COMMAND` or `rebyte COMMAND -h` for contextual
help. `rebyte --version` prints the exact binary version. Help and human output
use terminal-aware color; redirected output and `NO_COLOR` remain plain.

| Command | Purpose |
|---|---|
| `encode` | Turn a file or folder into an unsigned `ra1_`/`.rba` artifact |
| `decode` | Verify and reconstruct an unsigned artifact into a new path |
| `key generate` | Create a random encrypted private key and public trust document |
| `key inspect` | Validate and display a public key, fingerprint, channel and status |
| `key status` | Produce an active, retired or revoked public trust document |
| `pack` | Read a directory without following symlinks, sign and self-verify a capsule |
| `hash` | Compute or check the RAP file-domain BLAKE3 digest |
| `patch` | Create, inspect, preview and atomically apply JSON/TOML semantic patches |
| `inspect` | Parse bounded metadata; unverified data is labelled as such |
| `verify` | Verify encoding, publisher, signature, payload and every file |
| `diff` | Compare a verified capsule with a root without writing |
| `apply` | Verify, preview and execute a recoverable transaction |
| `transactions` | List retained or interrupted transactions |
| `resume` / `rollback` | Recover an interrupted transaction explicitly |
| `doctor` | Report version, platform, trust keys and apply capability |
| `shell-env` | Export the absolute executable path as `REBYTE` for the selected shell |
| `completions` | Generate Bash, Zsh, Fish, Elvish or `PowerShell` completions |

The full syntax, JSON schemas, stdin behavior and exit-code contract are in
[the CLI reference](docs/cli.md). Practical deployment patterns are collected
in [use cases](docs/use-cases.md).

### Input and trust

Capsule consumers accept a positional `rb1_` token, `-` for a token on stdin,
or `--file release.rbc` for the binary envelope. Public trust is always local
and explicit:

```console
rebyte verify TOKEN --trusted-key publisher.public.json
printf '%s\n' "$REBYTE_TOKEN" | rebyte verify - --trusted-key publisher.public.json
rebyte verify --file release.rbc \
  --trusted-key current.public.json \
  --trusted-key next.public.json
```

Production is the default trust channel. Staging and development require
explicit opt-in:

```console
rebyte verify --file staging.rbc \
  --trusted-key staging.public.json \
  --trust-channel staging
```

The bundled development fixture exists only for tests and local evaluation;
it is rejected unless `--trust-channel development` is present.

## Keys and signing

`key generate` obtains a 32-byte Ed25519 seed from the operating-system random
source. The private document encrypts that seed with XChaCha20-Poly1305 using a
key derived by Argon2id (64 `MiB`, three iterations, one lane). Public identity,
salt and nonce are authenticated as associated data. JSON parsers reject
unknown fields, non-canonical Base64URL and identity mismatches.

On Unix, Rebyte creates private and passphrase-bearing outputs with mode `0600`
and refuses to load secret files accessible by group or other users. Windows
uses inherited ACLs; restrict them explicitly for a dedicated publisher
account. The detailed offline ceremony, backup strategy, Windows ACL example,
rotation and emergency revocation process are in
[key management](docs/key-management.md).

Never:

- commit a private key, passphrase or generated capsule containing secrets;
- put the private key inside the directory passed to `rebyte pack`;
- store the private key and passphrase in the same backup or secret;
- use command-line arguments or ordinary environment variables for a
  production passphrase;
- distribute a new public key without comparing its Key ID out of band.

For high-value online signing, implement the `rebyte_signature::Signer` trait
against a reviewed KMS or HSM. The encrypted local signer is intended for an
offline release workstation or a tightly controlled build environment; Rebyte
does not pretend a JSON file is a hardware trust boundary.

### Rotation and revocation

Deploy the next active public key to all verifiers before signing with it. RAP
v1 has no trusted timestamp, so `retired` and `revoked` both reject every
capsule signed by that key; `revoked` communicates compromise, while `retired`
communicates planned removal.

```console
rebyte key status old.public.json \
  --status retired \
  --output old.retired.public.json

rebyte key status compromised.public.json \
  --status revoked \
  --output compromised.revoked.public.json
```

Replace the active document in verifier configuration with the new status
document. Do not merely remove a compromised key when operators need a clear
“known revoked” diagnosis.

## RAP file hashes

`rebyte hash` is streaming and bounded to the selected standard or large
single-file limit. Its
result is a domain-separated BLAKE3 digest using context `rebyte:v1:file`; it
is intentionally different from a generic `b3sum` of the same bytes.

A digest verifies bytes but cannot reconstruct them: infinitely many possible
files must map into the finite 256-bit digest space. Use `encode` when the
result must carry enough information to recreate the file, and `hash` when the
bytes already exist and only comparison is required.

```console
rebyte hash ./artifact/config.toml
rebyte hash ./large-image.raw --limits large
rebyte hash ./artifact/config.toml --json
rebyte hash ./artifact/config.toml --check "$EXPECTED_RAP_DIGEST"
printf 'exact bytes' | rebyte hash -
```

A successful `--check` exits with code 0. A mismatch exits with code 5 and
prints both expected and computed digests without changing any file. Capsule
root digests are shown by `pack`, `inspect` and `verify`; they cover the fixed
header, canonical manifest and compressed payload, not the final signature.

## Emergency semantic patches

Semantic patches change a logical JSON or TOML field without replacing every
source byte. They are useful when local comments or unrelated configuration
must survive an emergency change.

Create a patch bound to the exact current file:

```fish
set TARGET ./service.toml
set EXPECTED (rebyte hash "$TARGET" | string split ' ' | head -n 1)

rebyte patch create \
  --format toml \
  --target-digest "$EXPECTED" \
  --operation 'test:/server/port=80' \
  --operation 'set:/server/port=8080' \
  --operation 'remove:/server/legacy' \
  --output emergency.rbp.json
```

Review, preview and apply it:

```console
rebyte patch inspect emergency.rbp.json
rebyte patch apply emergency.rbp.json \
  --target ./service.toml --dry-run
rebyte patch apply emergency.rbp.json \
  --target ./service.toml --yes --backup
```

Paths use RFC 6901 JSON Pointer (`/server/port`; encode `~` as `~0` and `/`
inside a key as `~1`). JSON supports object keys and array indexes, with `-`
appending to an array. TOML v1 intentionally addresses table keys only so
comments and surrounding layout remain predictable. The apply command rejects
duplicate JSON keys, symlinks, stale digests, failed `test` operations,
existing backups and concurrent target changes. It stages on the same
filesystem, preserves permissions, atomically replaces one file and verifies
the committed digest.

Semantic patches are unsigned local instructions: integrity and preconditions
do not authenticate an author. Treat externally received patches as untrusted,
or distribute the resulting exact file through a signed capsule. See the
[semantic patch specification](schemas/semantic-patch-v1.md).

## Shell setup

`shell-env` resolves the running executable to an absolute path and emits one
quoted assignment. Apply it to the current shell:

```fish
# Fish
./target/release/rebyte shell-env fish | source
$REBYTE --version
```

```bash
# Bash
eval "$(./target/release/rebyte shell-env bash)"

# Zsh
eval "$(./target/release/rebyte shell-env zsh)"
```

```powershell
# PowerShell
./target/release/rebyte.exe shell-env powershell | Invoke-Expression
& $env:REBYTE --version
```

The generated variable is `REBYTE`; it is exported for child processes. Shell
completion generation remains separate through `rebyte completions SHELL`.

## Recovery

Transactions live under `<root>/.rebyte/transactions/`. A crash can expose a
prefix of a multi-file change, but the persisted journal, staged data,
precondition digests and original backups permit deterministic recovery:

```console
rebyte transactions --root ./destination
rebyte resume TRANSACTION_ID --root ./destination
rebyte rollback TRANSACTION_ID --root ./destination
```

`resume` hashes staged data again and rechecks every target precondition.
`rollback` restores digest-verified backups and removes files created by the
transaction. A new apply is rejected while an unfinished transaction exists.
If recovery reports a conflict, preserve `.rebyte/` and investigate concurrent
changes instead of deleting the journal.

Rebyte synchronizes file contents and journals before rename. Unix also
synchronizes containing directories. Rust does not expose a portable Windows
directory-fsync operation, so Windows uses durable file flushes plus atomic
per-file rename and journal recovery.

## JSON and automation

Commands with `--json` emit a versioned object with `schemaVersion: 1` and no
ANSI controls. Errors go to stderr and retain the documented exit code. A safe
non-interactive deployment first verifies or performs a dry run and then uses
`--yes`:

```console
rebyte verify --file release.rbc \
  --trusted-key publisher.public.json --json > verification.json

rebyte apply --file release.rbc \
  --trusted-key publisher.public.json \
  --root ./destination --dry-run --json > plan.json

rebyte apply --file release.rbc \
  --trusted-key publisher.public.json \
  --root ./destination --yes --backup --json > apply.json
```

Do not parse human output. JSON fields are additive within Rebyte 1.x; scripts
must ignore unknown fields and check `schemaVersion` before interpretation.

## Rust API

`rebyte-core` is the stable consumer and producer facade. Only a
`FullyVerifiedCapsule` can reach diff or filesystem application APIs.

Unsigned single-file tokens are available through a small byte-slice API:

```rust
use rebyte_core::{
    FileTokenOptions, SecurityLimits, decode_file_token, encode_file_token,
};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let original = b"byte-exact content\n";
let encoded = encode_file_token(original, &FileTokenOptions::default())?;
let decoded = decode_file_token(encoded.token(), &SecurityLimits::V1)?;
assert_eq!(decoded.bytes(), original);
# Ok(())
# }
```

The decoded API labels this data by type but deliberately provides no
publisher identity. Its digest is integrity metadata, not an authenticity
decision.

```rust,no_run
use std::path::Path;

use rebyte_core::{
    ApplyOptions, CapsuleInput, TrustedKeyring, VerificationPolicy,
    apply_transaction, verify_capsule,
};

# fn example(bytes: &[u8], keyring: &TrustedKeyring) -> Result<(), Box<dyn std::error::Error>> {
let policy = VerificationPolicy::PRODUCTION;
let verified = verify_capsule(CapsuleInput::Binary(bytes), &policy, keyring)?;
apply_transaction(
    &verified,
    Path::new("./application"),
    &ApplyOptions::default(),
)?;
# Ok(())
# }
```

Verification is encoded as typestates:
`Unverified → StructurallyValid → SignatureVerified → PayloadVerified →
FullyVerified`. The workspace separates format, codec, integrity, compression,
signature, packing, verification, diff and apply responsibilities into crates
with `#![forbid(unsafe_code)]`.

## WebAssembly

`rebyte-wasm` exports only `pack_unsigned`, `inspect` and `verify_structure`.
Browser packing uses `CompressionAlgorithm::None`; a trusted native service
must revalidate semantic input, compress and sign. The WebAssembly dependency
tree contains no private key, trust decision, filesystem or network API.

```console
wasm-pack build crates/rebyte-wasm --target web
```

## Distribution

Tagged releases produce archives for Linux x64 glibc/musl, Linux ARM64 glibc,
macOS Intel/Apple Silicon and Windows x64. Release assets include SHA-256
checksums, a `CycloneDX` SBOM, auditable dependency metadata and `GitHub` artifact
attestations.

```console
sha256sum -c rebyte-cli-x86_64-unknown-linux-gnu.tar.xz.sha256
gh attestation verify rebyte-cli-x86_64-unknown-linux-gnu.tar.xz \
  --repo pedro5g/Rebyte
```

Follow the complete [release verification procedure](docs/release.md) before
production installation.

## Development

The workspace uses Rust 1.97.1, Edition 2024 and resolver 3.

```console
cargo xtask check
cargo xtask test
cargo check -p rebyte-wasm --target wasm32-unknown-unknown
cargo check --manifest-path fuzz/Cargo.toml --bins
cargo xtask security
```

CI runs Linux, Linux ARM64, macOS Intel/ARM, Windows x64 and WebAssembly jobs.
Scheduled workflows add Miri, fuzzing, mutation sampling, coverage and
benchmarks. Current measured targets and baselines are documented in
[quality](docs/quality.md).

## Security

No software is “100% secure”. Rebyte 1.1 provides a stable, fail-closed design
and adversarial tests, but has not claimed an independent security audit.
Report suspected vulnerabilities privately according to
[SECURITY.md](SECURITY.md); never attach production keys or secret material to
a public issue.

## License

Copyright (c) 2026 Pedro Martins (pedro5g).

Licensed under either Apache License, Version 2.0 or the MIT license, at your
option.
