# Rebyte CLI reference

Copyright (c) 2026 Pedro Martins (pedro5g)

This document describes the stable Rebyte 1.x command interface. The live
binary remains authoritative for installed options:

```console
rebyte --version
rebyte -h
rebyte help verify
```

## Common conventions

- Capsule input is a positional `rb1_` token, `-` for token stdin, or
  `--file PATH` for a binary `.rbc` envelope.
- `--trusted-key PATH` is repeatable and loads a strict public trust document.
- production keys are accepted by default; `--trust-channel staging` and
  `--trust-channel development` are explicit opt-ins.
- `--json` writes one schema-versioned JSON object to stdout.
- diagnostic errors go to stderr and never include private keys, passphrases,
  capsule tokens or file content.
- existing key, capsule, token and reconstructed output files are never
  overwritten.
- `ra1_` artifact tokens and `.rba` files provide integrity without publisher
  authentication; legacy `rf1_` file tokens remain decode-only;
  `rb1_` RAP tokens require signature and trust verification.

## Simple unsigned artifacts

### `encode`

```text
rebyte encode FILE|DIRECTORY|- [--compression auto|zstd|none]
              [--profile fast|balanced|maximum]
              [--dictionary auto|none]
              [--include-name | --name NAME]
              [--suggest-path RELATIVE_PATH]
              [--format token|binary] [--limits standard|large]
  [--output PATH] [--json]
```

Without `--output`, token format writes only the `ra1_` token and a newline to
stdout, making command substitution safe. `auto` tries deterministic
Zstandard and keeps it only when its payload is smaller. Files and complete
portable directory trees are supported; symlinks and special files are
rejected. Optional name and relative-path fields are untrusted reconstruction
hints.

`--dictionary auto` deterministically samples canonical file order, trains a
bounded shared Zstandard dictionary, and retains it only when dictionary bytes
plus compressed bytes beat ordinary Zstandard. Training needs at least eight
usable file samples and is aimed at folders containing similar small files.
`none` skips this CPU work. Single large files rely on the selected Zstandard
profile instead.

Binary format requires `--output` and creates a canonical `.rba` without
Base64URL expansion. `--limits large` requires binary format and a seekable
file or directory. Its streaming implementation hashes the source, verifies
the same bytes while encoding, self-verifies the staged envelope, and creates
the destination without replacing an existing path.

### `decode`

```text
rebyte decode TOKEN [--output PATH] [--json]
rebyte decode --file TOKEN_OR_RBA [--output PATH]
  [--limits standard|large] [--json]
rebyte decode - [--output PATH] [--json]
rebyte decode TOKEN --root PATH --accept-suggested-path [--name NAME]
```

Decode validates canonical Base64URL, the fixed header, declared lengths,
compression limits and the embedded domain-separated digest before creating
the output. A supplied `--output` always overrides embedded hints. Without it,
Rebyte previews the suggested destination and writes nothing until
`--accept-suggested-path` is supplied. The preview digest is rechecked during
the writing pass to prevent an input-swap race.

Existing outputs are never replaced. Successful reports say
`authenticated: false`: the token proves internal consistency, not authorship.

For large artifacts use `.rba`, `--file` and `--limits large`; operating
systems impose different command-line length limits. Compression effectiveness
depends on input redundancy. Base64URL and the fixed header can make
incompressible small files larger than their source.

## Publisher commands

### `key generate`

```text
rebyte key generate --name NAME
  [--channel production|staging|development]
  [--private-key PATH] [--public-key PATH]
  [--passphrase-file PATH] [--json]
```

Defaults are `rebyte-private-key.json`, `rebyte-public-key.json` and production
channel. Without a passphrase file, the controlling TTY prompts twice.

### `key inspect`

```text
rebyte key inspect PUBLIC_KEY [--json]
```

Validates the complete document and derived Key ID before displaying it.

### `key status`

```text
rebyte key status PUBLIC_KEY
  --status retired|revoked --output PATH [--json]
```

Writes a new document so status changes can be reviewed and deployed without
silently mutating the original trust record. Status transitions are monotonic:
a retired or revoked key cannot be made active again.

### `pack`

```text
rebyte pack --root DIR --private-key PATH --output PATH --producer NAME
  [--producer-version VERSION] [--name NAME] [--description TEXT]
  [--compression zstd|none] [--format binary|token]
  [--passphrase-file PATH] [--json]
```

The directory walker sorts UTF-8 paths deterministically, rejects symlinks and
non-regular files, preserves the Unix executable bit, enforces RAP limits and
self-verifies the signed result. The default output is binary `.rbc`; token
format writes one newline-terminated `rb1_` value.

### `hash`

```text
rebyte hash PATH|- [--check LOWERCASE_HEX]
  [--limits standard|large] [--json]
```

Computes the domain-separated RAP file digest incrementally. `--check` expects
exactly 64 lowercase hexadecimal characters. `large` raises only the bounded
streaming byte limit; it does not change the algorithm or digest.

## Semantic patch commands

### `patch create`

```text
rebyte patch create --format json|toml
  --operation EXPRESSION [--operation EXPRESSION ...]
  [--target-digest LOWERCASE_HEX] --output PATCH [--json]
```

Expressions are evaluated in command order:

- `test:/pointer=JSON` requires an existing semantic value;
- `set:/pointer=JSON` inserts or replaces below an existing parent;
- `remove:/pointer` removes an existing value.

Values use JSON syntax even when the target is TOML, so strings retain their
JSON quotes. The patch output is strict, versioned JSON and is created
exclusively.

### `patch inspect`

```text
rebyte patch inspect PATCH [--json]
```

Bounds the document to 2 `MiB`, rejects duplicate keys and unknown fields, and
validates the version, format, digest, operation count and every pointer. It
does not read or change a target.

### `patch apply`

```text
rebyte patch apply PATCH --target FILE
  [--dry-run | --yes] [--backup] [--json]
```

The target is opened without following symlinks and bounded to 64 `MiB`.
Without `--yes`, Rebyte prints a sanitized line diff and defaults confirmation
to “no”. `--dry-run` never writes. `--backup` exclusively creates
`<target>.rebyte.bak` with the original bytes and permissions.

Before commit, Rebyte verifies the optional exact digest and ordered semantic
tests, stages serialized output beside the target, rechecks the target digest,
atomically replaces that one file, synchronizes it and verifies the committed
digest. Existing backup names, stale targets and concurrent changes fail
closed. JSON arrays are supported; TOML operations are table-key paths in v1.

## Consumer commands

### `inspect`

Parses only bounded canonical structure. Metadata is untrusted unless the
reported verification field is `valid` under the supplied keyring and policy.

```console
rebyte inspect --file release.rbc --trusted-key publisher.public.json
```

### `verify`

Runs the complete `Unverified → StructurallyValid → SignatureVerified →
PayloadVerified → FullyVerified` pipeline and reconstructs file bytes only in
memory.

```console
rebyte verify --file release.rbc --trusted-key publisher.public.json --json
```

### `diff`

Compares each verified file with a local root. Text files may include a unified
line diff; binary changes report sizes without printing content.

```console
rebyte diff --file release.rbc \
  --trusted-key publisher.public.json --root ./application
```

### `apply`

```text
rebyte apply INPUT --trusted-key PATH [--root DIR]
  [--dry-run] [--yes] [--backup] [--json]
```

`--dry-run` creates no `.rebyte/` state. `--yes` affects confirmation only.
`--backup` retains a committed journal and original bytes for explicit
rollback. Without `--yes`, EOF or any answer other than `y`/`yes` cancels.

### Transaction recovery

```console
rebyte transactions --root ./application [--json]
rebyte resume TRANSACTION_ID --root ./application [--json]
rebyte rollback TRANSACTION_ID --root ./application [--json]
```

Resume and rollback never accept a capsule or weaker trust flag; they operate
only on bounded persisted journals and digest-verified staged/backup files.

## Operations

### `doctor`

```console
rebyte doctor \
  --trusted-key publisher.public.json \
  --trusted-key next.public.json \
  --json
```

Reports Rebyte/RAP versions, platform, configured keys by channel and
filesystem-apply availability. It does not contact a network or mutate trust.

### `shell-env`

```console
rebyte shell-env bash
rebyte shell-env zsh
rebyte shell-env fish
rebyte shell-env powershell
```

Prints a safely quoted assignment of the absolute running binary path to the
exported `REBYTE` variable. A subprocess cannot mutate its parent shell, so
evaluate the output with `eval`, Fish `source`, or PowerShell
`Invoke-Expression`, as shown in the README.

### `completions`

```console
rebyte completions bash > rebyte.bash
rebyte completions zsh > _rebyte
rebyte completions fish > rebyte.fish
rebyte completions powershell > _rebyte.ps1
```

## JSON compatibility

Every JSON response contains `schemaVersion`. Rebyte 1.x may add fields but
will not change the meaning or type of an existing field without a schema
version change. Consumers must ignore unknown fields, validate the schema and
also check the process exit code.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success, including cancellation before writes |
| 1 | generic command or input/output failure |
| 2 | malformed, non-canonical or oversized input |
| 3 | invalid Ed25519 signature |
| 4 | publisher Key ID absent from the supplied keyring |
| 5 | digest, payload, decompression or `hash --check` mismatch |
| 6 | unsupported RAP protocol version |
| 7 | trust policy, key status or key-document failure |
| 8 | unsafe path, symlink or non-regular filesystem object |
| 9 | target precondition or transaction conflict |
| 10 | journal, recovery or filesystem transaction failure |

Clap usage errors exit with its standard nonzero usage status before Rebyte
handles a command. Scripts should treat every undocumented nonzero status as a
failure.
