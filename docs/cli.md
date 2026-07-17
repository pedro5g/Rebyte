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
- existing key and capsule output files are never overwritten.

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
rebyte hash PATH|- [--check LOWERCASE_HEX] [--json]
```

Computes the domain-separated RAP file digest incrementally. `--check` expects
exactly 64 lowercase hexadecimal characters.

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
