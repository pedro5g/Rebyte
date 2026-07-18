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
  authentication; `rb1_` RAP tokens require signature and trust verification.

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

## Chain commands

Chain commands operate entirely offline. Control documents and encrypted
capsules can be carried by any transport, but Rebyte itself opens no network
connection. Every output uses exclusive creation and existing paths are never
replaced.

### `chain identity generate`

```text
rebyte chain identity generate --name NAME
  [--private-key IDENTITY.rbk]
  [--public-key IDENTITY.public.json]
  [--passphrase-file PATH] [--json]
```

Generates independent Ed25519 signing and X25519 HPKE seed material from
operating-system cryptographic randomness. The private `.rbk` is protected by
Argon2id and XChaCha20-Poly1305; its public package self-signs the display name,
both public keys and a fresh package nonce. The default outputs are
`rebyte-identity.rbk` and `rebyte-identity.public.json`.

Without `--passphrase-file`, the controlling terminal prompts twice without
echo. A passphrase file must satisfy the same private-file policy as publisher
keys. Never send the `.rbk` or its passphrase to another group member.

### `chain identity inspect`

```text
rebyte chain identity inspect IDENTITY.public.json [--json]
```

Rejects unknown fields, reformatted non-canonical JSON, invalid Base64URL,
malformed public keys, a changed encryption key or an invalid self-signature.
The reported `Identity ID` commits both purpose-specific keys.

### `chain group create`

```text
rebyte chain group create --name NAME
  --member ALICE.public.json
  [--member BOB.public.json ...]
  --threshold T --output GROUP.proposal.json [--json]
```

Public identities are validated, sorted and deduplicated. The immutable
`GroupId` commits the group name, random nonce, every complete public identity
and the capsule threshold. `1 <= T <= N`, with at most 64 members. `T` controls
later capsule approvals; group formation itself always requires all `N`
members.

### `chain group accept`

```text
rebyte chain group accept GROUP.proposal.json
  --private-key MEMBER.rbk [--passphrase-file PATH]
  --output MEMBER.group-acceptance.json [--json]
```

Recomputes the complete `GroupId`, requires the unlocked identity to be one of
the proposed members and signs the exact group/member binding. A private key
that does not correspond to the originally shared public identity cannot fill
that member's slot.

### `chain group finalize`

```text
rebyte chain group finalize GROUP.proposal.json
  --acceptance ALICE.group-acceptance.json
  [--acceptance BOB.group-acceptance.json ...]
  --output GROUP.json [--json]
```

Requires exactly one valid acceptance from every proposed member. Missing,
duplicate, foreign, rebound or incorrectly signed acceptances fail closed. The
output is the canonical unanimous group certificate used by capsule creation.

### `chain group inspect`

```text
rebyte chain group inspect GROUP.proposal.json [--json]
rebyte chain group inspect GROUP.json [--json]
```

For a proposal, revalidates `GroupId`, every identity proof, threshold and
canonical order so each member can review before accepting. For a certificate,
it additionally verifies every unanimous formation acceptance.

### `chain capsule create`

```text
rebyte chain capsule create --group GROUP.json --artifact ARTIFACT.rba
  --recipient ALICE.public.json
  [--recipient BOB.public.json ...]
  --output CAPSULE.proposal.rbep [--json]

rebyte chain capsule create --group GROUP.json --patch PATCH.json
  --recipient ALICE.public.json
  --output PATCH.proposal.rbep [--json]

rebyte chain capsule create --group GROUP.json --artifact ARTIFACT.rba
  --recipient READER.public.json
  --witness ALICE.public.json --witness BOB.public.json
  --release-threshold 2
  --not-before 2026-08-01T12:00:00Z
  [--maximum-releases 1]
  --output TIMED.proposal.rbep [--json]
```

Exactly one input is required. `--artifact` accepts a canonical `.rba` produced
by `rebyte encode --format binary`; `--patch` accepts canonical output from
`rebyte patch create`. Rebyte fully verifies the selected content, generates a
fresh 256-bit content-encryption key, encrypts it once with XChaCha20-Poly1305
and wraps that same key independently to every recipient using RFC 9180 HPKE.
Recipients are sorted, unique and limited to 64.

Without witnesses, Rebyte creates a direct-release Access Contract that binds the complete
group controller set, sealing threshold, content kind/digest/length, recipient
identities and the exact-artifact or semantic-patch capabilities. The resulting
`ProposalId` commits that contract, the group certificate, HPKE slots and
ciphertext digest. A group member is not implicitly a recipient.

With one or more `--witness` values, Rebyte creates a quorum contract and
HPKE-wraps one Shamir CEK share per witness. `--release-threshold` defaults to
all witnesses. `--not-before` accepts RFC 3339 with an explicit offset or
non-negative Unix milliseconds. A finite `--maximum-releases` requires the
threshold to equal the witness count.

### `chain capsule approve`

```text
rebyte chain capsule approve CAPSULE.proposal.rbep
  --private-key MEMBER.rbk [--passphrase-file PATH]
  --output MEMBER.capsule-approval.json [--json]
```

Only a member of the embedded unanimous group can approve. The Ed25519
signature binds `GroupId`, `ProposalId` and approving `IdentityId`, preventing
an approval from being reused for another group, member or encrypted proposal.

### `chain capsule finalize`

```text
rebyte chain capsule finalize CAPSULE.proposal.rbep
  --approval ALICE.capsule-approval.json
  [--approval BOB.capsule-approval.json ...]
  --output CAPSULE.rbe [--json | --print-token]
```

Verifies unique approvals against the immutable group threshold and emits the
canonical binary `.rbe`. `--print-token` additionally writes the equivalent
single-line `rbe2_` Base64URL form to stdout. The text token contains the same
encrypted bytes and can be very large; prefer `.rbe` for files and directories
that are not small.

### `chain capsule inspect`

```text
rebyte chain capsule inspect --file CAPSULE.proposal.rbep [--json]
rebyte chain capsule inspect --file CAPSULE.rbe [--json]
rebyte chain capsule inspect rbe2_TOKEN [--json]
```

For a proposal, validates the complete group certificate, Access Contract,
proposal commitments, recipients and canonical encoding so members can review
the `ContractId`, release policy and capabilities before approving. For a final
envelope, it additionally verifies the threshold approvals. Inspection never
decrypts the artifact. Public recipient names and capsule sizes are not
confidential metadata.

### `chain capsule open`

```text
rebyte chain capsule open --file CAPSULE.rbe
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --output FILE_OR_DIRECTORY [--raw-artifact] [--json]

rebyte chain capsule open rbe2_TOKEN
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --output FILE_OR_DIRECTORY [--json]
```

The output is created only after group, threshold, proposal, recipient HPKE,
payload AEAD, exact artifact length, Chain digest and inner `.rba` verification
all succeed. `--raw-artifact` writes the decrypted canonical `.rba` instead of
reconstructing its contents.

Each explicitly listed recipient can open independently after finalization.
The capsule threshold authorizes creation of the envelope; envelope v2 direct
release does not require fresh member participation for every open. Time and
maximum-release policies use the separate `chain release` ceremony below.

### `chain capsule diff`

```text
rebyte chain capsule diff --file CAPSULE.rbe
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --root DIRECTORY [--path SINGLE_FILE_TARGET] [--json]
```

Requires the contract's `diff` capability. The CLI verifies consensus,
contract, recipient HPKE, payload AEAD and the inner `.rba` before comparing
files and explicit directories through the confined read-only diff engine.
`--path` overrides approved name metadata only for a single-file artifact;
`--root` selects the destination root for a directory artifact.

### `chain capsule apply`

```text
rebyte chain capsule apply --file CAPSULE.rbe
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --root DIRECTORY [--path SINGLE_FILE_TARGET]
  [--dry-run | --yes] [--backup] [--json]
```

Requires the contract's `apply` capability. Unless `--yes` is supplied, Rebyte
shows the verified diff and asks for confirmation. `--dry-run` performs every
cryptographic and read-only filesystem check without writing.

Application reuses the same persistent journal, staging, precondition digest,
per-file atomic rename, post-write digest and rollback engine as signed RAP.
Explicit empty directories are journaled before creation and are removed on
rollback when they did not exist before the transaction. `--backup` retains
the committed journal and original bytes for an explicit later rollback.

### `chain capsule patch`

```text
rebyte chain capsule patch --file PATCH.rbe
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --target CONFIG.json [--dry-run | --yes] [--backup] [--json]
```

Requires an `applySemanticPatch` contract and canonical semantic-patch
plaintext. Consensus, contract, recipient HPKE, AEAD, digest and patch schema
are verified before the target is read. Patch preconditions and `test`
operations run before preview; commit revalidates the original digest, stages
beside the target, atomically replaces it and hashes the committed result.
`--backup` preserves the exact original bytes as `<target>.rebyte.bak`.

### `chain release request`

```text
rebyte chain release request --file CAPSULE.rbe
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --output REQUEST.json [--json]
```

Verifies the quorum capsule, confirms that the identity is a contract
recipient, generates a fresh 256-bit nonce and signs a request bound to the
exact envelope, proposal and contract. Send the same request and capsule to
each selected witness.

### `chain release grant`

```text
rebyte chain release grant --file CAPSULE.rbe
  --request REQUEST.json
  --private-key WITNESS.rbk [--passphrase-file PATH]
  --ledger WITNESS.ledger
  --acknowledge-local-authority
  --output WITNESS.grant.json [--json]
```

Verifies every binding and signature, checks the contract release time against
the witness OS clock, unwraps only that witness's share and atomically records
the request in a locked append-only ledger. The share is HPKE-encrypted to the
requesting recipient and the grant is signed by the witness.

`--acknowledge-local-authority` is mandatory because an ordinary OS clock and
local file are not intrinsically rollback-resistant. This command is strong
only when the witness host protects both. Production applications should
implement the Rust `TrustedClock` and `ReleaseLedger` interfaces with
hardware-backed or independently operated authority state.

### `chain release open`

```text
rebyte chain release open --file CAPSULE.rbe
  --request REQUEST.json
  --grant ALICE.grant.json --grant BOB.grant.json
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --output FILE_OR_DIRECTORY [--raw-artifact] [--json]
```

Requires exactly the contract threshold of unique witness grants. Rebyte
verifies their signatures, request bindings, observed times, ordinals and
share coordinates before reconstructing the CEK. Payload and artifact
verification then follows the normal strict path.

### `chain release patch`

```text
rebyte chain release patch --file PATCH.rbe
  --request REQUEST.json
  --grant ALICE.grant.json --grant BOB.grant.json
  --private-key RECIPIENT.rbk [--passphrase-file PATH]
  --target CONFIG.json [--dry-run | --yes] [--backup] [--json]
```

Performs the same quorum verification and then routes canonical patch content
through semantic preconditions, preview, confirmation, backup and atomic
replacement. A finite release allowance limits new witness-authorized
requests; it cannot prevent replay of grants or plaintext already retained by
the authorized recipient.

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
