# Rebyte security model

Copyright (c) 2026 Pedro Martins (pedro5g)

## Verification order

The only permitted order for a signed capsule is:

1. enforce the textual or binary input limit;
2. decode Base64URL when the input is a token;
3. parse the fixed header with checked arithmetic;
4. parse the canonical manifest within declared limits;
5. validate algorithms, metadata, paths, ordering and ranges;
6. recompute the capsule digest and verify publisher policy and Ed25519;
7. decompress into bounded staging while hashing each reconstructed file;
8. compare all file digests and the declared output size;
9. calculate and display a sanitized plan;
10. receive confirmation unless `--yes` was supplied;
11. commit through the recoverable transaction engine;
12. reopen and hash committed files before completing the journal.

No target path is written before step 10. Controlled staging and journal data
may be created below the reserved `.rebyte/` directory and are removed after a
successful transaction.

An unsigned `ra1_`/`.rba` artifact follows a smaller, separate pipeline: bound
input, validate canonical Base64URL when textual, parse its fixed header and
canonical manifest, enforce exact stored and reconstructed lengths, decompress
into staging, compare envelope, content and per-file domain-separated digests,
and only then create a new output. Directory entries are portable and
symlinks are forbidden. There is deliberately no publisher or trust-policy
step, so this mode must not authorize installation or execution. The removed
`rf1_` format is not accepted by the definitive CLI/API.

An optional artifact dictionary is stored inside the canonical manifest. It
is bounded, covered by the envelope digest, permitted only for Zstandard and
never loaded from a destination or external path. Encoders retain a trained
candidate only after measuring a net reduction including its manifest cost.

## Chain envelope boundary

Chain identity v1 generates independent Ed25519 signing and X25519 HPKE keys.
The public package self-signs both keys, display name and a random nonce.
`IdentityId` is a domain-separated BLAKE3 commitment to that proof. The
passphrase-protected `.rbk` stores both private seeds under Argon2id and
XChaCha20-Poly1305. The current v2 scheme uses the RFC 9106 high-memory
profile (256 MiB, one pass, four lanes); v1 documents (64 MiB, three passes,
one lane) still unlock and `chain identity rekey` upgrades them in place with
a fresh salt and nonce. Exactly these two scheme-and-parameter pairs are
accepted; any other combination is rejected before key derivation. Public
identity, KDF parameters, salt and nonce are authenticated associated data.
Unlocking re-derives and compares both public keys. Secret seeds and
reconstructed Shamir shares remain in zeroizing containers, and debug output
for encrypted private documents redacts ciphertext and KDF inputs.

Group formation is always unanimous. `GroupId` commits the random group nonce,
threshold and complete sorted public identity packages. Every member signs the
same `GroupId` together with its own `IdentityId`; a different private key
cannot occupy that member slot.

Capsule creation first fully verifies a canonical `.rba` or Semantic Patch v1
and creates or validates a canonical Access Contract. The contract must exactly
match the group, complete controller set, sealing threshold, recipients,
content kind, protected-content digest and exact byte length.

Direct-recipient creation then generates a random 256-bit CEK and encrypts the
content once with XChaCha20-Poly1305. RFC 9180
HPKE Base mode with X25519-HKDF-SHA256, HKDF-SHA256 and ChaCha20-Poly1305 wraps
the same CEK independently to every sorted recipient. The proposal commitment
covers:

- the complete unanimous group certificate and `GroupId`;
- the complete Access Contract and `ContractId`;
- proposal and payload nonces;
- every complete recipient identity and HPKE slot;
- the encrypted payload digest.

At least the group's configured `T` unique members sign the exact
`GroupId || ProposalId || MemberIdentityId` binding. Duplicate members,
reordered data, approvals for another proposal and trailing bytes are rejected.

Opening verifies the canonical envelope, group formation, approval threshold,
all commitments and the exact recipient before HPKE decapsulation. Plaintext is
released only after payload authentication, exact length/digest checks and the
strict decoder selected by the contract content kind. CLI reconstruction uses
exclusive output creation and does not overwrite an existing path.
Contract-gated Chain diff and apply
convert the verified inner artifact into authenticated file/directory entries,
then reuse the capability-confined transaction engine. Empty directories are
journaled before creation; file staging, precondition checks, per-file renames,
post-write verification and rollback retain the same guarantees as signed RAP.

The capsule threshold authorizes envelope creation. Direct release is not a
threshold secret-sharing scheme and does not require members to approve every
future open. Every explicitly listed recipient can decrypt independently.

Challenge release wraps the same CEK twice: HPKE slots for listed recipients
(the audited path) and one XChaCha20-Poly1305 wrap under an Argon2id
derivation of a creator-chosen secret solution, bound to the proposal core as
associated data. The solution commitment is derived from the Argon2id output,
so every brute-force guess pays the full memory-hard cost. A challenge is a
cost gate, not access control: anyone holding the envelope may search, the
race cannot be revoked after publication, and challenge capsules must never
protect real confidential data. Claim documents prove solution knowledge via
a keyed digest that only another solution holder can verify; creator awards
countersign one claim as the human-arbitrated winner.

Identity status documents are owner-signed statements that retire or revoke a
Chain identity for new operations. `chain group create` and
`chain capsule create` reject denied members, recipients and witnesses when
the documents are supplied; distribution is offline and best-effort, and
historical envelopes remain openable because Chain has no trusted time.

For quorum release, the CEK is split into `N` Shamir shares over GF(256) with
threshold `T`; each witness receives one share under a distinct HPKE context.
The recipient signs a fresh envelope-bound request. A witness validates that
request, recipient, trusted time and release allowance, unwraps only its share,
constructs and signs a recipient-encrypted grant in memory, then atomically
records the request before returning it. A construction failure consumes no
allowance. Opening requires exactly `T` unique valid grants with one common
ledger ordinal, verifies the canonical witness coordinate of every share,
reconstructs the CEK and then repeats payload AEAD, digest, length and content
decoding.

Finite maximum-release policies require every witness (`T = N`). A repeated
request is idempotent; a different request consumes another allowance. The
native append-only ledger uses an advisory lock, chained BLAKE3 records,
`fsync` and restrictive permissions. It fails closed on mutation and safely
trims only an incomplete final crash record.

That local provider is cooperative, not an independent source of trusted time
or rollback-proof state. The CLI requires `--acknowledge-local-authority`.
Production deployments must back the `TrustedClock` and `ReleaseLedger` traits
with protected witness hosts, secure time and monotonic state. Even a valid
single release cannot force a recipient to delete retained grants, plaintext
or key material; replaying an already granted session remains possible.

## Semantic patch boundary

Semantic Patch v1 is a separate local format. On its own it is unsigned; inside
Chain v2 its exact canonical bytes are encrypted, contract-bound and approved
before application. The parser accepts at most 2 `MiB`, 512 operations, 64
pointer components and 1024 pointer bytes.
Unknown fields, duplicate JSON object keys, invalid pointer escapes and
unsupported TOML array paths are rejected. Values are data only: no expression,
template, command, environment interpolation, network or lifecycle hook is
evaluated.

Application opens the existing regular target without following symlinks,
checks an optional RAP file digest and ordered semantic `test` operations,
serializes in memory, stages beside the target, revalidates the original
digest, and replaces one file atomically. The result is reopened and hashed.
An optional backup is created exclusively and never overwritten. This provides
safe local preconditions and crash resistance for one file, not publisher
authentication or a multi-file transaction.

## Cryptographic domains

RAP v1 uses BLAKE3 derive-key mode with these exact context strings:

- `rebyte:v1:file`
- `rebyte:v1:manifest`
- `rebyte:v1:payload`
- `rebyte:v1:capsule`
- `rebyte:v1:key-id`

The Ed25519 message is the ASCII bytes `rebyte:v1:signature\0` followed by the
32-byte capsule digest. The capsule digest covers the canonical 80-byte header,
manifest bytes and compressed payload bytes. Consequently it also commits to
the publisher key ID, algorithms, lengths, paths and per-file digests.

The key ID is the 32-byte `rebyte:v1:key-id` digest of the Ed25519 public key.
It is an identifier, not an authorization decision. Trust channel and status
come from the local keyring.

All Ed25519 trust boundaries reject weak public keys and use strict signature
verification. This applies to RAP publishers, Chain identity proofs, group
acceptances, proposal approvals, release requests and witness grants.

Chain uses distinct derive-key contexts for identity IDs, group IDs, group
certificate digests, protected-content digests, proposal-core digests,
ciphertext digests, proposal IDs and envelope IDs. Ed25519 messages and AEAD
associated data also carry distinct fixed byte domains. The exact v2 strings
and binary layouts are frozen in [the Chain specification](../schemas/chain-v2.md).
Access policy encoding and its enforcement boundary are frozen separately in
[Access Contract v1](../schemas/access-contract-v1.md).

## Trust policy

- Active production keys are accepted by default.
- Active staging and development keys require an explicit allowed channel.
- Unknown, retired and revoked keys are rejected.
- RAP v1 has no creation timestamp, expiry semantics or user trust store.
- Test private keys are conspicuously labelled and never accepted as
  production keys.

## Filesystem guarantees

The root is opened as a directory capability. Protocol paths are portable and
prevalidated, and existing components are opened without following symlinks.
`.rebyte` is reserved for transaction state and cannot be a capsule target.

Before mutation, the engine records target precondition digests, stages and
verifies new bytes, copies recoverable backups, persists the journal and
revalidates targets. Each replacement is an atomic rename within the target
filesystem. A crash may expose a prefix of the requested changes, but the next
run can inspect, roll back or resume the persisted transaction.

Private keys and passphrase files are opened with `nofollow`. Regular-file
type, size and private Unix permission checks are performed on the same opened
handle that is read, avoiding a separate path-based permission-check window.

## Process hardening

The CLI hardens its own process best-effort at startup: the core-dump limit
is set to zero on Unix, and the Linux process is additionally marked
non-dumpable, which also blocks `ptrace` attachment by other unprivileged
processes. This keeps decrypted seeds and passphrases out of crash files and
casual debugger reach. It is not protection against root, a debugger started
before the process, cold-boot attacks or a compromised operating system, and
failures are ignored so restricted sandboxes can still run read-only
commands.

## Resource limits

| Resource | RAP v1 default |
|---|---:|
| Text token | 48 MiB |
| Binary capsule | 34 MiB |
| Manifest | 2 MiB |
| Compressed payload | 32 MiB |
| Reconstructed output | 128 MiB |
| Single file | 64 MiB |
| File count | 512 |
| UTF-8 path | 1024 bytes |
| Compression ratio | 200:1 |

Chain standard limits add 64 group members, 64 recipients, a 16 KiB Access
Contract, a 38 MiB binary envelope and a 52 MiB text token while retaining the
simple-artifact policy for the inner `.rba`.

Applications may lower these values. Raising them is a local policy decision;
the capsule or artifact cannot change them. The unsigned streaming
`LARGE_ARTIFACT` policy is an explicit CLI choice for `.rba` files and remains
bounded to 256 GiB reconstructed bytes, 256 GiB stored bytes, 64 MiB manifest
and 100,000 entries. Inline tokens never receive this larger policy.

## Unsafe and dependencies

Project crates forbid handwritten unsafe Rust. Dependencies may contain unsafe
internals and therefore remain part of the audit surface. Cargo.lock, RustSec,
license/source policy, fuzzing, Miri-compatible code paths and release SBOMs
provide complementary controls; none is presented as a proof of correctness.
