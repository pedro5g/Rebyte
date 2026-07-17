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
step, so this mode must not authorize installation or execution. Legacy
`rf1_` tokens retain their original single-file decode pipeline.

An optional artifact dictionary is stored inside the canonical manifest. It
is bounded, covered by the envelope digest, permitted only for Zstandard and
never loaded from a destination or external path. Encoders retain a trained
candidate only after measuring a net reduction including its manifest cost.

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

Applications may lower these values. Raising them is a local policy decision;
the capsule or artifact cannot change them. The unsigned streaming
`LARGE_ARTIFACT` policy is an explicit CLI choice for `.rba` files and remains
bounded to 256 GiB reconstructed bytes, 64 GiB stored bytes, 64 MiB manifest
and 100,000 entries. Inline tokens never receive this larger policy.

## Unsafe and dependencies

Project crates forbid handwritten unsafe Rust. Dependencies may contain unsafe
internals and therefore remain part of the audit surface. Cargo.lock, RustSec,
license/source policy, fuzzing, Miri-compatible code paths and release SBOMs
provide complementary controls; none is presented as a proof of correctness.
