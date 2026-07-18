# Rebyte Chain envelope v2

Copyright (c) 2026 Pedro Martins (pedro5g)

Status: implemented native format. The implementation is fail-closed and
covered by unit, integration, mutation, truncation and fuzz-harness tests. It
has not received an independent cryptographic audit.

## Scope

Chain envelope v2 transports one canonical Rebyte `.rba` artifact or one
canonical Semantic Patch v1 document with:

- self-custodied identities containing independent signing and encryption keys;
- unanimous proof-of-possession when a group is formed;
- `T-of-N` Ed25519 authorization of one exact encrypted capsule proposal;
- a canonical Access Contract binding content, controllers, recipients,
  capabilities and the content-key release mechanism;
- one payload ciphertext and either one HPKE-wrapped CEK per direct recipient
  or one HPKE-wrapped Shamir share per release witness;
- byte-exact file/directory reconstruction or bounded semantic application
  after full validation.

The capsule sealing threshold authorizes envelope creation. It does not
require members to come online again for each open. Every listed recipient can
open a direct-release contract independently with its own private identity.
Quorum-release contracts require a fresh recipient-signed request and the
configured number of independently signed witness grants. Each grant carries
only that witness's share, encrypted to the requesting recipient.

## Algorithms

Suite `1` fixes:

| Purpose | Algorithm |
|---|---|
| Member proof and approvals | Ed25519 |
| Recipient key wrapping | RFC 9180 HPKE Base mode: X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305 |
| Quorum CEK sharing | Shamir secret sharing over GF(256), 32-byte secret, 1-byte nonzero share coordinate |
| Artifact payload | XChaCha20-Poly1305 with a fresh random 256-bit CEK |
| Fingerprints and commitments | BLAKE3 derive-key mode with distinct contexts |
| Private identity KDF | Argon2id v1.3, 64 MiB, 3 iterations, 1 lane |
| Private identity encryption | XChaCha20-Poly1305 |
| Text encoding | Base64URL without padding |

Signing and encryption private keys are independently generated. An
`IdentityId` covers the display name, both public keys, a random package nonce
and the Ed25519 proof. Rebyte never derives a group key by concatenating,
hashing or XORing members' private keys.

All random keys, nonces and salts come from the operating-system cryptographic
random source. Failure to obtain entropy aborts the operation.

## Canonical control documents

Public identities, encrypted private identities, group proposals, group
acceptances, group certificates, capsule approvals, release requests and
release grants are strict
schema-versioned JSON documents. Unknown fields are rejected. Base64URL fields
must be unpadded and canonical.

For JSON control documents, the wire representation is exactly the UTF-8
pretty JSON emitted by
the Rust implementation, including field order, two-space indentation and one
final line feed. Parsing and reserialization must reproduce every byte.
Whitespace-reformatted JSON is therefore rejected even if its data model is
equivalent.

Identity and group display names contain 1 to 256 UTF-8 bytes and no control
characters. A group contains 1 to 64 sorted, unique identities. Its capsule
threshold satisfies `1 <= T <= N`.

Group formation is always `N-of-N`. Each acceptance signs:

```text
"rebyte chain group acceptance v1\0" ||
GroupId ||
MemberIdentityId
```

The `GroupId` commits to the version, name, random group nonce, capsule
threshold and every complete public identity package in ascending
`IdentityId` order. A certificate is valid only when every proposed member has
one valid acceptance made by that member's declared Ed25519 key.

## Private identity bundle

An `.rbk` stores:

- the complete self-signed public identity;
- fixed Argon2id parameters;
- a random 16-byte salt;
- a random 24-byte nonce;
- encrypted independent 32-byte Ed25519 and X25519 seed material.

The fixed KDF parameters, public identity, salt and nonce are authenticated as
AEAD associated data. Unlocking re-derives both public keys and the
`IdentityId`; a mismatch is rejected. Passphrases contain 12 to 1024 bytes.

The encrypted bundle and passphrase must be kept in separate verified backups.
Losing both the bundle and every recovery copy makes its recipient slots
unrecoverable. Copying the public identity never grants decryption authority.

## Binary proposal

Integers are unsigned big-endian. `bytes32` means a `u32` byte length followed
by exactly that many bytes. There are no alignment bytes.

```text
CapsuleProposal {
    magic                 [4]byte = "RBEP"
    wire_version          u16 = 2
    crypto_suite          u16 = 1
    group_certificate     bytes32
    access_contract       bytes32
    proposal_nonce        [32]byte
    content_digest        [32]byte
    content_size          u64
    payload_nonce         [24]byte
    key_holder_count      u16
    key_holders[key_holder_count] {
        public_identity   bytes32
        hpke_encapped_key [32]byte
        wrapped_key       [48]byte direct | [49]byte quorum
    }
    ciphertext            bytes32
    proposal_id           [32]byte
}
```

Key holders are sorted and unique by `IdentityId`; v2 permits 1 to 64. They
are the direct recipients for `directRecipients` and the witnesses for
`quorum`. The protected content is fully decoded and verified before
encryption. The encoder:

1. validates that the contract exactly binds the group ID, complete controller
   set, sealing threshold, recipient set, content digest, content size and
   content kind;
2. validates that key holders exactly equal the direct recipients or quorum
   witnesses selected by the release policy;
3. generates a fresh 32-byte CEK, proposal nonce and payload nonce;
4. computes the group-certificate, contract and proposal-core commitments;
5. encrypts the complete canonical `.rba` or patch once with
   XChaCha20-Poly1305;
6. for direct release, HPKE-wraps the same 32-byte CEK for every recipient;
7. for quorum release, splits the CEK with a degree `T-1` polynomial over
   GF(256) and HPKE-wraps one 33-byte `x || y[32]` share for every witness;
8. computes `ProposalId` over the group, contract, holders, HPKE slots and
   ciphertext digest.

The group, proposal nonce, holder identity and release mode are bound into HPKE `info`.
The proposal-core digest is HPKE associated data. The full proposal core is
payload associated data. Reordering, removing, adding or substituting a
recipient invalidates the proposal.

## Capsule approval and final envelope

One approval signs:

```text
"rebyte chain capsule approval v2\0" ||
GroupId ||
ProposalId ||
ApprovingMemberIdentityId
```

An approval from a non-member, another group, another proposal or the wrong
private key is invalid. Duplicate approvals never count twice.

```text
CapsuleEnvelope {
    magic                 [4]byte = "RBEE"
    wire_version          u16 = 2
    crypto_suite          u16 = 1
    proposal              bytes32
    approval_count        u16
    approvals[approval_count] {
        member_id         [32]byte
        signature         [64]byte
    }
    envelope_id           [32]byte
}
```

Approvals are sorted and unique by member identity. `approval_count` must meet
the immutable threshold in the unanimous group certificate. `EnvelopeId`
commits to `ProposalId` and every approval identity/signature pair.

A binary envelope uses `.rbe`. The textual form is `rbe2_` followed by
unpadded Base64URL of those exact bytes. Text is transport encoding, not
additional cryptography.

Envelope v1 and the `rbe1_` text form are deliberately not accepted by the v2
decoder. Applications must never guess a version or reinterpret old bytes
under new authorization semantics.

## Quorum release session

A recipient creates canonical `rebyte-chain-release-request` JSON containing
`EnvelopeId`, `ProposalId`, `ContractId`, its complete public identity, a fresh
32-byte nonce, `RequestId` and an Ed25519 signature. The request message is:

```text
"rebyte chain release request signature v1\0" ||
version || EnvelopeId || ProposalId || ContractId || request_nonce ||
bytes32(recipient_public_identity)
```

`RequestId` is BLAKE3 derive-key mode over that message and signature with
context `Rebyte Chain release request id v1 2026-07-18`.

Each witness verifies the complete envelope, request signature, recipient,
contract, trusted time and durable ledger. It unwraps only its own proposal
share, atomically records the request and HPKE-wraps the share to the
requesting recipient. Canonical `rebyte-chain-release-grant` JSON binds:

- `RequestId`, `EnvelopeId` and the complete witness public identity;
- the witness-observed Unix time in milliseconds;
- the durable ledger ordinal;
- a fresh HPKE encapsulation and 49-byte encrypted share;
- a domain-separated `GrantId` and witness Ed25519 signature.

The recipient accepts exactly `T` unique grants from contract witnesses,
verifies every signature/binding/time/ordinal, HPKE-opens each share and checks
that its coordinate matches the witness's canonical policy position. Shamir
interpolation reconstructs the CEK at `x = 0`; payload AEAD, digest, length and
the content decoder are then revalidated.

Finite `maximumSuccessfulReleases` requires `T = N`. Without a consensus
ledger, this prevents two different concurrent requests from succeeding
through partially overlapping quorums. A repeated `RequestId` is idempotent
and retains its original ordinal.

The native CLI's append-only ledger and operating-system clock are a
cooperative authority. They are useful only on a witness host whose clock,
filesystem and backups are protected from rollback. A production authority
must implement the `TrustedClock` and `ReleaseLedger` traits with independent
trusted time and monotonic durable state.

## Standard limits

| Resource | Limit |
|---|---:|
| Group members | 64 |
| Recipients | 64 |
| Release witnesses | 64 |
| Release request or grant JSON | 256 KiB |
| Group JSON inside an envelope | 1 MiB |
| Public identity JSON inside a slot | 64 KiB |
| Binary proposal or envelope | 38 MiB |
| Canonical Access Contract | 16 KiB |
| Textual `rbe2_` token | 52 MiB |
| Inner artifact policy | `SecurityLimits::SIMPLE_ARTIFACT` |
| Semantic patch plaintext | 2 MiB |

Every declared length uses checked conversion and arithmetic. Unknown versions
or suites, zero recipients, duplicates, non-canonical ordering, truncation,
trailing bytes and limit violations are rejected.

## Opening order

Protected plaintext is released only after:

1. bounding the token or binary input;
2. strict Base64URL decoding when textual;
3. canonical proposal and envelope parsing with no trailing bytes;
4. verifying every public identity and unanimous group acceptance;
5. validating the canonical Access Contract and its identifier;
6. proving exact equality between the contract and group, sealing threshold,
   recipients, content digest and content size;
7. recomputing `GroupId`, `ProposalId` and `EnvelopeId`;
8. verifying the configured number of unique capsule approvals;
9. selecting direct release or verifying a fresh recipient request plus `T`
   unique witness grants;
10. finding the opener's exact recipient identity and `decrypt` capability;
11. HPKE-decapsulating the direct CEK, or the witness shares and reconstructing
    the CEK;
12. authenticating and decrypting the payload;
13. checking the exact plaintext length and protected-content digest;
14. selecting the strict decoder from the contract content kind;
15. decoding the inner canonical `.rba` or Semantic Patch v1;
16. reconstructing through the exclusive no-symlink path, or applying
    semantic operations through precondition, preview, confirmation, atomic
    replacement and post-write verification.

Cryptographic failures do not expose partial keys or plaintext in error
messages. Existing output paths are never overwritten by the CLI.

## Security boundary

The envelope protects confidentiality from parties without a listed recipient
private key and, for quorum mode, the configured witness shares. It
authenticates the group authorization that finalized it. It
does not hide payload size, recipient count or public identities. It cannot
force a recipient to delete plaintext after opening, protect secrets on a
compromised endpoint, independently prove a global timestamp or revoke
plaintext/key/grants already retained by an authorized recipient. A maximum
release count limits fresh witness-authorized sessions; it cannot make already
released bytes mathematically disappear.

The cryptographic constructions follow
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) for HPKE and
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) for Ed25519. Independent
review remains required before high-value deployment.
