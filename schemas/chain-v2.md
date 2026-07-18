# Rebyte Chain envelope v2

Copyright (c) 2026 Pedro Martins (pedro5g)

Status: implemented native format. The implementation is fail-closed and
covered by unit, integration, mutation, truncation and fuzz-harness tests. It
has not received an independent cryptographic audit.

## Scope

Chain envelope v2 transports one canonical Rebyte `.rba` artifact with:

- self-custodied identities containing independent signing and encryption keys;
- unanimous proof-of-possession when a group is formed;
- `T-of-N` Ed25519 authorization of one exact encrypted capsule proposal;
- a canonical Access Contract binding content, controllers, recipients,
  capabilities and the content-key release mechanism;
- one payload ciphertext and one HPKE-wrapped content key per recipient;
- byte-exact file or portable-directory reconstruction after full validation.

The capsule sealing threshold authorizes envelope creation. It does not
require members to come online again for each open. Every listed recipient can
open a direct-release contract independently with its own private identity.
Quorum-release contracts are represented by the contract protocol but rejected
by envelope v2 until the interactive key-share protocol is implemented.

## Algorithms

Suite `1` fixes:

| Purpose | Algorithm |
|---|---|
| Member proof and approvals | Ed25519 |
| Recipient key wrapping | RFC 9180 HPKE Base mode: X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305 |
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
acceptances, group certificates and capsule approvals are strict
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
    artifact_digest       [32]byte
    artifact_size         u64
    payload_nonce         [24]byte
    recipient_count       u16
    recipients[recipient_count] {
        public_identity   bytes32
        hpke_encapped_key [32]byte
        wrapped_cek       [48]byte
    }
    ciphertext            bytes32
    proposal_id           [32]byte
}
```

Recipients are sorted and unique by `IdentityId`; v2 permits 1 to 64. The
inner artifact is fully decoded and verified before encryption. The encoder:

1. validates that the contract exactly binds the group ID, complete controller
   set, sealing threshold, recipient set, artifact digest, artifact size and
   exact-artifact content kind;
2. rejects quorum release rather than weakening it to direct recipient slots;
3. generates a fresh 32-byte CEK, proposal nonce and payload nonce;
4. computes the group-certificate, contract and proposal-core commitments;
5. encrypts the complete canonical `.rba` once with XChaCha20-Poly1305;
6. uses RFC 9180 HPKE independently for each public X25519 recipient key;
7. wraps only the same 32-byte CEK in each recipient slot;
8. computes `ProposalId` over the group, contract, recipients, HPKE slots and
   ciphertext digest.

The group, proposal nonce and recipient identity are bound into HPKE `info`.
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

## Standard limits

| Resource | Limit |
|---|---:|
| Group members | 64 |
| Recipients | 64 |
| Group JSON inside an envelope | 1 MiB |
| Public identity JSON inside a slot | 64 KiB |
| Binary proposal or envelope | 38 MiB |
| Canonical Access Contract | 16 KiB |
| Textual `rbe2_` token | 52 MiB |
| Inner artifact policy | `SecurityLimits::SIMPLE_ARTIFACT` |

Every declared length uses checked conversion and arithmetic. Unknown versions
or suites, zero recipients, duplicates, non-canonical ordering, truncation,
trailing bytes and limit violations are rejected.

## Opening order

Plaintext `.rba` bytes are released only after:

1. bounding the token or binary input;
2. strict Base64URL decoding when textual;
3. canonical proposal and envelope parsing with no trailing bytes;
4. verifying every public identity and unanimous group acceptance;
5. validating the canonical Access Contract and its identifier;
6. proving exact equality between the contract and group, sealing threshold,
   recipients, content digest and content size;
7. recomputing `GroupId`, `ProposalId` and `EnvelopeId`;
8. verifying the configured number of unique capsule approvals;
9. rejecting any unsupported release policy;
10. finding the opener's exact recipient identity and `decrypt` capability;
11. HPKE-decapsulating that recipient's CEK slot;
12. authenticating and decrypting the payload;
13. checking the exact plaintext length and Chain artifact digest;
14. decoding and fully verifying the inner canonical `.rba`;
15. reconstructing through the existing exclusive, no-symlink artifact path.

Cryptographic failures do not expose partial keys or plaintext in error
messages. Existing output paths are never overwritten by the CLI.

## Security boundary

The envelope protects confidentiality from parties without a listed recipient
private key and authenticates the group authorization that finalized it. It
does not hide payload size, recipient count or public identities. It cannot
force a recipient to delete plaintext after opening, protect secrets on a
compromised endpoint, prove a global timestamp or revoke a capsule already
possessed by an authorized recipient.

The cryptographic constructions follow
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) for HPKE and
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) for Ed25519. Independent
review remains required before high-value deployment.
