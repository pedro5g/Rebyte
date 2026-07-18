# Rebyte Access Contract v1

Copyright (c) 2026 Pedro Martins (pedro5g)

Status: the canonical contract types and codec are implemented. Direct
recipient release is implemented by Chain envelope v2. Quorum release is
specified but rejected by the envelope until an independently reviewed,
interactive key-share protocol is implemented.

## Purpose

An Access Contract is the immutable authorization statement for one exact
protected object. It keeps five questions separate:

1. Which group controls capsule sealing?
2. Which identities may receive protected content?
3. Which exact plaintext digest and length are governed?
4. Which operations does the application intend to expose?
5. Which cryptographic mechanism releases the content key?

The contract never contains private keys, plaintext, passphrases or executable
instructions. It is not itself encryption. A consumer must bind it to an
encrypted envelope and fail closed when it cannot implement the selected
release mechanism.

## Canonical encoding

All integers are unsigned big-endian. Arrays contain a `u16` count followed by
that number of exact 32-byte `PrincipalId` values. Every participant array is
non-empty, sorted by raw bytes and contains no duplicate.

```text
AccessContract {
    magic                       [4]byte = "RBAC"
    version                     u16 = 1
    contract_nonce              [32]byte
    group_id                    [32]byte
    controller_count            u16
    controllers                 [controller_count][32]byte
    seal_threshold              u16
    recipient_count             u16
    recipients                  [recipient_count][32]byte
    capability_bits             u16
    content_kind                u8
    content_digest              [32]byte
    content_size                u64
    release_kind                u8
    release_body                varies
    contract_id                 [32]byte
}
```

`contract_nonce` is fresh 256-bit operating-system entropy. It ensures that
two independently issued contracts remain distinct even when every visible
policy field is equal.

`ContractId` is BLAKE3 derive-key mode over every preceding canonical byte
using the context:

```text
Rebyte access contract id v1 2026-07-18
```

The text form is `rc1_` followed by unpadded canonical Base64URL of the same
bytes. A contract is limited to 16 KiB binary or 22 KiB textual form.

## Participants and thresholds

`PrincipalId` is a protocol-neutral 32-byte identity. Chain v2 maps its
`IdentityId` and `GroupId` bytes directly into this type.

There are at most 64 controllers, recipients or release witnesses.
`seal_threshold` satisfies:

```text
1 <= seal_threshold <= controller_count
```

Chain v2 additionally requires exact equality between controllers and all
members of the unanimously formed group, and equality between
`seal_threshold` and the group's capsule threshold.

## Content commitment

Content kinds are:

| Value | Kind | Meaning |
|---:|---|---|
| 1 | `ExactArtifact` | Canonical byte-exact `.rba` file or directory |
| 2 | `SemanticPatch` | Canonical bounded structured patch |

The digest algorithm is selected by the binding protocol. Chain v2 uses its
domain-separated BLAKE3 embedded-artifact digest. Both the 32-byte digest and
the exact plaintext byte length must match before encryption and after
decryption.

## Capabilities

Known capability bits are:

| Bit | Name |
|---:|---|
| 0 | `inspectMetadata` |
| 1 | `decrypt` |
| 2 | `reconstruct` |
| 3 | `diff` |
| 4 | `apply` |
| 5 | `applySemanticPatch` |

An empty set or any unknown bit is invalid. Exact artifacts require `decrypt`
and at least one of `reconstruct`, `diff` or `apply`. Semantic patches require
`decrypt` and `applySemanticPatch`.

Capabilities constrain conforming APIs and user interfaces. Once an API
returns unrestricted plaintext to a hostile process, cryptography cannot
prevent that process from copying or modifying it. High-assurance capability
isolation therefore also requires a trusted execution boundary.

## Release policies

### Direct recipients

`release_kind = 1` has no body. The envelope may wrap its content-encryption
key independently to every listed recipient.

Direct release intentionally has no clock or usage fields. A standalone
decoder on an untrusted endpoint cannot reliably detect clock rollback, state
restoration or copied plaintext.

### Quorum release

`release_kind = 2` has:

```text
QuorumRelease {
    witness_count               u16
    witnesses                   [witness_count][32]byte
    release_threshold           u16
    has_not_before              u8
    not_before_unix_ms?         u64
    has_maximum_releases        u8
    maximum_successful_releases? u32
}
```

Each optional field begins with `0` for absent or `1` followed by its value.
Other tags are invalid. A maximum release count must be greater than zero.
The release threshold satisfies `1 <= T <= witness_count`.

Unix milliseconds are used because they are interoperable and sufficient for
authorization UX. More decimal precision does not make time more trustworthy.
Witnesses must obtain time from a documented trusted source, authenticate
fresh release requests and durably coordinate consumption of release
allowances.

`maximum_successful_releases = 1` means witnesses authorize at most one fresh
content-key release event. It does not mean an already authorized recipient
can be forced to forget a retained key or plaintext. Enforcing that stronger
claim requires trusted hardware that controls every use of the plaintext.

## Strict validation

Decoders reject:

- unknown versions, content kinds, release kinds, optional tags or capability
  bits;
- zero, duplicate, oversized or non-canonically ordered participant sets;
- invalid thresholds and zero release limits;
- incompatible content/capability combinations;
- truncation, trailing bytes, non-canonical Base64URL and oversized input;
- any mismatch between the stored `ContractId` and canonical body.

The Chain v2 binding additionally rejects a contract whose group, controllers,
threshold, recipients, content kind, digest or length differs from the
proposal. Unsupported release policies return a policy error before any
plaintext or content key is exposed.
