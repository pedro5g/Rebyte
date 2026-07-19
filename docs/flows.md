# Rebyte usage flows

Copyright (c) 2026 Pedro Martins (pedro5g)

This page maps every implemented Rebyte workflow as a diagram, so a reader can
see the complete space of possibilities before choosing one. Each section
links to the reference that freezes its exact behavior. Draft capabilities are
explicitly marked and are not part of any release.

## Choosing a flow

```mermaid
flowchart TD
    S{What must the receiver get?}
    S -->|proof bytes are unchanged| H[rebyte hash<br/>domain-separated BLAKE3]
    S -->|the exact bytes back| A{Who may read them?}
    S -->|one changed config field| P[patch create / apply<br/>Semantic Patch v1]
    A -->|anyone holding the token| T{Must the producer be authenticated?}
    T -->|no| ART[encode / decode<br/>ra1_ token or .rba file]
    T -->|yes| RAP[key generate → pack →<br/>verify → diff → apply<br/>rb1_ / .rbc]
    A -->|only listed identities| C{Fresh cooperation at each opening?}
    C -->|no · offline open| DIR[chain capsule create →<br/>approve → finalize → open<br/>.rbe / rbe2_]
    C -->|yes · witnesses, time, count| Q[chain release request →<br/>grant → open]
```

Properties never upgrade silently: a digest is not a signature, a signature is
not encryption, and encryption to a recipient is not fresh consent. The
[concepts guide](concepts.md) explains each rung; the
[security model](security-model.md) freezes the verification order.

## Unsigned artifact

```mermaid
flowchart LR
    I[file or portable directory] --> E[encode]
    E -->|ra1_ token| X[any transport:<br/>chat, QR, file, USB]
    E -->|.rba binary| X
    X --> D[decode]
    D -->|every digest verified| O[byte-exact copy]
    D -->|any mutation| R[typed rejection,<br/>no output written]
```

No key, no identity: corruption detection only. Reference:
[Artifact Token v1](../schemas/artifact-token-v1.md).

## Signed publisher capsule

```mermaid
flowchart LR
    K[key generate<br/>encrypted private + public doc] --> PK[pack<br/>sign exact tree]
    PK --> V[verify / inspect<br/>trust channel + strict Ed25519]
    V --> DF[diff / apply --dry-run<br/>sanitized preview]
    DF --> AP[apply<br/>journaled transaction]
    AP -->|interrupted| RC[transactions →<br/>resume / rollback]
    K -.->|rotation / compromise| ST[key status<br/>retired / revoked]
```

Trust is local and explicit: verifiers accept only keys they were given.
References: [RAP v1](../schemas/rap-v1.md), [key management](key-management.md).

## Chain identity lifecycle

```mermaid
stateDiagram-v2
    [*] --> Generated: chain identity generate
    Generated --> Published: share .public.json
    Published --> Trusted: compare fingerprint words out of band
    Generated --> BackedUp: chain identity backup (T-of-N shares)
    BackedUp --> Distributed: one signed share per trustee
    Trusted --> InUse: groups, capsules, witnessing
    InUse --> Lost: device or passphrase lost
    Lost --> Restored: chain identity restore (any T shares)
    Restored --> BackedUp: issue fresh shares
    Restored --> InUse: same IdentityId, new passphrase
    InUse --> Denied: chain identity status (retired / revoked)
    Denied --> Denied: rejected by group and capsule creation
```

The proquint fingerprint (sixteen pronounceable words shown by `generate` and
`inspect`) exists for the `Published → Trusted` edge: read the words aloud
over an independent channel before admitting an identity to a group.

### Threshold backup ceremony

```mermaid
sequenceDiagram
    autonumber
    participant O as Owner
    participant T as Trustees 1..N
    participant R as Recovery machine
    O->>O: unlock .rbk, split both seeds T-of-N
    O->>T: one signed share document each
    Note over T: below T shares reveal nothing;<br/>any T shares are the identity
    O--xO: bundle or passphrase lost
    T-->>R: T distinct shares collected
    R->>R: verify share signatures and identity binding
    R->>R: reconstruct seeds, verify against public identity
    R->>R: re-encrypt .rbk under a new passphrase
    R->>O: same IdentityId restored
```

Shares carry no passphrase protection by design: guard each one like a secret
and never store two shares together. Operational guidance lives in the
[Chain operations runbook](chain-operations.md).

## Group consensus and direct capsule

```mermaid
sequenceDiagram
    autonumber
    participant C as Coordinator
    participant M as Every member
    participant R as Listed recipient
    C->>M: group create → canonical proposal
    M-->>C: group accept (proves own private key)
    C->>C: group finalize (always unanimous)
    C->>C: capsule create · encrypt once,<br/>HPKE slot per recipient
    C->>M: capsule proposal
    M-->>C: capsule approve (T of N sign exact ProposalId)
    C->>C: capsule finalize → .rbe / rbe2_
    C-->>R: envelope by any transport
    R->>R: capsule open / diff / apply<br/>full verification before plaintext
```

Controllers, recipients and capabilities are independent sets bound by the
Access Contract; changing any protected field invalidates every approval.
References: [Chain v2](../schemas/chain-v2.md),
[Access Contract v1](../schemas/access-contract-v1.md),
[Chain architecture](chain-architecture.md).

## Quorum release session

```mermaid
sequenceDiagram
    autonumber
    participant R as Recipient
    participant W as Witnesses 1..N
    R->>R: release request · fresh signed RequestId
    R->>W: request + envelope
    W->>W: verify recipient, trusted time,<br/>durable allowance
    W-->>R: release grant · signed HPKE share,<br/>one common ordinal
    R->>R: release open · exactly T unique grants,<br/>interpolate CEK, re-verify AEAD + digests
```

Rolling back a single witness ledger only desynchronizes its ordinal and the
open fails closed; defeating a finite release limit requires consistently
rolling back every witness. The CLI file ledger needs
`--acknowledge-local-authority`; production requires protected `TrustedClock`
and `ReleaseLedger` providers.

## Semantic patch

```mermaid
flowchart LR
    PC[patch create<br/>typed JSON/TOML operations] --> PI[patch inspect]
    PI --> PD[patch apply --dry-run]
    PD --> PA[patch apply<br/>preconditions + atomic replace]
    PC -.->|confidential + approved| CE[chain capsule create --patch<br/>same consensus envelope]
    CE --> CP[chain capsule patch]
```

Patch values are inert data; nothing is executed. Standalone patches are
unsigned local instructions — carry them inside Chain when authorship and
authorization matter. Reference:
[Semantic Patch v1](../schemas/semantic-patch-v1.md).

## Challenge capsule

```mermaid
flowchart LR
    CR[creators choose a secret solution] --> EN[capsule create --challenge-solution-file<br/>CEK wrapped under Argon2id of solution]
    EN --> PUB[publish token · open race]
    PUB --> SV{solver insight}
    SV -->|understood the hint| SMALL[small search space]
    SV -->|brute force| LARGE[large search space<br/>full Argon2id cost per guess]
    SMALL --> OPEN[chain challenge solve<br/>solution → CEK → prize]
    LARGE --> OPEN
    CR -.->|audited path| AUD[creators open via<br/>chain capsule open]
    OPEN --> CL[chain challenge claim →<br/>creator award countersignature]
```

A challenge is a cost gate, not access control: anyone holding the envelope
may search, the race is irrevocable after publication, and real confidential
data must never sit behind one. Reference:
[Challenge v1](../schemas/challenge-v1.md).

## Draft flows — not implemented

The following diagram describes a design draft only
([Key Sequence v1](../schemas/key-sequence-v1.md)). No release implements it.

### Key sequence (draft)

```mermaid
flowchart LR
    CEK[content key] --> L1[HPKE layer · key 1]
    L1 --> L2[HPKE layer · key 2]
    L2 --> L3[HPKE layer · key n]
    L3 --> ENV[envelope + ordered public recipe]
    ENV --> U3[unwrap with private key n]
    U3 --> U2[unwrap with private key 2]
    U2 --> U1[unwrap with private key 1]
    U1 --> OPEN[verified plaintext]
```

The gain is custody separation — each key on a different device or location.
Keys are never derived from other keys; every position is an ordinary
identity with its own backup lifecycle.
