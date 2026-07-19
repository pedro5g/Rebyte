# Rebyte Chain Challenge v1 — draft

Copyright (c) 2026 Pedro Martins (pedro5g)

Status: core implemented (`rebyte-contract` release tag 3, `rebyte-chain`
challenge module, `rebyte chain challenge` CLI). Sharded sub-puzzles remain a
draft extension. The implemented v1 encodes the solution as an exact secret
byte string chosen by the creators; the "parameter vector" is expressed
through that string's documented construction and the public hint rather than
a machine-readable schema.

Frozen vectors (`rebyte-chain/src/vector_tests.rs`) pin the Argon2id solution
derivation, the commitment construction and one complete finalized challenge
envelope. A failing vector means stored challenges would stop opening; never
update an expected value without a version bump and a re-encode plan.

## Concept

A challenge capsule is an encrypted envelope whose content key is released by
**solving**, not by identity. The creators choose a secret parameter vector,
derive the content-encryption key (CEK) wrapping from it, and publish the
capsule together with any hints they want. Anyone holding the token may
attempt to open it, alone or in a team, with any amount of computation.
Whoever reconstructs the exact parameter vector opens the capsule and holds
the prize.

The intended difficulty is **insight plus work**: creators point at the
parameters through hints, documentation or a puzzle narrative. A solver who
understands the pointers searches a small space; a solver who does not brute
forces a large one. Difficulty therefore adapts to comprehension, never to
the number of participants: an offline capsule cannot observe how many people
are solving, and this specification makes no such claim.

## Release policy

`ReleasePolicy::Challenge` (wire tag 3) extends Access Contract v1 with:

```text
Challenge {
    kdfMemoryKib        u32   per-guess Argon2id memory cost, 8 MiB..=1 GiB
    kdfIterations       u32   per-guess Argon2id passes, 1..=16
    solutionCommitment  32B   BLAKE3 derive-key commitment to the derived key
    challengeSalt       16B   random per-capsule Argon2id salt
    hint                utf8  <=1024 bytes, no control characters
}
```

The envelope proposal additionally carries one challenge slot after the
payload ciphertext, present exactly when the contract release is Challenge
and committed by the `ProposalId`:

```text
ChallengeSlot {
    nonce       24B   fresh random XChaCha20-Poly1305 nonce
    wrappedKey  48B   XChaCha20-Poly1305(CEK) under the derived solution key
}
```

- The solution is an exact secret byte string (1..=4096 bytes; the CLI
  ignores one trailing newline). Two solvers with the same insight must
  produce identical bytes; ambiguity is a creator error.
- `derivedKey = Argon2id(solution, challengeSalt, kdfMemoryKib,
  kdfIterations, 1 lane)`. Each guess costs one full evaluation; the
  memory-hard work function narrows GPU and custom-hardware advantage.
- `solutionCommitment = BLAKE3-derive("Rebyte Chain challenge commitment v1
  2026-07-18", derivedKey)`. Deriving the commitment from the Argon2id
  output — never from the raw solution — keeps every brute-force check at
  full cost while giving honest solvers a constant-time success check.
- The challenge wrap uses associated data bound to the proposal core digest,
  so hints, contract and ciphertext cannot be recombined.

## Sharded challenges

Implemented as `ReleasePolicy::ShardedChallenge` (wire tag 4). The CEK is
split into `N` Shamir shares over GF(256) with threshold `T`; each share is
wrapped under an independent sub-solution. A team divides sub-puzzles among
its members and pools recovered shares; a lone solver grinds them
sequentially. Progress is observable — `chain challenge check` verifies one
sub-solution against its shard commitment — without weakening the unsolved
shards.

```text
ShardedChallenge {
    kdfMemoryKib   u32   per-guess Argon2id memory cost, 8 MiB..=1 GiB
    kdfIterations  u32   per-guess Argon2id passes, 1..=16
    threshold      u16   1..=shardCount recovered shares reconstruct the CEK
    shardCount     u16   2..=32
    shards[]             per shard: salt 16B, commitment 32B,
                         hint u16-length utf8 <=128B
    hint           utf8  overall hint, <=1024 bytes
}
```

The envelope carries one shard slot per contract shard after the payload
ciphertext, present exactly when the release is ShardedChallenge and
committed by the `ProposalId`:

```text
ChallengeShardSlot {
    nonce         24B   fresh random XChaCha20-Poly1305 nonce
    wrappedShare  49B   XChaCha20-Poly1305(share) under the derived
                        sub-solution key; share = 1B coordinate + 32B data
}
```

- `shardKey_i = Argon2id(subSolution_i, salt_i, kdfMemoryKib,
  kdfIterations, 1 lane)`; the commitment is
  `BLAKE3-derive("Rebyte Chain challenge shard commitment v1 2026-07-19",
  shardKey_i)`, so every brute-force check pays full cost.
- The shard wrap AAD binds the zero-based shard index and the proposal
  core, so shares cannot be re-indexed or moved between envelopes.
- Opening requires exactly `threshold` distinct verified sub-solutions.
- Sharded claims replace the solution-derived proof key with
  `BLAKE3-derive("Rebyte Chain sharded challenge claim key v1 2026-07-19",
  CEK)`; a listed recipient judge recovers the CEK through its own audited
  slot and verifies claims without ever holding the sub-solutions.

## Winner protocol

Solving is self-evident — the solver holds the plaintext — but exclusivity is
not enforceable offline: a published solution opens the capsule for everyone.
When one official winner matters, the human creators arbitrate:

1. the solver produces a signed claim binding the envelope, contract, a
   fresh nonce and a proof digest keyed by the derived solution key — never
   the raw solution; only another solution holder can verify the proof;
2. a creator verifies the proof with the solution and countersigns the first
   claim it accepts, producing a signed award naming that solver;
3. the countersigned claim is the portable winner certificate.

## Creator-audited release

A challenge capsule MAY additionally carry ordinary direct-recipient or
quorum slots for the creators. This is the "audit" path: creators can always
open their own capsule, or grant a quorum release, without solving.

## Explicit limits

- A challenge is a **cost gate, not access control**. Content behind a
  challenge is public information with a price. Never protect real
  intellectual property, personal data or credentials with a challenge.
- No calendar time. A challenge bounds work, not dates; witness quorum
  release remains the only date mechanism.
- The race is irrevocable. Publishing the token publishes the race; creators
  can open early but cannot cancel other solvers.
- Single-puzzle solve time has high variance; a lucky guess can succeed
  immediately. Sharding reduces but does not remove variance.
- Wall-clock difficulty is an economic estimate. Creators control total
  expected work, not the hardware other people own.
- Solving consumes real energy on solver machines by design.

## Abuse cases required in tests

Wrong solutions at every length; solutions differing only in canonical
encoding; tampered commitments, salts, schemas and wrapped keys; challenge
slots rebound to other envelopes; shard subsets below threshold; duplicate
shard coordinates; claim documents rebound to other envelopes or solvers;
and countersignatures from non-creator identities.
