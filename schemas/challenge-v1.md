# Rebyte Chain Challenge v1 — draft

Copyright (c) 2026 Pedro Martins (pedro5g)

Status: design draft. No release implements this document yet. Field names,
domains and limits are not frozen; frozen behavior will be recorded here and
covered by canonical vectors before any implementing release.

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

`ReleasePolicy::Challenge` extends Access Contract v1 with:

```text
Challenge {
    workFunction        argon2id-v1 (memory-hard guess cost) — fixed for v1
    kdfMemoryKib        per-guess Argon2id memory cost
    kdfIterations       per-guess Argon2id passes
    parameterSchema     canonical description of the parameter vector fields
    solutionCommitment  BLAKE3 derive-key commitment to the canonical solution
    challengeSalt       random 32-byte salt; prevents cross-capsule precomputation
    wrappedKey          XChaCha20-Poly1305(CEK) under KDF(solution)
}
```

- The **canonical solution encoding** is the strict binary serialization of
  the parameter vector under `parameterSchema`. Two solvers with the same
  insight must produce identical bytes; ambiguity is a creator error.
- Each guess costs one Argon2id evaluation. The memory-hard work function
  narrows the advantage of GPUs and custom hardware over ordinary computers.
- `solutionCommitment` gives solvers a cheap local success check before the
  AEAD unwrap. A wrong solution fails both the commitment and the AEAD.
- The challenge slot binds to the proposal core digest exactly like HPKE
  slots, so hints, contract and ciphertext cannot be recombined.

## Sharded challenges

To reduce luck variance and support teams, a challenge MAY split the CEK into
`N` Shamir shares over GF(256) with threshold `T`, each share wrapped under an
independent sub-solution. A team divides sub-puzzles among its members and
pools recovered shares; a lone solver grinds them sequentially. Progress is
observable ("11 of 20 shares solved") without weakening the unsolved shares.

## Winner protocol

Solving is self-evident — the solver holds the plaintext — but exclusivity is
not enforceable offline: a published solution opens the capsule for everyone.
When one official winner matters, the human creators arbitrate:

1. the solver produces a signed claim document binding the envelope ID, its
   identity and the solution commitment (never the raw solution);
2. creators countersign the first valid claim they accept;
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
