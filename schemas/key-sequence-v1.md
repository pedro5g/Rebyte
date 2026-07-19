# Rebyte Chain Key Sequence v1

Copyright (c) 2026 Pedro Martins (pedro5g)

Status: implemented (`rebyte-contract` release tag 5, `rebyte-chain`
key-sequence envelope support, `chain capsule create --recipient-sequence`
and `chain capsule open-sequence`).

## Concept

A key sequence requires one recipient to hold **several** private keys and
apply them in a declared order before the content key is recovered. The CEK
is wrapped in nested HPKE layers ("onion" wrapping): the innermost layer
encapsulates to the first listed key, and each further layer encapsulates the
previous ciphertext to the next key. Opening unwraps in reverse order; a
missing or wrong key at any position fails closed without revealing whether
deeper layers would have succeeded.

Holding the capsule and one key is deliberately insufficient. The practical
security gain comes from **storage separation**: each listed key should live
on a different device, location or custody arrangement, so one stolen laptop
or leaked backup no longer opens the capsule. Two sequence keys stored in the
same folder provide essentially the security of one key; the specification
and CLI documentation must state this plainly.

## Derivation rule

Chain architecture already fixes the rule this document inherits: Rebyte
MUST NOT derive a new private key by concatenating, XORing or otherwise
improvising over existing private keys. A "more powerful key" is expressed
as this access policy over independent keys, never as key-material
arithmetic. Every sequence position is an ordinary self-custodied identity
with its own generation, backup and revocation lifecycle.

## Recipe

The envelope publishes an ordered recipe of the required key identities:

```text
KeySequence { depth u16 }        release tag 5; 2..=8, uniform per capsule

per recipient slot:
    holder                       outermost public identity (ordinary slot)
    encappedKey    32B           outermost HPKE encapsulation
    wrappedKey     48*depth B    nested ciphertext; layer i seals
                                 (encapped_{i-1} || ct_{i-1}), innermost
                                 layer seals the 32B CEK
per slot recipe (after ciphertext, committed by the ProposalId):
    inner identities             depth-1 full public documents, innermost
                                 first; the slot holder is the last position
```

Each layer's HPKE info binds the group, proposal nonce, position holder and
the zero-based position index, so a key cannot be applied at another
position. The contract recipient entry for one sequence is a composite
principal: `BLAKE3-derive("Rebyte Chain key sequence principal v1
2026-07-19", ids innermost..outermost)`. Opened content reports that
composite principal as its recipient.

Version 1 restrictions: every sequence in one capsule shares the same depth,
no identity may repeat inside one sequence, outermost identities must be
distinct across sequences, and sequence capsules protect exact artifacts
with the standard apply capability set.

- The order is part of the Access Contract through the composite principal,
  so reordering, dropping or substituting a position changes the
  `ContractId` and `ProposalId` and invalidates approvals.
- The recipe is public metadata, consistent with Chain's existing exposure
  of recipient identities. Hiding *which* keys are required is a non-goal.
- The CLI prints the recipe when the capsule is created and after `inspect`,
  and accepts repeated ordered `--private-key`/`--passphrase-file` arguments
  on open. Machine output lists the ordered identity IDs and fingerprints so
  the receiving side knows exactly which bundles to unlock and in which
  order.

## Composition

A key sequence composes with existing release policies: each direct
recipient slot MAY independently be a single key or a sequence, and quorum
witness shares keep their single-key slots. Challenge and sequence layers do
not mix inside one slot in v1.

## Explicit limits

- All listed keys compromised together means the capsule is open; a sequence
  multiplies custody effort, not cryptographic strength beyond its weakest
  storage separation.
- Losing any one sequence key loses access; pair every sequence key with its
  own threshold backup shares before distributing capsules that require it.
- A sequence does not add deniability, freshness or revocation; it only
  changes how many independent secrets one opening requires.

## Abuse cases required in tests

Layers applied out of order; layers unwrapped with a key from another
position; truncated and extended layer lists; recipes reordered relative to
the contract; sequences where two positions reuse one identity; missing
middle keys; and mutation of any single layer ciphertext.
