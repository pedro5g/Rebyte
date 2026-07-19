# Rebyte Chain operations

Copyright (c) 2026 Pedro Martins (pedro5g)

This runbook turns the Chain protocol into an explicit deployment ceremony.
It assumes the reader has reviewed the
[system architecture](architecture.md),
[threat model](threat-model.md) and
[Chain v2 specification](../schemas/chain-v2.md).

Chain is self-custodied: Rebyte has no recovery server, master key or hidden
administrator identity. Losing every usable private bundle or quorum share can
make content permanently unrecoverable.

## Select a security profile

| Need | Recommended profile |
|---|---|
| Move already trusted bytes | unsigned `ra1_`/`.rba` |
| Authenticate a public release | signed RAP `.rbc` |
| Encrypt once for listed recipients | Chain direct release |
| Require fresh human/system cooperation | Chain quorum release |
| Enforce an embargo | quorum plus protected trusted clocks |
| Limit fresh release sessions | unanimous quorum plus shared/monotonic ledger |

Do not use an unsigned artifact across a trust boundary. Do not use direct
release when fresh consent, an embargo or a release counter is required.

## Identity ceremony

Each person creates an independent Chain identity on a controlled workstation:

```console
rebyte chain identity generate \
  --name "Alice release officer" \
  --private-key alice.rbk \
  --public-key alice.public.json

rebyte chain identity inspect alice.public.json
```

The `.rbk` and its passphrase are secret. The public JSON is designed for
distribution. Authenticate its displayed identity ID over a second channel
before admitting it to a group.

For every identity:

1. keep the encrypted bundle and passphrase in separate systems;
2. maintain at least two verified offline recovery copies;
3. restrict local permissions/ACLs and exclude files from backups not intended
   to hold key material;
4. never send `.rbk`, passphrase, decrypted content or release ledger through
   issue trackers or ordinary logs;
5. test recovery with a non-production capsule.

## Threshold identity backup

Losing every `.rbk` copy or the passphrase makes an identity unrecoverable.
Shamir backup shares remove that single point of failure without creating a
recovery authority:

```console
rebyte chain identity backup \
  --private-key alice.rbk \
  --passphrase-file alice.passphrase \
  --share-count 5 --threshold 3 \
  --output-dir ./alice-shares

rebyte chain identity restore \
  --share share-from-carol.json \
  --share share-from-dan.json \
  --share share-from-erin.json \
  --private-key alice-restored.rbk \
  --public-key alice-restored.public.json \
  --passphrase-file alice-new.passphrase
```

Rules for a real ceremony:

1. any `threshold` shares reconstruct the identity **without a passphrase**;
   hand each share to a different trustee over a verified channel and never
   store two shares in one place;
2. trustees verify the embedded identity ID and fingerprint words against the
   owner before accepting custody;
3. choose `threshold >= 2` so no single trustee holds the identity, and
   `share-count` high enough to survive losing trustees;
4. after any restore, or when a share may have been exposed, immediately
   create a fresh backup — old shares remain able to meet the old threshold;
5. rehearse the restore with a non-production identity before relying on it.

## Group formation

The coordinator creates one canonical proposal:

```console
rebyte chain group create \
  --name "Release officers" \
  --member alice.public.json \
  --member bob.public.json \
  --threshold 2 \
  --output officers.proposal.json
```

Every member independently inspects the complete member set, threshold and
`GroupId`, then signs with the private key matching the public identity that
was originally proposed:

```console
rebyte chain group accept officers.proposal.json \
  --private-key alice.rbk \
  --output alice.acceptance.json
```

While acceptances trickle in, the coordinator can check progress without
finalizing anything — the report names each pending member and flags any
document that can never count (wrong group, invalid signature, duplicate):

```console
rebyte chain ceremony status --group officers.proposal.json \
  --acceptance alice.acceptance.json
```

The same command with `--capsule PROPOSAL --approval ...` tracks capsule
approvals against the group threshold.

Finalize only after receiving one valid acceptance from every proposed member:

```console
rebyte chain group finalize officers.proposal.json \
  --acceptance alice.acceptance.json \
  --acceptance bob.acceptance.json \
  --output officers.group.json
```

Group formation is `N-of-N`; the configured threshold applies to later capsule
approval. Adding/removing a member or changing the threshold creates a
different group.

## Direct encrypted delivery

Encode exact source bytes first, keeping keys outside the source tree:

```console
rebyte encode ./confidential \
  --format binary \
  --profile maximum \
  --output confidential.rba
```

Create a proposal with every intended recipient listed explicitly:

```console
rebyte chain capsule create \
  --group officers.group.json \
  --artifact confidential.rba \
  --recipient customer-a.public.json \
  --recipient customer-b.public.json \
  --output confidential.proposal.rbep
```

Controllers must inspect the contract ID, recipients, capabilities, content
digest/size and release policy before approving. Finalize only with the exact
group threshold. Each listed recipient can then open independently; group
members do not need to return.

## Quorum and embargo deployment

Use distinct protected witness identities. Independent operators and hosts
reduce the chance that one compromise controls the threshold.

```console
rebyte chain capsule create \
  --group officers.group.json \
  --artifact confidential.rba \
  --recipient customer.public.json \
  --witness witness-a.public.json \
  --witness witness-b.public.json \
  --release-threshold 2 \
  --not-before 2026-08-01T12:00:00Z \
  --maximum-releases 1 \
  --output embargo.proposal.rbep
```

After normal proposal approval and finalization, the recipient creates one
fresh request. Every selected witness receives the same capsule and request.

```console
rebyte chain release request \
  --file embargo.rbe \
  --private-key customer.rbk \
  --output embargo.request.json
```

The built-in CLI authority is suitable for local testing:

```console
rebyte chain release grant \
  --file embargo.rbe \
  --request embargo.request.json \
  --private-key witness-a.rbk \
  --ledger witness-a.ledger \
  --acknowledge-local-authority \
  --output witness-a.grant.json
```

For production, replace the OS-clock/file-ledger authority through the
`TrustedClock` and `ReleaseLedger` Rust interfaces. Each witness deployment
must provide:

- authenticated, monitored time with a documented failure policy;
- durable monotonic release state protected from rollback and cloning;
- exclusive request serialization across replicas;
- restricted key access and independent operator control;
- backup/recovery that cannot restore an older release counter;
- audit records containing IDs and decisions, never shares, CEKs or plaintext.

The recipient opens with exactly the required unique grants:

```console
rebyte chain release open \
  --file embargo.rbe \
  --request embargo.request.json \
  --grant witness-a.grant.json \
  --grant witness-b.grant.json \
  --private-key customer.rbk \
  --output ./restored
```

## Review checklist

Before a controller signs a capsule proposal, verify:

- `GroupId`, `ContractId` and `ProposalId` over an authenticated channel;
- the complete recipient and witness sets;
- approval and release thresholds;
- content kind, digest and reconstructed byte count;
- allowed capabilities: decrypt, diff, apply or semantic patch;
- whether release is direct or quorum;
- exact `not-before` and maximum-release values;
- whether the destination hint is appropriate and remains locally overridable.

Before a witness grants a request, verify:

- the same finalized envelope and request reached every witness;
- the requester is an explicit recipient;
- trusted time is at/after the contract boundary;
- the request ID is fresh or an idempotent retry;
- the next ordinal can be durably committed;
- no error path logs the decrypted share.

Before a recipient writes content, run inspect/diff or dry-run and select the
destination explicitly. Suggested paths are signed or contract-bound metadata,
not permission to write.

## Audit bundle

`rebyte chain capsule audit --file CAPSULE.rbe --output BUNDLE_DIR` verifies a
finalized envelope and exports everything a reviewer needs without granting
access: the full verification report bound to the exact envelope bytes by a
BLAKE3 hash, the group certificate, approving member IDs, and one reusable
public identity document with proquint fingerprint per participant. Archive
one bundle per delivered capsule; content stays encrypted inside it.

## Rotation, compromise and recovery

Chain envelope v2 has no online revocation service. Rotation creates a new
identity/group and new envelopes. Existing direct recipients that retained a
private key can still open historical envelopes. A passphrase change is not
rotation: `chain identity rekey` re-encrypts the same identity locally and
nothing distributed changes.

On suspected identity or witness compromise:

1. stop creating approvals or grants with the affected identity;
2. preserve public IDs, envelope/request IDs and non-secret audit evidence;
3. move to clean hosts and generate replacement identities;
4. form a new group and issue new contracts;
5. re-encrypt unreleased content with a fresh CEK;
6. assume already released plaintext may have been copied;
7. publish an incident statement through the deployment's authenticated
   communication channel.

Do not recover a finite release ledger by restoring an old snapshot. If current
monotonic state cannot be proven, fail closed and require a reviewed migration
to a new contract.

## Production readiness record

For each deployment, retain:

- exact Rebyte version and verified binary provenance;
- reviewed protocol/suite versions;
- authenticated participant identity IDs;
- approved group/contract/proposal/envelope IDs;
- witness authority design and rollback analysis;
- key backup/recovery test date;
- CI, fuzz, dependency-audit and independent-review evidence;
- incident owners and rotation procedure.

Rebyte provides the cryptographic and transactional primitives. The deployment
remains responsible for endpoint compromise, screenshots, copied plaintext,
swap/crash dumps, physical access and the correctness of external authority
adapters.
