# Rebyte threat model

Copyright (c) 2026 Pedro Martins (pedro5g)

## Assets

Rebyte protects the bytes and portable metadata of files reconstructed below a
root directory selected by the local user. It also protects the authenticity
of the publisher and the integrity of signed capsules presented to the CLI.
Unsigned `ra1_`/`.rba` artifacts and standalone semantic patches make no
authenticity claim.

Chain additionally protects encrypted `.rba` confidentiality from parties that
do not possess an explicitly listed recipient private identity. It
authenticates unanimous group formation and the configured threshold of member
approvals for one exact encrypted proposal. Quorum release additionally keeps
the CEK unavailable until a listed recipient obtains the configured number of
fresh, signed witness shares.

## Trust boundaries

- Capsules, tokens, manifests, payloads, paths, metadata and terminal text are
  hostile until verification completes.
- The selected root and the local trust policy are controlled by the user.
- Public keys may be embedded or supplied by a trusted host application.
- Signing keys and KMS credentials are outside the CLI, Wasm module and RAP.
- Chain `.rbk` identities and passphrases are controlled by their individual
  owners; public identities and exchanged approvals are hostile until verified.
- Each quorum witness is an independent authority for its private share,
  trusted time and durable release ledger. The native file ledger inherits the
  rollback resistance of its host and storage.
- The operating system, filesystem and Rust dependencies are trusted only to
  the degree documented in the security model.

## In-scope attackers

The implementation assumes an attacker can truncate, extend or mutate any
capsule or file-token byte; forge lengths and offsets; exploit integer
conversion; submit compression bombs; inject terminal controls; race
filesystem paths; create links; interrupt the process at any transaction state;
and replay a correctly signed capsule.

For Chain, the attacker may also substitute a public encryption key, claim
another member slot with the wrong private key, duplicate or reorder members,
recipients and approvals, replay an approval against another proposal, remove
a recipient, mutate an HPKE slot or encrypted payload, supply a wrong
passphrase or attempt to open as an unlisted identity. Against quorum release,
the attacker may replay or rebind requests/grants, duplicate witnesses, forge
times/ordinals, corrupt shares, race allowance consumption, roll back a
cooperative ledger or control fewer than the release threshold of witnesses.

## Security objectives

1. Reject malformed input before attacker-controlled allocation or indexing.
2. Verify publisher policy, signature and all digests before target writes.
3. Confine every target below the locally selected root.
4. Never execute generated content, commands, hooks or network requests.
5. Make each file replacement atomic and a multi-file operation recoverable.
6. Reconstruct file content exactly and verify it after the final write.
7. Produce deterministic RAP v1 bytes for identical inputs and options.
8. Never represent an unsigned artifact or standalone semantic patch as authenticated.
9. Bind every Chain identity to distinct signing and encryption public keys.
10. Require every proposed member to prove its own private signing key before
    a group exists.
11. Require `T` unique valid member approvals before a Chain envelope exists.
12. Release Chain plaintext only to a listed recipient after HPKE, AEAD,
    commitment and inner-artifact verification.
13. For quorum contracts, release no CEK until a fresh recipient request and
    `T` unique witness grants pass every signature, time, ledger and binding
    check.

## Explicit non-goals

- Confidentiality for RAP, unsigned artifacts or standalone semantic patches.
- DRM, prevention of ciphertext redistribution or forced deletion of plaintext
  already recovered by a Chain recipient.
- Hiding Chain payload length, group membership, recipient count or public
  identity metadata.
- Treating direct release as fresh `T-of-N` cooperation; direct recipients can
  open independently after finalization.
- Preventing replay after a recipient has retained a complete valid grant set,
  reconstructed CEK or plaintext.
- Strong date or usage enforcement when enough witnesses are compromised, or
  when the witness clock/ledger can be rolled back.
- Global atomicity across multiple files or filesystems.
- Preservation of ownership, ACLs, xattrs, timestamps or platform-specific
  permission bits other than the portable executable flag.
- Protection from a compromised operating system, trusted signing key, root
  user, malicious dependency or physical storage failure.
- Proving generated source code is safe to compile or execute.
- Deleting files in RAP v1.
- Authenticating the author, freshness or authorization of an unsigned
  artifact or standalone semantic patch outside a verified Chain envelope.

## Abuse cases required in tests

Tests must cover truncated input at every structural boundary; oversized and
overlapping ranges; duplicate or non-canonical entries; path traversal and
platform prefixes; invalid UTF-8; unknown algorithms and keys; modified
signatures and digests; decompression bombs; terminal escapes; symlink races;
concurrent target changes; permission and disk failures; and interruption at
every journal transition.

Chain tests additionally cover wrong identity proofs, wrong private member
keys, incomplete groups, threshold boundaries, duplicate approvals, proposal
replay, unlisted recipients, multi-recipient byte equality, mutation,
representative truncation, trailing bytes, canonical round trips, Shamir
threshold subsets, early release, duplicate grants, wrong recipients, grant
mutation, idempotent request replay and exhausted allowances. A
dedicated fuzz target exercises the bounded envelope parser.
