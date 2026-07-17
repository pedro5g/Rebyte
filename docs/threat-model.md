# Rebyte threat model

Copyright (c) 2026 Pedro Martins (pedro5g)

## Assets

Rebyte protects the bytes and portable metadata of files reconstructed below a
root directory selected by the local user. It also protects the authenticity
of the publisher and the integrity of the capsule presented to the CLI.

## Trust boundaries

- Capsules, tokens, manifests, payloads, paths, metadata and terminal text are
  hostile until verification completes.
- The selected root and the local trust policy are controlled by the user.
- Public keys may be embedded or supplied by a trusted host application.
- Signing keys and KMS credentials are outside the CLI, Wasm module and RAP.
- The operating system, filesystem and Rust dependencies are trusted only to
  the degree documented in the security model.

## In-scope attackers

The implementation assumes an attacker can truncate, extend or mutate any
capsule byte; forge lengths and offsets; exploit integer conversion; submit
compression bombs; inject terminal controls; race filesystem paths; create
links; interrupt the process at any transaction state; and replay a correctly
signed capsule.

## Security objectives

1. Reject malformed input before attacker-controlled allocation or indexing.
2. Verify publisher policy, signature and all digests before target writes.
3. Confine every target below the locally selected root.
4. Never execute generated content, commands, hooks or network requests.
5. Make each file replacement atomic and a multi-file operation recoverable.
6. Reconstruct file content exactly and verify it after the final write.
7. Produce deterministic RAP v1 bytes for identical inputs and options.

## Explicit non-goals

- Confidentiality, encryption, DRM or prevention of token redistribution.
- Global atomicity across multiple files or filesystems.
- Preservation of ownership, ACLs, xattrs, timestamps or platform-specific
  permission bits other than the portable executable flag.
- Protection from a compromised operating system, trusted signing key, root
  user, malicious dependency or physical storage failure.
- Proving generated source code is safe to compile or execute.
- Deleting files in RAP v1.

## Abuse cases required in tests

Tests must cover truncated input at every structural boundary; oversized and
overlapping ranges; duplicate or non-canonical entries; path traversal and
platform prefixes; invalid UTF-8; unknown algorithms and keys; modified
signatures and digests; decompression bombs; terminal escapes; symlink races;
concurrent target changes; permission and disk failures; and interruption at
every journal transition.
