# Security review — 2026-07-18

Copyright (c) 2026 Pedro Martins (pedro5g)

## Status and scope

This is a maintainer source review of Rebyte 1.2, not an independent
cryptographic audit or certification. It covered protocol parsing, trust
decisions, key documents, Chain identity/group/proposal/release flows,
compression bounds, private-file I/O, transaction recovery, dependency policy
and adversarial tests.

“Fixed” means a regression is implemented and locally tested. It does not mean
the product is proven secure. High-value deployments still require independent
review and an environment-specific threat model.

## Findings addressed

| ID | Severity | Finding | Resolution |
|---|---|---|---|
| SR-01 | High | Third-party Ed25519 keys used permissive verification, which can accept weak-key edge cases | reject weak public keys at identity/trust ingestion and use `verify_strict` at every signature boundary |
| SR-02 | Medium | A release allowance was committed before HPKE grant construction completed | issue the complete in-memory grant first and commit only after successful issuance; errors consume no allowance |
| SR-03 | Medium | Individually valid witness grants could carry different ledger ordinals | require one identical nonzero ordinal across the exact quorum |
| SR-04 | Medium | Identity seeds and Shamir shares created ordinary non-zeroizing array copies | keep sensitive arrays and vectors inside `Zeroizing` through derivation and CEK reconstruction |
| SR-05 | Medium | Private-file permissions were checked before a second path open | open private inputs once with `nofollow`, then check type, size and permissions on that handle |
| SR-06 | Low | Derived `Debug` exposed encrypted private material, salts and nonces | use explicitly redacted private-document debug output |
| SR-07 | Low | Failed ledger append could leave a partial in-process tail | truncate and synchronize back to the last complete length before failing closed |

Regression coverage includes weak Ed25519 keys, issuance failure without
allowance consumption, mixed witness ordinals, redacted debug output, no-follow
private reads and restrictive Unix permissions.

## Confirmed design controls

- RFC 9180 HPKE X25519 decapsulation rejects an all-zero shared secret in the
  selected backend.
- Every signature class has a distinct message domain and strict verification.
- Payload encryption, key wrapping and stored private keys use distinct AEAD
  contexts and authenticated metadata.
- Canonical parsers reject unknown fields/algorithms, duplicates, malformed
  ordering, truncation and trailing bytes.
- Resource limits are local policy and apply before decompression.
- Chain releases authenticate recipient request, envelope, contract, witness,
  time observation, ordinal and encrypted share.
- Filesystem writes remain behind verification, preview/consent and recovery.

## Residual risks

1. No independent review has validated the custom encodings, Shamir
   implementation, AEAD bindings or crash-state machine.
2. The CLI witness clock and file ledger inherit rollback and cloning risks
   from the host. Hash-chained records cannot detect restoration of an older
   valid complete file.
3. A recipient with plaintext, a complete grant set or CEK can retain it.
   “Open once” is a fresh-release limit, not mathematical deletion or DRM.
4. Encrypted key documents permit offline passphrase guessing. Argon2id raises
   its cost but cannot rescue a low-entropy passphrase.
5. Chain exposes public identities, group shape, recipient/witness counts and
   approximate payload size.
6. Current identity encryption is classical. Post-quantum migration requires
   a new versioned crypto suite and hybrid test vectors.
7. Dependencies and the OS may contain unsafe code or vulnerabilities even
   though production Rebyte crates forbid handwritten unsafe Rust.
8. Multi-file apply is recoverable but can expose a committed prefix after a
   crash until resume or rollback.
9. Root, debugger, malware or physical control of an unlocked endpoint is
   outside the cryptographic boundary.

## Standards alignment

- Ed25519 uses the stricter weak-key checks provided by
  [`ed25519-dalek`](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict).
- Recipient encryption uses the DHKEM validation required by
  [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.4).
- Private-key derivation uses Argon2id with 64 MiB and three iterations. The
  v1 lane count is compatibility-bound and differs from the four-lane second
  recommendation in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-4).
  Changing it requires a new encrypted-document version and migration plan.
- Passphrase length is only an input floor, not an entropy measurement. Use a
  long password-manager-generated secret for offline key protection.

## Reproduction and validation

```console
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo xtask security
cargo deny check
cargo audit
```

Scheduled validation should additionally run Miri, every fuzz target,
cross-platform integration tests, mutation sampling, coverage and transaction
fault injection. See [quality](quality.md) and [release
verification](release.md).
