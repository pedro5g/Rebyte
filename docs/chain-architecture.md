# Rebyte Chain architecture

Status: design draft for the next protocol family. Nothing in this document is
accepted by Rebyte 1.2 or promised as a stable wire format.

Rebyte Chain is a local-first, self-custodied system for sharing byte-exact
Rebyte artifacts with explicit cryptographic access policies. Its history is an
append-only, signed Merkle directed acyclic graph (DAG). It is not a
cryptocurrency, public blockchain or global source of consensus.

The design keeps four properties independent:

1. BLAKE3 content identifiers detect substitution and corruption.
2. Ed25519 signatures authenticate an identity and its decisions.
3. Hybrid public-key encryption provides confidentiality to recipients.
4. Access policies define which independently authenticated participants must
   cooperate.

Combining these properties in one object does not make them interchangeable. A
signature does not encrypt data, a digest cannot reconstruct data, and a local
event log cannot prove that a remote recipient deleted plaintext.

## Product boundary

The first Chain release is intended to provide:

- any number of self-custodied identities and keys per user;
- encrypted, portable key-bundle import and export;
- one ciphertext shared with one or many recipients;
- `1-of-N`, `T-of-N` and `N-of-N` access policies;
- offline approval files bound to one capsule and one opening session;
- an inspectable, tamper-evident history with deterministic fork and merge;
- the existing byte-exact `.rba` artifact as the encrypted content;
- native CLI and browser-safe WebAssembly APIs over the same codecs.

It does not initially provide:

- proof of work, mining, tokens or a globally replicated ledger;
- a trusted global timestamp or total ordering of offline events;
- permanent revocation of plaintext a recipient already recovered;
- enforceable single-use or self-destruction on an untrusted device;
- anonymity against traffic analysis, file-size analysis or a malicious
  application origin;
- automatic semantic merging of file contents;
- FROST, MLS, hardware enclaves or a network relay.

Semantic patches remain a separate, signed content type. They can later be
carried inside a Chain envelope without giving the patch language authority to
execute code.

## Terminology and object model

### Identity

An identity is a local label associated with independent purpose-specific key
pairs:

- an Ed25519 signing key for authorship, approvals and graph events;
- an X25519 key-encapsulation key for receiving encrypted key material.

Encryption and signing keys MUST be distinct. A `KeyId` is a domain-separated
32-byte fingerprint of the algorithm, purpose and canonical public key. Names,
avatars and contact information are local metadata unless included in a signed
identity statement.

Users MAY keep multiple identities and multiple active, retired or revoked keys
for each identity. Rebyte MUST NOT derive a new private key by concatenating,
XORing or otherwise improvising over existing private keys. Requiring several
keys is represented by an access policy.

### Key bundle

An `.rbk` key bundle is a canonical, versioned document containing public
identity data and encrypted private key material. A fresh random vault key
encrypts the secrets with an AEAD. A passphrase-derived Argon2id key wraps the
vault key. Parameters, salt, nonce, public identity and format version are
authenticated as associated data. KDF profiles follow
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) and remain encoded in the
bundle so that stronger future profiles can coexist.

Import MUST validate public/private correspondence, duplicate `KeyId` values,
canonical encoding, algorithms, limits and KDF parameters before committing the
bundle. Export MUST be exclusive by default, use restrictive permissions where
the platform exposes them, synchronize the completed file and never print
private material.

Losing every private bundle and recovery copy makes the encrypted data
unrecoverable. Self-custody removes a central recovery authority; it does not
remove the need for verified offline backups.

### Encrypted envelope

An `.rbe` Rebyte Encrypted Envelope contains:

- fixed magic, protocol version, suite identifiers and strict limits;
- a random envelope identifier;
- the digest and length of one canonical inner `.rba` artifact;
- a canonical access policy and its digest;
- one encrypted recipient slot per policy member;
- a chunked, authenticated ciphertext of the compressed artifact;
- optional bounded display metadata;
- the sender signing `header || policy || slots || ciphertext digest`.

The encoder generates a fresh random 256-bit content-encryption key (CEK) for
every envelope. The artifact is encrypted once. Recipient slots encapsulate
only CEK-related key material, so adding recipients does not duplicate a large
payload.

The candidate recipient construction is HPKE as specified by
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), using a registered X25519
ciphersuite and the RFC test vectors. The exact suite and chunked payload AEAD
remain unfrozen until dependency review, WebAssembly validation and immutable
cross-language vectors are complete.

Compression MUST finish before encryption. Ciphertext is intentionally
incompressible, and compressed size can reveal information. Applications MUST
not automatically expose secret-dependent compression to attacker-controlled
plaintext in an interactive oracle.

## Access policies

Chain v1 uses a flat, canonical policy:

```text
Policy {
    members: sorted unique SigningKeyId + EncryptionKeyId pairs
    required: integer T
    total: integer N
}
```

`1 <= T <= N` is mandatory. `1-of-N` lets any listed recipient open the
artifact. `N-of-N` requires everyone. An “80%” user choice is frozen as
`T = ceil(80 * N / 100)` when the envelope is created; changing membership
creates a new policy and envelope.

For `1-of-N`, every recipient slot wraps the same CEK. For `T-of-N`, the CEK is
split into independently encrypted shares by a reviewed threshold secret
sharing construction. Each member receives exactly one authenticated share.
The capsule binds the member list, threshold, share index and encryption suite
to the signed policy digest.

An opening session has a fresh random `SessionId` and ephemeral encryption
public key. A participant decrypts its share locally and creates a signed
`.rbauth` approval that binds:

```text
EnvelopeId || PolicyDigest || SessionId || OpenerEphemeralKey || Expiry
```

The share is encrypted to the opener's ephemeral key. The opener reconstructs
the CEK only after collecting `T` unique, valid approvals. Replayed approvals,
duplicate members, approvals for another envelope or session, expired
approvals and non-members are rejected.

Once an authorized opener reconstructs the CEK or plaintext, software cannot
force that person to forget it. Requiring fresh approval for every future open
needs an online authority, trusted hardware, or participants who never release
reusable key material; those are different deployment models.

Independent signed approvals are the v1 threshold mechanism. FROST, specified
by [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591), can later make one
threshold signature compact, but it requires purpose-built key shares,
coordinated setup and two interactive signing rounds. It cannot safely turn an
arbitrary collection of existing private keys into one group key.

## Signed Merkle event graph

Every state transition is a canonical event:

```text
Event {
    version
    kind
    parents[]       // sorted unique EventIds
    author_key_id
    lamport_counter
    wall_time_ms?   // display metadata only
    body_digest
    signature
}

BodyId = BLAKE3("rebyte chain event body v1" || canonical_event_without_signature)
Signature = Ed25519("rebyte chain event signature v1" || BodyId)
EventId = BLAKE3("rebyte chain event id v1" || BodyId || Signature)
```

Initial event kinds are:

- identity created;
- key added, retired or revoked;
- envelope created or shared;
- opening requested;
- approval granted or refused;
- graph heads merged.

Parent identifiers and Lamport counters establish causal order without trusting
a device clock. Optional Unix milliseconds help humans but MUST NOT decide key
validity, conflict winners or authorization. Zeptosecond timestamps add digits,
not trust: ordinary hardware cannot measure them meaningfully and offline clocks
can be wrong or malicious.

Two devices can create valid events while disconnected. This creates branches,
not corruption. A merge event references every accepted head. Deterministic
validation verifies each parent, signature, counter and object digest; policy
decisions remain explicit when histories conflict.

The graph proves that the retained events have not been silently edited. It
does not prove that every real-world action was recorded, that a remote clock
was correct, or that all peers agree on one canonical history.

## Local-first browser application

The web application is a static, installable PWA. After a verified initial
load, a service worker may make the interface available offline. IndexedDB
stores canonical encrypted objects, graph events, public contacts and encrypted
key bundles. Plaintext and unwrapped keys MUST remain in memory only for the
shortest practical operation and be zeroized on lock where the runtime permits.

IndexedDB encryption protects data at rest. It does not protect an unlocked
vault from JavaScript served by the same origin, malicious browser extensions,
browser compromise, screen capture or memory inspection. WebAssembly shares
the browser security boundary and is not a hardware enclave.

For high-value self-custody, distribution should add:

- pinned and signed desktop builds;
- reproducible build evidence and signed updates;
- a strict Content Security Policy with no third-party scripts;
- no telemetry and no network access after the application shell is loaded;
- an independently reviewable self-hosted build;
- explicit lock, export and backup ceremonies.

Web Crypto and non-extractable platform keys MAY protect a local device key,
but non-extractability cannot replace the portable encrypted backup required by
the self-custody model. Browser storage follows the
[IndexedDB specification](https://www.w3.org/TR/IndexedDB-3/); cryptographic
integration must account for the threat model and algorithm requirements in
the [Web Cryptography specification](https://www.w3.org/TR/WebCryptoAPI/).

## Verification and opening pipeline

No plaintext reaches a destination until all applicable stages succeed:

1. Decode the bounded, canonical envelope without allocating from untrusted
   lengths.
2. Verify suite identifiers, structure, unique members, policy and ciphertext
   digest.
3. Verify the sender signature and local trust policy.
4. Match a `1-of-N` recipient or validate `T` session-bound approvals.
5. Decapsulate recipient material and reconstruct the CEK in secret memory.
6. Authenticate and decrypt every chunk into same-filesystem staging.
7. Decode the inner artifact and verify its root and per-file BLAKE3 digests.
8. Show the effective destination, file list, overwrite decisions and policy.
9. Reconstruct using the existing no-follow, journaled transaction engine.
10. Verify written bytes, close handles and report a signed local event.

Failure at any stage deletes staging data and returns a typed, non-secret error.
Authentication failures do not reveal which key, share or ciphertext field was
closest to valid.

## Revocation and rotation

Key status is an authenticated graph event and local trust decision:

- `active` keys may receive new envelopes and approve sessions;
- `retired` keys may open historical envelopes but not receive new ones;
- `revoked` keys are rejected at or after a locally trusted revocation event.

Offline revocation is not retroactive. A peer that never receives the event can
continue using its prior state, and revocation cannot erase already recovered
plaintext. Rotating a member or threshold requires a new policy and rewrapping
or re-encrypting the relevant CEK material.

Long-lived asynchronous groups with forward secrecy and post-compromise
security are a later problem. Rebyte SHOULD evaluate Messaging Layer Security,
[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420), rather than inventing a
group ratchet.

## Proposed CLI boundary

Names are provisional and will not be exposed until the codecs and vectors are
stable:

```console
rebyte identity generate --name "Pedro" --output pedro.rbk
rebyte identity public pedro.rbk --output pedro.identity.json
rebyte identity import pedro.rbk

rebyte encrypt ./project \
  --sender pedro.rbk \
  --recipient ana.identity.json \
  --recipient bruno.identity.json \
  --threshold 1 \
  --output project.rbe

rebyte open project.rbe --identity ana.rbk --output ./project

rebyte open request project.rbe --identity ana.rbk --output session.rbreq
rebyte approve session.rbreq --identity bruno.rbk --output bruno.rbauth
rebyte open project.rbe \
  --identity ana.rbk \
  --approval bruno.rbauth \
  --output ./project

rebyte chain inspect
rebyte chain verify
rebyte chain export --output history.rbchain
rebyte chain merge history.rbchain
```

Every mutation defaults to preview plus explicit confirmation. JSON output is
versioned. Passphrases are read from an interactive terminal or protected file,
not ordinary command-line arguments or environment variables.

## Implementation gates

The feature progresses only through these reviewable gates:

1. Freeze the threat model, canonical layouts, limits, suites and immutable
   manual vectors.
2. Add separate signing/encryption identities and encrypted `.rbk` bundles.
3. Implement single-recipient HPKE and chunked authenticated `.rbe` payloads.
4. Extend the same ciphertext to canonical `1-of-N` recipients.
5. Add session-bound `T-of-N` approvals and adversarial share tests.
6. Add the signed Merkle DAG, offline fork/merge and revocation semantics.
7. Expose read-only WASM codecs, then an encrypted IndexedDB repository.
8. Build the PWA only after native and WASM vectors match byte for byte.

Each gate requires canonical round trips, mutation and truncation rejection,
wrong-key indistinguishability, nonce-uniqueness checks, threshold boundary
tests, replay tests, fuzzing, secret-zeroization review, browser vectors and
the full Linux, macOS and Windows CI matrix.
