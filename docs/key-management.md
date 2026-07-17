# Publisher key management

Copyright (c) 2026 Pedro Martins (pedro5g)

This guide defines an operational ceremony for Rebyte 1.x publisher keys. It
does not replace an organization’s cryptographic key-management policy or an
independent review of the signing environment.

## Key roles

Rebyte separates three things:

| Material | Secret | Purpose |
|---|---:|---|
| encrypted private document | yes | unlock an Ed25519 signing seed |
| passphrase | yes | derive the private-document encryption key |
| public trust document | no | authorize a publisher, channel and status |

The private document and passphrase must not share a storage system, backup,
administrator account or delivery channel. The public document may be
distributed broadly, but its Key ID must be authenticated out of band.

## Cryptographic format

`rebyte key generate` obtains the 32-byte Ed25519 seed, 16-byte salt and
24-byte nonce from the operating-system cryptographic random source. Version 1
private documents use:

- Argon2id v1.3 with 65,536 KiB, three iterations and one lane;
- a 256-bit derived encryption key;
- XChaCha20-Poly1305 with a unique 192-bit nonce;
- authenticated associated data covering the document domain, public key,
  Key ID, salt and nonce;
- canonical unpadded Base64URL for binary JSON fields.

The parser rejects unknown fields and future algorithms. A wrong passphrase or
any authenticated modification produces the same non-secret-bearing error.
Decrypted buffers and derived keys are zeroized on drop; operating-system
copies, crash dumps and swap remain deployment responsibilities.

## Offline generation ceremony

Use a patched, dedicated workstation with full-disk encryption. Disconnect
network access before creating the key. Record the Rebyte binary checksum and
version in the release log.

On Linux or macOS:

```console
rebyte --version
umask 077
printf '%s\n' 'use-a-random-password-manager-generated-passphrase' \
  > publisher.passphrase

rebyte key generate \
  --name "Acme production releases" \
  --channel production \
  --private-key acme-production.private.json \
  --public-key acme-production.public.json \
  --passphrase-file publisher.passphrase

rebyte key inspect acme-production.public.json
```

When no `--passphrase-file` is provided, Rebyte reads and confirms the
passphrase directly from the controlling terminal without echo. Prefer this
interactive mode when automation is unnecessary.

Rebyte creates the private file as `0600` on Unix and refuses to load it if
group or other permission bits are set. Confirm independently:

```console
stat -c '%a %n' acme-production.private.json publisher.passphrase
chmod 600 acme-production.private.json publisher.passphrase
```

On macOS, use `stat -f '%Lp %N'` instead of the GNU `stat -c` form.

On Windows, create the key under a dedicated publisher account and replace
inherited ACLs with an explicit user-only ACL:

```powershell
rebyte key generate `
  --name "Acme production releases" `
  --private-key acme-production.private.json `
  --public-key acme-production.public.json

icacls acme-production.private.json /inheritance:r
icacls acme-production.private.json /grant:r "$env:USERNAME:(R,W)"
icacls acme-production.private.json
```

Windows ACL syntax can vary under managed domains. Confirm the resulting ACL
with the organization’s Windows security tooling before using the key.

## Public-key enrollment

Transfer only the public JSON file to verifier hosts. Compare the Key ID over a
second authenticated channel, such as an in-person record or signed release
ticket:

```console
rebyte key inspect acme-production.public.json
rebyte doctor --trusted-key acme-production.public.json --json
```

Store the public document in a root-owned or administrator-controlled
configuration directory. Passing a public document from the same untrusted
location as the capsule defeats publisher authentication.

```console
rebyte verify --file release.rbc \
  --trusted-key /etc/rebyte/trust/acme-production.public.json
```

Multiple `--trusted-key` flags are supported for planned rotation and separate
publishers. Duplicate Key IDs are rejected.

## Signing and self-verification

Keep private material outside the directory being packaged:

```console
rebyte pack \
  --root /build/staged-artifact \
  --private-key /offline-keys/acme-production.private.json \
  --passphrase-file /run/secrets/rebyte-passphrase \
  --output /release/acme-1.4.0.rbc \
  --producer "acme-release-pipeline" \
  --producer-version "1.4.0" \
  --name "Acme 1.4.0"
```

Before writing the output, `pack` rebuilds a local one-key production keyring
and runs the complete verifier over the new envelope. This catches codec,
signature, compression and payload integration failures; it does not replace
independent verification on the deployment host.

## Automation

An automated publisher should inject a short-lived mode-`0600` passphrase file
from its secret manager, run one signing job and destroy the runner. Do not put
the passphrase in a process argument or ordinary environment variable.

```console
install -m 600 /dev/null /run/secrets/rebyte-passphrase
secret-manager read rebyte/publisher-passphrase \
  > /run/secrets/rebyte-passphrase

rebyte pack --root ./staging \
  --private-key /secure/publisher.private.json \
  --passphrase-file /run/secrets/rebyte-passphrase \
  --output ./release.rbc \
  --producer ci-release --json > ./release-report.json
```

The illustrative `secret-manager` command is not executed by Rebyte and must
be replaced by the platform’s reviewed secret-injection mechanism.

## Rotation

1. Generate a new private/public pair with a new name or generation marker.
2. Authenticate the new Key ID out of band.
3. Deploy both old and new active public documents to every verifier.
4. Sign a canary capsule with the new key and verify it everywhere.
5. Move production signing to the new private key.
6. Replace the old active public document with a `retired` document.
7. Destroy or archive the old private key according to retention policy.

```console
rebyte key status old.public.json \
  --status retired \
  --output old.retired.public.json
```

RAP v1 has no trusted signing timestamp. A retired key cannot safely accept
“old but valid” capsules, so retired keys are rejected exactly like revoked
keys. Maintain historical artifacts in a separately controlled archive if
long-term validation is required.

## Emergency revocation

If compromise is suspected:

1. stop every publisher using the key;
2. create and distribute a revoked trust document;
3. reject all capsules signed by that Key ID;
4. generate and enroll a replacement key from a clean system;
5. rebuild affected artifacts from known-good source;
6. investigate distribution logs and preserve evidence.

```console
rebyte key status compromised.public.json \
  --status revoked \
  --output compromised.revoked.public.json
```

Do not remove the compromised entry silently when retaining it as revoked gives
operators a precise policy error instead of an ambiguous unknown-key error.

## Backup and recovery

Maintain at least two encrypted private-document backups and separate
passphrase recovery material. Test restoration on an offline machine by
signing and verifying a non-production fixture. Never test a backup by
displaying or exporting the decrypted seed.

Loss of either the private document or passphrase makes signing impossible.
Loss of the public document is recoverable only if a trusted copy or verified
Key ID remains; Rebyte intentionally offers no command that exposes a private
seed.

## KMS and HSM integrations

High-value online signing should keep the private key non-exportable in a KMS
or HSM. Implement `rebyte_signature::Signer`, map the device’s Ed25519 public
key to `public_key()`, and sign the exact domain-separated 52-byte message
provided to `sign()`. Do not hash that message again unless the device API
explicitly implements plain Ed25519 with the exact bytes supplied.

Device adapters, network clients and production credentials do not belong in
the core verifier or browser crate. Review and deploy them as a separate trust
boundary.
