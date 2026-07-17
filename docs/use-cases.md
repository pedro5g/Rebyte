# Rebyte use cases

Copyright (c) 2026 Pedro Martins (pedro5g)

These examples show intended Rebyte deployment patterns. Rebyte transfers
artifacts; it is not a package manager or remote executor. RAP capsules
authenticate public artifacts, while Chain capsules additionally encrypt an
artifact for explicit self-custodied recipient identities.

## One-file sharing without a trust decision

For a local demo, test fixture or already trusted communication channel, create
an unsigned artifact without managing keys:

```console
rebyte encode notes.txt --output notes.ra1
rebyte decode --file notes.ra1 --output restored-notes.txt
rebyte hash notes.txt
rebyte hash restored-notes.txt
```

The hashes must match and `decode` refuses a mutated token. This mode is not
suitable for software updates or untrusted downloads because an attacker can
replace both content and digest by producing another token. Use a signed RAP
capsule in those cases.

## Air-gapped application release

On the offline publisher workstation:

```console
rebyte pack --root ./staged-release \
  --private-key ./keys/production.private.json \
  --output ./out/application-2.3.1.rbc \
  --producer application-release \
  --producer-version 2.3.1 \
  --name "Application 2.3.1"
```

Transfer the capsule over approved removable media. The target needs only the
public key:

```console
rebyte verify --file application-2.3.1.rbc \
  --trusted-key /opt/rebyte/trust/production.public.json
rebyte apply --file application-2.3.1.rbc \
  --trusted-key /opt/rebyte/trust/production.public.json \
  --root /opt/application --dry-run
```

Record the capsule root digest printed independently by publisher and target.

## CI-built static website

Build the site in a sandbox, stage only final bytes and sign from a protected
release job. Rebyte never invokes the site generator:

```console
rebyte pack --root ./dist \
  --private-key /run/keys/site.private.json \
  --passphrase-file /run/secrets/site.passphrase \
  --output ./site.rbc \
  --producer web-release-ci --json > site-pack-report.json
```

Deployment first captures a machine-readable plan, then applies the same
verified capsule:

```console
rebyte apply --file site.rbc --trusted-key site.public.json \
  --root /srv/www --dry-run --json > plan.json
rebyte apply --file site.rbc --trusted-key site.public.json \
  --root /srv/www --yes --backup --json > result.json
```

## Two-person encrypted release approval

Alice and Bob first form a group with threshold `2`; each must independently
accept the same `GroupId`. A recipient named Customer shares only
`customer.public.json`.

```console
rebyte chain group create --name "Release officers" \
  --member alice.public.json --member bob.public.json \
  --threshold 2 --output officers.proposal.json

rebyte chain group accept officers.proposal.json \
  --private-key alice.rbk --passphrase-file alice.passphrase \
  --output alice.group-acceptance.json
rebyte chain group accept officers.proposal.json \
  --private-key bob.rbk --passphrase-file bob.passphrase \
  --output bob.group-acceptance.json

rebyte chain group finalize officers.proposal.json \
  --acceptance alice.group-acceptance.json \
  --acceptance bob.group-acceptance.json \
  --output officers.group.json
```

The coordinator encodes the exact directory, encrypts it for Customer and
collects both proposal-bound approvals:

```console
rebyte encode ./confidential-release --format binary --output release.rba
rebyte chain capsule create --group officers.group.json \
  --artifact release.rba --recipient customer.public.json \
  --output release.proposal.rbep

rebyte chain capsule approve release.proposal.rbep \
  --private-key alice.rbk --passphrase-file alice.passphrase \
  --output alice.release-approval.json
rebyte chain capsule approve release.proposal.rbep \
  --private-key bob.rbk --passphrase-file bob.passphrase \
  --output bob.release-approval.json

rebyte chain capsule finalize release.proposal.rbep \
  --approval alice.release-approval.json \
  --approval bob.release-approval.json \
  --output confidential-release.rbe
```

Neither officer needs Customer's private key. Customer verifies the two
approvals and decrypts locally:

```console
rebyte chain capsule open --file confidential-release.rbe \
  --private-key customer.rbk --passphrase-file customer.passphrase \
  --output ./confidential-release-restored
```

For an 80% creation policy, compute `T = ceil(0.8 * N)` at group creation; a
five-member group uses `--threshold 4`. This controls how many officers
authorize the encrypted proposal. It does not require four officers to return
each time Customer opens the already finalized envelope.

## Signed configuration baseline

Package non-secret configuration that must be byte-identical across machines.
Do not include credentials because capsule content is authenticated but not
encrypted.

```console
rebyte pack --root ./baseline \
  --private-key configuration.private.json \
  --output baseline.rbc --producer config-control

rebyte diff --file baseline.rbc \
  --trusted-key configuration.public.json --root /etc/example
```

Text changes receive line summaries, while binary changes remain content-safe.

## Emergency logical configuration change

When a locally customized TOML file needs one controlled field change, bind a
semantic patch to the exact current digest and retain unrelated comments:

```console
rebyte hash ./service.toml
rebyte patch create --format toml \
  --target-digest "$CURRENT_RAP_DIGEST" \
  --operation 'test:/server/port=80' \
  --operation 'set:/server/port=8080' \
  --output port-emergency.rbp.json

rebyte patch apply port-emergency.rbp.json \
  --target ./service.toml --dry-run
rebyte patch apply port-emergency.rbp.json \
  --target ./service.toml --yes --backup
```

Use semantic patches only as local reviewed instructions. For authenticated
distribution, apply the change in a controlled publisher workspace and package
the resulting exact configuration in a signed capsule.

## Firmware or binary assets

RAP preserves arbitrary bytes and an executable boolean. Use `hash` to compare
one staged file with a separately published RAP digest before packing:

```console
rebyte hash ./firmware/device.bin --check "$EXPECTED_RAP_DIGEST"
rebyte pack --root ./firmware --private-key firmware.private.json \
  --output firmware.rbc --producer firmware-release
```

The RAP digest is domain-separated and must not be substituted for a generic
BLAKE3 or SHA-256 release checksum. Use standard release checksums to verify
download transport and RAP verification to authenticate capsule semantics.

## Staging promotion

Generate separate staging and production keys. Staging verification requires
an explicit flag:

```console
rebyte verify --file candidate.rbc \
  --trusted-key staging.public.json \
  --trust-channel staging
```

Promotion must rebuild and sign the capsule with the production key. Editing a
staging public document to call it production changes local policy metadata but
does not implement a controlled promotion process.

## Planned key rotation

Enroll both active keys before the cutover:

```console
rebyte verify --file canary.rbc \
  --trusted-key generation-1.public.json \
  --trusted-key generation-2.public.json
```

After all publishers use generation 2, deploy a retired generation-1 document
and keep generation 2 active. See [key management](key-management.md) for the
full ceremony.

## Crash recovery

If an apply process stops after staging or during a multi-file commit:

```console
rebyte transactions --root /opt/application
rebyte resume TRANSACTION_ID --root /opt/application
```

Choose rollback instead when the deployment should return to its original
state:

```console
rebyte rollback TRANSACTION_ID --root /opt/application
```

Do not run both concurrently and do not delete `.rebyte/transactions` manually.
