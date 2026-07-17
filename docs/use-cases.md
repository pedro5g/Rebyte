# Rebyte use cases

Copyright (c) 2026 Pedro Martins (pedro5g)

These examples show intended Rebyte deployment patterns. Rebyte transfers
artifacts; it is not a package manager, remote executor or secret-distribution
system.

## One-file sharing without a trust decision

For a local demo, test fixture or already trusted communication channel, create
an unsigned file token without managing keys:

```console
rebyte encode notes.txt --output notes.rf1
rebyte decode --file notes.rf1 --output restored-notes.txt
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
