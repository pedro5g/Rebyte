# Security policy

## Supported versions

| Version | Supported |
|---|---:|
| 1.x | yes |
| 0.x | no |

Security fixes target the latest 1.x release and `main`. RAP v1 compatibility
is maintained across Rebyte 1.x unless accepting existing data would preserve
a vulnerability.

## Reporting a vulnerability

Use the private security advisory feature of the GitHub repository. Do not open
a public issue for suspected vulnerabilities, private keys or exploit samples.

Reports should include the affected command or API, a minimal reproducer,
impact, platform and Rebyte version or commit. Maintainers will acknowledge a
complete report, coordinate remediation and credit, and publish an advisory
after a fix is available.

The project does not claim to be bug-free or independently audited. High-value
deployments should review the protocol, signing integration and local
filesystem assumptions in their own threat model.

Unsigned `rf1_` file tokens are a convenience transport with bounded
decompression and digest verification. They do not authenticate an author and
must not replace signed RAP capsules at a trust boundary.

## Key compromise

For suspected publisher-key compromise, stop signing immediately, deploy a
`revoked` public trust document, replace the key from a clean offline system
and rebuild affected capsules. Follow [publisher key
management](docs/key-management.md); never send a private document or
passphrase in a vulnerability report.

## Release verification

Official release archives are expected to have SHA-256 checksum companions, a
CycloneDX SBOM and a GitHub artifact attestation. Verify all three before
deployment. Absence or failure of any release evidence is a distribution
incident and should be reported privately.
