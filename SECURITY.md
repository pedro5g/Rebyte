# Security policy

## Supported versions

Rebyte has not released a production version yet. Security fixes currently
target the latest commit on `main`.

## Reporting a vulnerability

Use the private security advisory feature of the GitHub repository. Do not open
a public issue for suspected vulnerabilities, private keys or exploit samples.

Reports should include the affected command or API, a minimal reproducer,
impact, platform and Rebyte version or commit. Maintainers will acknowledge a
complete report, coordinate remediation and credit, and publish an advisory
after a fix is available.

The project does not claim to be bug-free or suitable as a security boundary
without independent review.

## Release verification

Official release archives are expected to have SHA-256 checksum companions, a
CycloneDX SBOM and a GitHub artifact attestation. Verify all three before
deployment. Absence or failure of any release evidence is a distribution
incident and should be reported privately.
