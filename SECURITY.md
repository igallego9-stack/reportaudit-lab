# Security Policy

## Supported versions

| Version | Supported          | End of security support |
|---------|--------------------|-------------------------|
| 1.x     | :white_check_mark: | 2031-12-31              |
| < 1.0   | :x:                | --                      |

## Reporting a vulnerability

Please **do not** open a public issue. Report it privately through GitHub:
**Security > Report a vulnerability**
https://github.com/igallego9-stack/reportaudit-lab/security/advisories/new

Include the affected version, steps to reproduce, the impact you observed
and, if you have one, a suggested fix.

## What to expect

- Acknowledgement within **3 business days**.
- Initial assessment within **10 business days**.
- Coordinated disclosure: we aim to release a fix and publish a security
  advisory within **90 days**. We will credit you unless you prefer otherwise.

## Safe harbour

We will not take legal action against researchers who act in good faith,
avoid privacy violations and service disruption, and give us reasonable
time to fix the issue before disclosing it.

## Verifying our releases

Every release includes a CycloneDX SBOM, SHA-256 checksums and
Sigstore-signed provenance attestations. To verify a download:

```bash
sha256sum -c SHA256SUMS
gh attestation verify reportaudit-<version>.tar.gz --repo igallego9-stack/reportaudit-lab
```
