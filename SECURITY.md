# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x | ✓ |

## Reporting a Vulnerability

If you discover a security vulnerability in `elastic-stig-audit`:

1. **Do not open a public GitHub issue**
2. Email: security@audit-forge.io
3. Include: description, reproduction steps, impact assessment
4. We will respond within 48 hours and provide a fix within 14 days for critical issues

## Scope

- False negatives (check passes when it should fail) — HIGH priority
- False positives — MEDIUM priority
- Information disclosure via audit output — MEDIUM priority
- Dependency vulnerabilities — handled via automated scanning

## Out of Scope

- Issues in Elasticsearch itself (report to Elastic: https://www.elastic.co/community/security)
- Issues in the NVD or CISA KEV APIs
