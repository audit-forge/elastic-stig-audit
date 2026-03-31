# elastic-stig-audit

**CIS Elasticsearch Container Security Benchmark — Automated Audit Tool**

Automated security assessment for Elasticsearch instances deployed in Docker containers, Kubernetes pods, or accessible via REST API. Checks 28 security controls across authentication, encryption, network security, authorization, logging, cluster security, and container runtime hardening.

---

## Features

- **28 automated security checks** covering all major Elasticsearch attack surfaces
- **CVE/KEV scanning** — NVD API v2 + CISA Known Exploited Vulnerabilities catalog
- **Multi-framework mappings** — NIST 800-53, NIST 800-171, CMMC 2.0, MITRE ATT&CK, D3FEND
- **Multiple output formats** — terminal, CSV (21 cols), JSON, SARIF 2.1.0, evidence bundle (ZIP)
- **Three connection modes** — Docker exec, kubectl exec, direct REST API
- **Zero dependencies** — Python 3.10+ standard library only
- **CI/CD ready** — SARIF output for GitHub Security tab, exit codes for pipeline gates

---

## Quick Start

```bash
# Clone
git clone https://github.com/audit-forge/elastic-stig-audit.git
cd elastic-stig-audit

# Audit a running Docker container
python audit.py --mode docker --container my-elasticsearch

# Audit a Kubernetes pod
python audit.py --mode kubectl --pod es-0 --namespace elastic

# Audit via direct REST API (HTTPS)
python audit.py --mode direct \
  --host 10.0.0.5 --port 9200 \
  --username elastic --password mypassword --scheme https

# Full output suite
python audit.py --mode docker --container my-elasticsearch \
  --sarif results.sarif \
  --json results.json \
  --csv results.csv \
  --bundle evidence.zip
```

---

## Installation

**Requirements:** Python 3.10+, Docker CLI or kubectl (for container modes)

```bash
# No pip install required — zero dependencies
git clone https://github.com/audit-forge/elastic-stig-audit.git
cd elastic-stig-audit
python audit.py --help

# Optional: install as CLI tool
pip install -e .
elastic-stig-audit --mode docker --container my-es
```

---

## Connection Modes

### Docker Mode (default)
```bash
python audit.py --mode docker --container <name-or-id>
```
Runs `docker exec <container> curl ...` to query the Elasticsearch REST API from inside the container.

### Kubernetes Mode
```bash
python audit.py --mode kubectl --pod <pod-name> [--namespace <ns>]
```
Runs `kubectl exec <pod> -n <namespace> -- curl ...` to query Elasticsearch.

### Direct Mode
```bash
python audit.py --mode direct --host <host> --port <port> \
  [--username <user>] [--password <pass>] [--scheme https]
```
Queries Elasticsearch REST API directly from the audit host. Useful for cloud-managed deployments (AWS OpenSearch, Elastic Cloud).

---

## Output Formats

| Flag | Format | Use Case |
|------|--------|----------|
| _(default)_ | Terminal | Developer/ops review |
| `--csv FILE` | CSV (21 cols) | Compliance spreadsheet, GRC tool import |
| `--json FILE` | JSON | SIEM integration, custom reporting |
| `--sarif FILE` | SARIF 2.1.0 | GitHub Security tab, Azure DevOps |
| `--bundle FILE` | ZIP | Auditor evidence package |

### CSV Columns (21)
`Control_ID, Title, Severity, Result, Category, Actual, Expected, Description, Rationale, CIS_Control, NIST_800_53, NIST_800_171, CMMC_Level, MITRE_ATTACK, MITRE_D3FEND, Remediation, References, CVE_ID, KEV_Score, CVE_Remediation, Local_Path`

---

## Security Checks

### Authentication (ES-AUTH-*)
| ID | Check | Severity |
|----|-------|----------|
| ES-AUTH-001 | xpack.security.enabled must be true | CRITICAL |
| ES-AUTH-002 | Built-in 'elastic' user default password changed | CRITICAL |
| ES-AUTH-003 | Password minimum length ≥ 12 characters | MEDIUM |
| ES-AUTH-004 | API key authentication service enabled | MEDIUM |
| ES-AUTH-005 | Authentication realm explicitly configured | MEDIUM |

### Encryption (ES-ENC-*)
| ID | Check | Severity |
|----|-------|----------|
| ES-ENC-001 | TLS enabled for HTTP (REST API) | HIGH |
| ES-ENC-002 | TLS enabled for transport (node-to-node) | HIGH |
| ES-ENC-003 | Strong cipher suites only (no RC4/3DES) | HIGH |
| ES-ENC-004 | Certificate verification not disabled | HIGH |
| ES-ENC-005 | Encryption at rest on data directory | MEDIUM |

### Network Security (ES-NET-*)
| ID | Check | Severity |
|----|-------|----------|
| ES-NET-001 | network.host not bound to 0.0.0.0 | HIGH |
| ES-NET-002 | HTTP port changed from default 9200 | LOW |
| ES-NET-003 | Transport port changed from default 9300 | LOW |
| ES-NET-004 | CORS disabled or strictly configured | MEDIUM |

### Authorization (ES-AUTHZ-*)
| ID | Check | Severity |
|----|-------|----------|
| ES-AUTHZ-001 | Custom RBAC roles configured | HIGH |
| ES-AUTHZ-002 | No wildcard write/delete permissions | HIGH |
| ES-AUTHZ-003 | Anonymous access disabled | CRITICAL |
| ES-AUTHZ-004 | Field/document level security where needed | MEDIUM |

### Logging (ES-LOG-*)
| ID | Check | Severity |
|----|-------|----------|
| ES-LOG-001 | xpack.security.audit.enabled=true | HIGH |
| ES-LOG-002 | Required audit events configured | MEDIUM |
| ES-LOG-003 | HTTP access logging configured | MEDIUM |
| ES-LOG-004 | Slow query logging configured | LOW |

### Cluster Security (ES-CLUS-*)
| ID | Check | Severity |
|----|-------|----------|
| ES-CLUS-001 | Cluster name ≠ 'elasticsearch' | MEDIUM |
| ES-CLUS-002 | Node name explicitly configured | LOW |
| ES-CLUS-003 | Discovery seed hosts explicitly set | MEDIUM |
| ES-CLUS-004 | Shard allocation awareness configured | LOW |

### Container Runtime (ES-CONT-*)
| ID | Check | Severity |
|----|-------|----------|
| ES-CONT-001 | Non-root user (elasticsearch/UID 1000) | HIGH |
| ES-CONT-002 | No privileged mode | CRITICAL |
| ES-CONT-003 | Drop ALL capabilities | HIGH |
| ES-CONT-004 | Read-only root filesystem | MEDIUM |
| ES-CONT-005 | Memory and CPU limits configured | HIGH |
| ES-CONT-006 | No host namespace sharing | HIGH |

### Vulnerability Management
| ID | Check | Severity |
|----|-------|----------|
| ES-VER-001 | No known CVEs (NVD + CISA KEV) | CRITICAL/HIGH |

---

## Framework Mappings

Each check maps to:
- **NIST SP 800-53 Rev 5** — FedRAMP control identifiers
- **NIST SP 800-171 Rev 2** — CUI protection controls (mapped from 800-53)
- **CMMC 2.0** — Level 1 or Level 2 classification
- **MITRE ATT&CK** — Enterprise/Containers matrix technique IDs
- **MITRE D3FEND** — Defensive countermeasure technique IDs

---

## CVE Scanning

The tool queries the NVD API v2 and CISA KEV catalog for CVEs affecting the detected Elasticsearch version:

```bash
# Run with CVE scanning (default)
python audit.py --mode docker --container my-es

# Skip CVE scanning (faster)
python audit.py --mode docker --container my-es --skip-cve

# Set NVD API key for higher rate limits
export NVD_API_KEY=your-api-key
python audit.py --mode docker --container my-es
```

See [docs/CVE_SCANNING.md](docs/CVE_SCANNING.md) for details.

---

## CI/CD Integration

### GitHub Actions
```yaml
- name: Elasticsearch Security Audit
  run: |
    python audit.py --mode docker --container my-es \
      --sarif es-audit.sarif \
      --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: es-audit.sarif
```

### Exit Codes
- `0` — all checks passed (or no findings above `--fail-on` threshold)
- `1` — findings found above threshold

```bash
# Fail pipeline on CRITICAL findings
python audit.py --mode docker --container my-es --fail-on critical

# Fail pipeline on any HIGH or CRITICAL findings
python audit.py --mode docker --container my-es --fail-on high
```

---

## Benchmark Reference

[benchmarks/CIS_Elasticsearch_Container_Benchmark_v1.0.md](benchmarks/CIS_Elasticsearch_Container_Benchmark_v1.0.md)

This benchmark documents all 28 controls with assessment procedures, pass conditions, and remediation guidance.

---

## Documentation

- [docs/RUN_BENCHMARK.md](docs/RUN_BENCHMARK.md) — Complete usage guide with examples
- [docs/CVE_SCANNING.md](docs/CVE_SCANNING.md) — CVE/KEV scanning configuration
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to add checks or contribute
- [SECURITY.md](SECURITY.md) — Vulnerability reporting policy

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

*Part of the [audit-forge](https://github.com/audit-forge) security toolchain.*
