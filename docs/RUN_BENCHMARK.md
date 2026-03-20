# Running the Elasticsearch Security Benchmark

This guide explains how to run `elastic-stig-audit` against Elasticsearch in different deployment scenarios.

---

## Prerequisites

- Python 3.9 or later
- `curl` installed (used by the runner inside the container or on the audit host)
- Docker CLI (for `--mode docker`)
- `kubectl` (for `--mode kubectl`)

---

## Quickstart

```bash
git clone https://github.com/audit-forge/elastic-stig-audit.git
cd elastic-stig-audit

# Verify Python version
python3 --version  # 3.9+

# Run against a Docker container
python audit.py --mode docker --container elasticsearch --no-tls
```

---

## Docker Mode

The most common mode for local development and CI pipelines.

```bash
# Basic run
python audit.py --mode docker --container elasticsearch

# With HTTPS (if container has TLS configured)
python audit.py --mode docker --container elasticsearch

# All outputs
python audit.py --mode docker --container elasticsearch \
  --sarif results.sarif \
  --json results.json \
  --csv results.csv \
  --bundle evidence.zip

# Skip CVE scan (faster)
python audit.py --mode docker --container elasticsearch --skip-cve

# Verbose (show runner commands)
python audit.py --mode docker --container elasticsearch --verbose
```

### Starting a Test Container

```bash
# Elasticsearch 8.x with security disabled (for testing)
docker run -d \
  --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0

# Elasticsearch 8.x with security enabled
docker run -d \
  --name elasticsearch-secure \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "ELASTIC_PASSWORD=mypassword" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0
```

---

## Kubernetes Mode

```bash
# Basic
python audit.py --mode kubectl --pod elasticsearch-0

# With namespace
python audit.py --mode kubectl --pod elasticsearch-0 --namespace elastic

# All outputs
python audit.py --mode kubectl --pod elasticsearch-0 --namespace elastic \
  --sarif results.sarif --json results.json --csv results.csv
```

### ECK (Elastic Cloud on Kubernetes)

```bash
# Find your pod
kubectl get pods -n elastic -l elasticsearch.k8s.elastic.co/cluster-name=my-cluster

# Run audit
python audit.py --mode kubectl \
  --pod my-cluster-es-default-0 \
  --namespace elastic
```

---

## Direct Mode

Use when Elasticsearch is accessible from the audit host — cloud-managed services, VPN-connected clusters, or port-forwarded local instances.

```bash
# HTTP
python audit.py --mode direct --host 10.0.0.5 --port 9200

# HTTPS with credentials
python audit.py --mode direct \
  --host es.example.com \
  --port 9200 \
  --scheme https \
  --username elastic \
  --password mypassword

# Port-forward from Kubernetes
kubectl port-forward svc/elasticsearch-es-http 9200:9200 -n elastic &
python audit.py --mode direct --host 127.0.0.1 --port 9200 \
  --scheme https --username elastic --password $(kubectl get secret -n elastic \
    elasticsearch-es-elastic-user -o go-template='{{.data.elastic | base64decode}}')
```

---

## Output Formats

### Terminal Report (default)

The terminal report shows a summary and detailed findings sorted by severity:

```
elastic-stig-audit — CIS Elasticsearch Container Security Assessment
Target: elasticsearch
Mode: docker | Connected: True | Generated: 2026-03-19T21:00:00+00:00

Executive summary:
  PASS 18 | FAIL 7 | WARN 3 | ERROR 0 | SKIP 0
  CRITICAL 2 | HIGH 4 | MEDIUM 3 | LOW 1 | INFO 0
  Risk posture: HIGH RISK | Actionable findings: 10

Top findings:
  - [FAIL/CRITICAL] ES-AUTH-001 (1.1) xpack.security enabled
  - [FAIL/CRITICAL] ES-AUTHZ-003 (4.3) Anonymous access disabled
  ...
```

### CSV Output

The CSV contains 21 columns for compliance reporting and GRC tool import:

| Column | Description |
|--------|-------------|
| Control_ID | e.g., ES-AUTH-001 |
| Title | Check name |
| Severity | CRITICAL/HIGH/MEDIUM/LOW/INFO |
| Result | PASS/FAIL/WARN/SKIP/ERROR |
| Category | Authentication/Encryption/etc. |
| Actual | What was found |
| Expected | What should be there |
| Description | Full description |
| Rationale | Why this matters |
| CIS_Control | CIS Benchmark section |
| NIST_800_53 | e.g., AC-2; IA-5 |
| NIST_800_171 | e.g., 3.5.1; 3.5.7 |
| CMMC_Level | 1 or 2 |
| MITRE_ATTACK | e.g., T1078; T1190 |
| MITRE_D3FEND | e.g., D3-UAP; D3-SPP |
| Remediation | Fix guidance |
| References | Documentation links |
| CVE_ID | e.g., CVE-2023-31419 |
| KEV_Score | CISA KEV status |
| CVE_Remediation | CVE-specific fix |
| Local_Path | Binary path |

### SARIF Output (GitHub/GitLab CI)

```yaml
# .github/workflows/security.yml
- name: Run Elasticsearch Security Audit
  run: |
    python audit.py --mode docker --container elasticsearch \
      --sarif elastic-audit.sarif \
      --fail-on high

- name: Upload Security Results
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: elastic-audit.sarif
    category: elastic-stig-audit
```

### Evidence Bundle (ZIP)

The bundle contains everything needed for an audit package:

```
elastic-stig-bundle.zip
├── manifest.json       # Bundle metadata
├── results.json        # Full findings (JSON)
├── results.sarif       # SARIF 2.1.0
├── snapshot.json       # Node settings snapshot
├── summary.txt         # Human-readable summary
└── evidence/
    ├── ES-AUTH-001.json
    ├── ES-ENC-001.json
    └── ... (one file per check)
```

---

## CI/CD Integration

### Fail-On Thresholds

```bash
# Fail on any CRITICAL finding
python audit.py --mode docker --container es --fail-on critical

# Fail on HIGH or CRITICAL
python audit.py --mode docker --container es --fail-on high

# Fail on any actionable finding
python audit.py --mode docker --container es --fail-on any

# Never fail (reporting only)
python audit.py --mode docker --container es --fail-on none
```

### GitLab CI

```yaml
elasticsearch-security:
  stage: security
  script:
    - python audit.py --mode docker --container $ES_CONTAINER
        --sarif gl-sast-report.sarif
        --fail-on high
  artifacts:
    reports:
      sast: gl-sast-report.sarif
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | NVD API key for higher CVE scan rate limits |
| `ES_AUDIT_HOST` | Override default host (direct mode) |
| `ES_AUDIT_PASSWORD` | Elasticsearch password (avoid passing on CLI) |

---

## Interpreting Results

### Status Values

| Status | Meaning |
|--------|---------|
| **PASS** | Control met — no action required |
| **FAIL** | Control not met — remediation required |
| **WARN** | Configuration present but suboptimal or manual verification needed |
| **SKIP** | Check not applicable for this connection mode |
| **ERROR** | Check could not be completed (connection error, permission denied) |

### Risk Posture

| Posture | Meaning |
|---------|---------|
| `HIGH RISK` | FAIL or ERROR findings present |
| `REVIEW REQUIRED` | WARN findings present, no FAIL/ERROR |
| `BASELINE ACCEPTABLE` | All checks PASS or SKIP |

---

## Troubleshooting

### Cannot connect to Elasticsearch

```bash
# Test connectivity manually
docker exec elasticsearch curl -s http://localhost:9200/
# or
curl -u elastic:password https://localhost:9200/

# Run with verbose output
python audit.py --mode docker --container elasticsearch --verbose
```

### Security API returns 403

The audit user needs the `monitor` or `superuser` role to access most security endpoints:

```bash
# Create a read-only audit user
curl -X POST -u elastic:password https://localhost:9200/_security/user/auditor \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "audit-password",
    "roles": ["monitor", "view_index_metadata"],
    "full_name": "Security Auditor"
  }'

python audit.py --mode direct --host localhost \
  --username auditor --password audit-password
```

### CVE scan is slow

Set an NVD API key for 50 req/30s instead of 5 req/30s:
```bash
export NVD_API_KEY=<your-key>
python audit.py --mode docker --container elasticsearch
```

Or skip CVE scanning:
```bash
python audit.py --mode docker --container elasticsearch --skip-cve
```
