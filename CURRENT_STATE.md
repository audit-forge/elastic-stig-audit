# elastic-stig-audit — Current State

**Last validated:** 2026-03-31
**Python:** 3.14.3
**pytest:** 9.0.2

---

## What this tool is

A Python stdlib-only audit CLI for Elasticsearch deployed in Docker or Kubernetes containers. It implements a community-developed CIS-style security benchmark covering 28 controls across 7 domains plus CVE/KEV vulnerability scanning. Zero external dependencies.

---

## Test status (evidence)

```
python3 -m pytest test/ -q
94 passed in 0.14s
```

Breakdown by file:
- `test/test_checks.py` — 56 tests covering all 7 check categories + framework mappings
- `test/test_cve_scanner.py` — 23 tests covering version detection, cache helpers, NVD/KEV fetch, result building (all network calls mocked)
- `test/test_runner.py` — 12 tests covering runner initialization, curl construction, and snapshot
- `test/test_sarif_output.py` — 3 tests covering SARIF artifact URI sanitization and help URI validation

---

## What works

- **28 automated controls** across 7 domains (auth, encryption, network, authz, logging, cluster, container)
- **3 connection modes**: `--mode docker`, `--mode kubectl`, `--mode direct`
- **4 output formats**: terminal (default), `--json FILE`, `--sarif FILE`, `--csv FILE`, `--bundle FILE`
- **CSV export** with 21 compliance columns including NIST 800-53, NIST 800-171, CMMC 2.0, MITRE ATT&CK/D3FEND
- **CVE/KEV scanning** via NVD API v2 + CISA KEV catalog with 24-hour cache
- **Evidence bundling**: ZIP archive with per-check evidence files, snapshot, SARIF
- **All tests pass** with no network calls required (CVE scanner tests fully mocked)
- **Framework enrichment**: all 28 check IDs have NIST 800-171, CMMC, MITRE ATT&CK/D3FEND mappings verified in tests
- **CI integration job**: GitHub Actions runs the full audit against a live single-node Elasticsearch 8.12.0 service on every push to main

---

## What does not work / known limitations

1. **No local integration test fixtures.** The unit test suite uses `FakeRunner` mocks throughout; there is no `test/run_fixtures.sh` or Docker Compose fixture for local developer use. CI fills this gap with a GitHub Actions integration job (`.github/workflows/test.yml`) that runs the full audit against a live Elasticsearch 8.12.0 service on every push to main, but this is not reproducible offline.

2. **CVE scanner is best-effort only.** NVD keyword search returns false positives and misses version-specific CVEs. It does not use the CPE-based NVD search, which would be more accurate. Rate limiting without an API key (6s sleep per request) makes it slow in CI.

3. **AUTH-002 (elastic default password) cannot actually verify the password hash.** The check uses a heuristic: if the security API is accessible without credentials, security may be weak. It cannot definitively confirm the password was changed. Manual verification is required.

4. **ENC-005 (encryption at rest) always returns WARN.** Disk-level encryption cannot be verified via the Elasticsearch REST API. This is documented in the check and benchmark but produces noise in automated reports.

5. **Container checks (CONT-001 through CONT-006) SKIP in `--mode direct`.** There is no container runtime to inspect. For cloud-managed Elasticsearch (Elastic Cloud, AWS OpenSearch), all 6 container checks are SKIP.

6. **CLUS-002 (node name) heuristic may produce false WARNs.** Detects auto-generated names by checking for 22-character base62 strings. Legitimate short hostnames that match this pattern would be incorrectly flagged.

7. **No check for `action.auto_create_index: "*"`.** Wildcard auto-create index is a data injection risk that is not currently covered. Documented as a v1.1 candidate.

8. **No check for ES 8.x enrollment token security.** `xpack.security.enrollment.enabled` controls whether the cluster accepts new node enrollment. Not currently assessed.

9. **No check for snapshot repository access controls.** Snapshots can exfiltrate all cluster data. Not currently covered.

---

## Code quality notes

- Zero external dependencies (stdlib only)
- No known injection vulnerabilities; subprocess calls use list args (not shell=True)
- No hardcoded credentials
- GitHub Actions CI runs tests on Python 3.10–3.12 matrix

---

## v1.0 boundary decision

This tool is **functionally complete as a v1.0 baseline** with the following caveats:

- The absence of real-instance integration tests means v1.0 is a "unit-tested baseline" not a "fixture-validated" tool like pg-stig-audit or mongo-stig-audit.
- The benchmark document (`benchmarks/CIS_Elasticsearch_Container_Benchmark_v1.0.md`) is a community draft, clearly labeled as such, not an official CIS benchmark.
- All 28 check implementations are consistent with the benchmark text and have passing unit tests.

**Not blocking v1.0:** integration test fixtures, auto_create_index check, enrollment token check, snapshot repo check.

---

## v1.1 backlog

- Local integration test fixtures (`test/run_fixtures.sh` + Docker Compose for offline developer use)
- `action.auto_create_index` check (ES-AUTHZ-005)
- `xpack.security.enrollment.enabled` check (ES-AUTH-006)
- Snapshot repository security check (ES-AUTH-007)
- CPE-based NVD CVE lookup (more accurate than keyword search)
- Cross-cluster search/replication security checks
- `node.roles` dedicated topology check (master/data/coordinating separation)
