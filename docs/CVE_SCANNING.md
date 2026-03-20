# CVE Scanning — elastic-stig-audit

`elastic-stig-audit` includes an integrated CVE/KEV vulnerability scanner that checks the detected Elasticsearch version against:

1. **NVD API v2** — NIST National Vulnerability Database
2. **CISA KEV Catalog** — Known Exploited Vulnerabilities

---

## How It Works

1. **Version Detection** — Queries `GET /` to extract the Elasticsearch version (e.g., `8.12.0`)
2. **NVD Lookup** — Searches NVD API v2 for CVEs matching `elasticsearch <version>`
3. **KEV Cross-Reference** — Checks each CVE ID against the CISA KEV catalog
4. **Severity Calculation** — CRITICAL if KEV hit or CVSS ≥ 9.0; HIGH if CVSS ≥ 7.0; else MEDIUM
5. **CheckResult** — Emits `ES-VER-001` with all CVE IDs and KEV status

---

## Usage

```bash
# CVE scanning runs by default
python audit.py --mode docker --container elasticsearch

# Skip CVE scanning (faster)
python audit.py --mode docker --container elasticsearch --skip-cve

# Set NVD API key for higher rate limits (50 req/30s vs 5 req/30s)
export NVD_API_KEY=<your-nvd-api-key>
python audit.py --mode docker --container elasticsearch
```

---

## Caching

Results are cached in `data/` for 24 hours to avoid repeated API calls:

```
data/
├── cve_cache.json   # NVD CVE data keyed by product:version
└── kev_cache.json   # CISA KEV catalog (full list)
```

```bash
# Clear cache to force fresh fetch
rm data/cve_cache.json data/kev_cache.json
python audit.py --mode docker --container elasticsearch
```

---

## NVD API Key

Without an API key, NVD limits requests to 5 per 30 seconds. The scanner automatically sleeps to respect this limit. With an API key, the limit is 50 requests per 30 seconds.

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

```bash
# Set in environment
export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Or pass in CI/CD secrets
# GitHub Actions:
# env:
#   NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
```

---

## Interpreting Results

### PASS — No CVEs Found

```
[PASS/INFO] ES-VER-001 Elasticsearch version 8.12.0 — CVE/KEV vulnerability scan
  Actual: version=8.12.0, cves=0
```

### FAIL — CVEs Found

```
[FAIL/CRITICAL] ES-VER-001 Elasticsearch version 7.10.0 — CVE/KEV vulnerability scan
  Severity: CRITICAL | Category: vulnerability-management
  Actual: version=7.10.0, cves=12, kev_hits=2
  CVEs: CVE-2021-22144 (CVSS: 9.1); CVE-2021-22137 (CVSS: 8.1); ...
  KEV:  HIGH_PRIORITY (CISA KEV - Added: 2022-01-10)
```

The CSV output includes full CVE details:

| Column | Example |
|--------|---------|
| CVE_ID | CVE-2021-22144; CVE-2021-22137 |
| KEV_Score | HIGH_PRIORITY (CISA KEV - Added: 2022-01-10) |
| CVE_Remediation | Upgrade Elasticsearch to 7.17.x or 8.x. CISA KEV required action for CVE-2021-22144: Apply updates per vendor instructions. |

---

## Known Elasticsearch CVEs (Examples)

| CVE | CVSS | Description |
|-----|------|-------------|
| CVE-2021-22144 | 9.1 | Remote code execution via Grok patterns |
| CVE-2021-22137 | 8.1 | Information disclosure via document metadata |
| CVE-2023-31419 | 7.5 | Stack overflow via _search?q= parameter |
| CVE-2023-46673 | 7.5 | Denial of service via malformed TLS |
| CVE-2024-23450 | 7.5 | Node crash via corrupt cluster state |

For the full list, see: https://nvd.nist.gov/vuln/search/results?query=elasticsearch

---

## Offline Use

If the audit environment has no internet access:

```bash
# Pre-populate cache from an internet-connected machine
python - <<'EOF'
from checks.cve_scanner import fetch_cve_data, load_kev_catalog
import os
cache_dir = "data"
os.makedirs(cache_dir, exist_ok=True)
load_kev_catalog(cache_dir)
fetch_cve_data("elasticsearch", "8.12.0", cache_dir)
print("Cache populated")
EOF

# Copy data/ directory to air-gapped machine
# Then run with the populated cache:
python audit.py --mode docker --container elasticsearch
# Will use cached data even without network
```

---

## CI/CD Pipeline Integration

### GitHub Actions with CVE gate

```yaml
- name: Elasticsearch CVE Scan
  env:
    NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
  run: |
    python audit.py \
      --mode docker \
      --container elasticsearch \
      --csv cve-report.csv \
      --fail-on critical

- name: Upload CVE report
  uses: actions/upload-artifact@v4
  with:
    name: elasticsearch-cve-report
    path: cve-report.csv
```
