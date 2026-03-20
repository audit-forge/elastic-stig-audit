# Contributing to elastic-stig-audit

Thank you for contributing! This guide explains how to add new security checks, improve existing ones, and submit pull requests.

---

## Adding a New Check

### 1. Choose or Create a Check Module

Checks live in `checks/`. Add to an existing module or create a new one:

```
checks/
├── auth_checks.py      # ES-AUTH-*
├── encryption_checks.py # ES-ENC-*
├── network_checks.py   # ES-NET-*
├── authz_checks.py     # ES-AUTHZ-*
├── logging_checks.py   # ES-LOG-*
├── cluster_checks.py   # ES-CLUS-*
└── container_checks.py # ES-CONT-*
```

### 2. Assign a Check ID

Follow the naming pattern:
- `ES-AUTH-NNN` — Authentication
- `ES-ENC-NNN` — Encryption
- `ES-NET-NNN` — Network
- `ES-AUTHZ-NNN` — Authorization
- `ES-LOG-NNN` — Logging
- `ES-CLUS-NNN` — Cluster
- `ES-CONT-NNN` — Container

### 3. Implement the Check

```python
from .base import BaseChecker, CheckResult, Severity, Status

class MyChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        node_settings = self.runner.get_node_settings()
        value = node_settings.get("my.setting", "")

        return [self._check_my_setting(value)]

    def _check_my_setting(self, value: str) -> CheckResult:
        passes = value == "expected"
        return CheckResult(
            check_id="ES-NEW-001",
            title="My new check",
            status=Status.PASS if passes else Status.FAIL,
            severity=Severity.HIGH,
            benchmark_control_id="8.1",
            cis_id="CIS-ES-8.1",
            fedramp_control="AC-6",
            nist_800_53_controls=["AC-6"],
            description="Detailed description of what this checks.",
            rationale="Why this matters from a security perspective.",
            actual=f"my.setting={value!r}",
            expected="my.setting=expected",
            remediation="How to fix it.",
            references=["CIS Elasticsearch Benchmark v1.0 §8.1"],
            category="MyCategory",
            evidence_type="runtime-config",
            evidence=[
                self.evidence("node_settings.my_setting", value, "GET /_nodes/_local/settings")
            ],
        )
```

### 4. Add to `checks/__init__.py`

```python
from .my_checks import MyChecker

ALL_CHECKERS = [
    ...,
    MyChecker,
]
```

### 5. Add Framework Mappings

In `mappings/frameworks.py`:

```python
FRAMEWORK_MAP: dict[str, dict] = {
    ...,
    "ES-NEW-001": {
        "nist_800_171": ["3.1.5"],
        "cmmc_level": 1,
        "mitre_attack": ["T1078"],
        "mitre_d3fend": ["D3-UAP"],
    },
}
```

### 6. Document in the Benchmark

Add a section to `benchmarks/CIS_Elasticsearch_Container_Benchmark_v1.0.md`.

### 7. Write a Test

```python
# test/test_my_check.py
import sys; sys.path.insert(0, ".")
from checks.my_checks import MyChecker

class FakeRunner:
    mode = "direct"
    def get_node_settings(self): return {"my.setting": "expected"}
    def get_cluster_settings(self): return {}
    def evidence(self, *a, **kw): return {}

def test_pass():
    checker = MyChecker(FakeRunner())
    results = checker.run()
    assert results[0].status.value == "PASS"

def test_fail():
    r = FakeRunner()
    r.get_node_settings = lambda: {}
    checker = MyChecker(r)
    results = checker.run()
    assert results[0].status.value in ("FAIL", "WARN")
```

---

## Code Style

- Python 3.9+ compatible
- Zero external dependencies (stdlib only)
- Type hints preferred but not mandatory
- PEP 8 formatting

---

## Pull Request Process

1. Fork and create a branch: `git checkout -b feat/es-new-001`
2. Add check + mapping + test
3. Run existing tests: `python -m pytest test/`
4. Open PR with description of the control being added

---

## Reporting False Positives

Open a GitHub issue with:
- Elasticsearch version
- Connection mode
- Check ID and observed output
- Expected behavior
