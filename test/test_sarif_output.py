from checks.base import CheckResult, Severity, Status
from output.sarif import build_sarif


def _sample_result(references=None):
    return CheckResult(
        check_id="ES-AUTH-001",
        title="Elasticsearch security features must be enabled",
        status=Status.FAIL,
        severity=Severity.CRITICAL,
        description="Security should be enabled",
        actual="xpack.security.enabled=false",
        expected="xpack.security.enabled=true",
        references=references or [],
        category="Authentication",
    )


def test_sarif_uses_repo_safe_artifact_uri_for_http_targets():
    doc = build_sarif(
        [_sample_result()],
        {"display_name": "http://localhost:9200"},
        "elastic-stig-audit",
        "1.0.0",
    )
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uri"].startswith("targets/")
    assert "uriBaseId" not in loc
    assert "://" not in loc["uri"]


def test_sarif_omits_non_url_help_uri():
    doc = build_sarif(
        [_sample_result(["CIS Elasticsearch Benchmark v1.0 §1.1"])],
        {"display_name": "docker://es01"},
        "elastic-stig-audit",
        "1.0.0",
    )
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert "helpUri" not in rule


def test_sarif_keeps_valid_https_help_uri():
    doc = build_sarif(
        [_sample_result(["https://example.com/control/1", "CIS Elasticsearch Benchmark v1.0 §1.1"])],
        {"display_name": "docker://es01"},
        "elastic-stig-audit",
        "1.0.0",
    )
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://example.com/control/1"
