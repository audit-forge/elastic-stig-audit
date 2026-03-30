"""Unit tests for the CVE/KEV scanner module.

All network calls are patched so tests run offline.
"""
import sys
import os
import json
import tempfile
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from checks.cve_scanner import (
    detect_elasticsearch_version,
    fetch_cve_data,
    load_kev_catalog,
    cve_to_check_result,
    _load_cache,
    _save_cache,
)
from checks.base import Status, Severity


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _fake_nvd_response(cve_list: list[dict]) -> bytes:
    """Encode a minimal NVD API v2 response."""
    return json.dumps({"vulnerabilities": cve_list}).encode("utf-8")


def _nvd_item(cve_id: str, description: str, cvss: float) -> dict:
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": cvss}}
                ]
            },
            "published": "2024-01-01T00:00:00Z",
        }
    }


def _kev_response(cve_ids: list[str]) -> bytes:
    vulns = [
        {
            "cveID": cid,
            "dateAdded": "2024-01-15",
            "requiredAction": "Apply vendor patch immediately.",
        }
        for cid in cve_ids
    ]
    return json.dumps({"vulnerabilities": vulns}).encode("utf-8")


# ---------------------------------------------------------------------------
# detect_elasticsearch_version
# ---------------------------------------------------------------------------

class TestDetectElasticsearchVersion:
    def _runner(self, response: dict | None):
        runner = MagicMock()
        runner.api_get.return_value = response
        return runner

    def test_returns_version_from_api(self):
        runner = self._runner({"version": {"number": "8.12.0"}})
        assert detect_elasticsearch_version(runner) == "8.12.0"

    def test_returns_none_when_api_fails(self):
        runner = self._runner(None)
        assert detect_elasticsearch_version(runner) is None

    def test_returns_none_when_version_missing(self):
        runner = self._runner({"cluster_name": "prod"})
        assert detect_elasticsearch_version(runner) is None

    def test_strips_whitespace(self):
        runner = self._runner({"version": {"number": "  7.17.0  "}})
        assert detect_elasticsearch_version(runner) == "7.17.0"


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

class TestCacheHelpers:
    def test_load_cache_returns_none_for_missing_file(self):
        assert _load_cache("/tmp/nonexistent_elastic_test_xyz.json") is None

    def test_save_and_load_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "test_cache.json")
            _save_cache(path, [{"cveID": "CVE-2024-0001"}])
            result = _load_cache(path)
            assert result is not None
            assert result["data"] == [{"cveID": "CVE-2024-0001"}]

    def test_load_cache_returns_none_when_expired(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old_cache.json")
            stale_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
            with open(path, "w") as f:
                json.dump({"cached_at": stale_time, "data": []}, f)
            assert _load_cache(path) is None


# ---------------------------------------------------------------------------
# fetch_cve_data
# ---------------------------------------------------------------------------

class TestFetchCveData:
    def test_returns_empty_list_on_api_error(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("urllib.request.urlopen", side_effect=Exception("network error")):
                with patch("time.sleep"):  # skip rate-limit sleep
                    result = fetch_cve_data("elasticsearch", "8.12.0", d)
        assert result == []

    def test_filters_cves_not_mentioning_product(self):
        """CVEs whose description does not contain 'elasticsearch' should be excluded."""
        items = [
            _nvd_item("CVE-2024-0001", "A vulnerability in elasticsearch 8.12", 7.5),
            _nvd_item("CVE-2024-0002", "A vulnerability in apache httpd", 9.8),
        ]
        mock_resp = MagicMock()
        mock_resp.read.return_value = _fake_nvd_response(items)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with tempfile.TemporaryDirectory() as d:
            with patch("urllib.request.urlopen", return_value=mock_resp):
                with patch("time.sleep"):
                    result = fetch_cve_data("elasticsearch", "8.12.0", d)

        assert len(result) == 1
        assert result[0]["cve_id"] == "CVE-2024-0001"

    def test_uses_cache_on_second_call(self):
        """Second call with fresh cache should not hit the network."""
        items = [_nvd_item("CVE-2024-0001", "elasticsearch 8.12 vulnerability", 7.5)]
        mock_resp = MagicMock()
        mock_resp.read.return_value = _fake_nvd_response(items)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with tempfile.TemporaryDirectory() as d:
            with patch("urllib.request.urlopen", return_value=mock_resp) as mock_url:
                with patch("time.sleep"):
                    fetch_cve_data("elasticsearch", "8.12.0", d)
                    fetch_cve_data("elasticsearch", "8.12.0", d)
            # Should only have made one real network request
            assert mock_url.call_count == 1

    def test_returns_cvss_score(self):
        items = [_nvd_item("CVE-2024-0001", "elasticsearch 8.12 critical", 9.8)]
        mock_resp = MagicMock()
        mock_resp.read.return_value = _fake_nvd_response(items)
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with tempfile.TemporaryDirectory() as d:
            with patch("urllib.request.urlopen", return_value=mock_resp):
                with patch("time.sleep"):
                    result = fetch_cve_data("elasticsearch", "8.12.0", d)

        assert result[0]["cvss_score"] == 9.8

    def test_handles_http_error(self):
        import urllib.error
        with tempfile.TemporaryDirectory() as d:
            with patch(
                "urllib.request.urlopen",
                side_effect=urllib.error.HTTPError(None, 403, "Forbidden", {}, None)
            ):
                with patch("time.sleep"):
                    result = fetch_cve_data("elasticsearch", "8.12.0", d)
        assert result == []


# ---------------------------------------------------------------------------
# load_kev_catalog
# ---------------------------------------------------------------------------

class TestLoadKevCatalog:
    def test_returns_dict_keyed_by_cve_id(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = _kev_response(["CVE-2024-0001", "CVE-2024-0002"])
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with tempfile.TemporaryDirectory() as d:
            with patch("urllib.request.urlopen", return_value=mock_resp):
                kev = load_kev_catalog(d)

        assert "CVE-2024-0001" in kev
        assert "CVE-2024-0002" in kev
        assert kev["CVE-2024-0001"]["dateAdded"] == "2024-01-15"

    def test_returns_empty_dict_on_error(self):
        with tempfile.TemporaryDirectory() as d:
            with patch("urllib.request.urlopen", side_effect=Exception("network error")):
                kev = load_kev_catalog(d)
        assert kev == {}

    def test_uses_cache(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = _kev_response(["CVE-2024-9999"])
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with tempfile.TemporaryDirectory() as d:
            with patch("urllib.request.urlopen", return_value=mock_resp) as mock_url:
                load_kev_catalog(d)
                load_kev_catalog(d)
            assert mock_url.call_count == 1


# ---------------------------------------------------------------------------
# cve_to_check_result
# ---------------------------------------------------------------------------

class TestCveToCheckResult:
    def test_no_cves_returns_pass(self):
        result = cve_to_check_result([], {}, "elasticsearch", "8.12.0", "/data")
        assert result.status == Status.PASS
        assert result.check_id == "ES-VER-001"
        assert result.severity == Severity.INFO

    def test_cves_without_kev_high_cvss_returns_fail_high(self):
        cves = [{"cve_id": "CVE-2024-0001", "cvss_score": 7.5, "description": "vuln"}]
        result = cve_to_check_result(cves, {}, "elasticsearch", "8.12.0", "/data")
        assert result.status == Status.FAIL
        assert result.severity == Severity.HIGH

    def test_cves_with_kev_hit_returns_critical(self):
        cves = [{"cve_id": "CVE-2024-0001", "cvss_score": 7.5, "description": "vuln"}]
        kev = {"CVE-2024-0001": {"dateAdded": "2024-01-01", "requiredAction": "Patch immediately."}}
        result = cve_to_check_result(cves, kev, "elasticsearch", "8.12.0", "/data")
        assert result.status == Status.FAIL
        assert result.severity == Severity.CRITICAL
        assert "HIGH_PRIORITY" in result.kev_score

    def test_cvss_9_returns_critical(self):
        cves = [{"cve_id": "CVE-2024-9999", "cvss_score": 9.8, "description": "critical vuln"}]
        result = cve_to_check_result(cves, {}, "elasticsearch", "8.12.0", "/data")
        assert result.severity == Severity.CRITICAL

    def test_cvss_low_returns_medium(self):
        cves = [{"cve_id": "CVE-2024-0001", "cvss_score": 4.3, "description": "minor vuln"}]
        result = cve_to_check_result(cves, {}, "elasticsearch", "8.12.0", "/data")
        assert result.severity == Severity.MEDIUM

    def test_cve_ids_included_in_result(self):
        cves = [
            {"cve_id": "CVE-2024-0001", "cvss_score": 7.5, "description": "vuln 1"},
            {"cve_id": "CVE-2024-0002", "cvss_score": 6.0, "description": "vuln 2"},
        ]
        result = cve_to_check_result(cves, {}, "elasticsearch", "8.12.0", "/data")
        assert "CVE-2024-0001" in result.cve_ids
        assert "CVE-2024-0002" in result.cve_ids

    def test_version_appears_in_title(self):
        result = cve_to_check_result([], {}, "elasticsearch", "7.17.0", "/data")
        assert "7.17.0" in result.title

    def test_no_cves_has_empty_cve_ids(self):
        result = cve_to_check_result([], {}, "elasticsearch", "8.12.0", "/data")
        assert result.cve_ids == []
