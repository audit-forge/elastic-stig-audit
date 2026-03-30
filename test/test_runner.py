"""Tests for ElasticsearchRunner."""
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from runner import ElasticsearchRunner


def test_runner_defaults():
    r = ElasticsearchRunner()
    assert r.mode == "docker"
    assert r.host == "127.0.0.1"
    assert r.port == 9200
    assert r.scheme == "http"


def test_base_url_http():
    r = ElasticsearchRunner(mode="direct", host="10.0.0.1", port=9200, scheme="http")
    assert r._base_url() == "http://10.0.0.1:9200"


def test_base_url_https():
    r = ElasticsearchRunner(mode="direct", host="es.example.com", port=9243, scheme="https")
    assert r._base_url() == "https://es.example.com:9243"


def test_base_curl_direct_no_auth():
    r = ElasticsearchRunner(mode="direct", host="127.0.0.1", port=9200, scheme="http")
    cmd = r._base_curl()
    assert "curl" in cmd
    assert "-u" not in cmd


def test_base_curl_direct_with_auth():
    r = ElasticsearchRunner(
        mode="direct", host="127.0.0.1", port=9200, scheme="https",
        username="elastic", password="secret"
    )
    cmd = r._base_curl()
    assert "-u" in cmd
    assert "elastic:secret" in cmd
    assert "-k" in cmd  # insecure (audit mode)


def test_base_curl_docker_requires_container():
    r = ElasticsearchRunner(mode="docker")
    with pytest.raises(ValueError, match="--container"):
        r._base_curl()


def test_base_curl_docker():
    r = ElasticsearchRunner(mode="docker", container="my-es")
    cmd = r._base_curl()
    assert cmd[:3] == ["docker", "exec", "my-es"]
    assert "curl" in cmd


def test_base_curl_kubectl_requires_pod():
    r = ElasticsearchRunner(mode="kubectl")
    with pytest.raises(ValueError, match="--pod"):
        r._base_curl()


def test_base_curl_kubectl():
    r = ElasticsearchRunner(mode="kubectl", pod="es-0", namespace="elastic")
    cmd = r._base_curl()
    assert "kubectl" in cmd
    assert "exec" in cmd
    assert "-n" in cmd
    assert "elastic" in cmd
    assert "es-0" in cmd


def test_exec_command_not_found():
    r = ElasticsearchRunner(mode="direct")
    res = r.exec(["nonexistent-command-xyz-12345"])
    assert res.returncode != 0
    assert r.last_error is not None


def test_security_response_error_payload_sanitized():
    r = ElasticsearchRunner(mode="direct")
    assert r._sanitize_security_response({"error": "boom", "status": 405}) == {}
    assert r._sanitize_security_response({"elastic": {"enabled": True}}) == {"elastic": {"enabled": True}}



def test_snapshot_returns_dict():
    r = ElasticsearchRunner(mode="direct")
    # snapshot will fail to connect but should return a dict
    snap = r.snapshot()
    assert isinstance(snap, dict)
    assert "command_log_tail" in snap
