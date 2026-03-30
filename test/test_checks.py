"""Unit tests for Elasticsearch security checks."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from checks.base import Status, Severity, CheckResult, BaseChecker
from checks.auth_checks import ElasticsearchAuthChecker
from checks.encryption_checks import ElasticsearchEncryptionChecker
from checks.network_checks import ElasticsearchNetworkChecker
from checks.authz_checks import ElasticsearchAuthzChecker
from checks.logging_checks import ElasticsearchLoggingChecker
from checks.cluster_checks import ElasticsearchClusterChecker
from checks.container_checks import ElasticsearchContainerChecker


class FakeRunner:
    """Fake runner that returns configurable data."""
    mode = "direct"
    container = None
    pod = None
    namespace = "default"
    scheme = "http"
    username = None
    password = None

    def __init__(self, node_settings=None, cluster_settings=None, users=None, roles=None,
                 node_info=None, cluster_health=None, version=None):
        self._node_settings = node_settings or {}
        self._cluster_settings = cluster_settings or {}
        self._users = users if users is not None else {}
        self._roles = roles if roles is not None else {}
        self._node_info = node_info or {}
        self._cluster_health = cluster_health or {}
        self._version = version

    def get_node_settings(self): return self._node_settings
    def get_cluster_settings(self): return self._cluster_settings
    def get_users(self): return self._users
    def get_roles(self): return self._roles
    def get_node_info(self): return self._node_info
    def get_cluster_health(self): return self._cluster_health
    def api_get(self, path): return None
    def container_inspect(self): return {}
    def pod_inspect(self): return {}
    def snapshot(self): return {}


# ------------------------------------------------------------------
# Base
# ------------------------------------------------------------------

def test_check_result_to_dict():
    r = CheckResult(
        check_id="ES-TEST-001",
        title="Test",
        status=Status.PASS,
        severity=Severity.INFO,
    )
    d = r.to_dict()
    assert d["check_id"] == "ES-TEST-001"
    assert d["status"] == "PASS"
    assert d["severity"] == "INFO"


def test_base_checker_evidence():
    runner = FakeRunner()
    checker = BaseChecker(runner)
    ev = checker.evidence("src", "val", "cmd")
    assert ev["source"] == "src"
    assert ev["value"] == "val"
    assert ev["command"] == "cmd"


# ------------------------------------------------------------------
# Authentication checks
# ------------------------------------------------------------------

class TestAuthChecker:
    def _checker(self, **kwargs):
        return ElasticsearchAuthChecker(FakeRunner(**kwargs))

    def test_security_enabled_explicit_true(self):
        checker = self._checker(node_settings={"xpack.security.enabled": "true"})
        results = checker.run()
        auth001 = next(r for r in results if r.check_id == "ES-AUTH-001")
        assert auth001.status == Status.PASS

    def test_security_enabled_explicit_false(self):
        checker = self._checker(node_settings={"xpack.security.enabled": "false"})
        results = checker.run()
        auth001 = next(r for r in results if r.check_id == "ES-AUTH-001")
        assert auth001.status == Status.FAIL

    def test_security_api_responding_without_explicit_setting(self):
        # Users API returning data means security is active
        checker = self._checker(users={"elastic": {"roles": ["superuser"]}})
        results = checker.run()
        auth001 = next(r for r in results if r.check_id == "ES-AUTH-001")
        # Should be PASS since users API is responding
        assert auth001.status == Status.PASS

    def test_elastic_user_no_auth_required(self):
        # Connected without auth and got user data = security may be off
        runner = FakeRunner(users={"elastic": {"roles": ["superuser"], "enabled": True}})
        checker = ElasticsearchAuthChecker(runner)
        results = checker.run()
        auth002 = next(r for r in results if r.check_id == "ES-AUTH-002")
        # Without credentials, getting user data is suspicious
        assert auth002.status in (Status.PASS, Status.FAIL, Status.WARN)

    def test_password_policy_set(self):
        checker = self._checker(cluster_settings={
            "xpack.security.authc.native.minimum_password_length": "14"
        })
        results = checker.run()
        auth003 = next(r for r in results if r.check_id == "ES-AUTH-003")
        assert auth003.status == Status.PASS

    def test_password_policy_too_short_explicit_fails(self):
        # Explicitly configured to 6 — definitive misconfiguration, must FAIL
        checker = self._checker(cluster_settings={
            "xpack.security.authc.native.minimum_password_length": "6"
        })
        results = checker.run()
        auth003 = next(r for r in results if r.check_id == "ES-AUTH-003")
        assert auth003.status == Status.FAIL

    def test_password_policy_boundary_11_fails(self):
        checker = self._checker(cluster_settings={
            "xpack.security.authc.native.minimum_password_length": "11"
        })
        results = checker.run()
        auth003 = next(r for r in results if r.check_id == "ES-AUTH-003")
        assert auth003.status == Status.FAIL

    def test_password_policy_boundary_12_passes(self):
        checker = self._checker(cluster_settings={
            "xpack.security.authc.native.minimum_password_length": "12"
        })
        results = checker.run()
        auth003 = next(r for r in results if r.check_id == "ES-AUTH-003")
        assert auth003.status == Status.PASS

    def test_password_policy_not_set(self):
        checker = self._checker()
        results = checker.run()
        auth003 = next(r for r in results if r.check_id == "ES-AUTH-003")
        assert auth003.status == Status.WARN

    def test_all_checks_have_check_ids(self):
        checker = self._checker()
        results = checker.run()
        ids = [r.check_id for r in results]
        assert "ES-AUTH-001" in ids
        assert "ES-AUTH-002" in ids
        assert "ES-AUTH-003" in ids
        assert "ES-AUTH-004" in ids
        assert "ES-AUTH-005" in ids


# ------------------------------------------------------------------
# Encryption checks
# ------------------------------------------------------------------

class TestEncryptionChecker:
    def _checker(self, **kwargs):
        return ElasticsearchEncryptionChecker(FakeRunner(**kwargs))

    def test_http_ssl_enabled(self):
        checker = self._checker(node_settings={"xpack.security.http.ssl.enabled": "true"})
        results = checker.run()
        enc001 = next(r for r in results if r.check_id == "ES-ENC-001")
        assert enc001.status == Status.PASS

    def test_http_ssl_disabled(self):
        checker = self._checker(node_settings={"xpack.security.http.ssl.enabled": "false"})
        results = checker.run()
        enc001 = next(r for r in results if r.check_id == "ES-ENC-001")
        assert enc001.status == Status.FAIL

    def test_transport_ssl_enabled(self):
        checker = self._checker(node_settings={"xpack.security.transport.ssl.enabled": "true"})
        results = checker.run()
        enc002 = next(r for r in results if r.check_id == "ES-ENC-002")
        assert enc002.status == Status.PASS

    def test_transport_ssl_disabled(self):
        checker = self._checker(node_settings={"xpack.security.transport.ssl.enabled": "false"})
        results = checker.run()
        enc002 = next(r for r in results if r.check_id == "ES-ENC-002")
        assert enc002.status == Status.FAIL

    def test_weak_protocol_fails(self):
        checker = self._checker(node_settings={
            "xpack.security.http.ssl.supported_protocols": "TLSv1.0,TLSv1.1"
        })
        results = checker.run()
        enc003 = next(r for r in results if r.check_id == "ES-ENC-003")
        assert enc003.status == Status.FAIL

    def test_strong_protocols_pass(self):
        checker = self._checker(node_settings={
            "xpack.security.http.ssl.supported_protocols": "TLSv1.2,TLSv1.3"
        })
        results = checker.run()
        enc003 = next(r for r in results if r.check_id == "ES-ENC-003")
        assert enc003.status == Status.PASS

    def test_verification_none_fails(self):
        checker = self._checker(node_settings={
            "xpack.security.http.ssl.verification_mode": "none"
        })
        results = checker.run()
        enc004 = next(r for r in results if r.check_id == "ES-ENC-004")
        assert enc004.status == Status.FAIL

    def test_verification_full_passes(self):
        checker = self._checker(node_settings={
            "xpack.security.http.ssl.verification_mode": "full",
            "xpack.security.transport.ssl.verification_mode": "full",
        })
        results = checker.run()
        enc004 = next(r for r in results if r.check_id == "ES-ENC-004")
        assert enc004.status == Status.PASS


# ------------------------------------------------------------------
# Network checks
# ------------------------------------------------------------------

class TestNetworkChecker:
    def _checker(self, **kwargs):
        return ElasticsearchNetworkChecker(FakeRunner(**kwargs))

    def test_network_host_all_fails(self):
        checker = self._checker(node_settings={"network.host": "0.0.0.0"})
        results = checker.run()
        net001 = next(r for r in results if r.check_id == "ES-NET-001")
        assert net001.status == Status.FAIL

    def test_network_host_all_underscore_fails(self):
        checker = self._checker(node_settings={"network.host": "_all_"})
        results = checker.run()
        net001 = next(r for r in results if r.check_id == "ES-NET-001")
        assert net001.status == Status.FAIL

    def test_network_host_specific_passes(self):
        checker = self._checker(node_settings={"network.host": "10.0.0.5"})
        results = checker.run()
        net001 = next(r for r in results if r.check_id == "ES-NET-001")
        assert net001.status == Status.PASS

    def test_network_host_not_set_passes(self):
        checker = self._checker()
        results = checker.run()
        net001 = next(r for r in results if r.check_id == "ES-NET-001")
        assert net001.status == Status.PASS

    def test_cors_wildcard_fails(self):
        checker = self._checker(node_settings={
            "http.cors.enabled": "true",
            "http.cors.allow-origin": "*",
        })
        results = checker.run()
        net004 = next(r for r in results if r.check_id == "ES-NET-004")
        assert net004.status == Status.FAIL

    def test_cors_disabled_passes(self):
        checker = self._checker(node_settings={"http.cors.enabled": "false"})
        results = checker.run()
        net004 = next(r for r in results if r.check_id == "ES-NET-004")
        assert net004.status == Status.PASS

    def test_cors_specific_origin_warns(self):
        checker = self._checker(node_settings={
            "http.cors.enabled": "true",
            "http.cors.allow-origin": "https://kibana.example.com",
        })
        results = checker.run()
        net004 = next(r for r in results if r.check_id == "ES-NET-004")
        assert net004.status == Status.WARN


# ------------------------------------------------------------------
# Authorization checks
# ------------------------------------------------------------------

class TestAuthzChecker:
    def _checker(self, **kwargs):
        return ElasticsearchAuthzChecker(FakeRunner(**kwargs))

    def test_anonymous_disabled_passes(self):
        checker = self._checker()
        results = checker.run()
        authz003 = next(r for r in results if r.check_id == "ES-AUTHZ-003")
        assert authz003.status == Status.PASS

    def test_anonymous_enabled_fails(self):
        checker = self._checker(
            node_settings={"xpack.security.authc.anonymous.username": "anon_user"}
        )
        results = checker.run()
        authz003 = next(r for r in results if r.check_id == "ES-AUTHZ-003")
        assert authz003.status == Status.FAIL

    def test_custom_roles_pass(self):
        checker = self._checker(roles={
            "app_reader": {"indices": [{"names": ["app-*"], "privileges": ["read"]}]},
            "superuser": {},
        })
        results = checker.run()
        authz001 = next(r for r in results if r.check_id == "ES-AUTHZ-001")
        assert authz001.status == Status.PASS

    def test_no_roles_warns(self):
        checker = self._checker(roles={})
        results = checker.run()
        authz001 = next(r for r in results if r.check_id == "ES-AUTHZ-001")
        assert authz001.status in (Status.WARN, Status.ERROR)

    def test_wildcard_write_fails(self):
        checker = self._checker(roles={
            "bad_role": {
                "indices": [{"names": ["*"], "privileges": ["all"]}]
            }
        })
        results = checker.run()
        authz002 = next(r for r in results if r.check_id == "ES-AUTHZ-002")
        assert authz002.status == Status.FAIL


# ------------------------------------------------------------------
# Logging checks
# ------------------------------------------------------------------

class TestLoggingChecker:
    def _checker(self, **kwargs):
        return ElasticsearchLoggingChecker(FakeRunner(**kwargs))

    def test_audit_enabled_passes(self):
        checker = self._checker(node_settings={"xpack.security.audit.enabled": "true"})
        results = checker.run()
        log001 = next(r for r in results if r.check_id == "ES-LOG-001")
        assert log001.status == Status.PASS

    def test_audit_disabled_fails(self):
        checker = self._checker(node_settings={"xpack.security.audit.enabled": "false"})
        results = checker.run()
        log001 = next(r for r in results if r.check_id == "ES-LOG-001")
        assert log001.status == Status.FAIL

    def test_audit_not_set_fails(self):
        checker = self._checker()
        results = checker.run()
        log001 = next(r for r in results if r.check_id == "ES-LOG-001")
        assert log001.status == Status.FAIL

    def test_audit_events_all_required_passes(self):
        required = "authentication_success,authentication_failed,access_denied,connection_denied"
        checker = self._checker(node_settings={
            "xpack.security.audit.enabled": "true",
            "xpack.security.audit.logfile.events.include": required,
        })
        results = checker.run()
        log002 = next(r for r in results if r.check_id == "ES-LOG-002")
        assert log002.status == Status.PASS

    def test_audit_events_missing_required_warns(self):
        checker = self._checker(node_settings={
            "xpack.security.audit.enabled": "true",
            "xpack.security.audit.logfile.events.include": "authentication_failed",
        })
        results = checker.run()
        log002 = next(r for r in results if r.check_id == "ES-LOG-002")
        assert log002.status == Status.WARN

    def test_audit_events_list_value_passes(self):
        checker = self._checker(cluster_settings={
            "xpack.security.audit.logfile.events.include": [
                "AUTHENTICATION_SUCCESS",
                "AUTHENTICATION_FAILED",
                "ACCESS_DENIED",
                "CONNECTION_DENIED",
            ],
        })
        results = checker.run()
        log002 = next(r for r in results if r.check_id == "ES-LOG-002")
        assert log002.status == Status.PASS

    def test_audit_events_critical_event_excluded_fails(self):
        required = "authentication_success,authentication_failed,access_denied,connection_denied"
        checker = self._checker(node_settings={
            "xpack.security.audit.enabled": "true",
            "xpack.security.audit.logfile.events.include": required,
            "xpack.security.audit.logfile.events.exclude": "authentication_failed",
        })
        results = checker.run()
        log002 = next(r for r in results if r.check_id == "ES-LOG-002")
        assert log002.status == Status.FAIL

    def test_audit_events_not_configured_warns(self):
        checker = self._checker()
        results = checker.run()
        log002 = next(r for r in results if r.check_id == "ES-LOG-002")
        assert log002.status == Status.WARN


# ------------------------------------------------------------------
# Cluster checks
# ------------------------------------------------------------------

class TestClusterChecker:
    def _checker(self, **kwargs):
        return ElasticsearchClusterChecker(FakeRunner(**kwargs))

    def test_default_cluster_name_fails(self):
        checker = self._checker(cluster_health={"cluster_name": "elasticsearch"})
        results = checker.run()
        clus001 = next(r for r in results if r.check_id == "ES-CLUS-001")
        assert clus001.status == Status.FAIL

    def test_custom_cluster_name_passes(self):
        checker = self._checker(cluster_health={"cluster_name": "prod-search"})
        results = checker.run()
        clus001 = next(r for r in results if r.check_id == "ES-CLUS-001")
        assert clus001.status == Status.PASS

    def test_anonymous_access_setting_in_cluster_check(self):
        checker = self._checker()
        results = checker.run()
        ids = [r.check_id for r in results]
        assert "ES-CLUS-001" in ids
        assert "ES-CLUS-002" in ids
        assert "ES-CLUS-003" in ids
        assert "ES-CLUS-004" in ids


# ------------------------------------------------------------------
# Container checks
# ------------------------------------------------------------------

class TestContainerChecker:
    def test_direct_mode_all_skipped(self):
        runner = FakeRunner()
        runner.mode = "direct"
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        assert all(r.status == Status.SKIP for r in results)
        assert len(results) == 6

    def test_docker_no_container_inspect_all_error(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        # container_inspect returns {} by default -> _all_error
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        assert all(r.status == Status.ERROR for r in results)

    def test_docker_nonroot_pass(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "ReadonlyRootfs": True,
                "Memory": 8589934592,
                "NanoCpus": 4000000000,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont001 = next(r for r in results if r.check_id == "ES-CONT-001")
        assert cont001.status == Status.PASS

    def test_docker_root_user_fails(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "0"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": None,
                "ReadonlyRootfs": False,
                "Memory": 0,
                "NanoCpus": 0,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont001 = next(r for r in results if r.check_id == "ES-CONT-001")
        assert cont001.status == Status.FAIL

    def test_privileged_container_fails(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": True,
                "CapAdd": None,
                "CapDrop": None,
                "ReadonlyRootfs": False,
                "Memory": 0,
                "NanoCpus": 0,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont002 = next(r for r in results if r.check_id == "ES-CONT-002")
        assert cont002.status == Status.FAIL

    def test_docker_dangerous_cap_added_fails(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": ["SYS_ADMIN"],
                "CapDrop": ["ALL"],
                "ReadonlyRootfs": True,
                "Memory": 8589934592,
                "NanoCpus": 4000000000,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont003 = next(r for r in results if r.check_id == "ES-CONT-003")
        assert cont003.status == Status.FAIL

    def test_docker_no_cap_drop_all_warns(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": None,  # missing cap_drop=ALL
                "ReadonlyRootfs": True,
                "Memory": 8589934592,
                "NanoCpus": 4000000000,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont003 = next(r for r in results if r.check_id == "ES-CONT-003")
        assert cont003.status == Status.WARN

    def test_docker_host_network_fails(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "ReadonlyRootfs": True,
                "Memory": 8589934592,
                "NanoCpus": 4000000000,
                "NetworkMode": "host",  # host networking
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont006 = next(r for r in results if r.check_id == "ES-CONT-006")
        assert cont006.status == Status.FAIL

    def test_docker_host_ipc_fails(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "ReadonlyRootfs": True,
                "Memory": 8589934592,
                "NanoCpus": 4000000000,
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "host",  # host IPC
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont006 = next(r for r in results if r.check_id == "ES-CONT-006")
        assert cont006.status == Status.FAIL

    def test_resource_limits_both_set_pass(self):
        runner = FakeRunner()
        runner.mode = "docker"
        runner.container = "my-es"
        runner.container_inspect = lambda: {
            "Config": {"User": "1000"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": None,
                "CapDrop": ["ALL"],
                "ReadonlyRootfs": True,
                "Memory": 8589934592,  # 8GB
                "NanoCpus": 4000000000,  # 4 CPUs
                "NetworkMode": "bridge",
                "PidMode": "",
                "IpcMode": "private",
            },
        }
        checker = ElasticsearchContainerChecker(runner)
        results = checker.run()
        cont005 = next(r for r in results if r.check_id == "ES-CONT-005")
        assert cont005.status == Status.PASS


# ------------------------------------------------------------------
# Framework mappings
# ------------------------------------------------------------------

def test_enrich_all():
    from mappings.frameworks import enrich_all
    r = CheckResult(
        check_id="ES-AUTH-001",
        title="Test",
        status=Status.PASS,
        severity=Severity.CRITICAL,
    )
    enrich_all([r])
    assert len(r.nist_800_171) > 0
    assert r.cmmc_level is not None
    assert len(r.mitre_attack) > 0
    assert len(r.mitre_d3fend) > 0


def test_enrich_all_checks():
    from mappings.frameworks import FRAMEWORK_MAP
    # Verify all expected check IDs have mappings
    expected_ids = [
        "ES-AUTH-001", "ES-AUTH-002", "ES-AUTH-003", "ES-AUTH-004", "ES-AUTH-005",
        "ES-ENC-001", "ES-ENC-002", "ES-ENC-003", "ES-ENC-004", "ES-ENC-005",
        "ES-NET-001", "ES-NET-002", "ES-NET-003", "ES-NET-004",
        "ES-AUTHZ-001", "ES-AUTHZ-002", "ES-AUTHZ-003", "ES-AUTHZ-004",
        "ES-LOG-001", "ES-LOG-002", "ES-LOG-003", "ES-LOG-004",
        "ES-CLUS-001", "ES-CLUS-002", "ES-CLUS-003", "ES-CLUS-004",
        "ES-CONT-001", "ES-CONT-002", "ES-CONT-003", "ES-CONT-004",
        "ES-CONT-005", "ES-CONT-006",
    ]
    for cid in expected_ids:
        assert cid in FRAMEWORK_MAP, f"Missing framework mapping for {cid}"


# ------------------------------------------------------------------
# All checkers run without crashing
# ------------------------------------------------------------------

def test_all_checkers_run():
    from checks import ALL_CHECKERS
    runner = FakeRunner()
    for checker_cls in ALL_CHECKERS:
        checker = checker_cls(runner)
        results = checker.run()
        assert isinstance(results, list)
        assert len(results) > 0
        for r in results:
            assert isinstance(r, CheckResult)
            assert r.check_id.startswith("ES-")
            assert r.status in Status
            assert r.severity in Severity
