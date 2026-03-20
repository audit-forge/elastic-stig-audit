"""Network security checks for Elasticsearch.

Controls:
  ES-NET-001 — network.host not bound to 0.0.0.0 (all interfaces)
  ES-NET-002 — HTTP port not default 9200 (advisory/INFO)
  ES-NET-003 — Transport port not default 9300 (advisory/INFO)
  ES-NET-004 — CORS must be disabled or strictly configured
"""
from .base import BaseChecker, CheckResult, Severity, Status


class ElasticsearchNetworkChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        node_settings = self.runner.get_node_settings()
        cluster_settings = self.runner.get_cluster_settings()

        return [
            self._check_network_host(node_settings, cluster_settings),
            self._check_http_port(node_settings, cluster_settings),
            self._check_transport_port(node_settings, cluster_settings),
            self._check_cors(node_settings, cluster_settings),
        ]

    def _check_network_host(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-NET-001: network.host must not be 0.0.0.0 (all interfaces)."""
        network_host = (
            node_settings.get("network.host", "")
            or cluster_settings.get("network.host", "")
        )

        # Also check http.host separately (can override network.host for HTTP)
        http_host = node_settings.get("http.host", "")
        transport_host = node_settings.get("transport.host", "")

        insecure_values = {"0.0.0.0", "_all_", "_site_"}

        bound_all = (
            network_host in insecure_values
            or http_host in insecure_values
        )

        if not network_host:
            # Default is loopback (_local_) — generally safe
            status = Status.PASS
            actual = "network.host not set (default: _local_ loopback only)"
        elif bound_all:
            status = Status.FAIL
            actual = f"network.host={network_host!r} — bound to all interfaces"
        else:
            status = Status.PASS
            actual = f"network.host={network_host!r}"

        return CheckResult(
            check_id="ES-NET-001",
            title="Elasticsearch must not bind to all network interfaces (0.0.0.0)",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="3.1",
            cis_id="CIS-ES-3.1",
            fedramp_control="SC-7",
            nist_800_53_controls=["SC-7", "CM-7"],
            description=(
                "The network.host setting must not be configured to 0.0.0.0 or _all_, "
                "which would make Elasticsearch accessible on all network interfaces. "
                "Bind to specific IP addresses or use a load balancer/proxy."
            ),
            rationale=(
                "Binding to all interfaces exposes Elasticsearch to any network reachable by the host, "
                "including potentially untrusted networks. In cloud environments, this can expose "
                "the cluster to the public internet if security groups are misconfigured."
            ),
            actual=actual,
            expected="network.host set to specific IP, hostname, or _local_ (loopback)",
            remediation=(
                "In elasticsearch.yml, bind to a specific interface:\n"
                "  network.host: 10.0.0.5\n"
                "or for a multi-home server:\n"
                "  network.bind_host: 127.0.0.1\n"
                "  network.publish_host: <cluster-internal-ip>\n"
                "Use a reverse proxy (nginx/HAProxy) to expose HTTPS externally."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §3.1",
                "Elastic: Network settings",
                "NIST SP 800-53 SC-7",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.network",
                    {
                        "network.host": network_host,
                        "http.host": http_host,
                        "transport.host": transport_host,
                    },
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_http_port(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-NET-002: Default HTTP port 9200 should be changed (advisory)."""
        http_port = (
            node_settings.get("http.port", "")
            or cluster_settings.get("http.port", "9200")
            or "9200"
        )

        using_default = http_port == "9200" or http_port == ""

        return CheckResult(
            check_id="ES-NET-002",
            title="HTTP port should not use the default value (9200)",
            status=Status.WARN if using_default else Status.PASS,
            severity=Severity.LOW,
            benchmark_control_id="3.2",
            cis_id="CIS-ES-3.2",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7"],
            description=(
                "Changing the default HTTP port (9200) from the well-known default adds a "
                "minor layer of obscurity, making automated scanning less effective. "
                "This is a defense-in-depth control."
            ),
            rationale=(
                "Automated scanners routinely probe well-known ports. While not a primary security "
                "control, non-default ports can reduce exposure to opportunistic attacks. "
                "This is a LOW severity advisory only."
            ),
            actual=f"http.port={http_port}",
            expected="http.port set to a non-default value (not 9200)",
            remediation=(
                "Optional: change in elasticsearch.yml:\n"
                "  http.port: 9243\n"
                "Ensure firewall rules and load balancers are updated accordingly."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §3.2",
                "Elastic: http.port setting",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[
                self.evidence("node_settings.http.port", http_port, "GET /_nodes/_local/settings")
            ],
        )

    def _check_transport_port(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-NET-003: Default transport port 9300 should be changed (advisory)."""
        transport_port = (
            node_settings.get("transport.port", "")
            or cluster_settings.get("transport.port", "9300")
            or "9300"
        )

        using_default = transport_port == "9300" or transport_port == ""

        return CheckResult(
            check_id="ES-NET-003",
            title="Transport port should not use the default value (9300)",
            status=Status.WARN if using_default else Status.PASS,
            severity=Severity.LOW,
            benchmark_control_id="3.3",
            cis_id="CIS-ES-3.3",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7"],
            description=(
                "Changing the default transport port (9300) from the well-known value adds "
                "a minor layer of obscurity. This is a defense-in-depth control for the "
                "node-to-node communication channel."
            ),
            rationale=(
                "The transport port handles inter-node cluster communication. "
                "While protected by TLS and authentication, using a non-default port "
                "reduces automated discovery of cluster nodes by scanning tools."
            ),
            actual=f"transport.port={transport_port}",
            expected="transport.port set to a non-default value (not 9300)",
            remediation=(
                "Optional: in elasticsearch.yml:\n"
                "  transport.port: 9301\n"
                "Update discovery.seed_hosts on all cluster nodes accordingly."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §3.3",
                "Elastic: Transport settings",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.transport.port", transport_port, "GET /_nodes/_local/settings"
                )
            ],
        )

    def _check_cors(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-NET-004: CORS must be disabled or strictly configured with an allowlist."""
        cors_enabled = (
            node_settings.get("http.cors.enabled", "")
            or cluster_settings.get("http.cors.enabled", "false")
        )
        cors_allow_origin = (
            node_settings.get("http.cors.allow-origin", "")
            or cluster_settings.get("http.cors.allow-origin", "")
        )

        if cors_enabled.lower() == "false" or not cors_enabled:
            status = Status.PASS
            actual = "http.cors.enabled=false (CORS disabled)"
        elif cors_allow_origin in ("*", "/.*/"):
            status = Status.FAIL
            actual = f"http.cors.enabled=true, allow-origin={cors_allow_origin!r} (wildcard)"
        elif cors_enabled.lower() == "true" and cors_allow_origin:
            status = Status.WARN
            actual = f"http.cors.enabled=true, allow-origin={cors_allow_origin!r}"
        else:
            status = Status.WARN
            actual = f"http.cors.enabled={cors_enabled}, allow-origin=<not set>"

        return CheckResult(
            check_id="ES-NET-004",
            title="CORS must be disabled or restricted to a strict origin allowlist",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="3.4",
            cis_id="CIS-ES-3.4",
            fedramp_control="SC-7",
            nist_800_53_controls=["SC-7", "SI-10"],
            description=(
                "Cross-Origin Resource Sharing (CORS) for the Elasticsearch HTTP API must be "
                "disabled or strictly configured to allow only known, trusted origins. "
                "A wildcard (*) allow-origin is a critical misconfiguration."
            ),
            rationale=(
                "A wildcard CORS policy allows any web page to make requests to the Elasticsearch "
                "API using the victim user's browser credentials. This enables CSRF-style attacks "
                "where malicious sites can exfiltrate or modify data in Elasticsearch."
            ),
            actual=actual,
            expected="http.cors.enabled=false, or allow-origin set to specific trusted origins",
            remediation=(
                "Disable CORS in elasticsearch.yml:\n"
                "  http.cors.enabled: false\n"
                "If CORS is required for Kibana:\n"
                "  http.cors.enabled: true\n"
                "  http.cors.allow-origin: \"https://kibana.example.com\"\n"
                "  http.cors.allow-headers: X-Requested-With,Content-Type,Content-Length,Authorization\n"
                "Never use http.cors.allow-origin: \"*\""
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §3.4",
                "Elastic: HTTP settings (cors)",
                "OWASP: CORS misconfiguration",
                "NIST SP 800-53 SC-7",
            ],
            category="Network",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.cors",
                    {"enabled": cors_enabled, "allow-origin": cors_allow_origin},
                    "GET /_nodes/_local/settings",
                )
            ],
        )
