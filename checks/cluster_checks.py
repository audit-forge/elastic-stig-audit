"""Cluster security checks for Elasticsearch.

Controls:
  ES-CLUS-001 — Cluster name not default 'elasticsearch'
  ES-CLUS-002 — Node name configured
  ES-CLUS-003 — Discovery seed hosts secured (not open)
  ES-CLUS-004 — Shard allocation awareness configured
"""
from .base import BaseChecker, CheckResult, Severity, Status


class ElasticsearchClusterChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        node_settings = self.runner.get_node_settings()
        cluster_settings = self.runner.get_cluster_settings()
        node_info = self.runner.get_node_info()
        cluster_health = self.runner.get_cluster_health()

        return [
            self._check_cluster_name(node_settings, cluster_settings, cluster_health),
            self._check_node_name(node_settings, node_info),
            self._check_discovery(node_settings, cluster_settings),
            self._check_shard_allocation(node_settings, cluster_settings),
        ]

    def _check_cluster_name(
        self, node_settings: dict, cluster_settings: dict, cluster_health: dict
    ) -> CheckResult:
        """ES-CLUS-001: Cluster name must not be the default 'elasticsearch'."""
        cluster_name = (
            node_settings.get("cluster.name", "")
            or cluster_settings.get("cluster.name", "")
            or cluster_health.get("cluster_name", "")
        )

        if not cluster_name:
            status = Status.WARN
            actual = "cluster.name not detectable via API"
        elif cluster_name.lower() in ("elasticsearch", "my-application"):
            status = Status.FAIL
            actual = f"cluster.name={cluster_name!r} (default value)"
        else:
            status = Status.PASS
            actual = f"cluster.name={cluster_name!r}"

        return CheckResult(
            check_id="ES-CLUS-001",
            title="Cluster name must not use the default value 'elasticsearch'",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="6.1",
            cis_id="CIS-ES-6.1",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "CM-6"],
            description=(
                "The cluster.name setting must be changed from the default value 'elasticsearch' "
                "to a unique, environment-specific name. Nodes with matching cluster names "
                "will join the same cluster automatically."
            ),
            rationale=(
                "Using the default cluster name creates a risk that stray nodes (from test "
                "environments, misconfigured containers, or attacker-controlled systems) "
                "with the same default name could inadvertently join the production cluster. "
                "A unique cluster name is a zero-cost security control."
            ),
            actual=actual,
            expected="cluster.name set to a unique, environment-specific value",
            remediation=(
                "In elasticsearch.yml:\n"
                "  cluster.name: prod-ecommerce-cluster\n"
                "Use distinct names for dev/staging/prod environments."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §6.1",
                "Elastic: cluster.name setting",
                "NIST SP 800-53 CM-6",
            ],
            category="Cluster",
            evidence_type="runtime-config",
            evidence=[
                self.evidence("cluster_name", cluster_name, "GET /_cluster/health")
            ],
        )

    def _check_node_name(self, node_settings: dict, node_info: dict) -> CheckResult:
        """ES-CLUS-002: Node name must be explicitly configured."""
        node_name = (
            node_settings.get("node.name", "")
            or node_info.get("name", "")
        )

        # Default node name in ES is the hostname — check if it looks like a UUID (auto-generated)
        is_uuid_like = len(node_name) == 22 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in node_name)

        if not node_name:
            status = Status.WARN
            actual = "node.name not detectable"
        elif is_uuid_like:
            status = Status.WARN
            actual = f"node.name={node_name!r} (appears auto-generated)"
        else:
            status = Status.PASS
            actual = f"node.name={node_name!r}"

        return CheckResult(
            check_id="ES-CLUS-002",
            title="Node name must be explicitly configured with a meaningful identifier",
            status=status,
            severity=Severity.LOW,
            benchmark_control_id="6.2",
            cis_id="CIS-ES-6.2",
            fedramp_control="CM-6",
            nist_800_53_controls=["CM-6"],
            description=(
                "The node.name setting should be explicitly configured with a meaningful, "
                "unique identifier. Auto-generated node names make cluster management, "
                "log correlation, and incident response more difficult."
            ),
            rationale=(
                "Explicit node names enable clear identification in logs, metrics, and alerts. "
                "When investigating a security incident, being able to correlate audit log "
                "entries to specific nodes is essential for accurate forensic analysis."
            ),
            actual=actual,
            expected="node.name set to descriptive, environment-specific name",
            remediation=(
                "In elasticsearch.yml:\n"
                "  node.name: prod-es-node-01\n"
                "Use a naming convention like: <env>-<cluster>-node-<num>"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §6.2",
                "Elastic: node.name setting",
            ],
            category="Cluster",
            evidence_type="runtime-config",
            evidence=[
                self.evidence("node_name", node_name, "GET /_nodes/_local/settings")
            ],
        )

    def _check_discovery(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-CLUS-003: Discovery must be secured with explicit seed hosts."""
        seed_hosts = (
            node_settings.get("discovery.seed_hosts", "")
            or node_settings.get("cluster.initial_master_nodes", "")
            or cluster_settings.get("discovery.seed_hosts", "")
        )
        # Check for multicast discovery (deprecated but still dangerous)
        discovery_type = node_settings.get("discovery.type", "")

        # Multicast is a security risk — allows auto-discovery
        if discovery_type == "single-node":
            status = Status.WARN
            actual = "discovery.type=single-node (development mode — not suitable for production)"
        elif seed_hosts:
            status = Status.PASS
            actual = f"discovery.seed_hosts={seed_hosts!r}"
        else:
            status = Status.WARN
            actual = "discovery.seed_hosts not configured (may use default broadcast)"

        return CheckResult(
            check_id="ES-CLUS-003",
            title="Cluster discovery must use explicit seed hosts, not broadcast discovery",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="6.3",
            cis_id="CIS-ES-6.3",
            fedramp_control="SC-7",
            nist_800_53_controls=["SC-7", "CM-7"],
            description=(
                "Cluster node discovery must use explicit seed hosts (discovery.seed_hosts) "
                "rather than broadcast/multicast discovery. Broadcast discovery allows any "
                "Elasticsearch node on the same network segment to join the cluster."
            ),
            rationale=(
                "Without explicit seed hosts, the discovery protocol may use broadcast "
                "mechanisms that allow unauthorized nodes to discover and potentially join "
                "the cluster. Explicit seed hosts ensure only known, trusted nodes "
                "participate in cluster formation."
            ),
            actual=actual,
            expected="discovery.seed_hosts configured with explicit list of trusted nodes",
            remediation=(
                "In elasticsearch.yml:\n"
                "  discovery.seed_hosts:\n"
                "    - es-node-01.internal:9300\n"
                "    - es-node-02.internal:9300\n"
                "    - es-node-03.internal:9300\n"
                "  cluster.initial_master_nodes:\n"
                "    - es-node-01\n"
                "    - es-node-02\n"
                "    - es-node-03"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §6.3",
                "Elastic: Discovery and cluster formation",
                "NIST SP 800-53 SC-7",
            ],
            category="Cluster",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.discovery",
                    {"seed_hosts": seed_hosts, "discovery_type": discovery_type},
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_shard_allocation(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-CLUS-004: Shard allocation awareness should be configured for multi-zone deployments."""
        allocation_awareness = (
            node_settings.get("cluster.routing.allocation.awareness.attributes", "")
            or cluster_settings.get("cluster.routing.allocation.awareness.attributes", "")
        )
        # Check for disk-based allocation
        disk_threshold = (
            cluster_settings.get("cluster.routing.allocation.disk.threshold_enabled", "true")
        )

        if allocation_awareness:
            status = Status.PASS
            actual = f"routing.allocation.awareness.attributes={allocation_awareness!r}"
        elif disk_threshold.lower() == "false":
            status = Status.WARN
            actual = "disk-based allocation disabled (cluster.routing.allocation.disk.threshold_enabled=false)"
        else:
            status = Status.WARN
            actual = "shard allocation awareness not configured — single-zone deployment or default settings"

        return CheckResult(
            check_id="ES-CLUS-004",
            title="Shard allocation awareness should be configured for resilient cluster topology",
            status=status,
            severity=Severity.LOW,
            benchmark_control_id="6.4",
            cis_id="CIS-ES-6.4",
            fedramp_control="CP-9",
            nist_800_53_controls=["CP-9", "SC-6"],
            description=(
                "Shard allocation awareness should be configured for multi-zone deployments "
                "to ensure data replicas are distributed across failure domains (availability zones, "
                "racks, data centers). Disk-based shard allocation should remain enabled."
            ),
            rationale=(
                "Without allocation awareness, Elasticsearch may place primary and replica shards "
                "on nodes in the same availability zone, creating a single point of failure. "
                "A zone outage could result in data loss if both primary and replica are affected."
            ),
            actual=actual,
            expected="awareness attributes configured for zone/rack isolation",
            remediation=(
                "For AWS/GCP/Azure multi-AZ deployments:\n"
                "  In elasticsearch.yml:\n"
                "    cluster.routing.allocation.awareness.attributes: zone\n"
                "    node.attr.zone: us-east-1a\n"
                "  Force balanced zone allocation:\n"
                "    cluster.routing.allocation.awareness.force.zone.values: us-east-1a,us-east-1b,us-east-1c"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §6.4",
                "Elastic: Shard allocation awareness",
                "NIST SP 800-53 CP-9",
            ],
            category="Cluster",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.allocation",
                    {"awareness": allocation_awareness, "disk_threshold": disk_threshold},
                    "GET /_cluster/settings?include_defaults=true",
                )
            ],
        )
