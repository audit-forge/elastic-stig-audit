"""Logging and auditing checks for Elasticsearch.

Controls:
  ES-LOG-001 — Audit logging enabled (xpack.security.audit.enabled)
  ES-LOG-002 — Audit events include authentication and access events
  ES-LOG-003 — Access/slow log configured
  ES-LOG-004 — Slow query logging (search/index slowlog)
"""
from .base import BaseChecker, CheckResult, Severity, Status


def _normalize_events(value) -> set[str]:
    if not value:
        return set()
    if isinstance(value, list):
        return {str(e).strip().lower() for e in value if str(e).strip()}
    if isinstance(value, str):
        return {e.strip().lower() for e in value.split(",") if e.strip()}
    return {str(value).strip().lower()} if str(value).strip() else set()


class ElasticsearchLoggingChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        node_settings = self.runner.get_node_settings()
        cluster_settings = self.runner.get_cluster_settings()

        return [
            self._check_audit_logging(node_settings, cluster_settings),
            self._check_audit_events(node_settings, cluster_settings),
            self._check_access_logging(node_settings, cluster_settings),
            self._check_slowlog(node_settings, cluster_settings),
        ]

    def _check_audit_logging(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-LOG-001: Security audit logging must be enabled."""
        audit_enabled = (
            node_settings.get("xpack.security.audit.enabled", "")
            or cluster_settings.get("xpack.security.audit.enabled", "")
        )

        if audit_enabled.lower() == "true":
            status = Status.PASS
        elif audit_enabled.lower() == "false":
            status = Status.FAIL
        else:
            # Not set = disabled by default
            status = Status.FAIL
            audit_enabled = audit_enabled or "<not set, defaults to false>"

        return CheckResult(
            check_id="ES-LOG-001",
            title="Elasticsearch security audit logging must be enabled",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="5.1",
            cis_id="CIS-ES-5.1",
            fedramp_control="AU-2",
            nist_800_53_controls=["AU-2", "AU-12"],
            description=(
                "The xpack.security.audit.enabled setting must be set to true to record "
                "security events including authentication successes/failures, authorization "
                "decisions, and REST/transport API access."
            ),
            rationale=(
                "Audit logging is the primary mechanism for detecting unauthorized access, "
                "tracking user activity, and providing forensic evidence after a security incident. "
                "Without audit logging, it is impossible to determine who accessed what data or "
                "when a breach occurred."
            ),
            actual=f"xpack.security.audit.enabled={audit_enabled}",
            expected="xpack.security.audit.enabled=true",
            remediation=(
                "In elasticsearch.yml:\n"
                "  xpack.security.audit.enabled: true\n"
                "  xpack.security.audit.logfile.events.include:\n"
                "    - authentication_success\n"
                "    - authentication_failed\n"
                "    - access_denied\n"
                "    - connection_denied\n"
                "    - run_as_denied\n"
                "    - anonymous_access_denied"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §5.1",
                "Elastic: Audit logging",
                "NIST SP 800-53 AU-2",
            ],
            category="Logging",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.audit.enabled",
                    audit_enabled,
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_audit_events(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-LOG-002: Audit log must capture authentication and authorization events."""
        audit_include = (
            node_settings.get("xpack.security.audit.logfile.events.include", "")
            or cluster_settings.get("xpack.security.audit.logfile.events.include", "")
        )
        audit_exclude = (
            node_settings.get("xpack.security.audit.logfile.events.exclude", "")
            or cluster_settings.get("xpack.security.audit.logfile.events.exclude", "")
        )

        required_events = {
            "authentication_success",
            "authentication_failed",
            "access_denied",
            "connection_denied",
        }

        configured = _normalize_events(audit_include)
        excluded = _normalize_events(audit_exclude)

        if not configured:
            # Default events in ES include auth failures but not successes
            status = Status.WARN
            actual = "audit events not explicitly configured (using defaults — auth_failure + access_denied)"
        else:
            missing = required_events - configured
            if missing:
                status = Status.WARN
                actual = f"configured events: {sorted(configured)}, missing: {sorted(missing)}"
            else:
                status = Status.PASS
                actual = f"configured events include all required: {sorted(configured & required_events)}"

        # Check if critical events are excluded
        if excluded:
            critical_excluded = required_events & excluded
            if critical_excluded:
                status = Status.FAIL
                actual += f" | CRITICAL EVENTS EXCLUDED: {sorted(critical_excluded)}"

        return CheckResult(
            check_id="ES-LOG-002",
            title="Audit log must capture authentication and access control events",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="5.2",
            cis_id="CIS-ES-5.2",
            fedramp_control="AU-2",
            nist_800_53_controls=["AU-2", "AU-3"],
            description=(
                "Security audit events must be explicitly configured to include at minimum: "
                "authentication_success, authentication_failed, access_denied, and connection_denied. "
                "Critical events must not be in the exclude list."
            ),
            rationale=(
                "The default audit event configuration may not capture all events required by "
                "compliance frameworks. Authentication success events are needed to trace "
                "legitimate access patterns. Access denied events are critical for detecting "
                "privilege escalation attempts."
            ),
            actual=actual,
            expected=(
                "events.include: [authentication_success, authentication_failed, "
                "access_denied, connection_denied]"
            ),
            remediation=(
                "In elasticsearch.yml:\n"
                "  xpack.security.audit.logfile.events.include:\n"
                "    - authentication_success\n"
                "    - authentication_failed\n"
                "    - access_denied\n"
                "    - connection_denied\n"
                "    - anonymous_access_denied\n"
                "    - run_as_denied\n"
                "    - tampered_request\n"
                "  xpack.security.audit.logfile.events.exclude: []"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §5.2",
                "Elastic: Audit events",
                "NIST SP 800-53 AU-3",
            ],
            category="Logging",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.audit_events",
                    {"include": audit_include, "exclude": audit_exclude},
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_access_logging(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-LOG-003: HTTP access logging should be configured."""
        # Elasticsearch uses log4j for general logging; check for logger settings
        # Access logging is typically configured via log4j2.properties
        logger_level = (
            node_settings.get("logger.level", "")
            or cluster_settings.get("logger.level", "")
        )
        # In cluster settings, dynamic logger can be set
        access_log = (
            cluster_settings.get("logger.org.elasticsearch.http.HttpTracer", "")
            or node_settings.get("logger.org.elasticsearch.http.HttpTracer", "")
        )
        logger_default = (
            cluster_settings.get("logger._root", "")
            or node_settings.get("logger._root", "")
        )

        if access_log and access_log.lower() not in ("off", "fatal"):
            status = Status.PASS
            actual = f"HttpTracer logger level={access_log}"
        elif logger_level or logger_default:
            status = Status.WARN
            actual = f"general logger.level={logger_level or logger_default}, HttpTracer not explicitly configured"
        else:
            status = Status.WARN
            actual = "access logging not explicitly configured (verify log4j2.properties)"

        return CheckResult(
            check_id="ES-LOG-003",
            title="HTTP access logging must be configured",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="5.3",
            cis_id="CIS-ES-5.3",
            fedramp_control="AU-12",
            nist_800_53_controls=["AU-12", "AU-14"],
            description=(
                "Elasticsearch HTTP access logging should be enabled to record all REST API "
                "requests. This provides an audit trail for compliance and incident response."
            ),
            rationale=(
                "Access logs record every HTTP request to the Elasticsearch REST API, providing "
                "a complete trace of data access and modifications. This is required for "
                "compliance audits and post-incident forensic analysis."
            ),
            actual=actual,
            expected="HttpTracer logger configured at TRACE level, or audit logging covers all access",
            remediation=(
                "Enable HTTP access tracing dynamically:\n"
                "PUT /_cluster/settings {\n"
                "  \"transient\": {\"logger.org.elasticsearch.http.HttpTracer\": \"TRACE\"}\n"
                "}\n"
                "Or in log4j2.properties:\n"
                "  logger.http_tracer.name = org.elasticsearch.http.HttpTracer\n"
                "  logger.http_tracer.level = trace"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §5.3",
                "Elastic: Logging configuration",
                "NIST SP 800-53 AU-12",
            ],
            category="Logging",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "cluster_settings.logger",
                    {"level": logger_level, "http_tracer": access_log},
                    "GET /_cluster/settings?include_defaults=true",
                )
            ],
        )

    def _check_slowlog(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-LOG-004: Slow query logging (search and indexing slowlog) must be configured."""
        # Slow log thresholds are per-index, but defaults can be set at node level
        search_slowlog = (
            node_settings.get("index.search.slowlog.threshold.query.warn", "")
            or cluster_settings.get("index.search.slowlog.threshold.query.warn", "")
        )
        index_slowlog = (
            node_settings.get("index.indexing.slowlog.threshold.index.warn", "")
            or cluster_settings.get("index.indexing.slowlog.threshold.index.warn", "")
        )
        # Dynamic cluster-wide defaults
        slowlog_default = (
            cluster_settings.get("logger.index.search.slowlog", "")
            or cluster_settings.get("logger.index.indexing.slowlog", "")
        )

        has_slowlog = bool(search_slowlog or index_slowlog or slowlog_default)

        if has_slowlog:
            status = Status.PASS
            actual = (
                f"search_slowlog_warn={search_slowlog or '<not set>'}, "
                f"index_slowlog_warn={index_slowlog or '<not set>'}"
            )
        else:
            status = Status.WARN
            actual = "slowlog thresholds not configured at cluster level (per-index defaults apply)"

        return CheckResult(
            check_id="ES-LOG-004",
            title="Slow query logging should be configured for search and indexing operations",
            status=status,
            severity=Severity.LOW,
            benchmark_control_id="5.4",
            cis_id="CIS-ES-5.4",
            fedramp_control="AU-12",
            nist_800_53_controls=["AU-12"],
            description=(
                "Search and indexing slowlog should be configured to log queries and indexing "
                "operations that exceed configurable thresholds. This aids in performance "
                "monitoring and detecting anomalous query patterns."
            ),
            rationale=(
                "Slow query logging helps identify expensive or abusive queries that could "
                "indicate data exfiltration attempts (e.g., large wildcard scans) or "
                "denial-of-service attacks via expensive aggregations."
            ),
            actual=actual,
            expected="search and index slowlog configured at cluster or index level",
            remediation=(
                "Configure slowlog thresholds via index template or per-index:\n"
                "PUT /my-index/_settings {\n"
                "  \"index.search.slowlog.threshold.query.warn\": \"10s\",\n"
                "  \"index.search.slowlog.threshold.query.info\": \"5s\",\n"
                "  \"index.indexing.slowlog.threshold.index.warn\": \"10s\"\n"
                "}\n"
                "Or set cluster defaults for new indices in index templates."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §5.4",
                "Elastic: Slow log",
                "NIST SP 800-53 AU-12",
            ],
            category="Logging",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.slowlog",
                    {"search_warn": search_slowlog, "index_warn": index_slowlog},
                    "GET /_nodes/_local/settings",
                )
            ],
        )
