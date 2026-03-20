"""Authorization checks for Elasticsearch.

Controls:
  ES-AUTHZ-001 — RBAC configured (roles exist, used appropriately)
  ES-AUTHZ-002 — Least privilege — no wildcard index/cluster permissions for regular users
  ES-AUTHZ-003 — Anonymous access disabled
  ES-AUTHZ-004 — Field/document-level security available (Platinum+)
"""
from .base import BaseChecker, CheckResult, Severity, Status


class ElasticsearchAuthzChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        node_settings = self.runner.get_node_settings()
        cluster_settings = self.runner.get_cluster_settings()
        roles = self.runner.get_roles()
        users = self.runner.get_users()

        return [
            self._check_rbac_configured(roles, users),
            self._check_least_privilege(roles, users),
            self._check_anonymous_access(node_settings, cluster_settings),
            self._check_field_document_security(node_settings, cluster_settings, roles),
        ]

    def _check_rbac_configured(self, roles: dict, users: dict) -> CheckResult:
        """ES-AUTHZ-001: RBAC must be configured with custom roles, not just built-in roles."""
        if not roles and not users:
            return CheckResult(
                check_id="ES-AUTHZ-001",
                title="Role-Based Access Control (RBAC) must be configured",
                status=Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id="4.1",
                cis_id="CIS-ES-4.1",
                fedramp_control="AC-3",
                nist_800_53_controls=["AC-3", "AC-6"],
                description="RBAC posture could not be assessed — security API unavailable.",
                rationale="RBAC enables fine-grained access control for Elasticsearch indices and cluster operations.",
                actual="Security API not accessible",
                expected="custom roles defined with least-privilege index/cluster permissions",
                remediation="Ensure Elasticsearch security is enabled and the audit user has permission to call GET /_security/role.",
                references=[
                    "CIS Elasticsearch Benchmark v1.0 §4.1",
                    "Elastic: Role-Based Access Control",
                ],
                category="Authorization",
                evidence_type="runtime-config",
                evidence=[self.evidence("security_roles", "unavailable", "GET /_security/role")],
            )

        # Built-in role names
        builtin_roles = {
            "superuser", "kibana_admin", "kibana_system", "logstash_system",
            "beats_system", "apm_system", "remote_monitoring_agent", "remote_monitoring_collector",
            "monitoring_user", "rollup_admin", "rollup_user", "index_admin",
            "data_frame_transforms_admin", "data_frame_transforms_user", "watcher_admin", "watcher_user",
            "reporting_user", "viewer", "editor",
        }

        custom_roles = set(roles.keys()) - builtin_roles if roles else set()
        has_custom_roles = len(custom_roles) > 0

        if not roles:
            actual = "no roles returned — security may not be active or no permission to list roles"
            status = Status.WARN
        elif has_custom_roles:
            actual = f"{len(custom_roles)} custom role(s): {sorted(list(custom_roles))[:5]}"
            status = Status.PASS
        else:
            actual = f"only built-in roles in use ({len(roles)} total) — no custom roles defined"
            status = Status.WARN

        return CheckResult(
            check_id="ES-AUTHZ-001",
            title="Role-Based Access Control (RBAC) must be configured with custom roles",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="4.1",
            cis_id="CIS-ES-4.1",
            fedramp_control="AC-3",
            nist_800_53_controls=["AC-3", "AC-6"],
            description=(
                "Custom RBAC roles must be defined to enforce least-privilege access to "
                "Elasticsearch indices and cluster operations. Relying only on built-in "
                "roles (like 'superuser') is insufficient for regulated environments."
            ),
            rationale=(
                "RBAC is the primary authorization mechanism in Elasticsearch. "
                "Without custom roles, users are assigned overly broad built-in roles "
                "that may grant more permissions than necessary for their function. "
                "Custom roles allow precise scoping of index patterns and operations."
            ),
            actual=actual,
            expected="custom roles defined with scoped index patterns and specific privileges",
            remediation=(
                "Create application-specific roles:\n"
                "POST /_security/role/app_reader {\n"
                "  \"indices\": [{\"names\": [\"app-*\"], \"privileges\": [\"read\"]}]\n"
                "}\n"
                "Avoid assigning the 'superuser' role to service accounts or application users."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §4.1",
                "Elastic: Define roles",
                "NIST SP 800-53 AC-3, AC-6",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "security_roles.summary",
                    {"total_roles": len(roles) if roles else 0, "custom_roles": len(custom_roles)},
                    "GET /_security/role",
                )
            ],
        )

    def _check_least_privilege(self, roles: dict, users: dict) -> CheckResult:
        """ES-AUTHZ-002: Check for wildcard index permissions or manage cluster rights on non-admin roles."""
        if not roles:
            return CheckResult(
                check_id="ES-AUTHZ-002",
                title="Roles must enforce least-privilege index and cluster permissions",
                status=Status.SKIP,
                severity=Severity.HIGH,
                benchmark_control_id="4.2",
                cis_id="CIS-ES-4.2",
                fedramp_control="AC-6",
                nist_800_53_controls=["AC-6"],
                description="Cannot assess least-privilege — roles not available.",
                rationale="Wildcard index permissions grant access to all indices, violating least privilege.",
                actual="roles not accessible",
                expected="no wildcard index permissions on application roles",
                remediation="Enable security and grant audit user permission to call GET /_security/role.",
                references=["CIS Elasticsearch Benchmark v1.0 §4.2", "Elastic: Define roles"],
                category="Authorization",
                evidence_type="runtime-config",
                evidence=[],
            )

        violations = []
        for role_name, role_def in roles.items():
            if role_name in ("superuser",):
                continue  # superuser is expected to have all
            indices = role_def.get("indices", [])
            cluster = role_def.get("cluster", [])
            for idx_perm in indices:
                names = idx_perm.get("names", [])
                privs = idx_perm.get("privileges", [])
                if "*" in names and any(p in privs for p in ("all", "write", "delete")):
                    violations.append(f"{role_name}: indices[*] with {privs}")
            if "all" in cluster and role_name not in ("superuser",):
                violations.append(f"{role_name}: cluster[all]")

        if violations:
            status = Status.FAIL
            actual = f"{len(violations)} privilege violation(s): {violations[:3]}"
        else:
            status = Status.PASS
            actual = f"checked {len(roles)} roles — no wildcard write violations found"

        return CheckResult(
            check_id="ES-AUTHZ-002",
            title="Roles must enforce least-privilege index and cluster permissions",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="4.2",
            cis_id="CIS-ES-4.2",
            fedramp_control="AC-6",
            nist_800_53_controls=["AC-6", "AC-3"],
            description=(
                "No role (other than superuser) should grant write/delete permissions "
                "to all indices (*) or full cluster management (cluster:all). "
                "Index patterns must be scoped to the minimum required for the application."
            ),
            rationale=(
                "Wildcard write permissions on all indices means a compromised application account "
                "can corrupt or delete any data in the cluster. Least-privilege scoping limits "
                "the blast radius of a compromised credential."
            ),
            actual=actual,
            expected="no roles with wildcard write/delete on all indices except superuser",
            remediation=(
                "Audit all roles: GET /_security/role\n"
                "Replace wildcard index patterns with specific ones:\n"
                "  'names': ['app-logs-*'] instead of 'names': ['*']\n"
                "Split read/write roles for application accounts."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §4.2",
                "Elastic: Index privileges",
                "NIST SP 800-53 AC-6",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "security_roles.privilege_check",
                    {"roles_checked": len(roles), "violations": violations[:5]},
                    "GET /_security/role",
                )
            ],
        )

    def _check_anonymous_access(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-AUTHZ-003: Anonymous access must be disabled."""
        anon_user = (
            node_settings.get("xpack.security.authc.anonymous.username", "")
            or cluster_settings.get("xpack.security.authc.anonymous.username", "")
        )
        anon_roles = (
            node_settings.get("xpack.security.authc.anonymous.roles", "")
            or cluster_settings.get("xpack.security.authc.anonymous.roles", "")
        )
        anon_authz_exception = (
            node_settings.get("xpack.security.authc.anonymous.authz_exception", "true")
            or cluster_settings.get("xpack.security.authc.anonymous.authz_exception", "true")
        )

        anonymous_enabled = bool(anon_user or anon_roles)

        if anonymous_enabled:
            status = Status.FAIL
            actual = f"anonymous.username={anon_user!r}, anonymous.roles={anon_roles!r}"
        else:
            status = Status.PASS
            actual = "anonymous access not configured (disabled)"

        return CheckResult(
            check_id="ES-AUTHZ-003",
            title="Anonymous access to Elasticsearch must be disabled",
            status=status,
            severity=Severity.CRITICAL,
            benchmark_control_id="4.3",
            cis_id="CIS-ES-4.3",
            fedramp_control="AC-2",
            nist_800_53_controls=["AC-2", "AC-14"],
            description=(
                "The anonymous realm must not be configured in Elasticsearch. "
                "Anonymous access allows unauthenticated requests to be processed "
                "as a configured user with assigned roles."
            ),
            rationale=(
                "Anonymous access bypasses authentication requirements, allowing any network "
                "client to access Elasticsearch data without credentials. "
                "This violates fundamental access control requirements in any regulated environment."
            ),
            actual=actual,
            expected="no anonymous.username or anonymous.roles configured",
            remediation=(
                "Ensure these are NOT present in elasticsearch.yml:\n"
                "  xpack.security.authc.anonymous.username\n"
                "  xpack.security.authc.anonymous.roles\n"
                "If present, remove them and restart the cluster."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §4.3",
                "Elastic: Anonymous access",
                "NIST SP 800-53 AC-14",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.anonymous",
                    {"username": anon_user, "roles": anon_roles, "authz_exception": anon_authz_exception},
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_field_document_security(
        self, node_settings: dict, cluster_settings: dict, roles: dict
    ) -> CheckResult:
        """ES-AUTHZ-004: Field/document-level security (FLS/DLS) usage documented."""
        # FLS/DLS requires Platinum or Enterprise license
        # Check if any roles have field_security or query (DLS) defined
        roles_with_fls = []
        roles_with_dls = []

        if roles:
            for role_name, role_def in roles.items():
                indices = role_def.get("indices", [])
                for idx in indices:
                    if idx.get("field_security"):
                        roles_with_fls.append(role_name)
                    if idx.get("query"):
                        roles_with_dls.append(role_name)

        has_fls = len(roles_with_fls) > 0
        has_dls = len(roles_with_dls) > 0

        if has_fls or has_dls:
            status = Status.PASS
            actual = f"FLS roles: {roles_with_fls}, DLS roles: {roles_with_dls}"
        elif not roles:
            status = Status.WARN
            actual = "roles not available — FLS/DLS usage cannot be verified"
        else:
            status = Status.WARN
            actual = f"no FLS/DLS configured in {len(roles)} roles — may be intentional"

        return CheckResult(
            check_id="ES-AUTHZ-004",
            title="Field-level and document-level security should be configured where applicable",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="4.4",
            cis_id="CIS-ES-4.4",
            fedramp_control="AC-3",
            nist_800_53_controls=["AC-3", "AC-16"],
            description=(
                "Where Elasticsearch indices contain mixed-sensitivity data, field-level security "
                "(FLS) and document-level security (DLS) should be used to restrict access to "
                "sensitive fields and documents within an index."
            ),
            rationale=(
                "Without FLS/DLS, all users with index read access can see all fields and documents. "
                "For multi-tenant deployments or indices mixing public and sensitive data, "
                "FLS/DLS provides granular data isolation without requiring separate indices."
            ),
            actual=actual,
            expected="FLS/DLS configured for roles accessing mixed-sensitivity indices",
            remediation=(
                "For roles accessing sensitive indices, add field/document security:\n"
                "POST /_security/role/restricted_reader {\n"
                "  \"indices\": [{\n"
                "    \"names\": [\"sensitive-*\"],\n"
                "    \"privileges\": [\"read\"],\n"
                "    \"field_security\": {\"grant\": [\"public_field\"], \"except\": [\"ssn\", \"dob\"]},\n"
                "    \"query\": \"{\\\"term\\\": {\\\"tenant_id\\\": \\\"{{_user.username}}\\\"}}\"\n"
                "  }]\n"
                "}\n"
                "Note: requires Platinum or Enterprise license."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §4.4",
                "Elastic: Field and document level security",
                "NIST SP 800-53 AC-3, AC-16",
            ],
            category="Authorization",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "security_roles.fls_dls",
                    {"roles_with_fls": roles_with_fls, "roles_with_dls": roles_with_dls},
                    "GET /_security/role",
                )
            ],
        )
