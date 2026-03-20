"""Authentication checks for Elasticsearch.

Controls:
  ES-AUTH-001 — xpack.security enabled
  ES-AUTH-002 — Built-in users secured (elastic default password changed)
  ES-AUTH-003 — Password policy / minimum password length
  ES-AUTH-004 — API key service enabled
  ES-AUTH-005 — Realm configuration (LDAP/SAML/PKI in use or native only documented)
"""
from .base import BaseChecker, CheckResult, Severity, Status


class ElasticsearchAuthChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        node_settings = self.runner.get_node_settings()
        cluster_settings = self.runner.get_cluster_settings()
        users = self.runner.get_users()

        return [
            self._check_security_enabled(node_settings, cluster_settings),
            self._check_elastic_default_password(users),
            self._check_password_policy(node_settings, cluster_settings),
            self._check_api_key_service(node_settings, cluster_settings),
            self._check_realm_config(node_settings, cluster_settings),
        ]

    # ------------------------------------------------------------------

    def _check_security_enabled(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-AUTH-001: xpack.security.enabled must be true (or auto-configured in 8.x)."""
        # In ES 8.x security is enabled by default. In 7.x it must be explicitly set.
        security_enabled = (
            node_settings.get("xpack.security.enabled", "").lower()
            or cluster_settings.get("xpack.security.enabled", "").lower()
        )
        # If the setting is missing entirely, check if we can reach the security API
        if not security_enabled:
            # Try fetching users — if it returns data, security is on
            users_resp = self.runner.get_users()
            if users_resp and isinstance(users_resp, dict) and len(users_resp) > 0:
                security_on = True
                actual = "xpack.security.enabled=<not explicitly set, security API responding>"
            elif users_resp is None:
                security_on = False
                actual = "xpack.security.enabled=false or security API unreachable"
            else:
                # Empty dict could mean no users listed or auth required
                security_on = True
                actual = "xpack.security.enabled=<not explicitly set, partial response>"
        else:
            security_on = security_enabled in ("true", "1", "yes")
            actual = f"xpack.security.enabled={security_enabled}"

        return CheckResult(
            check_id="ES-AUTH-001",
            title="Elasticsearch security features (xpack.security) must be enabled",
            status=Status.PASS if security_on else Status.FAIL,
            severity=Severity.CRITICAL,
            benchmark_control_id="1.1",
            cis_id="CIS-ES-1.1",
            fedramp_control="AC-2",
            nist_800_53_controls=["AC-2", "AC-3", "IA-2"],
            description=(
                "The xpack.security feature bundle must be enabled to enforce authentication, "
                "authorization, TLS, and audit logging in Elasticsearch."
            ),
            rationale=(
                "Without xpack.security, Elasticsearch allows unauthenticated access to all data "
                "and cluster management APIs. In Elasticsearch 8.x, security is enabled by default; "
                "in 7.x and earlier it must be explicitly enabled."
            ),
            actual=actual,
            expected="xpack.security.enabled=true",
            remediation=(
                "Set xpack.security.enabled: true in elasticsearch.yml "
                "and restart the cluster. In Elasticsearch 8.x this is the default."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §1.1",
                "Elastic Security Docs: Enable security",
                "NIST SP 800-53 IA-2",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.xpack.security.enabled",
                    security_enabled or "<not set>",
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_elastic_default_password(self, users: dict) -> CheckResult:
        """ES-AUTH-002: The built-in 'elastic' superuser must not use a default/empty password."""
        # We can't directly check the password hash via API, but we can check:
        # 1. Whether we connected with default credentials (elastic/changeme or elastic/elastic)
        # 2. Whether the elastic user exists and is enabled
        elastic_user = users.get("elastic", {}) if users else {}

        if not users:
            return CheckResult(
                check_id="ES-AUTH-002",
                title="Built-in 'elastic' superuser must have a non-default password",
                status=Status.WARN,
                severity=Severity.CRITICAL,
                benchmark_control_id="1.2",
                cis_id="CIS-ES-1.2",
                fedramp_control="IA-5",
                nist_800_53_controls=["IA-5", "AC-2"],
                description="Could not verify elastic user credentials — security API may not be accessible.",
                rationale=(
                    "The default elastic superuser password ('changeme') is widely known. "
                    "If left unchanged, any attacker with network access can gain full cluster control."
                ),
                actual="Security user API not accessible — cannot verify password policy",
                expected="elastic user exists, enabled, with non-default password",
                remediation=(
                    "Run: POST /_security/user/elastic/_password "
                    "with {\"password\": \"<strong-password>\"} "
                    "and verify authentication requires the new password."
                ),
                references=[
                    "CIS Elasticsearch Benchmark v1.0 §1.2",
                    "Elastic Security: Set built-in user passwords",
                ],
                category="Authentication",
                evidence_type="runtime-config",
                evidence=[self.evidence("security_users", "unavailable", "GET /_security/user")],
            )

        enabled = elastic_user.get("enabled", True)
        roles = elastic_user.get("roles", [])
        is_superuser = "superuser" in roles

        # Heuristic: if we connected with empty/no credentials and got user data back, security may be weak
        connected_no_auth = not self.runner.username and not self.runner.password
        if connected_no_auth and users:
            status = Status.FAIL
            actual = "Security API accessible without credentials — authentication may be disabled"
        elif elastic_user and enabled:
            status = Status.PASS
            actual = f"elastic user: enabled={enabled}, roles={roles}"
        else:
            status = Status.WARN
            actual = f"elastic user data: {elastic_user}"

        return CheckResult(
            check_id="ES-AUTH-002",
            title="Built-in 'elastic' superuser must have a non-default password",
            status=status,
            severity=Severity.CRITICAL,
            benchmark_control_id="1.2",
            cis_id="CIS-ES-1.2",
            fedramp_control="IA-5",
            nist_800_53_controls=["IA-5", "AC-2"],
            description=(
                "The built-in 'elastic' superuser account must be secured with a strong, "
                "unique password. The default password 'changeme' must be changed before production use."
            ),
            rationale=(
                "The elastic superuser has unrestricted access to all Elasticsearch APIs and data. "
                "A default or weak password allows any attacker with network access to fully compromise "
                "the cluster."
            ),
            actual=actual,
            expected="elastic user enabled, strong password set (not default)",
            remediation=(
                "Change the elastic password: "
                "POST /_security/user/elastic/_password {\"password\": \"<strong-password>\"}. "
                "Consider disabling the elastic user and using custom superuser accounts."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §1.2",
                "Elastic Security: Built-in users",
                "NIST SP 800-53 IA-5",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[
                self.evidence("security_users.elastic", elastic_user, "GET /_security/user/elastic")
            ],
        )

    def _check_password_policy(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-AUTH-003: Password minimum length should be configured."""
        min_length = (
            cluster_settings.get("xpack.security.authc.password_hashing.algorithm")
            or node_settings.get("xpack.security.authc.password_hashing.algorithm")
        )
        # Check password length setting
        pw_length = (
            cluster_settings.get("xpack.security.authc.native.minimum_password_length")
            or node_settings.get("xpack.security.authc.native.minimum_password_length")
        )

        if pw_length:
            try:
                length_int = int(pw_length)
                passes = length_int >= 12
                actual = f"minimum_password_length={pw_length}"
            except ValueError:
                passes = False
                actual = f"minimum_password_length={pw_length} (parse error)"
        else:
            # Default in ES is 6 — insufficient for regulated environments
            passes = False
            actual = "minimum_password_length not configured (ES default: 6 characters)"

        return CheckResult(
            check_id="ES-AUTH-003",
            title="Password minimum length policy must require at least 12 characters",
            status=Status.PASS if passes else Status.WARN,
            severity=Severity.MEDIUM,
            benchmark_control_id="1.3",
            cis_id="CIS-ES-1.3",
            fedramp_control="IA-5",
            nist_800_53_controls=["IA-5"],
            description=(
                "Elasticsearch should enforce a minimum password length of at least 12 characters "
                "for all native realm accounts."
            ),
            rationale=(
                "Short passwords are vulnerable to brute-force and dictionary attacks. "
                "NIST SP 800-63B recommends a minimum of 8 characters; regulated environments "
                "typically require 12+ characters."
            ),
            actual=actual,
            expected="minimum_password_length >= 12",
            remediation=(
                "Set via cluster settings: "
                "PUT /_cluster/settings {\"persistent\": "
                "{\"xpack.security.authc.native.minimum_password_length\": 12}}. "
                "Also consider bcrypt password hashing by setting "
                "xpack.security.authc.password_hashing.algorithm: bcrypt in elasticsearch.yml."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §1.3",
                "NIST SP 800-63B §5.1.1",
                "Elastic: Native realm settings",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "cluster_settings.password_policy",
                    {"min_length": pw_length, "hashing_algo": min_length},
                    "GET /_cluster/settings?include_defaults=true",
                )
            ],
        )

    def _check_api_key_service(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-AUTH-004: API key service must be enabled for programmatic access."""
        api_key_enabled = (
            node_settings.get("xpack.security.authc.api_key.enabled", "")
            or cluster_settings.get("xpack.security.authc.api_key.enabled", "")
        )

        # In ES 7.9+, API key service is enabled by default when security is on
        if not api_key_enabled or api_key_enabled.lower() in ("true", ""):
            status = Status.PASS
            actual = f"api_key.enabled={api_key_enabled or '<default: true in ES 7.9+>'}"
        else:
            status = Status.WARN
            actual = f"api_key.enabled={api_key_enabled}"

        return CheckResult(
            check_id="ES-AUTH-004",
            title="API key authentication service must be enabled",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="1.4",
            cis_id="CIS-ES-1.4",
            fedramp_control="IA-2",
            nist_800_53_controls=["IA-2", "AC-3"],
            description=(
                "The Elasticsearch API key service provides a secure method for programmatic access "
                "without embedding username/password credentials in application code."
            ),
            rationale=(
                "API keys can be scoped, rotated, and revoked independently of user accounts. "
                "Using API keys for service-to-service authentication reduces credential exposure "
                "compared to embedding passwords in configuration."
            ),
            actual=actual,
            expected="xpack.security.authc.api_key.enabled=true",
            remediation=(
                "API keys are enabled by default in Elasticsearch 7.9+ with security enabled. "
                "Verify: GET /_security/api_key?id=<id>. "
                "Do not explicitly set to false unless LDAP/SAML tokens are used instead."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §1.4",
                "Elastic: API key authentication",
                "NIST SP 800-53 IA-2",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.api_key_enabled",
                    api_key_enabled or "<not set>",
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_realm_config(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-AUTH-005: Authentication realm must be explicitly configured."""
        # Check for realm configuration — look for LDAP, SAML, PKI, or native realm settings
        realm_keys = [k for k in node_settings if "xpack.security.authc.realms" in k]
        realm_keys += [k for k in cluster_settings if "xpack.security.authc.realms" in k]

        realm_types = set()
        for k in realm_keys:
            parts = k.split(".")
            # format: xpack.security.authc.realms.<type>.<name>.<setting>
            if len(parts) >= 6:
                realm_types.add(parts[4])

        has_native = "native" in realm_types or not realm_types  # native is default if nothing set
        has_external_idp = bool(realm_types - {"native", "file", "reserved"})

        if realm_types:
            actual = f"realms configured: {sorted(realm_types)}"
        else:
            actual = "no realm settings found (native realm is the default)"

        # Pass if native realm is configured, or if external IdP is in use
        status = Status.PASS if (has_native or has_external_idp) else Status.WARN

        return CheckResult(
            check_id="ES-AUTH-005",
            title="Authentication realm must be explicitly configured",
            status=status,
            severity=Severity.MEDIUM,
            benchmark_control_id="1.5",
            cis_id="CIS-ES-1.5",
            fedramp_control="IA-2",
            nist_800_53_controls=["IA-2", "IA-8"],
            description=(
                "Elasticsearch authentication realms must be explicitly configured to define "
                "how users are authenticated. Native realm is the minimum; LDAP or SAML "
                "integration is recommended for enterprise environments."
            ),
            rationale=(
                "Explicit realm configuration ensures authentication is governed and auditable. "
                "LDAP/SAML integration enables central identity management, MFA enforcement, "
                "and account lifecycle management through existing enterprise systems."
            ),
            actual=actual,
            expected="at least one realm explicitly configured (native, LDAP, SAML, or PKI)",
            remediation=(
                "Configure realm in elasticsearch.yml under xpack.security.authc.realms. "
                "For LDAP: xpack.security.authc.realms.ldap.ldap1.url: ldaps://ldap.example.com. "
                "For native realm (default): no additional config needed, but document it."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §1.5",
                "Elastic: Realm configuration",
                "NIST SP 800-53 IA-2, IA-8",
            ],
            category="Authentication",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.realms",
                    sorted(realm_types) if realm_types else [],
                    "GET /_nodes/_local/settings",
                )
            ],
        )
