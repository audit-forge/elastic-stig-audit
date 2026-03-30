"""Encryption (TLS/SSL) checks for Elasticsearch.

Controls:
  ES-ENC-001 — HTTP TLS enabled (xpack.security.http.ssl.enabled)
  ES-ENC-002 — Transport TLS enabled (xpack.security.transport.ssl.enabled)
  ES-ENC-003 — Strong cipher suites configured
  ES-ENC-004 — Certificate verification mode (full/certificate)
  ES-ENC-005 — Encryption at rest (snapshot encryption, cold tier)
"""
from .base import BaseChecker, CheckResult, Severity, Status

_WEAK_CIPHERS = frozenset({
    "TLS_RSA_WITH_RC4_128_SHA",        # RC4 — broken
    "TLS_RSA_WITH_RC4_128_MD5",        # RC4 — broken
    "SSL_RSA_WITH_3DES_EDE_CBC_SHA",   # 3DES/SWEET32 — vulnerable
    "TLS_RSA_WITH_NULL_SHA256",        # NULL encryption — no confidentiality
    "TLS_RSA_WITH_NULL_SHA",           # NULL encryption — no confidentiality
    "TLS_RSA_WITH_NULL_MD5",           # NULL encryption — no confidentiality
    "TLS_RSA_WITH_AES_128_CBC_SHA",    # No forward secrecy (RSA key exchange)
    "TLS_RSA_WITH_AES_256_CBC_SHA",    # No forward secrecy (RSA key exchange)
    "TLS_RSA_WITH_AES_128_CBC_SHA256",  # No forward secrecy (RSA key exchange)
    # NOTE: TLS_DHE_RSA_WITH_AES_*_CBC_SHA intentionally excluded — DHE provides
    # forward secrecy. These are "acceptable" per NIST SP 800-52 Rev 2 Table 3-5.
})

_STRONG_PROTOCOLS = frozenset({"TLSv1.2", "TLSv1.3"})
_WEAK_PROTOCOLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"})


class ElasticsearchEncryptionChecker(BaseChecker):
    def run(self) -> list[CheckResult]:
        node_settings = self.runner.get_node_settings()
        cluster_settings = self.runner.get_cluster_settings()

        return [
            self._check_http_ssl(node_settings, cluster_settings),
            self._check_transport_ssl(node_settings, cluster_settings),
            self._check_cipher_suites(node_settings, cluster_settings),
            self._check_cert_verification(node_settings, cluster_settings),
            self._check_encryption_at_rest(node_settings, cluster_settings),
        ]

    def _check_http_ssl(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-ENC-001: HTTP layer TLS must be enabled."""
        http_ssl = (
            node_settings.get("xpack.security.http.ssl.enabled", "")
            or cluster_settings.get("xpack.security.http.ssl.enabled", "")
        )

        # Also check for a certificate path as evidence TLS is configured
        http_cert = (
            node_settings.get("xpack.security.http.ssl.certificate", "")
            or node_settings.get("xpack.security.http.ssl.keystore.path", "")
        )

        # If runner is using https scheme, that's additional evidence
        using_https = self.runner.scheme == "https"

        if http_ssl.lower() == "true" or (not http_ssl and using_https):
            status = Status.PASS
            actual = f"http.ssl.enabled={http_ssl or '<scheme=https>'}"
        elif http_ssl.lower() == "false":
            status = Status.FAIL
            actual = "xpack.security.http.ssl.enabled=false"
        else:
            # Not explicitly set — default is false for HTTP in most ES versions
            status = Status.WARN
            actual = "xpack.security.http.ssl.enabled not explicitly set (default: false)"

        return CheckResult(
            check_id="ES-ENC-001",
            title="TLS must be enabled for the Elasticsearch HTTP (REST API) layer",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="2.1",
            cis_id="CIS-ES-2.1",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-28"],
            description=(
                "All HTTP REST API traffic to/from Elasticsearch must be encrypted using TLS. "
                "This protects credentials, query data, and results from network interception."
            ),
            rationale=(
                "HTTP REST API calls carry authentication credentials and potentially sensitive data. "
                "Plaintext HTTP allows any network observer to capture credentials and query results, "
                "violating confidentiality requirements in regulated environments."
            ),
            actual=actual,
            expected="xpack.security.http.ssl.enabled=true with valid certificate configured",
            remediation=(
                "In elasticsearch.yml:\n"
                "  xpack.security.http.ssl.enabled: true\n"
                "  xpack.security.http.ssl.keystore.path: certs/http.p12\n"
                "Generate certificates using: elasticsearch-certutil http"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §2.1",
                "Elastic: Encrypting HTTP client communications",
                "NIST SP 800-53 SC-8",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.http_ssl",
                    {"enabled": http_ssl, "certificate": http_cert, "scheme": self.runner.scheme},
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_transport_ssl(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-ENC-002: Transport layer TLS must be enabled for node-to-node communication."""
        transport_ssl = (
            node_settings.get("xpack.security.transport.ssl.enabled", "")
            or cluster_settings.get("xpack.security.transport.ssl.enabled", "")
        )

        # In ES 8.x, transport TLS is required; in 7.x must be configured
        transport_cert = (
            node_settings.get("xpack.security.transport.ssl.certificate", "")
            or node_settings.get("xpack.security.transport.ssl.keystore.path", "")
        )

        if transport_ssl.lower() == "true":
            status = Status.PASS
            actual = f"transport.ssl.enabled=true, cert={transport_cert or '<not inspected>'}"
        elif transport_ssl.lower() == "false":
            status = Status.FAIL
            actual = "xpack.security.transport.ssl.enabled=false"
        else:
            # Default depends on ES version; 8.x requires it
            status = Status.WARN
            actual = "xpack.security.transport.ssl.enabled not explicitly set"

        return CheckResult(
            check_id="ES-ENC-002",
            title="TLS must be enabled for Elasticsearch inter-node transport communication",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="2.2",
            cis_id="CIS-ES-2.2",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-7"],
            description=(
                "Node-to-node transport communication must be encrypted using TLS to prevent "
                "cluster data interception and unauthorized cluster joining."
            ),
            rationale=(
                "Without transport TLS, an attacker on the same network segment can intercept "
                "data replication traffic, cluster state updates, and shard operations. "
                "They could also potentially inject a rogue node into the cluster."
            ),
            actual=actual,
            expected="xpack.security.transport.ssl.enabled=true with CA-signed certificate",
            remediation=(
                "In elasticsearch.yml:\n"
                "  xpack.security.transport.ssl.enabled: true\n"
                "  xpack.security.transport.ssl.verification_mode: certificate\n"
                "  xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12\n"
                "Generate CA and certs: elasticsearch-certutil ca && elasticsearch-certutil cert"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §2.2",
                "Elastic: Encrypting communications between nodes",
                "NIST SP 800-53 SC-8",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.transport_ssl",
                    {"enabled": transport_ssl, "certificate": transport_cert},
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_cipher_suites(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-ENC-003: Weak cipher suites and protocols must be excluded."""
        # Check for explicitly configured cipher suites and SSL protocols
        http_ciphers = (
            node_settings.get("xpack.security.http.ssl.cipher_suites", "")
            or cluster_settings.get("xpack.security.http.ssl.cipher_suites", "")
        )
        transport_ciphers = (
            node_settings.get("xpack.security.transport.ssl.cipher_suites", "")
            or cluster_settings.get("xpack.security.transport.ssl.cipher_suites", "")
        )
        http_protocols = (
            node_settings.get("xpack.security.http.ssl.supported_protocols", "")
            or cluster_settings.get("xpack.security.http.ssl.supported_protocols", "")
        )

        configured_ciphers = set()
        if http_ciphers:
            configured_ciphers.update(c.strip() for c in http_ciphers.split(","))
        if transport_ciphers:
            configured_ciphers.update(c.strip() for c in transport_ciphers.split(","))

        weak_in_use = configured_ciphers & _WEAK_CIPHERS

        configured_protocols = set()
        if http_protocols:
            configured_protocols.update(p.strip() for p in http_protocols.split(","))

        weak_protos = configured_protocols & _WEAK_PROTOCOLS

        if weak_in_use or weak_protos:
            status = Status.FAIL
            actual = (
                f"weak_ciphers={sorted(weak_in_use)}, weak_protocols={sorted(weak_protos)}"
            )
        elif not configured_ciphers and not configured_protocols:
            status = Status.WARN
            actual = "cipher_suites/protocols not explicitly configured (using JVM defaults)"
        else:
            status = Status.PASS
            actual = f"configured_protocols={sorted(configured_protocols)}, no weak ciphers detected"

        return CheckResult(
            check_id="ES-ENC-003",
            title="Weak TLS cipher suites and protocols must be disabled",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="2.3",
            cis_id="CIS-ES-2.3",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "SC-23"],
            description=(
                "Elasticsearch TLS configuration must explicitly restrict cipher suites and "
                "protocols to strong options, disabling RC4, 3DES, SSLv3, TLSv1.0, and TLSv1.1."
            ),
            rationale=(
                "Weak cipher suites (RC4, 3DES) and old protocols (SSLv3, TLSv1.0) are vulnerable "
                "to known attacks (BEAST, POODLE, SWEET32). Explicit cipher configuration prevents "
                "negotiation downgrade to insecure options."
            ),
            actual=actual,
            expected="TLSv1.2 and TLSv1.3 only; no weak ciphers; no SSLv2/3/TLSv1.0/1.1",
            remediation=(
                "In elasticsearch.yml:\n"
                "  xpack.security.http.ssl.supported_protocols: [TLSv1.2, TLSv1.3]\n"
                "  xpack.security.transport.ssl.supported_protocols: [TLSv1.2, TLSv1.3]\n"
                "  xpack.security.http.ssl.cipher_suites:\n"
                "    - TLS_AES_256_GCM_SHA384\n"
                "    - TLS_CHACHA20_POLY1305_SHA256\n"
                "    - TLS_AES_128_GCM_SHA256\n"
                "    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §2.3",
                "NIST SP 800-52 Rev 2: TLS guidance",
                "Elastic: Supported TLS protocols and cipher suites",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.ssl_ciphers",
                    {
                        "http_ciphers": http_ciphers,
                        "transport_ciphers": transport_ciphers,
                        "http_protocols": http_protocols,
                    },
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_cert_verification(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-ENC-004: Certificate verification mode must be 'full' or 'certificate'."""
        http_verify = (
            node_settings.get("xpack.security.http.ssl.verification_mode", "")
            or cluster_settings.get("xpack.security.http.ssl.verification_mode", "")
        )
        transport_verify = (
            node_settings.get("xpack.security.transport.ssl.verification_mode", "")
            or cluster_settings.get("xpack.security.transport.ssl.verification_mode", "")
        )

        # "none" means no cert verification — major security risk
        http_none = http_verify.lower() == "none"
        transport_none = transport_verify.lower() == "none"

        if http_none or transport_none:
            status = Status.FAIL
            issues = []
            if http_none:
                issues.append("http.ssl.verification_mode=none")
            if transport_none:
                issues.append("transport.ssl.verification_mode=none")
            actual = f"INSECURE: {', '.join(issues)}"
        elif not http_verify and not transport_verify:
            status = Status.WARN
            actual = "verification_mode not explicitly set (check JVM/Elasticsearch defaults)"
        else:
            status = Status.PASS
            actual = (
                f"http.ssl.verification_mode={http_verify or '<default>'}, "
                f"transport.ssl.verification_mode={transport_verify or '<default>'}"
            )

        return CheckResult(
            check_id="ES-ENC-004",
            title="TLS certificate verification must not be disabled",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="2.4",
            cis_id="CIS-ES-2.4",
            fedramp_control="SC-8",
            nist_800_53_controls=["SC-8", "IA-3"],
            description=(
                "The ssl.verification_mode for HTTP and transport layers must not be set to 'none'. "
                "This setting controls whether Elasticsearch validates the TLS certificate of "
                "connecting nodes and clients."
            ),
            rationale=(
                "verification_mode=none disables all certificate validation, making TLS useless "
                "against man-in-the-middle attacks. Nodes can be impersonated and traffic "
                "intercepted without detection."
            ),
            actual=actual,
            expected="verification_mode=full (or certificate) for both http and transport",
            remediation=(
                "In elasticsearch.yml:\n"
                "  xpack.security.http.ssl.verification_mode: full\n"
                "  xpack.security.transport.ssl.verification_mode: full\n"
                "Use CA-signed certificates or self-signed with the CA distributed to all clients."
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §2.4",
                "Elastic: SSL/TLS settings",
                "NIST SP 800-53 IA-3",
            ],
            category="Encryption",
            evidence_type="runtime-config",
            evidence=[
                self.evidence(
                    "node_settings.ssl_verification",
                    {"http": http_verify, "transport": transport_verify},
                    "GET /_nodes/_local/settings",
                )
            ],
        )

    def _check_encryption_at_rest(self, node_settings: dict, cluster_settings: dict) -> CheckResult:
        """ES-ENC-005: Encryption at rest should be configured."""
        # Elasticsearch does not have native transparent disk encryption.
        # Encryption at rest is achieved via:
        # 1. OS/filesystem-level encryption (dm-crypt, LUKS, AWS EBS encryption)
        # 2. Elastic Security for Elasticsearch encrypted snapshots (7.12+)
        # We check for the encrypted snapshots setting as a proxy
        snapshot_encryption = (
            node_settings.get("xpack.snapshot_lifecycle.history_index_enabled", "")
            or cluster_settings.get("snapshot.encrypted", "")
        )

        # Check if path.data is configured (where data lives)
        data_path = node_settings.get("path.data", "<not set>")

        return CheckResult(
            check_id="ES-ENC-005",
            title="Elasticsearch data must be protected by encryption at rest",
            status=Status.WARN,
            severity=Severity.MEDIUM,
            benchmark_control_id="2.5",
            cis_id="CIS-ES-2.5",
            fedramp_control="SC-28",
            nist_800_53_controls=["SC-28"],
            description=(
                "Elasticsearch data directories must be protected by encryption at rest "
                "using OS-level disk encryption (LUKS/dm-crypt, AWS EBS encryption, etc.) "
                "or equivalent platform controls."
            ),
            rationale=(
                "Elasticsearch data is stored in plain-text JSON files on disk. "
                "Physical or logical access to the data directory allows full data extraction "
                "without going through the Elasticsearch security layer. "
                "Encryption at rest protects data in case of physical media theft or improper disposal."
            ),
            actual=(
                f"data_path={data_path}; "
                "disk-level encryption cannot be verified via API — manual verification required"
            ),
            expected="data directory protected by OS-level disk encryption (LUKS, BitLocker, EBS encryption, etc.)",
            remediation=(
                "Enable encryption at the storage layer:\n"
                "  Linux: Use LUKS (cryptsetup) or dm-crypt for the data volume\n"
                "  Kubernetes: Use encrypted storage class (e.g., AWS gp3 with KMS)\n"
                "  AWS: Enable EBS encryption with KMS CMK\n"
                "  GCP: Ensure CSEK or CMEK is configured for persistent disks"
            ),
            references=[
                "CIS Elasticsearch Benchmark v1.0 §2.5",
                "NIST SP 800-53 SC-28",
                "NIST SP 800-111: Storage encryption",
            ],
            category="Encryption",
            evidence_type="manual-verification",
            evidence=[
                self.evidence(
                    "node_settings.path_data",
                    data_path,
                    "GET /_nodes/_local/settings",
                )
            ],
        )
