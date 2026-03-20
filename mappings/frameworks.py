"""
Framework mapping data for elastic-stig-audit.

Provides NIST SP 800-171 Rev 2, CMMC 2.0, MITRE ATT&CK, and MITRE D3FEND
mappings for each Elasticsearch audit control (keyed by check_id).

Mapping rationale
-----------------
NIST 800-171 Rev 2 (110 controls / 14 families) — derived from NIST SP 800-171
  Rev 2 Appendix D cross-reference to NIST SP 800-53 Rev 4/5.

CMMC 2.0 levels:
  Level 1 — 17 "basic safeguarding" practices
  Level 2 — all 110 NIST SP 800-171 Rev 2 practices
  Level 3 — NIST SP 800-172 additions

MITRE ATT&CK — Enterprise / Containers matrix
MITRE D3FEND — Defensive countermeasure knowledge graph

Key 800-53 → 800-171 cross-references used:
  AC-2, AC-3, AC-6  → 3.1.1, 3.1.2, 3.1.5, 3.1.6
  AU-2, AU-3, AU-12 → 3.3.1, 3.3.2
  CM-6, CM-7        → 3.4.2, 3.4.6, 3.4.7
  IA-2, IA-5        → 3.5.1, 3.5.3, 3.5.7, 3.5.10
  SC-7, SC-8, SC-28 → 3.13.1, 3.13.5, 3.13.8, 3.13.16
  SI-2, SI-10       → 3.14.1
"""

# ---------------------------------------------------------------------------
# Per-control framework data
# Key: check_id (string, must match checks/*.py)
# ---------------------------------------------------------------------------
FRAMEWORK_MAP: dict[str, dict] = {

    # ------------------------------------------------------------------ #
    # Section 1 – Authentication (ES-AUTH-*)
    # ------------------------------------------------------------------ #

    "ES-AUTH-001": {
        # xpack.security.enabled — the master security switch
        # 800-53: AC-3, IA-2 → 800-171: 3.1.2, 3.5.1
        # CMMC L1: 3.1.2 (limit system access to authorized users) and 3.5.1 (identify users) are Level 1
        "nist_800_171": ["3.1.2", "3.5.1", "3.5.2"],
        "cmmc_level": 1,
        # T1190: Exploit Public-Facing Application — disabled security = unauthenticated ES API
        # T1078: Valid Accounts — no security means any credential (including none) works
        "mitre_attack": ["T1190", "T1078"],
        # D3-ACH: Application Configuration Hardening — enabling xpack.security
        # D3-UAP: User Account Permissions — security feature gates all authz
        "mitre_d3fend": ["D3-ACH", "D3-UAP"],
    },

    "ES-AUTH-002": {
        # Built-in 'elastic' superuser default password
        # 800-53: IA-5 → 800-171: 3.5.7 (complexity), 3.5.8 (prohibit reuse), 3.5.10 (cryptographic protection)
        # CMMC L1: 3.5.7 basic password complexity is Level 1
        "nist_800_171": ["3.5.7", "3.5.8", "3.5.3"],
        "cmmc_level": 1,
        # T1078.001: Default Accounts — elastic/changeme is a well-known default credential
        # T1110.001: Password Guessing — weak/default password trivially guessable
        "mitre_attack": ["T1078.001", "T1110.001"],
        # D3-SPP: Strong Password Policy — enforce non-default credentials
        # D3-UAP: User Account Permissions — lock down superuser account
        "mitre_d3fend": ["D3-SPP", "D3-UAP"],
    },

    "ES-AUTH-003": {
        # Password minimum length policy
        # 800-53: IA-5 → 800-171: 3.5.7 (enforce complexity requirements)
        "nist_800_171": ["3.5.7"],
        "cmmc_level": 1,
        # T1110: Brute Force — short passwords are vulnerable to brute force
        "mitre_attack": ["T1110"],
        # D3-SPP: Strong Password Policy
        "mitre_d3fend": ["D3-SPP"],
    },

    "ES-AUTH-004": {
        # API key authentication service
        # 800-53: IA-2, AC-3 → 800-171: 3.5.1, 3.1.2
        "nist_800_171": ["3.5.1", "3.1.2"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — API keys are a form of valid credential management
        "mitre_attack": ["T1078"],
        # D3-UAP: User Account Permissions — scoped API keys limit blast radius
        "mitre_d3fend": ["D3-UAP"],
    },

    "ES-AUTH-005": {
        # Authentication realm configuration
        # 800-53: IA-2, IA-8 → 800-171: 3.5.1, 3.5.2
        # CMMC L1: 3.5.1 is Level 1
        "nist_800_171": ["3.5.1", "3.5.2"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — realm configuration governs who can authenticate
        "mitre_attack": ["T1078"],
        # D3-UAP: User Account Permissions
        # D3-ANET: Authentication Event Thresholding (via LDAP/SAML audit trails)
        "mitre_d3fend": ["D3-UAP"],
    },

    # ------------------------------------------------------------------ #
    # Section 2 – Encryption (ES-ENC-*)
    # ------------------------------------------------------------------ #

    "ES-ENC-001": {
        # HTTP TLS enabled
        # 800-53: SC-8 → 800-171: 3.13.8 (cryptographic mechanisms to prevent disclosure in transit)
        # CMMC L2: 3.13.8 is Level 2
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — plaintext HTTP exposes credentials and data
        # T1557: Adversary-in-the-Middle — unencrypted API susceptible to MITM
        "mitre_attack": ["T1040", "T1557"],
        # D3-ET: Encrypted Tunnels — TLS for HTTP REST API
        # D3-MH: Message Hardening
        "mitre_d3fend": ["D3-ET", "D3-MH"],
    },

    "ES-ENC-002": {
        # Transport TLS (node-to-node)
        # 800-53: SC-8, SC-7 → 800-171: 3.13.8, 3.13.1
        "nist_800_171": ["3.13.8", "3.13.1"],
        "cmmc_level": 2,
        # T1040: Network Sniffing — unencrypted transport exposes all shard data
        "mitre_attack": ["T1040"],
        # D3-ET: Encrypted Tunnels — transport TLS protects inter-node replication
        "mitre_d3fend": ["D3-ET"],
    },

    "ES-ENC-003": {
        # Cipher suites and TLS protocols
        # 800-53: SC-8, SC-23 → 800-171: 3.13.8
        "nist_800_171": ["3.13.8"],
        "cmmc_level": 2,
        # T1557.001: LLMNR/NBT-NS Poisoning — weak ciphers enable downgrade to breakable encryption
        "mitre_attack": ["T1040", "T1557"],
        # D3-ET: Encrypted Tunnels — strong cipher selection
        # D3-MH: Message Hardening
        "mitre_d3fend": ["D3-ET", "D3-MH"],
    },

    "ES-ENC-004": {
        # Certificate verification mode
        # 800-53: SC-8, IA-3 → 800-171: 3.13.8, 3.5.2
        "nist_800_171": ["3.13.8", "3.5.2"],
        "cmmc_level": 2,
        # T1557: Adversary-in-the-Middle — disabled cert verification allows MITM
        "mitre_attack": ["T1557"],
        # D3-ET: Encrypted Tunnels — cert validation prevents MITM
        "mitre_d3fend": ["D3-ET"],
    },

    "ES-ENC-005": {
        # Encryption at rest
        # 800-53: SC-28 → 800-171: 3.13.16 (protect CUI at rest)
        # CMMC L2: 3.13.16 is Level 2
        "nist_800_171": ["3.13.16"],
        "cmmc_level": 2,
        # T1530: Data from Cloud Storage — unencrypted storage exposed if physical access obtained
        # T1005: Data from Local System — data files accessible without going through ES API
        "mitre_attack": ["T1530", "T1005"],
        # D3-DAP: Data At Rest Protection — disk encryption
        "mitre_d3fend": ["D3-DAP"],
    },

    # ------------------------------------------------------------------ #
    # Section 3 – Network Security (ES-NET-*)
    # ------------------------------------------------------------------ #

    "ES-NET-001": {
        # network.host binding
        # 800-53: SC-7, CM-7 → 800-171: 3.13.1 (monitor/control communications at boundaries), 3.4.6
        # CMMC L1: 3.13.1 is Level 1
        "nist_800_171": ["3.13.1", "3.13.5", "3.4.6"],
        "cmmc_level": 1,
        # T1190: Exploit Public-Facing Application — broad binding exposes ES to untrusted networks
        # T1133: External Remote Services — 0.0.0.0 makes ES an external-facing service
        "mitre_attack": ["T1190", "T1133"],
        # D3-NI: Network Isolation — restrict to internal interfaces
        # D3-NTF: Network Traffic Filtering
        "mitre_d3fend": ["D3-NI", "D3-NTF"],
    },

    "ES-NET-002": {
        # HTTP port (advisory)
        # 800-53: CM-7 → 800-171: 3.4.6 (least functionality)
        "nist_800_171": ["3.4.6"],
        "cmmc_level": 2,
        # T1046: Network Service Discovery — default ports are scanned first
        "mitre_attack": ["T1046"],
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ACH"],
    },

    "ES-NET-003": {
        # Transport port (advisory)
        # 800-53: CM-7 → 800-171: 3.4.6
        "nist_800_171": ["3.4.6"],
        "cmmc_level": 2,
        "mitre_attack": ["T1046"],
        "mitre_d3fend": ["D3-ACH"],
    },

    "ES-NET-004": {
        # CORS configuration
        # 800-53: SC-7, SI-10 → 800-171: 3.13.1
        "nist_800_171": ["3.13.1"],
        "cmmc_level": 2,
        # T1185: Browser Session Hijacking — wildcard CORS enables cross-site request forgery
        # T1059.007: JavaScript — malicious JavaScript can make cross-origin ES requests
        "mitre_attack": ["T1185"],
        # D3-NI: Network Isolation — CORS policy limits which origins can access the API
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-NI", "D3-ACH"],
    },

    # ------------------------------------------------------------------ #
    # Section 4 – Authorization (ES-AUTHZ-*)
    # ------------------------------------------------------------------ #

    "ES-AUTHZ-001": {
        # RBAC configuration
        # 800-53: AC-3, AC-6 → 800-171: 3.1.1, 3.1.2, 3.1.5
        # CMMC L1: 3.1.1, 3.1.2, 3.1.5 are all Level 1
        "nist_800_171": ["3.1.1", "3.1.2", "3.1.5"],
        "cmmc_level": 1,
        # T1078: Valid Accounts — overly permissive roles are a valid accounts risk
        # T1098: Account Manipulation — without RBAC, privilege manipulation is easier
        "mitre_attack": ["T1078", "T1098"],
        # D3-RBAC: Role-Based Access Control
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-RBAC", "D3-UAP"],
    },

    "ES-AUTHZ-002": {
        # Least privilege — wildcard permissions
        # 800-53: AC-6 → 800-171: 3.1.5 (employ least privilege)
        # CMMC L1: 3.1.5 is Level 1
        "nist_800_171": ["3.1.5", "3.1.6"],
        "cmmc_level": 1,
        # T1565: Data Manipulation — write access to all indices enables data tampering
        # T1485: Data Destruction — write+delete on all indices enables mass data deletion
        "mitre_attack": ["T1565", "T1485"],
        # D3-RBAC: Role-Based Access Control — scoped roles
        "mitre_d3fend": ["D3-RBAC"],
    },

    "ES-AUTHZ-003": {
        # Anonymous access
        # 800-53: AC-2, AC-14 → 800-171: 3.1.1, 3.1.2
        # CMMC L1: 3.1.1, 3.1.2 are Level 1
        "nist_800_171": ["3.1.1", "3.1.2"],
        "cmmc_level": 1,
        # T1078.001: Default Accounts — anonymous realm acts like a built-in open account
        # T1190: Exploit Public-Facing Application — anonymous ES is trivially exploitable
        "mitre_attack": ["T1078.001", "T1190"],
        # D3-UAP: User Account Permissions — disable anonymous user
        "mitre_d3fend": ["D3-UAP"],
    },

    "ES-AUTHZ-004": {
        # Field/document level security
        # 800-53: AC-3, AC-16 → 800-171: 3.1.2, 3.1.3
        "nist_800_171": ["3.1.2", "3.1.3"],
        "cmmc_level": 2,
        # T1530: Data from Cloud Storage — FLS/DLS limits data exposure per user
        "mitre_attack": ["T1530"],
        # D3-RBAC: Role-Based Access Control — field-level security is granular RBAC
        "mitre_d3fend": ["D3-RBAC"],
    },

    # ------------------------------------------------------------------ #
    # Section 5 – Logging & Auditing (ES-LOG-*)
    # ------------------------------------------------------------------ #

    "ES-LOG-001": {
        # Audit logging enabled
        # 800-53: AU-2, AU-12 → 800-171: 3.3.1 (create/retain audit records), 3.3.2 (trace user actions)
        # CMMC L2: 3.3.1, 3.3.2 are Level 2
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — audit logging disabled = detection evasion
        "mitre_attack": ["T1562.001"],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    "ES-LOG-002": {
        # Audit events coverage
        # 800-53: AU-2, AU-3 → 800-171: 3.3.1, 3.3.2
        "nist_800_171": ["3.3.1", "3.3.2"],
        "cmmc_level": 2,
        # T1562.001: Disable or Modify Tools — incomplete event list can hide attacks
        "mitre_attack": ["T1562.001"],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    "ES-LOG-003": {
        # HTTP access logging
        # 800-53: AU-12, AU-14 → 800-171: 3.3.1
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        "mitre_attack": ["T1562.001"],
        "mitre_d3fend": ["D3-ALCA"],
    },

    "ES-LOG-004": {
        # Slow query logging
        # 800-53: AU-12 → 800-171: 3.3.1
        "nist_800_171": ["3.3.1"],
        "cmmc_level": 2,
        # T1499: Endpoint Denial of Service — slow queries may indicate resource exhaustion attacks
        "mitre_attack": ["T1499"],
        # D3-ALCA: Application Log Audit
        "mitre_d3fend": ["D3-ALCA"],
    },

    # ------------------------------------------------------------------ #
    # Section 6 – Cluster Security (ES-CLUS-*)
    # ------------------------------------------------------------------ #

    "ES-CLUS-001": {
        # Cluster name not default
        # 800-53: CM-6, CM-7 → 800-171: 3.4.2 (security configuration settings)
        # CMMC L2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        # T1068: Exploitation for Privilege Escalation — rogue node joining cluster with default name
        "mitre_attack": ["T1136"],
        # D3-ACH: Application Configuration Hardening
        "mitre_d3fend": ["D3-ACH"],
    },

    "ES-CLUS-002": {
        # Node name configured
        # 800-53: CM-6 → 800-171: 3.4.2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        "mitre_attack": [],
        # D3-ALCA: Application Log Audit — named nodes enable log correlation
        "mitre_d3fend": ["D3-ALCA"],
    },

    "ES-CLUS-003": {
        # Discovery seed hosts
        # 800-53: SC-7, CM-7 → 800-171: 3.13.1, 3.4.6
        # CMMC L1: 3.13.1 is Level 1
        "nist_800_171": ["3.13.1", "3.4.6"],
        "cmmc_level": 1,
        # T1136: Create Account — rogue nodes joining via broadcast discovery
        "mitre_attack": ["T1133", "T1136"],
        # D3-NI: Network Isolation — restrict which nodes can participate in discovery
        "mitre_d3fend": ["D3-NI"],
    },

    "ES-CLUS-004": {
        # Shard allocation awareness
        # 800-53: CP-9, SC-6 → 800-171: 3.8.9 (protect backups at storage locations)
        "nist_800_171": ["3.8.9"],
        "cmmc_level": 2,
        # T1499: Endpoint Denial of Service — single-zone deployment vulnerable to zone failure
        "mitre_attack": ["T1499"],
        # D3-ACH: Application Configuration Hardening — topology-aware allocation
        "mitre_d3fend": ["D3-ACH"],
    },

    # ------------------------------------------------------------------ #
    # Section 7 – Container Runtime (ES-CONT-*)
    # ------------------------------------------------------------------ #

    "ES-CONT-001": {
        # Non-root user
        # 800-53: AC-6, CM-7 → 800-171: 3.1.5, 3.1.6, 3.4.6
        # CMMC L1: 3.1.5 is Level 1
        "nist_800_171": ["3.1.5", "3.1.6", "3.4.6"],
        "cmmc_level": 1,
        # T1611: Escape to Host — root in container enables escape via kernel vulnerabilities
        # T1068: Exploitation for Privilege Escalation — root amplifies exploit impact
        "mitre_attack": ["T1611", "T1068"],
        # D3-CH: Container Hardening
        # D3-UAP: User Account Permissions
        "mitre_d3fend": ["D3-CH", "D3-UAP"],
    },

    "ES-CONT-002": {
        # No privileged mode
        # 800-53: CM-6 → 800-171: 3.4.2
        "nist_800_171": ["3.4.2", "3.4.6"],
        "cmmc_level": 2,
        "mitre_attack": ["T1611"],
        "mitre_d3fend": ["D3-CH"],
    },

    "ES-CONT-003": {
        # Drop capabilities
        # 800-53: CM-6, CM-7 → 800-171: 3.4.6, 3.4.7
        "nist_800_171": ["3.4.6", "3.4.7"],
        "cmmc_level": 2,
        "mitre_attack": ["T1611"],
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "ES-CONT-004": {
        # Read-only root filesystem
        # 800-53: CM-6 → 800-171: 3.4.2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        # T1014: Rootkit — writable root FS enables rootkit installation
        "mitre_attack": ["T1611", "T1014"],
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "ES-CONT-005": {
        # Resource limits
        # 800-53: SC-6, SI-17 → 800-171: 3.4.2
        "nist_800_171": ["3.4.2"],
        "cmmc_level": 2,
        "mitre_attack": ["T1499"],
        "mitre_d3fend": ["D3-CH", "D3-PH"],
    },

    "ES-CONT-006": {
        # Host namespace sharing
        # 800-53: SC-4, SC-7, AC-6 → 800-171: 3.13.1, 3.1.3, 3.1.5
        "nist_800_171": ["3.13.1", "3.1.3", "3.1.5"],
        "cmmc_level": 2,
        "mitre_attack": ["T1611", "T1049"],
        "mitre_d3fend": ["D3-CH", "D3-NI"],
    },
}


def enrich(result) -> None:
    """Enrich a CheckResult in-place with NIST 800-171, CMMC, MITRE ATT&CK, and MITRE D3FEND data.

    Only sets values if the check_id is present in the map AND the field is currently empty.
    """
    data = FRAMEWORK_MAP.get(result.check_id)
    if not data:
        return
    if not result.nist_800_171:
        result.nist_800_171 = data.get("nist_800_171", [])
    if result.cmmc_level is None:
        result.cmmc_level = data.get("cmmc_level")
    if not result.mitre_attack:
        result.mitre_attack = data.get("mitre_attack", [])
    if not result.mitre_d3fend:
        result.mitre_d3fend = data.get("mitre_d3fend", [])


def enrich_all(results: list) -> list:
    """Enrich a list of CheckResult objects in-place; returns the same list."""
    for r in results:
        enrich(r)
    return results
