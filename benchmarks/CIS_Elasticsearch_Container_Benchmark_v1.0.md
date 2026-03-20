# CIS Elasticsearch Container Security Benchmark v1.0

**Status:** Draft — Community Review
**Published:** 2026-03-19
**Tool Reference:** elastic-stig-audit v1.0.0
**Applies To:** Elasticsearch 7.x, 8.x deployed in Docker containers and Kubernetes pods

---

## Disclaimer

This document is a **community-developed security benchmark** for containerized Elasticsearch deployments. It is **not an official CIS benchmark** but follows CIS Benchmark methodology. Controls are derived from:

- Official Elastic Security documentation
- CIS Docker Benchmark v1.6
- CIS Kubernetes Benchmark v1.8
- NIST SP 800-53 Rev 5 (Security Controls)
- NIST SP 800-190 (Container Security)
- DISA Application Security and Development STIG

Always validate controls against your organization's security policy and applicable regulatory requirements.

---

## Overview

This benchmark provides security configuration guidance for Elasticsearch instances deployed as containers. It covers seven control domains:

| Section | Domain | Controls |
|---------|--------|---------|
| 1 | Authentication | ES-AUTH-001 — ES-AUTH-005 |
| 2 | Encryption | ES-ENC-001 — ES-ENC-005 |
| 3 | Network Security | ES-NET-001 — ES-NET-004 |
| 4 | Authorization | ES-AUTHZ-001 — ES-AUTHZ-004 |
| 5 | Logging & Auditing | ES-LOG-001 — ES-LOG-004 |
| 6 | Cluster Security | ES-CLUS-001 — ES-CLUS-004 |
| 7 | Container Runtime | ES-CONT-001 — ES-CONT-006 |
| — | Vulnerability Management | ES-VER-001 |

**Total Controls:** 28 automated checks + 1 CVE/KEV scan

---

## Severity Definitions

| Level | Description |
|-------|-------------|
| **CRITICAL** | Immediately exploitable; enables unauthenticated data access or RCE |
| **HIGH** | Significantly increases attack surface or enables privilege escalation |
| **MEDIUM** | Reduces security posture; may enable data exposure under specific conditions |
| **LOW** | Minor hardening gap; defense-in-depth improvement |
| **INFO** | Informational; configuration documented for audit trail |

---

## Section 1: Authentication

### ES-AUTH-001 — Enable Elasticsearch Security Features (xpack.security)

**Severity:** CRITICAL
**CIS Control:** 1.1
**NIST 800-53:** AC-2, AC-3, IA-2
**NIST 800-171:** 3.1.2, 3.5.1, 3.5.2
**CMMC Level:** 1
**MITRE ATT&CK:** T1190, T1078
**MITRE D3FEND:** D3-ACH, D3-UAP

**Description:**
The `xpack.security` feature bundle must be enabled to enforce authentication, authorization, TLS, and audit logging. In Elasticsearch 8.x, security is enabled by default. In 7.x it must be explicitly configured.

**Assessment Procedure:**
```bash
# Check node settings
curl -u elastic:password https://localhost:9200/_nodes/_local/settings?flat_settings=true | \
  python3 -c "import sys,json; data=json.load(sys.stdin); nodes=data['nodes']; \
  settings=next(iter(nodes.values()))['settings']; \
  print(settings.get('xpack.security.enabled', 'NOT SET'))"
```

**Pass Condition:** `xpack.security.enabled=true` (explicit or implied by security API responding)

**Remediation:**
```yaml
# elasticsearch.yml
xpack.security.enabled: true
```

**References:**
- Elastic: Enable security features: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html

---

### ES-AUTH-002 — Secure Built-in 'elastic' Superuser Password

**Severity:** CRITICAL
**CIS Control:** 1.2
**NIST 800-53:** IA-5, AC-2
**NIST 800-171:** 3.5.7, 3.5.8, 3.5.3
**CMMC Level:** 1
**MITRE ATT&CK:** T1078.001, T1110.001
**MITRE D3FEND:** D3-SPP, D3-UAP

**Description:**
The built-in `elastic` superuser account must not use the default password (`changeme`). The `elastic` account has unrestricted access to all Elasticsearch APIs and data.

**Assessment Procedure:**
```bash
# Attempt login with default credentials (should FAIL in hardened environment)
curl -u elastic:changeme https://localhost:9200/ -o /dev/null -w "%{http_code}"
# Expected: 401 (not 200)
```

**Pass Condition:** `elastic` user exists, is enabled, and does not accept default password

**Remediation:**
```bash
# Change elastic user password
curl -u elastic:changeme -X POST https://localhost:9200/_security/user/elastic/_password \
  -H 'Content-Type: application/json' \
  -d '{"password": "$(openssl rand -base64 32)"}'
```

---

### ES-AUTH-003 — Configure Password Minimum Length Policy

**Severity:** MEDIUM
**CIS Control:** 1.3
**NIST 800-53:** IA-5
**NIST 800-171:** 3.5.7
**CMMC Level:** 1
**MITRE ATT&CK:** T1110
**MITRE D3FEND:** D3-SPP

**Description:**
The native realm password minimum length must be configured to at least 12 characters. The Elasticsearch default is 6 characters, which is insufficient for regulated environments.

**Assessment Procedure:**
```bash
curl -u elastic:password https://localhost:9200/_cluster/settings?include_defaults=true | \
  python3 -c "import sys,json; data=json.load(sys.stdin); \
  all_settings = {**data.get('defaults',{}), **data.get('persistent',{})}; \
  print(all_settings.get('xpack.security.authc.native.minimum_password_length', 'NOT SET'))"
```

**Pass Condition:** `minimum_password_length >= 12`

**Remediation:**
```bash
curl -X PUT -u elastic:password https://localhost:9200/_cluster/settings \
  -H 'Content-Type: application/json' \
  -d '{"persistent": {"xpack.security.authc.native.minimum_password_length": 12}}'
```

---

### ES-AUTH-004 — Enable API Key Authentication Service

**Severity:** MEDIUM
**CIS Control:** 1.4
**NIST 800-53:** IA-2, AC-3
**NIST 800-171:** 3.5.1, 3.1.2
**CMMC Level:** 1
**MITRE ATT&CK:** T1078
**MITRE D3FEND:** D3-UAP

**Description:**
The API key service must be enabled for secure programmatic access. API keys can be scoped, rotated, and revoked independently of user accounts.

**Pass Condition:** API key service is enabled (default in ES 7.9+ with security on)

**Remediation:**
Do not explicitly set `xpack.security.authc.api_key.enabled: false`. Default is enabled when security is active.

---

### ES-AUTH-005 — Configure Authentication Realm Explicitly

**Severity:** MEDIUM
**CIS Control:** 1.5
**NIST 800-53:** IA-2, IA-8
**NIST 800-171:** 3.5.1, 3.5.2
**CMMC Level:** 1
**MITRE ATT&CK:** T1078
**MITRE D3FEND:** D3-UAP

**Description:**
Authentication realms must be explicitly configured. Native realm is the minimum; LDAP or SAML is recommended for enterprise environments to enable central identity management and MFA.

**Pass Condition:** At least one realm configured (native, LDAP, SAML, PKI, or Kerberos)

**Remediation:**
```yaml
# elasticsearch.yml — LDAP example
xpack.security.authc.realms.ldap.ldap1:
  url: "ldaps://ldap.example.com:636"
  bind_dn: "cn=elasticsearch,ou=service,dc=example,dc=com"
  user_search.base_dn: "ou=users,dc=example,dc=com"
  group_search.base_dn: "ou=groups,dc=example,dc=com"
```

---

## Section 2: Encryption

### ES-ENC-001 — Enable TLS for HTTP (REST API) Layer

**Severity:** HIGH
**CIS Control:** 2.1
**NIST 800-53:** SC-8, SC-28
**NIST 800-171:** 3.13.8
**CMMC Level:** 2
**MITRE ATT&CK:** T1040, T1557
**MITRE D3FEND:** D3-ET, D3-MH

**Description:**
All HTTP REST API traffic must be encrypted with TLS. This protects authentication credentials and data from network interception.

**Assessment Procedure:**
```bash
# Check if HTTPS is required (plaintext should fail)
curl http://localhost:9200/ -o /dev/null -w "%{http_code}"
# Expected: connection refused or 400 (if TLS-only)
```

**Pass Condition:** `xpack.security.http.ssl.enabled=true`

**Remediation:**
```yaml
# elasticsearch.yml
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12
```

```bash
# Generate certificates
elasticsearch-certutil http
```

---

### ES-ENC-002 — Enable TLS for Transport (Node-to-Node) Layer

**Severity:** HIGH
**CIS Control:** 2.2
**NIST 800-53:** SC-8, SC-7
**NIST 800-171:** 3.13.8, 3.13.1
**CMMC Level:** 2
**MITRE ATT&CK:** T1040
**MITRE D3FEND:** D3-ET

**Description:**
Inter-node transport communication must be encrypted to prevent cluster data interception and unauthorized node joining.

**Pass Condition:** `xpack.security.transport.ssl.enabled=true`

**Remediation:**
```yaml
# elasticsearch.yml
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/elastic-certificates.p12
```

```bash
# Generate CA and node certificates
elasticsearch-certutil ca
elasticsearch-certutil cert --ca elastic-stack-ca.p12
```

---

### ES-ENC-003 — Restrict Cipher Suites to Strong Algorithms

**Severity:** HIGH
**CIS Control:** 2.3
**NIST 800-53:** SC-8, SC-23
**NIST 800-171:** 3.13.8
**CMMC Level:** 2
**MITRE ATT&CK:** T1040, T1557
**MITRE D3FEND:** D3-ET, D3-MH

**Description:**
TLS configuration must explicitly restrict cipher suites and protocols. RC4, 3DES, SSLv3, TLSv1.0, and TLSv1.1 must be disabled.

**Pass Condition:** Only TLSv1.2 and TLSv1.3 enabled; no weak ciphers configured

**Remediation:**
```yaml
# elasticsearch.yml
xpack.security.http.ssl.supported_protocols: ["TLSv1.2", "TLSv1.3"]
xpack.security.transport.ssl.supported_protocols: ["TLSv1.2", "TLSv1.3"]
xpack.security.http.ssl.cipher_suites:
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```

---

### ES-ENC-004 — Require Certificate Verification

**Severity:** HIGH
**CIS Control:** 2.4
**NIST 800-53:** SC-8, IA-3
**NIST 800-171:** 3.13.8, 3.5.2
**CMMC Level:** 2
**MITRE ATT&CK:** T1557
**MITRE D3FEND:** D3-ET

**Description:**
SSL certificate verification must not be disabled (`verification_mode: none`). This setting is sometimes set for convenience during development but is catastrophic in production.

**Pass Condition:** `verification_mode` is `full` or `certificate`; not `none`

**Remediation:**
```yaml
# elasticsearch.yml
xpack.security.http.ssl.verification_mode: full
xpack.security.transport.ssl.verification_mode: full
```

---

### ES-ENC-005 — Protect Data at Rest with Encryption

**Severity:** MEDIUM
**CIS Control:** 2.5
**NIST 800-53:** SC-28
**NIST 800-171:** 3.13.16
**CMMC Level:** 2
**MITRE ATT&CK:** T1530, T1005
**MITRE D3FEND:** D3-DAP

**Description:**
Elasticsearch data directories must be protected by OS-level disk encryption. Elasticsearch does not provide native transparent disk encryption.

**Pass Condition:** Data volume protected by LUKS, BitLocker, AWS EBS encryption, or equivalent (manual verification required)

**Remediation:**
```bash
# Linux (LUKS)
cryptsetup luksFormat /dev/sdb
cryptsetup open /dev/sdb es-data
mkfs.ext4 /dev/mapper/es-data
mount /dev/mapper/es-data /usr/share/elasticsearch/data

# Kubernetes (AWS EBS with KMS)
# Use encrypted StorageClass:
# apiVersion: storage.k8s.io/v1
# kind: StorageClass
# metadata:
#   name: encrypted-gp3
# parameters:
#   encrypted: "true"
#   kmsKeyId: arn:aws:kms:us-east-1:ACCOUNT:key/KEY-ID
```

---

## Section 3: Network Security

### ES-NET-001 — Restrict Network Binding (Prevent 0.0.0.0)

**Severity:** HIGH
**CIS Control:** 3.1
**NIST 800-53:** SC-7, CM-7
**NIST 800-171:** 3.13.1, 3.13.5, 3.4.6
**CMMC Level:** 1
**MITRE ATT&CK:** T1190, T1133
**MITRE D3FEND:** D3-NI, D3-NTF

**Description:**
`network.host` must not be set to `0.0.0.0` or `_all_`. Binding to all interfaces exposes Elasticsearch to any network reachable by the host.

**Assessment Procedure:**
```bash
curl -u elastic:password https://localhost:9200/_nodes/_local/settings?flat_settings=true | \
  python3 -c "import sys,json; data=json.load(sys.stdin); \
  nodes=data['nodes']; s=next(iter(nodes.values()))['settings']; \
  print(s.get('network.host', 'NOT SET'))"
```

**Pass Condition:** `network.host` not equal to `0.0.0.0`, `_all_`, or `_site_`

**Remediation:**
```yaml
# elasticsearch.yml
network.host: 10.0.0.5  # or specific internal IP
# For multi-interface:
network.bind_host: 127.0.0.1
network.publish_host: 10.0.0.5
```

---

### ES-NET-002 — Change Default HTTP Port (Advisory)

**Severity:** LOW
**CIS Control:** 3.2
**NIST 800-53:** CM-7
**NIST 800-171:** 3.4.6
**CMMC Level:** 2

**Description:**
Changing the HTTP port from 9200 to a non-default value reduces exposure to automated scanning. This is a defense-in-depth advisory control.

**Remediation:**
```yaml
http.port: 9243
```

---

### ES-NET-003 — Change Default Transport Port (Advisory)

**Severity:** LOW
**CIS Control:** 3.3
**NIST 800-53:** CM-7
**NIST 800-171:** 3.4.6
**CMMC Level:** 2

**Description:**
Changing the transport port from 9300 reduces automated discovery of cluster nodes.

**Remediation:**
```yaml
transport.port: 9301
```

---

### ES-NET-004 — Disable or Restrict CORS

**Severity:** MEDIUM
**CIS Control:** 3.4
**NIST 800-53:** SC-7, SI-10
**NIST 800-171:** 3.13.1
**CMMC Level:** 2
**MITRE ATT&CK:** T1185
**MITRE D3FEND:** D3-NI, D3-ACH

**Description:**
CORS must be disabled or configured with a strict origin allowlist. A wildcard (`*`) `allow-origin` allows any web page to make requests using the user's browser credentials.

**Pass Condition:** `http.cors.enabled=false` OR `allow-origin` set to specific trusted origins (not `*`)

**Remediation:**
```yaml
# elasticsearch.yml — disable CORS
http.cors.enabled: false

# Or if required for Kibana:
http.cors.enabled: true
http.cors.allow-origin: "https://kibana.example.com"
http.cors.allow-headers: "X-Requested-With,Content-Type,Content-Length,Authorization"
# NEVER: http.cors.allow-origin: "*"
```

---

## Section 4: Authorization

### ES-AUTHZ-001 — Configure RBAC with Custom Roles

**Severity:** HIGH
**CIS Control:** 4.1
**NIST 800-53:** AC-3, AC-6
**NIST 800-171:** 3.1.1, 3.1.2, 3.1.5
**CMMC Level:** 1
**MITRE ATT&CK:** T1078, T1098
**MITRE D3FEND:** D3-RBAC, D3-UAP

**Description:**
Custom RBAC roles must be defined for application accounts. Relying solely on the built-in `superuser` role for application access is a critical misconfiguration.

**Assessment Procedure:**
```bash
curl -u elastic:password https://localhost:9200/_security/role | \
  python3 -c "import sys,json; roles=json.load(sys.stdin); print(f'{len(roles)} roles defined')"
```

**Remediation:**
```bash
# Create least-privilege read role
curl -X POST -u elastic:password https://localhost:9200/_security/role/app_reader \
  -H 'Content-Type: application/json' \
  -d '{
    "indices": [{
      "names": ["app-logs-*"],
      "privileges": ["read", "view_index_metadata"]
    }]
  }'
```

---

### ES-AUTHZ-002 — Enforce Least Privilege (No Wildcard Permissions)

**Severity:** HIGH
**CIS Control:** 4.2
**NIST 800-53:** AC-6
**NIST 800-171:** 3.1.5, 3.1.6
**CMMC Level:** 1
**MITRE ATT&CK:** T1565, T1485
**MITRE D3FEND:** D3-RBAC

**Description:**
No role (except `superuser`) should grant write/delete permissions to all indices (`*`). Wildcard write access means a compromised account can corrupt any data.

**Pass Condition:** No application roles with `indices: [{names: ['*'], privileges: ['all', 'write', 'delete']}]`

---

### ES-AUTHZ-003 — Disable Anonymous Access

**Severity:** CRITICAL
**CIS Control:** 4.3
**NIST 800-53:** AC-2, AC-14
**NIST 800-171:** 3.1.1, 3.1.2
**CMMC Level:** 1
**MITRE ATT&CK:** T1078.001, T1190
**MITRE D3FEND:** D3-UAP

**Description:**
Anonymous access allows unauthenticated requests to be processed as a configured user. This completely bypasses authentication.

**Pass Condition:** `xpack.security.authc.anonymous.username` and `anonymous.roles` not configured

**Remediation:**
```yaml
# Ensure these are NOT in elasticsearch.yml:
# xpack.security.authc.anonymous.username: anonymous_user
# xpack.security.authc.anonymous.roles: [viewer]
```

---

### ES-AUTHZ-004 — Implement Field/Document Level Security Where Needed

**Severity:** MEDIUM
**CIS Control:** 4.4
**NIST 800-53:** AC-3, AC-16
**NIST 800-171:** 3.1.2, 3.1.3
**CMMC Level:** 2
**MITRE ATT&CK:** T1530
**MITRE D3FEND:** D3-RBAC

**Description:**
For indices containing mixed-sensitivity data, field-level security (FLS) and document-level security (DLS) should restrict access to sensitive fields and documents. Requires Platinum or Enterprise license.

**Remediation:**
```bash
curl -X POST -u elastic:password https://localhost:9200/_security/role/restricted_reader \
  -H 'Content-Type: application/json' \
  -d '{
    "indices": [{
      "names": ["sensitive-*"],
      "privileges": ["read"],
      "field_security": {"grant": ["public_*"], "except": ["ssn", "dob", "credit_card"]},
      "query": "{\"term\": {\"tenant_id\": \"{{_user.username}}\"}}"
    }]
  }'
```

---

## Section 5: Logging & Auditing

### ES-LOG-001 — Enable Security Audit Logging

**Severity:** HIGH
**CIS Control:** 5.1
**NIST 800-53:** AU-2, AU-12
**NIST 800-171:** 3.3.1, 3.3.2
**CMMC Level:** 2
**MITRE ATT&CK:** T1562.001
**MITRE D3FEND:** D3-ALCA

**Description:**
`xpack.security.audit.enabled` must be set to `true`. Audit logging records authentication events, access decisions, and REST/transport API calls.

**Pass Condition:** `xpack.security.audit.enabled=true`

**Remediation:**
```yaml
# elasticsearch.yml
xpack.security.audit.enabled: true
xpack.security.audit.logfile.events.include:
  - authentication_success
  - authentication_failed
  - access_denied
  - connection_denied
  - run_as_denied
  - anonymous_access_denied
```

---

### ES-LOG-002 — Capture Required Audit Events

**Severity:** MEDIUM
**CIS Control:** 5.2
**NIST 800-53:** AU-2, AU-3
**NIST 800-171:** 3.3.1, 3.3.2
**CMMC Level:** 2

**Description:**
Audit events must include at minimum: `authentication_success`, `authentication_failed`, `access_denied`, and `connection_denied`. Critical events must not be in the exclude list.

---

### ES-LOG-003 — Configure HTTP Access Logging

**Severity:** MEDIUM
**CIS Control:** 5.3
**NIST 800-53:** AU-12, AU-14
**NIST 800-171:** 3.3.1
**CMMC Level:** 2

**Description:**
HTTP access logging via the `HttpTracer` logger should be enabled to record all REST API requests.

**Remediation:**
```bash
# Enable dynamically
curl -X PUT -u elastic:password https://localhost:9200/_cluster/settings \
  -H 'Content-Type: application/json' \
  -d '{"transient": {"logger.org.elasticsearch.http.HttpTracer": "TRACE"}}'
```

---

### ES-LOG-004 — Configure Slow Query Logging

**Severity:** LOW
**CIS Control:** 5.4
**NIST 800-53:** AU-12
**NIST 800-171:** 3.3.1
**CMMC Level:** 2

**Description:**
Slowlog should be configured to detect expensive or abusive queries.

**Remediation:**
```bash
curl -X PUT -u elastic:password https://localhost:9200/my-index/_settings \
  -H 'Content-Type: application/json' \
  -d '{
    "index.search.slowlog.threshold.query.warn": "10s",
    "index.search.slowlog.threshold.query.info": "5s",
    "index.indexing.slowlog.threshold.index.warn": "10s"
  }'
```

---

## Section 6: Cluster Security

### ES-CLUS-001 — Change Default Cluster Name

**Severity:** MEDIUM
**CIS Control:** 6.1
**NIST 800-53:** CM-7, CM-6
**NIST 800-171:** 3.4.2
**CMMC Level:** 2

**Description:**
`cluster.name` must be changed from the default `elasticsearch` to a unique value. Nodes with matching cluster names join automatically.

**Pass Condition:** `cluster.name` ≠ `elasticsearch`

**Remediation:**
```yaml
cluster.name: prod-search-cluster
```

---

### ES-CLUS-002 — Configure Explicit Node Names

**Severity:** LOW
**CIS Control:** 6.2
**NIST 800-53:** CM-6
**NIST 800-171:** 3.4.2
**CMMC Level:** 2

**Description:**
`node.name` should be explicitly set to enable log correlation and incident response.

**Remediation:**
```yaml
node.name: prod-es-node-01
```

---

### ES-CLUS-003 — Secure Discovery with Explicit Seed Hosts

**Severity:** MEDIUM
**CIS Control:** 6.3
**NIST 800-53:** SC-7, CM-7
**NIST 800-171:** 3.13.1, 3.4.6
**CMMC Level:** 1

**Description:**
`discovery.seed_hosts` must be explicitly configured. Broadcast discovery can allow unauthorized nodes to join the cluster.

**Remediation:**
```yaml
discovery.seed_hosts:
  - es-node-01.internal:9300
  - es-node-02.internal:9300
  - es-node-03.internal:9300
cluster.initial_master_nodes:
  - es-node-01
  - es-node-02
  - es-node-03
```

---

### ES-CLUS-004 — Configure Shard Allocation Awareness

**Severity:** LOW
**CIS Control:** 6.4
**NIST 800-53:** CP-9, SC-6
**NIST 800-171:** 3.8.9
**CMMC Level:** 2

**Description:**
Allocation awareness should be configured for multi-zone deployments to prevent primary and replica shards from being co-located in the same availability zone.

**Remediation:**
```yaml
node.attr.zone: us-east-1a
cluster.routing.allocation.awareness.attributes: zone
cluster.routing.allocation.awareness.force.zone.values: us-east-1a,us-east-1b,us-east-1c
```

---

## Section 7: Container Runtime Security

### ES-CONT-001 — Run as Non-Root User

**Severity:** HIGH
**CIS Control:** 7.1
**NIST 800-53:** AC-6, CM-7
**NIST 800-171:** 3.1.5, 3.1.6, 3.4.6
**CMMC Level:** 1
**MITRE ATT&CK:** T1611, T1068
**MITRE D3FEND:** D3-CH, D3-UAP

**Description:**
The Elasticsearch container must run as the `elasticsearch` user (UID 1000). The official Docker image uses this by default but may be overridden.

**Remediation:**
```yaml
# Kubernetes securityContext
securityContext:
  runAsUser: 1000
  runAsNonRoot: true
  runAsGroup: 1000
```

---

### ES-CONT-002 — Disable Privileged Mode

**Severity:** CRITICAL
**CIS Control:** 7.2
**NIST 800-53:** CM-7, AC-6
**NIST 800-171:** 3.4.2, 3.4.6
**CMMC Level:** 2

**Note:** Elasticsearch requires `vm.max_map_count=262144` on the host. This should be set via a privileged `initContainer` or node configuration tool — not by making the main Elasticsearch container privileged.

**Remediation:**
```yaml
initContainers:
  - name: configure-sysctl
    image: busybox
    securityContext:
      privileged: true  # Only the init container
    command: ['sysctl', '-w', 'vm.max_map_count=262144']
containers:
  - name: elasticsearch
    securityContext:
      privileged: false  # Main container is NOT privileged
```

---

### ES-CONT-003 — Drop All Linux Capabilities

**Severity:** HIGH
**CIS Control:** 7.3
**NIST 800-53:** CM-7, AC-6
**NIST 800-171:** 3.4.6, 3.4.7
**CMMC Level:** 2

**Remediation:**
```yaml
securityContext:
  capabilities:
    drop: [ALL]
    add: []  # Elasticsearch requires no added capabilities
```

---

### ES-CONT-004 — Use Read-Only Root Filesystem

**Severity:** MEDIUM
**CIS Control:** 7.4
**NIST 800-53:** CM-7, SC-28
**NIST 800-171:** 3.4.2
**CMMC Level:** 2

**Remediation:**
```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
  - name: es-data
    mountPath: /usr/share/elasticsearch/data
  - name: es-logs
    mountPath: /usr/share/elasticsearch/logs
  - name: es-tmp
    mountPath: /tmp
```

---

### ES-CONT-005 — Set Memory and CPU Resource Limits

**Severity:** HIGH
**CIS Control:** 7.5
**NIST 800-53:** SC-6, SI-17
**NIST 800-171:** 3.4.2
**CMMC Level:** 2

**Remediation:**
```yaml
resources:
  requests:
    memory: 4Gi
    cpu: 1000m
  limits:
    memory: 8Gi   # 2× JVM heap (-Xmx4g)
    cpu: 4000m
env:
  - name: ES_JAVA_OPTS
    value: "-Xms4g -Xmx4g"
```

---

### ES-CONT-006 — Disable Host Namespace Sharing

**Severity:** HIGH
**CIS Control:** 7.6
**NIST 800-53:** SC-4, SC-7, AC-6
**NIST 800-171:** 3.13.1, 3.1.3, 3.1.5
**CMMC Level:** 2

**Remediation:**
```yaml
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
```

---

## Vulnerability Management

### ES-VER-001 — No Known CVEs (NVD/KEV Scan)

**Severity:** CRITICAL/HIGH/MEDIUM (based on CVSS)
**NIST 800-53:** SI-2, RA-5
**NIST 800-171:** 3.14.1
**CMMC Level:** 2

**Description:**
The installed Elasticsearch version is checked against the NVD CVE database and CISA Known Exploited Vulnerabilities (KEV) catalog.

**Assessment Procedure:**
Automated via `elastic-stig-audit`'s CVE scanner module (see `docs/CVE_SCANNING.md`)

**Pass Condition:** No known CVEs for the detected version

**Remediation:** Upgrade to the latest stable Elasticsearch version. Monitor CISA KEV for urgent patches.

---

## Appendix A: Control Summary Matrix

| Control ID | Title | Severity | CMMC | NIST 800-171 | Auto |
|------------|-------|----------|------|--------------|------|
| ES-AUTH-001 | xpack.security enabled | CRITICAL | L1 | 3.1.2, 3.5.1 | ✓ |
| ES-AUTH-002 | Elastic user password | CRITICAL | L1 | 3.5.7, 3.5.8 | ✓ |
| ES-AUTH-003 | Password length policy | MEDIUM | L1 | 3.5.7 | ✓ |
| ES-AUTH-004 | API key service | MEDIUM | L1 | 3.5.1 | ✓ |
| ES-AUTH-005 | Realm configuration | MEDIUM | L1 | 3.5.1, 3.5.2 | ✓ |
| ES-ENC-001 | HTTP TLS | HIGH | L2 | 3.13.8 | ✓ |
| ES-ENC-002 | Transport TLS | HIGH | L2 | 3.13.8, 3.13.1 | ✓ |
| ES-ENC-003 | Cipher suites | HIGH | L2 | 3.13.8 | ✓ |
| ES-ENC-004 | Cert verification | HIGH | L2 | 3.13.8 | ✓ |
| ES-ENC-005 | Encryption at rest | MEDIUM | L2 | 3.13.16 | Partial |
| ES-NET-001 | Network binding | HIGH | L1 | 3.13.1, 3.13.5 | ✓ |
| ES-NET-002 | HTTP port | LOW | L2 | 3.4.6 | ✓ |
| ES-NET-003 | Transport port | LOW | L2 | 3.4.6 | ✓ |
| ES-NET-004 | CORS | MEDIUM | L2 | 3.13.1 | ✓ |
| ES-AUTHZ-001 | RBAC roles | HIGH | L1 | 3.1.1, 3.1.5 | ✓ |
| ES-AUTHZ-002 | Least privilege | HIGH | L1 | 3.1.5, 3.1.6 | ✓ |
| ES-AUTHZ-003 | Anonymous access | CRITICAL | L1 | 3.1.1, 3.1.2 | ✓ |
| ES-AUTHZ-004 | FLS/DLS | MEDIUM | L2 | 3.1.2, 3.1.3 | ✓ |
| ES-LOG-001 | Audit logging | HIGH | L2 | 3.3.1, 3.3.2 | ✓ |
| ES-LOG-002 | Audit events | MEDIUM | L2 | 3.3.1, 3.3.2 | ✓ |
| ES-LOG-003 | Access logging | MEDIUM | L2 | 3.3.1 | ✓ |
| ES-LOG-004 | Slow query log | LOW | L2 | 3.3.1 | ✓ |
| ES-CLUS-001 | Cluster name | MEDIUM | L2 | 3.4.2 | ✓ |
| ES-CLUS-002 | Node name | LOW | L2 | 3.4.2 | ✓ |
| ES-CLUS-003 | Discovery hosts | MEDIUM | L1 | 3.13.1 | ✓ |
| ES-CLUS-004 | Shard allocation | LOW | L2 | 3.8.9 | ✓ |
| ES-CONT-001 | Non-root user | HIGH | L1 | 3.1.5, 3.1.6 | ✓ |
| ES-CONT-002 | No privileged | CRITICAL | L2 | 3.4.2 | ✓ |
| ES-CONT-003 | Drop capabilities | HIGH | L2 | 3.4.6, 3.4.7 | ✓ |
| ES-CONT-004 | Read-only rootfs | MEDIUM | L2 | 3.4.2 | ✓ |
| ES-CONT-005 | Resource limits | HIGH | L2 | 3.4.2 | ✓ |
| ES-CONT-006 | Host namespaces | HIGH | L2 | 3.13.1, 3.1.5 | ✓ |
| ES-VER-001 | CVE/KEV scan | CRITICAL/HIGH | L2 | 3.14.1 | ✓ |

---

*This benchmark is maintained as part of the [audit-forge](https://github.com/audit-forge) project.*
