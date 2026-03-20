"""Container-level security checks for Elasticsearch (docker/kubectl modes only).

Controls:
  ES-CONT-001 — Non-root user (elasticsearch uid, not root)
  ES-CONT-002 — No privileged mode
  ES-CONT-003 — Minimal capabilities (drop ALL)
  ES-CONT-004 — Read-only root filesystem where possible
  ES-CONT-005 — Resource limits set (CPU/memory)
  ES-CONT-006 — No host namespace sharing (hostNetwork/hostPID/hostIPC)

All checks emit SKIP status when running in --mode direct.

References:
  CIS Docker Benchmark v1.6 §4, §5
  CIS Kubernetes Benchmark v1.8 §5.2
  NIST SP 800-190 Application Container Security Guide
"""
from .base import BaseChecker, CheckResult, Severity, Status

_DANGEROUS_CAPS = frozenset({
    "ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "NET_RAW",
    "SYS_RAWIO",
    "MKNOD",
    "AUDIT_CONTROL",
    "SYS_BOOT",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
})

_CONTAINER_CHECKS = [
    ("ES-CONT-001", "Verify Elasticsearch process runs as a non-root user"),
    ("ES-CONT-002", "Verify Elasticsearch container does not run in privileged mode"),
    ("ES-CONT-003", "Verify dangerous Linux capabilities are not granted to the Elasticsearch container"),
    ("ES-CONT-004", "Verify Elasticsearch container root filesystem is mounted read-only"),
    ("ES-CONT-005", "Verify Elasticsearch container has memory and CPU resource limits configured"),
    ("ES-CONT-006", "Verify Elasticsearch container does not share host network, PID, or IPC namespaces"),
]


class ElasticsearchContainerChecker(BaseChecker):
    """Assess container-level security controls (docker/kubectl modes only)."""

    def run(self) -> list[CheckResult]:
        mode = getattr(self.runner, "mode", "direct")

        if mode == "direct":
            return self._all_skipped()

        if mode == "docker":
            ctx = self._normalize_docker()
        elif mode == "kubectl":
            ctx = self._normalize_kubectl()
        else:
            return self._all_skipped()

        if ctx is None:
            return self._all_error(mode)

        return [
            self._check_nonroot(ctx),
            self._check_privileged(ctx),
            self._check_caps(ctx),
            self._check_readonly_rootfs(ctx),
            self._check_resource_limits(ctx),
            self._check_host_namespaces(ctx),
        ]

    # ------------------------------------------------------------------
    # Context normalizers
    # ------------------------------------------------------------------

    def _normalize_docker(self):
        data = self.runner.container_inspect()
        if not data:
            return None
        hc = data.get("HostConfig", {})
        cfg = data.get("Config", {})
        inspect_cmd = f"docker inspect {self.runner.container or '<container>'}"
        return {
            "source": "docker",
            "inspect_cmd": inspect_cmd,
            "user": (cfg.get("User") or "").strip(),
            "run_as_non_root": None,
            "allow_privilege_escalation": None,
            "privileged": bool(hc.get("Privileged", False)),
            "cap_add": [c.upper() for c in (hc.get("CapAdd") or [])],
            "cap_drop": [c.upper() for c in (hc.get("CapDrop") or [])],
            "read_only_rootfs": bool(hc.get("ReadonlyRootfs", False)),
            "memory_limit_set": int(hc.get("Memory", 0)) > 0,
            "cpu_limit_set": int(hc.get("NanoCpus", 0)) > 0,
            "host_network": hc.get("NetworkMode", "") == "host",
            "host_pid": hc.get("PidMode", "") == "host",
            "host_ipc": hc.get("IpcMode", "private") == "host",
            "raw": data,
        }

    def _normalize_kubectl(self):
        data = self.runner.pod_inspect()
        if not data:
            return None
        spec = data.get("spec", {})
        pod_sc = spec.get("securityContext", {})

        containers = spec.get("containers", [])
        # Prefer container with "elastic" or "elasticsearch" in name
        ctr = next(
            (c for c in containers if any(k in c.get("name", "").lower() for k in ("elastic", "es-"))),
            containers[0] if containers else {},
        )
        sc = ctr.get("securityContext", {})
        caps = sc.get("capabilities", {})
        limits = ctr.get("resources", {}).get("limits", {})

        run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
        run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot", False))
        inspect_cmd = (
            f"kubectl get pod -n {self.runner.namespace} {self.runner.pod or '<pod>'} -o json"
        )
        return {
            "source": "kubectl",
            "inspect_cmd": inspect_cmd,
            "user": str(run_as_user) if run_as_user is not None else "",
            "run_as_non_root": run_as_non_root,
            "allow_privilege_escalation": sc.get("allowPrivilegeEscalation"),
            "privileged": bool(sc.get("privileged", False)),
            "cap_add": [c.upper() for c in (caps.get("add") or [])],
            "cap_drop": [c.upper() for c in (caps.get("drop") or [])],
            "read_only_rootfs": bool(sc.get("readOnlyRootFilesystem", False)),
            "memory_limit_set": bool(limits.get("memory")),
            "cpu_limit_set": bool(limits.get("cpu")),
            "host_network": bool(spec.get("hostNetwork", False)),
            "host_pid": bool(spec.get("hostPID", False)),
            "host_ipc": bool(spec.get("hostIPC", False)),
            "raw": data,
        }

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_nonroot(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        user = ctx.get("user", "")
        run_as_non_root = ctx.get("run_as_non_root")

        if src == "docker":
            is_nonroot = bool(user) and user not in ("0", "root")
            actual = f"User={user!r}" if user else "User not set (defaults to root)"
        else:
            run_as_user_int = int(user) if user.isdigit() else None
            is_nonroot = bool(run_as_non_root) or (
                run_as_user_int is not None and run_as_user_int > 0
            )
            parts = []
            if user:
                parts.append(f"runAsUser={user}")
            if run_as_non_root is not None:
                parts.append(f"runAsNonRoot={run_as_non_root}")
            actual = ", ".join(parts) if parts else "runAsUser/runAsNonRoot not set"

        return CheckResult(
            check_id="ES-CONT-001",
            title="Verify Elasticsearch process runs as a non-root user",
            status=Status.PASS if is_nonroot else Status.FAIL,
            severity=Severity.HIGH,
            benchmark_control_id="7.1",
            cis_id="CIS-ES-7.1",
            fedramp_control="AC-6",
            nist_800_53_controls=["AC-6", "CM-7"],
            description=(
                "The Elasticsearch container must run as a non-root user. "
                "The official image uses UID 1000 (elasticsearch) by default."
            ),
            rationale=(
                "Running as root inside a container provides a privilege escalation path "
                "to the host if container isolation is bypassed. Elasticsearch itself does not "
                "require root privileges. NIST SP 800-190 §4.4.1 mandates non-root execution."
            ),
            actual=actual,
            expected="non-root UID (default: elasticsearch/UID 1000)",
            remediation=(
                "Dockerfile: USER 1000 (elasticsearch)\n"
                "Kubernetes securityContext:\n"
                "  runAsUser: 1000\n"
                "  runAsNonRoot: true\n"
                "  runAsGroup: 1000"
            ),
            references=[
                "CIS Docker Benchmark v1.6 §4.1",
                "CIS Kubernetes Benchmark v1.8 §5.2.6",
                "NIST SP 800-190 §4.4.1",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.user",
                    {"user": user, "run_as_non_root": run_as_non_root},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_privileged(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        privileged = ctx.get("privileged", False)
        ape = ctx.get("allow_privilege_escalation")

        if src == "kubectl":
            is_fail = privileged or (ape is True)
            actual_parts = [f"privileged={privileged}"]
            if ape is not None:
                actual_parts.append(f"allowPrivilegeEscalation={ape}")
            actual = ", ".join(actual_parts)
        else:
            is_fail = privileged
            actual = f"Privileged={privileged}"

        return CheckResult(
            check_id="ES-CONT-002",
            title="Verify Elasticsearch container does not run in privileged mode",
            status=Status.FAIL if is_fail else Status.PASS,
            severity=Severity.CRITICAL,
            benchmark_control_id="7.2",
            cis_id="CIS-ES-7.2",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "AC-6"],
            description=(
                "Elasticsearch containers must never run in privileged mode. "
                "Privileged containers have near-full access to the host kernel."
            ),
            rationale=(
                "Privileged mode disables all container isolation mechanisms including "
                "seccomp, AppArmor, SELinux, and capability restrictions. "
                "There is no legitimate Elasticsearch use case requiring privileged mode."
            ),
            actual=actual,
            expected="privileged=False, allowPrivilegeEscalation=False",
            remediation=(
                "Remove privileged: true from container spec.\n"
                "Kubernetes: set allowPrivilegeEscalation: false in securityContext.\n"
                "Note: Elasticsearch requires vm.max_map_count=262144 on the host "
                "for production use — set this via initContainer or node configuration, "
                "not via privileged containers."
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.4",
                "CIS Kubernetes Benchmark v1.8 §5.2.1",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.privileged",
                    {"privileged": privileged, "allowPrivilegeEscalation": ape},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_caps(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        cap_add = ctx.get("cap_add", [])
        cap_drop = ctx.get("cap_drop", [])

        dangerous_added = sorted(_DANGEROUS_CAPS & set(cap_add))
        drops_all = "ALL" in cap_drop

        if dangerous_added:
            status = Status.FAIL
        elif not drops_all:
            status = Status.WARN
        else:
            status = Status.PASS

        actual = (
            f"cap_add={cap_add or '[]'}, cap_drop={cap_drop or '[]'}"
            + (f" [DANGEROUS: {dangerous_added}]" if dangerous_added else "")
        )

        return CheckResult(
            check_id="ES-CONT-003",
            title="Dangerous Linux capabilities must not be granted to the Elasticsearch container",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="7.3",
            cis_id="CIS-ES-7.3",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "AC-6"],
            description=(
                "Elasticsearch does not require elevated Linux capabilities. "
                "The container must drop ALL capabilities with no dangerous ones added."
            ),
            rationale=(
                "Capabilities like SYS_ADMIN and NET_ADMIN significantly expand the container "
                "attack surface beyond what Elasticsearch requires for normal operation. "
                "Elasticsearch only needs to bind to ports and read/write its data directory."
            ),
            actual=actual,
            expected="cap_drop=[ALL], cap_add=[]",
            remediation=(
                "Kubernetes securityContext:\n"
                "  capabilities:\n"
                "    drop: [ALL]\n"
                "    add: []  # Elasticsearch needs no added capabilities\n"
                "Docker: --cap-drop ALL (no --cap-add needed)"
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.3",
                "CIS Kubernetes Benchmark v1.8 §5.2.8",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.capabilities",
                    {"cap_add": cap_add, "cap_drop": cap_drop},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_readonly_rootfs(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        read_only = ctx.get("read_only_rootfs", False)

        return CheckResult(
            check_id="ES-CONT-004",
            title="Elasticsearch container root filesystem should be mounted read-only",
            status=Status.PASS if read_only else Status.WARN,
            severity=Severity.MEDIUM,
            benchmark_control_id="7.4",
            cis_id="CIS-ES-7.4",
            fedramp_control="CM-7",
            nist_800_53_controls=["CM-7", "SC-28"],
            description=(
                "The Elasticsearch container root filesystem should be read-only. "
                "Data directories (/usr/share/elasticsearch/data) should be on separate volumes."
            ),
            rationale=(
                "A read-only root filesystem prevents attackers from installing backdoors or "
                "modifying Elasticsearch binaries at runtime. Data and logs should be on "
                "separate writable mounts, not the root filesystem."
            ),
            actual=f"ReadonlyRootfs={read_only}",
            expected="ReadonlyRootfs=True with /usr/share/elasticsearch/data on a separate volume",
            remediation=(
                "Kubernetes:\n"
                "  securityContext:\n"
                "    readOnlyRootFilesystem: true\n"
                "  volumeMounts:\n"
                "    - name: es-data\n"
                "      mountPath: /usr/share/elasticsearch/data\n"
                "    - name: es-logs\n"
                "      mountPath: /usr/share/elasticsearch/logs\n"
                "Docker: --read-only with data volume mount"
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.12",
                "CIS Kubernetes Benchmark v1.8 §5.2.4",
                "NIST SP 800-190 §4.4.3",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.read_only_rootfs",
                    read_only,
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_resource_limits(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        mem_set = ctx.get("memory_limit_set", False)
        cpu_set = ctx.get("cpu_limit_set", False)

        if mem_set and cpu_set:
            status = Status.PASS
        elif mem_set or cpu_set:
            status = Status.WARN
        else:
            status = Status.FAIL

        actual = f"memory_limit={'set' if mem_set else 'unset'}, cpu_limit={'set' if cpu_set else 'unset'}"

        return CheckResult(
            check_id="ES-CONT-005",
            title="Elasticsearch container must have memory and CPU resource limits configured",
            status=status,
            severity=Severity.HIGH,
            benchmark_control_id="7.5",
            cis_id="CIS-ES-7.5",
            fedramp_control="SC-6",
            nist_800_53_controls=["SC-6", "SI-17"],
            description=(
                "CPU and memory resource limits must be set for the Elasticsearch container "
                "to prevent resource exhaustion attacks and noisy-neighbor impacts on the host."
            ),
            rationale=(
                "Without limits, Elasticsearch can consume all available memory and CPU on the host. "
                "Elasticsearch's JVM heap is already bounded by ES_JAVA_OPTS, but container "
                "memory limits provide an additional safety boundary and prevent OOM kills "
                "of other critical workloads."
            ),
            actual=actual,
            expected="both memory and CPU limits set (recommended: memory ≥ 2× JVM heap)",
            remediation=(
                "Kubernetes:\n"
                "  resources:\n"
                "    requests:\n"
                "      memory: 4Gi\n"
                "      cpu: 1000m\n"
                "    limits:\n"
                "      memory: 8Gi  # 2× ES_JAVA_OPTS -Xmx4g\n"
                "      cpu: 4000m\n"
                "Docker: --memory 8g --cpus 4"
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.10",
                "CIS Kubernetes Benchmark v1.8 §5.2.3",
                "NIST SP 800-190 §4.5",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.resource_limits",
                    {"memory_limit_set": mem_set, "cpu_limit_set": cpu_set},
                    ctx["inspect_cmd"],
                )
            ],
        )

    def _check_host_namespaces(self, ctx: dict) -> CheckResult:
        src = ctx["source"]
        host_network = ctx.get("host_network", False)
        host_pid = ctx.get("host_pid", False)
        host_ipc = ctx.get("host_ipc", False)

        violations = []
        if host_network:
            violations.append("hostNetwork")
        if host_pid:
            violations.append("hostPID")
        if host_ipc:
            violations.append("hostIPC")

        actual = (
            f"hostNetwork={host_network}, hostPID={host_pid}, hostIPC={host_ipc}"
            + (f" [VIOLATIONS: {violations}]" if violations else "")
        )

        return CheckResult(
            check_id="ES-CONT-006",
            title="Elasticsearch container must not share host network, PID, or IPC namespaces",
            status=Status.FAIL if violations else Status.PASS,
            severity=Severity.HIGH,
            benchmark_control_id="7.6",
            cis_id="CIS-ES-7.6",
            fedramp_control="SC-4",
            nist_800_53_controls=["SC-4", "SC-7", "AC-6"],
            description=(
                "Host namespace sharing must be disabled for Elasticsearch containers. "
                "hostNetwork, hostPID, and hostIPC each collapse isolation boundaries "
                "between the container and the host."
            ),
            rationale=(
                "hostNetwork exposes Elasticsearch to all host interfaces and removes network "
                "isolation. hostPID allows the container to inspect and signal host processes. "
                "hostIPC allows shared memory access across container boundaries. "
                "None are required for Elasticsearch in a correctly designed deployment."
            ),
            actual=actual,
            expected="hostNetwork=False, hostPID=False, hostIPC=False",
            remediation=(
                "Remove hostNetwork, hostPID, and hostIPC from the pod spec.\n"
                "Elasticsearch nodes communicate via the transport port (9300); "
                "use a service or headless service instead of hostNetwork.\n"
                "Kubernetes example:\n"
                "  spec:\n"
                "    hostNetwork: false\n"
                "    hostPID: false\n"
                "    hostIPC: false"
            ),
            references=[
                "CIS Docker Benchmark v1.6 §5.14, §5.16, §5.17",
                "CIS Kubernetes Benchmark v1.8 §5.2.2, §5.2.3, §5.2.4",
                "NIST SP 800-190 §4.4.2",
            ],
            category="Container",
            evidence_type="container-config",
            evidence=[
                self.evidence(
                    f"container.{src}.namespaces",
                    {"hostNetwork": host_network, "hostPID": host_pid, "hostIPC": host_ipc},
                    ctx["inspect_cmd"],
                )
            ],
        )

    # ------------------------------------------------------------------
    # SKIP / ERROR helpers
    # ------------------------------------------------------------------

    def _all_skipped(self) -> list[CheckResult]:
        return [
            CheckResult(
                check_id=cid,
                title=title,
                status=Status.SKIP,
                severity=Severity.INFO,
                benchmark_control_id=f"7.{i + 1}",
                cis_id=f"CIS-ES-7.{i + 1}",
                description="Container-level controls require docker or kubectl mode.",
                rationale="Container inspection is not available in direct mode.",
                actual="direct mode — container inspection not available",
                expected="run with --mode docker or --mode kubectl",
                remediation=(
                    "Re-run with --mode docker --container <name> or "
                    "--mode kubectl --pod <name> to assess container-level controls."
                ),
                references=["CIS Docker Benchmark", "CIS Kubernetes Benchmark"],
                category="Container",
                evidence_type="container-config",
            )
            for i, (cid, title) in enumerate(_CONTAINER_CHECKS)
        ]

    def _all_error(self, mode: str) -> list[CheckResult]:
        container_ref = (
            self.runner.container if mode == "docker" else self.runner.pod
        ) or "<unknown>"
        inspect_cmd = (
            f"docker inspect {container_ref}"
            if mode == "docker"
            else f"kubectl get pod {container_ref} -o json"
        )
        return [
            CheckResult(
                check_id=cid,
                title=title,
                status=Status.ERROR,
                severity=Severity.HIGH,
                benchmark_control_id=f"7.{i + 1}",
                cis_id=f"CIS-ES-7.{i + 1}",
                description="Container inspection failed; controls could not be assessed.",
                rationale="Evidence cannot be collected if the runtime inspection command fails.",
                actual=f"inspection failed for {container_ref}",
                expected="successful container inspect output",
                remediation=(
                    f"Verify the container/pod exists and the audit user has permission to run: "
                    f"{inspect_cmd}"
                ),
                references=["CIS Docker Benchmark", "CIS Kubernetes Benchmark"],
                category="Container",
                evidence_type="container-config",
                evidence=[
                    self.evidence("container.inspect_error", f"failed: {inspect_cmd}", inspect_cmd)
                ],
            )
            for i, (cid, title) in enumerate(_CONTAINER_CHECKS)
        ]
