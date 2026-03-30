#!/usr/bin/env python3
"""Runner helpers for elastic-stig-audit.

Supports three connection modes:
  docker  — docker exec <container> curl ...
  kubectl — kubectl exec <pod> -n <namespace> -- curl ...
  direct  — curl directly to host:port from the audit host
"""
from dataclasses import dataclass, field
import json
import shlex
import subprocess
from typing import Optional


@dataclass
class ElasticsearchRunner:
    mode: str = "docker"
    container: Optional[str] = None
    pod: Optional[str] = None
    namespace: str = "default"
    host: str = "127.0.0.1"
    port: int = 9200
    username: Optional[str] = None
    password: Optional[str] = None
    scheme: str = "http"
    verbose: bool = False
    last_error: Optional[str] = None
    command_log: list = field(default_factory=list)

    def _base_curl(self) -> list[str]:
        """Build base curl command prefix for the configured mode."""
        curl_opts = ["curl", "-s", "--max-time", "10", "--connect-timeout", "5"]
        if self.scheme == "https":
            curl_opts += ["-k"]  # skip cert validation in audit context (inspected separately)
        if self.username and self.password:
            curl_opts += ["-u", f"{self.username}:{self.password}"]

        if self.mode == "direct":
            return curl_opts
        if self.mode == "docker":
            if not self.container:
                raise ValueError("--container is required for docker mode")
            return ["docker", "exec", self.container] + curl_opts
        if self.mode == "kubectl":
            if not self.pod:
                raise ValueError("--pod is required for kubectl mode")
            return ["kubectl", "exec", "-n", self.namespace, self.pod, "--"] + curl_opts
        raise ValueError(f"Unsupported mode: {self.mode}")

    def _base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def exec(self, command: list[str]) -> subprocess.CompletedProcess:
        if self.verbose:
            print("[runner]", shlex.join(command))
        try:
            res = subprocess.run(command, capture_output=True, text=True, timeout=30)
        except FileNotFoundError as exc:
            self.last_error = str(exc)
            self.command_log.append(
                {"command": shlex.join(command), "returncode": 127, "stdout": "", "stderr": str(exc)}
            )
            return subprocess.CompletedProcess(command, 127, "", str(exc))
        except subprocess.TimeoutExpired:
            self.last_error = "timeout"
            self.command_log.append(
                {"command": shlex.join(command), "returncode": 124, "stdout": "", "stderr": "timeout"}
            )
            return subprocess.CompletedProcess(command, 124, "", "timeout")
        self.last_error = res.stderr.strip() or None if res.returncode != 0 else None
        self.command_log.append(
            {
                "command": shlex.join(command),
                "returncode": res.returncode,
                "stdout": res.stdout.strip()[:2000],  # truncate for log
                "stderr": res.stderr.strip(),
            }
        )
        return res

    def api_get(self, path: str) -> Optional[dict]:
        """GET <path> from Elasticsearch REST API. Returns parsed JSON or None."""
        url = self._base_url() + path
        cmd = self._base_curl() + [url]
        res = self.exec(cmd)
        if res.returncode != 0 or not res.stdout.strip():
            return None
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return None

    def test_connection(self) -> bool:
        """Return True if Elasticsearch is reachable."""
        data = self.api_get("/")
        return data is not None and "version" in data

    def get_version(self) -> Optional[str]:
        """Return Elasticsearch version string (e.g. '8.12.0') or None."""
        data = self.api_get("/")
        if data:
            return data.get("version", {}).get("number")
        return None

    def get_cluster_settings(self) -> dict:
        """Return flattened cluster settings (persistent + transient + defaults)."""
        data = self.api_get("/_cluster/settings?include_defaults=true&flat_settings=true")
        if not data:
            return {}
        merged = {}
        for section in ("defaults", "persistent", "transient"):
            merged.update(data.get(section, {}))
        return merged

    def get_node_settings(self) -> dict:
        """Return the local node's settings dict."""
        data = self.api_get("/_nodes/_local/settings?flat_settings=true")
        if not data:
            return {}
        nodes = data.get("nodes", {})
        if not nodes:
            return {}
        first = next(iter(nodes.values()))
        return first.get("settings", {})

    def get_node_info(self) -> dict:
        """Return full local node info."""
        data = self.api_get("/_nodes/_local")
        if not data:
            return {}
        nodes = data.get("nodes", {})
        if not nodes:
            return {}
        return next(iter(nodes.values()), {})

    def get_cluster_health(self) -> dict:
        return self.api_get("/_cluster/health") or {}

    def _sanitize_security_response(self, data: Optional[dict]) -> dict:
        """Return {} for security API error payloads so checks don't mis-handle them as objects."""
        if not isinstance(data, dict):
            return {}
        if "error" in data and "status" in data:
            return {}
        return data

    def get_users(self) -> dict:
        """Return security users dict. Returns {} if security not enabled or API errors."""
        return self._sanitize_security_response(self.api_get("/_security/user"))

    def get_roles(self) -> dict:
        """Return security roles dict. Returns {} if security not enabled or API errors."""
        return self._sanitize_security_response(self.api_get("/_security/role"))

    def get_privileges(self) -> dict:
        """Return application privileges. Returns {} if security not enabled or API errors."""
        return self._sanitize_security_response(self.api_get("/_security/privilege"))

    def get_xpack_info(self) -> dict:
        """Return X-Pack info (license, features)."""
        return self.api_get("/_xpack") or {}

    def container_inspect(self) -> dict:
        """Return parsed `docker inspect` for the configured container, or {}."""
        if self.mode != "docker" or not self.container:
            return {}
        res = self.exec(["docker", "inspect", self.container])
        if res.returncode != 0:
            return {}
        try:
            data = json.loads(res.stdout)
            return data[0] if isinstance(data, list) and data else {}
        except (json.JSONDecodeError, IndexError):
            return {}

    def pod_inspect(self) -> dict:
        """Return parsed `kubectl get pod -o json` for the configured pod, or {}."""
        if self.mode != "kubectl" or not self.pod:
            return {}
        res = self.exec(
            ["kubectl", "get", "pod", "-n", self.namespace, self.pod, "-o", "json"]
        )
        if res.returncode != 0:
            return {}
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return {}

    def snapshot(self) -> dict:
        """Capture a runtime snapshot for evidence bundle."""
        container_meta = None
        if self.mode == "docker":
            container_meta = self.container_inspect() or None
        elif self.mode == "kubectl":
            container_meta = self.pod_inspect() or None

        node_settings = self.get_node_settings()
        cluster_settings = self.get_cluster_settings()

        return {
            "node_settings": node_settings,
            "cluster_settings": cluster_settings,
            "cluster_health": self.get_cluster_health(),
            "xpack_info": self.get_xpack_info(),
            "command_log_tail": self.command_log[-10:],
            "last_error": self.last_error,
            "container_meta": container_meta,
        }
