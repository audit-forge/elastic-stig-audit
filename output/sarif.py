"""SARIF 2.1.0 output for elastic-stig-audit.

Maps audit CheckResult objects to a SARIF run document suitable for
ingestion by GitHub Code Scanning, GitLab SAST, and compatible tooling.

Status → SARIF level:
  FAIL / ERROR  → "error"
  WARN          → "warning"
  PASS / SKIP   → "none"

Severity → rule defaultConfiguration.level:
  CRITICAL / HIGH → "error"
  MEDIUM          → "warning"
  LOW / INFO      → "note"
"""
import json
import re

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
SARIF_VERSION = "2.1.0"

_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}

_STATUS_TO_LEVEL = {
    "FAIL": "error",
    "ERROR": "error",
    "WARN": "warning",
    "PASS": "none",
    "SKIP": "none",
}


def _pascal(s: str) -> str:
    return "".join(w.capitalize() for w in s.replace("-", " ").replace("_", " ").split())


def _safe_help_uri(references) -> str | None:
    for ref in references or []:
        if isinstance(ref, str) and re.match(r"^https?://", ref):
            return ref
    return None


def _artifact_uri(target_info: dict) -> str:
    display = target_info.get("display_name") or "unknown"
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", display).strip("._") or "unknown"
    return f"targets/{sanitized}.target"


def _rule_from_result(r) -> dict:
    tags = list(r.nist_800_53_controls or [])
    if r.fedramp_control:
        tags.append(f"FedRAMP:{r.fedramp_control}")
    if r.benchmark_control_id:
        tags.append(f"CIS-ES:{r.benchmark_control_id}")
    if r.category:
        tags.append(r.category)
    if r.mitre_attack:
        tags.extend(f"ATT&CK:{t}" for t in r.mitre_attack)

    rule = {
        "id": r.check_id,
        "name": _pascal(r.title),
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.description or r.title},
        "defaultConfiguration": {
            "level": _SEVERITY_TO_LEVEL.get(r.severity.value, "warning"),
        },
        "properties": {
            "tags": tags,
            "precision": "medium",
            "problem.severity": _SEVERITY_TO_LEVEL.get(r.severity.value, "warning"),
        },
    }
    if r.remediation:
        rule["help"] = {
            "text": r.remediation,
            "markdown": f"**Remediation:** {r.remediation}",
        }
    help_uri = _safe_help_uri(r.references)
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def _result_entry(r, rule_index: int, artifact_uri: str) -> dict:
    level = _STATUS_TO_LEVEL.get(r.status.value, "warning")

    msg_parts = [r.description or r.title]
    if r.actual:
        msg_parts.append(f"Actual: {r.actual}")
    if r.expected:
        msg_parts.append(f"Expected: {r.expected}")

    logical_locations = []
    if r.evidence:
        logical_locations.append({"name": r.evidence[0]["source"], "kind": "module"})

    entry = {
        "ruleId": r.check_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": " | ".join(msg_parts)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri,
                    },
                    "region": {"startLine": 1},
                },
                "logicalLocations": logical_locations,
            }
        ],
        "properties": {
            "status": r.status.value,
            "severity": r.severity.value,
            "category": r.category,
            "evidence_type": r.evidence_type,
            "actual": r.actual,
            "expected": r.expected,
            "benchmark_control_id": r.benchmark_control_id,
            "fedramp_control": r.fedramp_control,
            "nist_800_53_controls": r.nist_800_53_controls or [],
            "nist_800_171": r.nist_800_171 or [],
            "cmmc_level": r.cmmc_level,
            "mitre_attack": r.mitre_attack or [],
            "mitre_d3fend": r.mitre_d3fend or [],
        },
    }
    return entry


def build_sarif(results, target_info: dict, tool_name: str, tool_version: str) -> dict:
    """Build a SARIF 2.1.0 document from audit results."""
    seen: dict[str, int] = {}
    rules: list[dict] = []
    for r in results:
        if r.check_id not in seen:
            seen[r.check_id] = len(rules)
            rules.append(_rule_from_result(r))

    artifact_uri = _artifact_uri(target_info)

    sarif_results = [_result_entry(r, seen[r.check_id], artifact_uri) for r in results]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/audit-forge/elastic-stig-audit",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "properties": {"target": target_info},
            }
        ],
    }


def write_sarif(path: str, results, target_info: dict, tool_name: str, tool_version: str) -> None:
    """Serialize a SARIF document to *path*."""
    doc = build_sarif(results, target_info, tool_name, tool_version)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
