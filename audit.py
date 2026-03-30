#!/usr/bin/env python3
"""elastic-stig-audit — CIS Elasticsearch Container Security Benchmark audit tool.

Runs automated security checks against an Elasticsearch instance deployed
in a Docker container, Kubernetes pod, or directly accessible via REST API.

Usage:
  # Docker mode (most common for local dev/CI)
  python audit.py --mode docker --container my-es

  # Kubernetes mode
  python audit.py --mode kubectl --pod es-0 --namespace elastic

  # Direct mode (Elasticsearch accessible from audit host)
  python audit.py --mode direct --host 10.0.0.5 --port 9200 --username elastic --password secret --scheme https

  # Full output suite
  python audit.py --mode docker --container my-es \\
      --sarif results.sarif --json results.json --csv results.csv --bundle evidence.zip
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(__file__))

from runner import ElasticsearchRunner  # noqa: E402
from checks import ALL_CHECKERS  # noqa: E402
from mappings.frameworks import enrich_all  # noqa: E402
from output import report  # noqa: E402
from output.sarif import write_sarif  # noqa: E402
from output.bundle import write_bundle  # noqa: E402

TOOL_NAME = "elastic-stig-audit"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "2026-03-19"


def parse_args():
    p = argparse.ArgumentParser(
        description="CIS Elasticsearch Container Security Benchmark audit tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Connection mode
    p.add_argument(
        "--mode",
        choices=["docker", "kubectl", "direct"],
        default="docker",
        help="Connection mode: docker (exec into container), kubectl (exec into pod), "
             "or direct (REST API from audit host). Default: docker",
    )

    # Docker options
    p.add_argument("--container", help="Docker container name or ID (docker mode)")

    # Kubernetes options
    p.add_argument("--pod", help="Kubernetes pod name (kubectl mode)")
    p.add_argument("--namespace", default="default", help="Kubernetes namespace (default: default)")

    # Direct connection options
    p.add_argument("--host", default="127.0.0.1", help="Elasticsearch host (direct mode, default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=9200, help="Elasticsearch HTTP port (default: 9200)")
    p.add_argument("--username", help="Elasticsearch username (direct mode)")
    p.add_argument("--password", help="Elasticsearch password (direct mode)")
    p.add_argument("--scheme", choices=["http", "https"], default="http",
                   help="HTTP scheme for direct mode (default: http)")

    # Output options
    p.add_argument("--json", metavar="FILE", help="Write raw results JSON to FILE")
    p.add_argument("--sarif", metavar="FILE", help="Write SARIF 2.1.0 results to FILE")
    p.add_argument("--bundle", metavar="FILE", help="Write evidence bundle (zip) to FILE")
    p.add_argument("--csv", metavar="FILE",
                   help="Write CSV results to FILE (21 columns including NIST 800-171, CMMC, MITRE)")

    # Behavior flags
    p.add_argument("--quiet", action="store_true", help="Suppress terminal report")
    p.add_argument("--verbose", action="store_true", help="Show runner commands")
    p.add_argument("--skip-cve", action="store_true",
                   help="Skip CVE/KEV vulnerability scan (faster, compliance-only)")
    p.add_argument(
        "--fail-on",
        choices=["any", "high", "critical", "none"],
        default="none",
        help="Exit non-zero if findings at this severity or higher exist. Default: none",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")

    return p.parse_args()


def build_target_info(args, runner, timestamp: str) -> dict:
    return {
        "mode": args.mode,
        "namespace": args.namespace if args.mode == "kubectl" else None,
        "container": args.container,
        "pod": args.pod,
        "host": args.host if args.mode == "direct" else None,
        "port": args.port if args.mode == "direct" else None,
        "scheme": args.scheme if args.mode == "direct" else "http",
        "display_name": (
            args.container
            or args.pod
            or f"{args.scheme}://{args.host}:{args.port}"
        ),
        "timestamp": timestamp,
        "connected": runner.test_connection(),
        "last_error": runner.last_error,
    }


def summarize(results) -> dict:
    status_counts = Counter(r.status.value for r in results)
    severity_counts = Counter(r.severity.value for r in results)
    actionable = sum(status_counts.get(k, 0) for k in ("FAIL", "WARN", "ERROR"))
    if status_counts.get("FAIL", 0) or status_counts.get("ERROR", 0):
        risk_posture = "HIGH RISK"
    elif status_counts.get("WARN", 0):
        risk_posture = "REVIEW REQUIRED"
    else:
        risk_posture = "BASELINE ACCEPTABLE"
    return {
        "status_counts": dict(status_counts),
        "severity_counts": dict(severity_counts),
        "actionable_findings": actionable,
        "risk_posture": risk_posture,
    }


def write_csv(filepath: str, results: list, target_info: dict) -> None:
    """Write audit results to CSV with 21 compliance columns."""
    fieldnames = [
        "Control_ID",
        "Title",
        "Severity",
        "Result",
        "Category",
        "Actual",
        "Expected",
        "Description",
        "Rationale",
        "CIS_Control",
        "NIST_800_53",
        "NIST_800_171",
        "CMMC_Level",
        "MITRE_ATTACK",
        "MITRE_D3FEND",
        "Remediation",
        "References",
        "CVE_ID",
        "KEV_Score",
        "CVE_Remediation",
        "Local_Path",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "Control_ID": r.check_id,
                "Title": r.title,
                "Severity": r.severity.value,
                "Result": r.status.value,
                "Category": r.category,
                "Actual": r.actual,
                "Expected": r.expected,
                "Description": r.description,
                "Rationale": r.rationale,
                "CIS_Control": r.cis_id or "",
                "NIST_800_53": "; ".join(r.nist_800_53_controls),
                "NIST_800_171": "; ".join(r.nist_800_171),
                "CMMC_Level": str(r.cmmc_level) if r.cmmc_level is not None else "",
                "MITRE_ATTACK": "; ".join(r.mitre_attack),
                "MITRE_D3FEND": "; ".join(r.mitre_d3fend),
                "Remediation": r.remediation,
                "References": "; ".join(r.references),
                "CVE_ID": "; ".join(r.cve_ids) if r.cve_ids else "",
                "KEV_Score": r.kev_score or "",
                "CVE_Remediation": r.cve_remediation or "",
                "Local_Path": r.local_path or "",
            })


def _should_exit_nonzero(results, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    thresholds = {"any": 0, "high": 3, "critical": 4}
    threshold = thresholds.get(fail_on, 0)

    for r in results:
        if r.status.value in ("FAIL", "ERROR"):
            sev = severity_rank.get(r.severity.value, 0)
            if sev >= threshold:
                return True
    return False


def main():
    args = parse_args()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Validate mode-specific args
    if args.mode == "docker" and not args.container:
        print("[error] --container is required for docker mode", file=sys.stderr)
        sys.exit(1)
    if args.mode == "kubectl" and not args.pod:
        print("[error] --pod is required for kubectl mode", file=sys.stderr)
        sys.exit(1)

    runner = ElasticsearchRunner(
        mode=args.mode,
        container=args.container,
        pod=args.pod,
        namespace=args.namespace,
        host=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        scheme=args.scheme,
        verbose=args.verbose,
    )

    # Run all checker modules
    results = []
    for checker_cls in ALL_CHECKERS:
        results.extend(checker_cls(runner).run())

    # Enrich with framework mappings (NIST 800-171, CMMC 2.0, MITRE ATT&CK, D3FEND)
    enrich_all(results)

    # CVE/KEV vulnerability scan
    if not args.skip_cve:
        from checks.cve_scanner import (
            detect_elasticsearch_version,
            fetch_cve_data,
            load_kev_catalog,
            cve_to_check_result,
        )
        cache_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(cache_dir, exist_ok=True)

        version = detect_elasticsearch_version(runner)
        if version:
            print(f"[cve] Detected Elasticsearch version: {version}")
            kev = load_kev_catalog(cache_dir)
            cves = fetch_cve_data("elasticsearch", version, cache_dir)
            local_path = "/usr/share/elasticsearch/bin/elasticsearch"
            cve_result = cve_to_check_result(cves, kev, "elasticsearch", version, local_path)
            results.append(cve_result)
        else:
            print("[cve] Could not detect Elasticsearch version, skipping CVE scan")

    results = sorted(
        results,
        key=lambda r: (r.status.value, r.severity.value, r.check_id),
    )
    target_info = build_target_info(args, runner, timestamp)
    summary = summarize(results)

    if not args.quiet:
        report.render(results, target_info, summary)

    # Structured outputs (JSON, SARIF, bundle)
    if args.json or args.sarif or args.bundle:
        snapshot = runner.snapshot()
        document = {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
            },
            "target": target_info,
            "summary": summary,
            "snapshot": snapshot,
            "results": [r.to_dict() for r in results],
        }

        if args.json:
            with open(args.json, "w") as f:
                json.dump(document, f, indent=2)
            print(f"[json]   Written to {args.json}")

        if args.sarif:
            write_sarif(args.sarif, results, target_info, TOOL_NAME, TOOL_VERSION)
            print(f"[sarif]  Written to {args.sarif}")

        if args.bundle:
            write_bundle(
                args.bundle,
                document,
                results,
                target_info,
                summary,
                snapshot,
                TOOL_NAME,
                TOOL_VERSION,
            )
            print(f"[bundle] Written to {args.bundle}")

    if args.csv:
        write_csv(args.csv, results, target_info)
        print(f"[csv]    Written to {args.csv}")

    # Exit code based on --fail-on threshold
    if _should_exit_nonzero(results, args.fail_on):
        sys.exit(1)


if __name__ == "__main__":
    main()
