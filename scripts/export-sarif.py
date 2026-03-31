#!/usr/bin/env python3
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def slug(text: str, max_len: int = 80) -> str:
    s = (text or "").lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    if not s:
        return "secforge-rule"
    return s[:max_len]


def sarif_level(severity: str) -> str:
    s = (severity or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


def load_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def ensure_findings_path(input_path: Path) -> Path:
    if input_path.is_dir():
        return input_path / "findings.json"
    return input_path


def build_rules_and_results(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in findings:
        category = str(f.get("category") or "secforge")
        title = str(f.get("title") or "Finding")
        desc = str(f.get("description") or "")
        sev = str(f.get("severity") or "INFO")
        tool = str(f.get("tool") or "secforge")
        cwe = str(f.get("cwe") or "")
        owasp = str(f.get("owasp") or "")

        rule_id = slug(f"{category}-{title}")
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": title[:128],
                "shortDescription": {"text": title[:256]},
                "fullDescription": {"text": (desc or title)[:1024]},
                "properties": {
                    "category": category,
                    "defaultSeverity": sev,
                    "tool": tool,
                    "cwe": cwe,
                    "owasp": owasp,
                },
            }

        message_parts = [f"[{sev}] {title}"]
        if desc:
            message_parts.append(desc)
        evidence = str(f.get("evidence") or "")
        if evidence:
            message_parts.append(f"Evidence: {evidence}")
        remediation = str(f.get("remediation") or "")
        if remediation:
            message_parts.append(f"Remediation: {remediation}")

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": sarif_level(sev),
            "message": {"text": "\n".join(message_parts)[:4000]},
            "properties": {
                "secforgeId": str(f.get("id") or ""),
                "severity": sev,
                "tool": tool,
                "also_found_by": f.get("also_found_by") or [],
                "category": category,
                "cwe": cwe,
                "owasp": owasp,
                "status": str(f.get("status") or "open"),
            },
        }

        url = str(f.get("url") or "")
        if url:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": url},
                    }
                }
            ]

        results.append(result)

    return list(rules_by_id.values()), results


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert findings.json to SARIF (findings.sarif).")
    parser.add_argument("input", help="Path to findings.json or a session directory containing it.")
    parser.add_argument("--out", help="Output path (default: alongside findings.json).")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser().resolve()
    findings_path = ensure_findings_path(input_path)
    if not findings_path.exists():
        print(f"ERROR: findings.json not found: {findings_path}", file=sys.stderr)
        return 2

    data = load_json(findings_path)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        print(f"ERROR: invalid findings.json format: {findings_path}", file=sys.stderr)
        return 2

    rules, results = build_rules_and_results(data.get("findings"))  # type: ignore[arg-type]

    out_path = Path(args.out).expanduser().resolve() if args.out else findings_path.with_suffix(".sarif")

    sarif: Dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecForge",
                        "informationUri": "https://github.com/Nosko666/SecForge",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": utc_now_iso(),
                    }
                ],
                "results": results,
            }
        ],
        "properties": {
            "target": data.get("target", ""),
            "scan_date": data.get("scan_date", ""),
            "scan_profile": data.get("scan_profile", ""),
        },
    }

    out_path.write_text(json.dumps(sarif, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

