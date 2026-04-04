"""SecForge v2 parsers: gitleaks + trufflehog (secrets detection)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, iter_jsonl, make_finding
from secforge.normalize import redact_text, truncate


# --- Gitleaks ---

@register("secrets/gitleaks.json")
def parse_gitleaks(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, list):
        return []
    findings: List[Dict[str, Any]] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_GITLEAKS", "500"))

    for item in data:
        if len(findings) >= max_items:
            break
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID") or item.get("rule") or ""
        desc = item.get("Description") or item.get("description") or ""
        file_path = item.get("File") or item.get("file") or ""
        start = item.get("StartLine") or item.get("startLine") or ""

        # Map rule to issue_key
        ik = "secrets.generic"
        rule_lower = rule.lower()
        if "aws" in rule_lower:
            ik = "secrets.aws_key"
        elif "stripe" in rule_lower:
            ik = "secrets.stripe_key"
        elif "github" in rule_lower:
            ik = "secrets.github_token"
        elif "private" in rule_lower and "key" in rule_lower:
            ik = "secrets.private_key"

        findings.append(make_finding(
            issue_key=ik,
            title="Secret detected (gitleaks)",
            severity="high",
            tool="gitleaks",
            category="secrets",
            asset_type="code",
            location={"file_path": str(file_path), "line": int(start) if str(start).isdigit() else None},
            description=truncate(redact_text(str(desc)), 600),
            evidence=truncate(redact_text(f"{file_path}:{start} rule={rule}"), 600),
            remediation_summary="Rotate the exposed credential, remove it from the repo history, and use a secrets manager.",
        ))
        findings[-1]["_tool_rule_id"] = rule
    return findings


# --- TruffleHog ---

@register("secrets/trufflehog.json")
def parse_trufflehog(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_TRUFFLEHOG", "500"))

    for obj in iter_jsonl(fpath):
        if len(findings) >= max_items:
            break
        if not isinstance(obj, dict):
            continue
        detector = obj.get("DetectorName") or obj.get("Detector") or "Secret"
        source = obj.get("SourceMetadata") or {}
        file_path = ""
        line = ""
        try:
            if isinstance(source, dict):
                d = source.get("Data") or {}
                if isinstance(d, dict):
                    fs = d.get("Filesystem") or d.get("filesystem") or {}
                    if isinstance(fs, dict):
                        file_path = fs.get("file") or fs.get("path") or ""
                        line = fs.get("line") or ""
        except Exception:
            pass

        # Map detector to issue_key
        ik = "secrets.generic"
        det_lower = detector.lower()
        if "aws" in det_lower:
            ik = "secrets.aws_key"
        elif "stripe" in det_lower:
            ik = "secrets.stripe_key"
        elif "github" in det_lower:
            ik = "secrets.github_token"
        elif "private" in det_lower:
            ik = "secrets.private_key"

        findings.append(make_finding(
            issue_key=ik,
            title=f"Secret detected: {detector}",
            severity="high",
            tool="trufflehog",
            category="secrets",
            asset_type="code",
            location={"file_path": str(file_path), "line": int(line) if str(line).isdigit() else None} if file_path else None,
            description="TruffleHog detected a potential secret. Secret values are intentionally redacted.",
            evidence=truncate(redact_text(f"{file_path}:{line}" if file_path else ""), 500),
            remediation_summary="Verify the finding, rotate credentials, and remove secrets from code + history.",
        ))
        findings[-1]["_tool_rule_id"] = detector
    return findings
