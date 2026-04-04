"""SecForge v2 parser: testssl.sh JSON output (ssl/testssl.json)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import normalize_severity_v2, redact_text, truncate


# testssl.sh severity mapping
_TESTSSL_SEV = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "INFO": "info", "OK": "info", "WARN": "medium",
    "NOT ok": "medium", "MODERATE": "medium",
}

# testssl finding IDs → issue_keys (tool-specific knowledge)
_ID_TO_ISSUE_KEY = {
    "HSTS": "headers.missing_hsts",
    "HSTS_time": "headers.missing_hsts",
    "BREACH": "tls.breach_vulnerable",
    "secure_renego": "tls.insecure_renegotiation",
    "forward_secrecy": "tls.no_forward_secrecy",
    "LOGJAM": "tls.weak_cipher",
    "SWEET32": "tls.weak_cipher",
    "POODLE_SSL": "tls.weak_protocol",
    "DROWN": "tls.weak_protocol",
    "BEAST": "tls.weak_protocol",
    "FREAK": "tls.weak_cipher",
}


@register("ssl/testssl.json")
def parse_testssl(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, list):
        return []

    target_host = context.get("target_host", "")
    findings: List[Dict[str, Any]] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_TESTSSL", "500"))

    for item in data:
        if len(findings) >= max_items:
            break
        if not isinstance(item, dict):
            continue

        tid = item.get("id") or ""
        sev_raw = item.get("severity") or "INFO"
        sev = _TESTSSL_SEV.get(sev_raw.strip(), normalize_severity_v2(sev_raw, "info"))
        finding_str = item.get("finding") or ""

        if sev == "info" and tid not in ("HSTS", "HSTS_time"):
            # Skip pure info entries unless they're important
            if tid not in _ID_TO_ISSUE_KEY:
                continue

        # Resolve issue_key from testssl finding ID
        issue_key = _ID_TO_ISSUE_KEY.get(tid, "")

        f = make_finding(
            issue_key=issue_key,
            title=f"TLS/SSL finding: {tid}" if tid else "TLS/SSL finding",
            severity=sev,
            tool="testssl",
            category="tls",
            asset={"type": "web", "host": target_host, "protocol": "https"},
            description=truncate(redact_text(finding_str), 600),
            evidence=truncate(redact_text(f"id={tid} severity={sev_raw}"), 300),
        )
        f["_tool_rule_id"] = tid
        findings.append(f)

    return findings
