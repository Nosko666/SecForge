"""SecForge v2 parser: OWASP ZAP (webapp/zap.json)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import normalize_severity_v2, redact_text, truncate

# ZAP alert names → issue_keys
_ALERT_TO_KEY = {
    "cross site scripting": "xss.reflected",
    "cross-site scripting": "xss.reflected",
    "sql injection": "sqli.generic",
    "remote os command injection": "injection.command",
    "remote code execution": "injection.command",
    "content security policy": "headers.missing_csp",
    "csp": "headers.missing_csp",
    "missing anti-clickjacking": "misconfig.missing_clickjacking_protection",
    "x-frame-options": "headers.missing_xfo",
    "strict-transport-security": "headers.missing_hsts",
    "x-content-type-options": "headers.missing_xcto",
    "cookie no httponly": "cookies.missing_httponly",
    "cookie without samesite": "cookies.missing_samesite",
    "x-powered-by": "headers.missing_xpb",
    "server leaks": "headers.missing_xpb",
    "csrf": "auth.missing_csrf",
    "anti-csrf": "auth.missing_csrf",
    "http only site": "tls.http_only_site",
    "sub resource integrity": "payment.missing_sri",
}


@register("webapp/zap.json")
def parse_zap(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []
    alerts = data.get("alerts", [])
    if not isinstance(alerts, list):
        return []

    findings: List[Dict[str, Any]] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_ZAP", "2000"))

    for a in alerts:
        if len(findings) >= max_items:
            break
        if not isinstance(a, dict):
            continue

        risk = a.get("risk") or a.get("riskdesc") or a.get("riskDesc") or ""
        sev = normalize_severity_v2(risk, "info")
        title = a.get("alert") or a.get("name") or "ZAP alert"
        url = a.get("url") or ""
        desc = a.get("desc") or a.get("description") or ""
        solution = a.get("solution") or ""
        evidence = a.get("evidence") or ""
        param = a.get("param") or ""
        attack = a.get("attack") or ""
        pluginid = str(a.get("pluginid") or a.get("pluginId") or "")

        # Resolve issue_key from alert name
        issue_key = ""
        title_lower = title.lower()
        for pattern, ik in _ALERT_TO_KEY.items():
            if pattern in title_lower:
                issue_key = ik
                break

        # CWE from ZAP
        vuln_ids = []
        cweid = str(a.get("cweid") or a.get("cweId") or "")
        if cweid.isdigit() and int(cweid) > 0:
            vuln_ids.append({"type": "CWE", "value": f"CWE-{int(cweid)}"})

        ev_parts = []
        if param:
            ev_parts.append(f"param={param}")
        if attack:
            ev_parts.append(f"attack={truncate(str(attack), 120)}")
        if evidence:
            ev_parts.append(f"evidence={truncate(str(evidence), 200)}")

        location = None
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            ep = parsed.path or ""
            location = {"endpoint": ep}
            if param:
                location["parameter"] = param

        f = make_finding(
            issue_key=issue_key,
            title=str(title),
            severity=sev,
            tool="zap",
            category="misconfig" if not issue_key else issue_key.split(".")[0],
            asset={"type": "web", "host": context.get("target_host", ""), "url": str(url)},
            location=location,
            description=truncate(redact_text(str(desc)), 600),
            evidence=truncate(redact_text("; ".join(ev_parts)), 500),
            remediation_summary=truncate(redact_text(str(solution)), 600),
            vuln_identifiers=vuln_ids if vuln_ids else None,
        )
        f["_tool_rule_id"] = pluginid
        findings.append(f)

    return findings
