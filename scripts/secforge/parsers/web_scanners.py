"""SecForge v2 parsers: nikto, dalfox, wapiti, whatweb, corscanner, interactsh."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, safe_read_text, iter_jsonl, make_finding
from secforge.normalize import normalize_severity_v2, redact_text, truncate


# --- Nikto ---

@register("webapp/nikto.json")
def parse_nikto(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if data is None:
        return []
    items: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        if isinstance(data.get("vulnerabilities"), list):
            items = [x for x in data["vulnerabilities"] if isinstance(x, dict)]
        elif isinstance(data.get("nikto"), list):
            for n in data["nikto"]:
                if isinstance(n, dict) and isinstance(n.get("item"), list):
                    items.extend([x for x in n["item"] if isinstance(x, dict)])
    elif isinstance(data, list):
        items = [x for x in data if isinstance(x, dict)]
    if not items:
        return []

    findings: List[Dict[str, Any]] = []
    for it in items[:500]:
        desc = it.get("description") or it.get("msg") or ""
        osvdb = str(it.get("OSVDB") or it.get("osvdb") or "")
        url = it.get("url") or ""
        f = make_finding(
            issue_key="",  # Let pipeline resolve
            title=truncate(str(desc), 200) if desc else "Nikto finding",
            severity="medium",
            confidence="likely",
            tool="nikto",
            category="misconfig",
            asset={"type": "web", "host": context.get("target_host", ""), "url": str(url)},
            description=truncate(redact_text(str(desc)), 500),
            evidence=f"OSVDB-{osvdb}" if osvdb and osvdb != "0" else "",
        )
        f["_tool_rule_id"] = f"OSVDB-{osvdb}" if osvdb and osvdb != "0" else ""
        findings.append(f)
    return findings


# --- Dalfox ---

@register("webapp/dalfox.json")
def parse_dalfox(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = safe_read_text(fpath).strip()
    if not raw:
        return []
    import json
    items: list = []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            items = parsed.get("result", parsed.get("results", [parsed]))
            if not isinstance(items, list):
                items = [parsed]
    except Exception:
        items = list(iter_jsonl(fpath))

    findings: List[Dict[str, Any]] = []
    for it in items[:500]:
        if not isinstance(it, dict):
            continue
        url = it.get("url") or it.get("target") or ""
        poc = it.get("poc") or it.get("payload") or ""
        findings.append(make_finding(
            issue_key="xss.reflected",
            title="XSS finding (dalfox)",
            severity="high" if "found" in str(it.get("type", "")).lower() else "medium",
            tool="dalfox",
            category="xss",
            asset={"type": "web", "host": context.get("target_host", ""), "url": str(url)},
            description="Dalfox reported a potential XSS vector.",
            evidence=truncate(redact_text(str(poc)), 400),
            remediation_summary="Apply output encoding, validate input, and deploy a strict CSP.",
        ))
    return findings


# --- Wapiti ---

@register("webapp/wapiti.json")
def parse_wapiti(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulnerabilities", {})
    if not isinstance(vulns, dict):
        return []

    _WAPITI_KEY = {
        "Cross Site Scripting": "xss.reflected",
        "SQL Injection": "sqli.generic",
        "Command execution": "injection.command",
        "Content Security Policy Configuration": "headers.missing_csp",
        "HTTP Secure Headers": "headers.missing_hsts",
        "HttpOnly Flag cookie": "cookies.missing_httponly",
        "Secure Flag cookie": "cookies.missing_secure",
    }

    findings: List[Dict[str, Any]] = []
    for vuln_type, items in vulns.items():
        if not isinstance(items, list):
            continue
        for it in items[:100]:
            if not isinstance(it, dict):
                continue
            url = it.get("url") or it.get("path") or ""
            info = it.get("info") or it.get("description") or ""
            evidence = it.get("parameter") or it.get("method") or ""
            ik = _WAPITI_KEY.get(vuln_type, "")
            findings.append(make_finding(
                issue_key=ik,
                title=f"Wapiti: {vuln_type}",
                severity="medium",
                tool="wapiti",
                category=ik.split(".")[0] if ik and "." in ik else "misconfig",
                asset={"type": "web", "host": context.get("target_host", ""), "url": str(url)},
                description=truncate(redact_text(str(info)), 700),
                evidence=truncate(redact_text(str(evidence)), 500),
            ))
    return findings


# --- WhatWeb ---

@register("webapp/whatweb.json")
def parse_whatweb(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, list) or not data:
        return []
    techs: List[str] = []
    for item in data[:10]:
        if not isinstance(item, dict):
            continue
        plugins = item.get("plugins", {})
        if isinstance(plugins, dict):
            for name, info in plugins.items():
                version = ""
                if isinstance(info, dict):
                    ver_list = info.get("version")
                    if isinstance(ver_list, list) and ver_list:
                        version = str(ver_list[0])
                entry = name
                if version:
                    entry += f" {version}"
                techs.append(entry)
    if not techs:
        return []
    return [make_finding(
        issue_key="discovery.tech_fingerprint",
        title="Technology fingerprint (whatweb)",
        severity="info",
        tool="whatweb",
        category="discovery",
        asset={"type": "web", "host": context.get("target_host", ""), "url": context.get("target_url", "")},
        description="WhatWeb identified technologies running on the target.",
        evidence=truncate(", ".join(techs[:30]), 800),
    )]


# --- CORScanner ---

@register("webapp/corscanner.json")
def parse_corscanner(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, (list, dict)):
        return []
    items = data if isinstance(data, list) else [data]
    findings: List[Dict[str, Any]] = []
    for item in items[:100]:
        if not isinstance(item, dict):
            continue
        url = item.get("url") or ""
        vuln = item.get("type") or item.get("vulnerability") or ""
        if vuln:
            findings.append(make_finding(
                issue_key="cors.misconfigured",
                title=f"CORS misconfiguration: {vuln}",
                severity="medium",
                tool="corscanner",
                category="cors",
                asset={"type": "web", "host": context.get("target_host", ""), "url": str(url)},
                description="CORScanner detected a CORS misconfiguration that could allow cross-origin data theft.",
                evidence=truncate(redact_text(str(vuln)), 500),
                remediation_summary="Restrict Access-Control-Allow-Origin to trusted origins only.",
            ))
    return findings


# --- Interactsh ---

@register("api/interactsh.json")
def parse_interactsh(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, (list, dict)):
        # Try JSONL
        items = list(iter_jsonl(fpath))
    else:
        items = data if isinstance(data, list) else [data]

    if not items:
        return []

    callbacks: List[str] = []
    for item in items[:50]:
        if isinstance(item, dict):
            proto = item.get("protocol") or ""
            uid = item.get("unique-id") or item.get("uniqueId") or ""
            if uid:
                callbacks.append(f"{proto}: {uid}")

    if not callbacks:
        return [make_finding(
            issue_key="discovery.oob_no_callbacks",
            title="Interactsh: no OOB callbacks received",
            severity="info",
            tool="interactsh",
            category="discovery",
            asset={"type": "web", "host": context.get("target_host", "")},
        )]

    return [make_finding(
        issue_key="injection.ssrf",
        title="Out-of-band callbacks detected (interactsh)",
        severity="high",
        tool="interactsh",
        category="injection",
        asset={"type": "web", "host": context.get("target_host", "")},
        description="Interactsh received out-of-band callbacks, indicating possible blind SSRF, XSS, or injection.",
        evidence=truncate("\n".join(callbacks[:20]), 800),
        remediation_summary="Investigate the source of OOB callbacks and fix the underlying injection vulnerability.",
    )]
