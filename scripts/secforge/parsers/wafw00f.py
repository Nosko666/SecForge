"""SecForge v2 parser: wafw00f (webapp/wafw00f.json or webapp/wafw00f.txt)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, safe_read_text, make_finding
from secforge.normalize import redact_text, truncate


@register("webapp/wafw00f.json")
def parse_wafw00f_json(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse wafw00f JSON output (list of objects with detected/firewall keys)."""
    data = load_json_file(fpath)
    if data is None:
        # Fall back to text parsing
        return _parse_as_text(fpath, context)

    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    if not items:
        return _parse_as_text(fpath, context)

    target_url = context.get("target_url", "")
    findings: List[Dict[str, Any]] = []

    for item in items[:50]:
        if not isinstance(item, dict):
            continue
        detected = item.get("detected") or item.get("Detected") or False
        firewall = str(item.get("firewall") or item.get("Firewall") or item.get("waf") or "")
        url = str(item.get("url") or item.get("URL") or target_url)

        if detected and firewall:
            evidence = f"WAF detected: {firewall}"
        elif detected:
            evidence = "WAF detected (name unknown)"
        else:
            evidence = "No WAF detected"

        findings.append(make_finding(
            issue_key="discovery.waf_detected",
            title="WAF detection result",
            severity="info",
            tool="wafw00f",
            category="discovery",
            asset={"type": "web", "host": context.get("target_host", ""), "url": url},
            description="A WAF can block/scatter scanner traffic and cause false negatives; tune scan intensity accordingly.",
            evidence=truncate(redact_text(evidence), 800),
            remediation_summary="If a WAF is present, use safe scan rates and validate findings with manual checks.",
        ))

    return findings if findings else _parse_as_text(fpath, context)


@register("webapp/wafw00f.txt")
def parse_wafw00f_text(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parse wafw00f plain-text output (fallback)."""
    return _parse_as_text(fpath, context)


def _parse_as_text(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    text = safe_read_text(fpath)
    if not text:
        return []
    waf = ""
    for line in text.splitlines():
        if "is behind" in line.lower() or ("waf" in line.lower() and "detected" in line.lower()):
            waf = line.strip()
            break
    if not waf:
        waf = "wafw00f output present (no WAF line detected)."
    return [make_finding(
        issue_key="discovery.waf_detected",
        title="WAF detection result",
        severity="info",
        tool="wafw00f",
        category="discovery",
        asset={"type": "web", "host": context.get("target_host", ""), "url": context.get("target_url", "")},
        description="A WAF can block/scatter scanner traffic and cause false negatives; tune scan intensity accordingly.",
        evidence=truncate(redact_text(waf), 800),
        remediation_summary="If a WAF is present, use safe scan rates and validate findings with manual checks.",
    )]
