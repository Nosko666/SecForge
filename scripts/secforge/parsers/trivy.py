"""SecForge v2 parser: Trivy rootfs (hardening/trivy-rootfs.json)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Set

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import normalize_severity_v2, redact_text, truncate
from secforge.schema import SEVERITY_ORDER


@register("hardening/trivy-rootfs.json")
def parse_trivy_rootfs(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if data is None:
        return []

    results: List[Dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("Results"), list):
        results = [r for r in data["Results"] if isinstance(r, dict)]
    elif isinstance(data, list):
        results = [r for r in data if isinstance(r, dict)]

    vulns: List[Dict[str, Any]] = []
    for r in results:
        vs = r.get("Vulnerabilities")
        if isinstance(vs, list):
            vulns.extend([v for v in vs if isinstance(v, dict)])

    if not vulns:
        return []

    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_TRIVY", "200"))
    _sev_order = {k.lower(): v for k, v in SEVERITY_ORDER.items()}
    findings: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    # Sort by severity desc
    sorted_vulns = sorted(vulns, key=lambda x: _sev_order.get(
        normalize_severity_v2(x.get("Severity"), "low"), 0), reverse=True)

    for v in sorted_vulns:
        if len(findings) >= max_items:
            break
        vid = str(v.get("VulnerabilityID") or "VULN")
        pkg = str(v.get("PkgName") or "")
        key = f"{vid}|{pkg}"
        if key in seen:
            continue
        seen.add(key)

        sev = normalize_severity_v2(v.get("Severity"), "low")
        if _sev_order.get(sev, 0) < _sev_order.get("high", 0):
            continue  # Only emit HIGH+ individually; summarize rest below

        installed = str(v.get("InstalledVersion") or "")
        fixed = str(v.get("FixedVersion") or "")
        title_text = str(v.get("Title") or vid)
        primary = str(v.get("PrimaryURL") or "")
        desc = str(v.get("Description") or "")

        evidence = []
        if pkg:
            evidence.append(f"package={pkg}")
        if installed:
            evidence.append(f"installed={installed}")
        if fixed:
            evidence.append(f"fixed={fixed}")
        if primary:
            evidence.append(f"ref={primary}")

        vuln_ids = [{"type": "CVE", "value": vid}] if vid.startswith("CVE-") else []

        findings.append(make_finding(
            issue_key="deps.vulnerable_package",
            title=f"OS vulnerability: {title_text}",
            severity=sev,
            tool="trivy",
            category="deps",
            asset={"type": "package", "package": pkg, "package_version": installed, "ecosystem": "os"},
            description=truncate(redact_text(desc), 700),
            evidence=truncate(redact_text("; ".join(evidence)), 700),
            remediation_summary="Update the affected package(s) and rebuild/patch the host as appropriate.",
            vuln_identifiers=vuln_ids if vuln_ids else None,
        ))

    # Summary for all severities
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        s = normalize_severity_v2(v.get("Severity"), "low")
        counts[s] = counts.get(s, 0) + 1

    findings.append(make_finding(
        issue_key="deps.vulnerable_package",
        title="Trivy rootfs vulnerability summary",
        severity="info",
        tool="trivy",
        category="deps",
        asset={"type": "host", "host": context.get("target_host", "this_server")},
        description="Trivy reported OS package vulnerabilities on the filesystem.",
        evidence=f"Counts: CRITICAL={counts.get('critical',0)}, HIGH={counts.get('high',0)}, MEDIUM={counts.get('medium',0)}, LOW={counts.get('low',0)}",
        remediation_summary="Prioritize CRITICAL/HIGH updates first; consider unattended upgrades and regular patching.",
    ))

    return findings
