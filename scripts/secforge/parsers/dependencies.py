"""SecForge v2 parsers: OSV-Scanner + pip-audit (dependency scanning)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import normalize_severity_v2, redact_text, truncate


# --- OSV-Scanner ---

@register("dependencies/osv.json")
def parse_osv(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []

    findings: List[Dict[str, Any]] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_OSV", "500"))

    for r in results:
        if len(findings) >= max_items:
            break
        if not isinstance(r, dict):
            continue
        pkgs = r.get("packages") or []
        pkg_names = []
        if isinstance(pkgs, list):
            for p in pkgs:
                if isinstance(p, dict) and p.get("name"):
                    pkg_names.append(str(p["name"]))

        vulns_list = r.get("vulnerabilities") or []
        if not isinstance(vulns_list, list):
            continue

        for v in vulns_list:
            if len(findings) >= max_items:
                break
            if not isinstance(v, dict):
                continue
            vid = v.get("id") or "OSV"
            summary = v.get("summary") or ""
            details = v.get("details") or ""
            severity_score = None
            sev_list = v.get("severity")
            if isinstance(sev_list, list) and sev_list:
                try:
                    severity_score = float(sev_list[0].get("score"))
                except Exception:
                    pass
            sev = normalize_severity_v2(severity_score, "medium")

            vuln_ids = []
            if str(vid).startswith("CVE-"):
                vuln_ids.append({"type": "CVE", "value": str(vid)})
            elif str(vid).startswith("GHSA-"):
                vuln_ids.append({"type": "GHSA", "value": str(vid)})
            else:
                vuln_ids.append({"type": "OSV", "value": str(vid)})

            findings.append(make_finding(
                issue_key="deps.vulnerable_package",
                title=f"Dependency vulnerability: {vid}",
                severity=sev,
                tool="osv-scanner",
                category="deps",
                asset={"type": "package", "package": pkg_names[0] if pkg_names else "", "ecosystem": ""},
                description=truncate(redact_text(summary or details), 800),
                evidence=truncate(redact_text("packages=" + ", ".join(pkg_names[:10])) if pkg_names else "", 700),
                remediation_summary="Update affected dependencies to non-vulnerable versions.",
                vuln_identifiers=vuln_ids,
            ))
    return findings


# --- pip-audit ---

@register("dependencies/pip-audit.json")
def parse_pip_audit(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, list):
        return []
    findings: List[Dict[str, Any]] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_PIP_AUDIT", "500"))

    for dep in data:
        if len(findings) >= max_items:
            break
        if not isinstance(dep, dict):
            continue
        name = dep.get("name") or ""
        dep_vulns = dep.get("vulns") or []
        if not isinstance(dep_vulns, list):
            continue
        for v in dep_vulns:
            if len(findings) >= max_items:
                break
            if not isinstance(v, dict):
                continue
            vid = v.get("id") or "VULN"
            desc = v.get("description") or ""
            fixed = v.get("fix_versions") or []

            vuln_ids = []
            if str(vid).startswith("CVE-"):
                vuln_ids.append({"type": "CVE", "value": str(vid)})
            elif str(vid).startswith("GHSA-"):
                vuln_ids.append({"type": "GHSA", "value": str(vid)})

            evidence = f"package={name}"
            if isinstance(fixed, list) and fixed:
                evidence += f" fixed_versions={','.join([str(x) for x in fixed[:5]])}"

            findings.append(make_finding(
                issue_key="deps.vulnerable_package",
                title=f"Python dependency vulnerability: {vid}",
                severity="medium",
                tool="pip-audit",
                category="deps",
                asset={"type": "package", "package": str(name), "ecosystem": "pip"},
                description=truncate(redact_text(str(desc)), 700),
                evidence=truncate(redact_text(evidence), 700),
                remediation_summary="Upgrade the vulnerable Python package to a fixed version.",
                vuln_identifiers=vuln_ids if vuln_ids else None,
            ))
    return findings
