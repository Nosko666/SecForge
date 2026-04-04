"""SecForge v2 parser: Nuclei (webapp/nuclei.json — JSONL format)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import iter_jsonl, make_finding
from secforge.normalize import normalize_severity_v2, redact_text, truncate


# Nuclei template tags → issue_key mapping (tool-specific knowledge)
_TAG_TO_ISSUE_KEY = {
    "csp": "headers.missing_csp",
    "hsts": "headers.missing_hsts",
    "x-frame-options": "headers.missing_xfo",
    "xss": "xss.reflected",
    "sqli": "sqli.generic",
    "ssrf": "injection.ssrf",
    "lfi": "injection.lfi",
    "rce": "injection.command",
    "ssti": "injection.ssti",
    "xxe": "injection.xxe",
    "cors": "cors.misconfigured",
    "exposure": "exposure.admin_panel",
}


@register("webapp/nuclei.json")
def parse_nuclei(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_NUCLEI", "2000"))

    for obj in iter_jsonl(fpath):
        if len(findings) >= max_items:
            break
        if not isinstance(obj, dict):
            continue

        info = obj.get("info", {}) if isinstance(obj.get("info"), dict) else {}
        sev = normalize_severity_v2(info.get("severity") or obj.get("severity"), "info")
        template_id = obj.get("template-id") or obj.get("templateID") or obj.get("template") or ""
        name = info.get("name") or template_id or "Nuclei finding"
        matched = obj.get("matched-at") or obj.get("matchedAt") or obj.get("host") or obj.get("url") or ""
        desc = info.get("description") or ""

        # Resolve issue_key from tags (tool-specific knowledge)
        tags = info.get("tags")
        issue_key = ""
        category = "misconfig"
        tag_set: set = set()
        if isinstance(tags, str):
            tag_set = {t.strip().lower() for t in tags.split(",") if t.strip()}
        elif isinstance(tags, list):
            tag_set = {str(t).strip().lower() for t in tags if str(t).strip()}

        for tag, ik in _TAG_TO_ISSUE_KEY.items():
            if tag in tag_set:
                issue_key = ik
                category = ik.split(".")[0] if "." in ik else "misconfig"
                break

        # Fallback: use template_id as the tool-specific rule_id
        if not issue_key:
            # Will be resolved to unknown.nuclei.<template_id> by the pipeline
            issue_key = ""  # Let pipeline use IssueKeyResolver.fallback()

        # Build evidence
        evidence_parts = []
        if template_id:
            evidence_parts.append(f"template={template_id}")
        matcher = obj.get("matcher-name") or obj.get("matcherName")
        if matcher:
            evidence_parts.append(f"matcher={matcher}")
        extracted = obj.get("extracted-results") or obj.get("extractedResults")
        if isinstance(extracted, list) and extracted:
            evidence_parts.append("extracted=" + ", ".join([str(x) for x in extracted[:5]]))

        # Vuln identifiers from Nuclei classification
        vuln_ids = []
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cve_id = classification.get("cve-id")
            if isinstance(cve_id, list):
                for c in cve_id[:3]:
                    if c:
                        vuln_ids.append({"type": "CVE", "value": str(c)})
            elif cve_id:
                vuln_ids.append({"type": "CVE", "value": str(cve_id)})
            cwe_id = classification.get("cwe-id")
            if isinstance(cwe_id, list):
                for c in cwe_id[:3]:
                    if c:
                        vuln_ids.append({"type": "CWE", "value": str(c)})
            elif cwe_id:
                vuln_ids.append({"type": "CWE", "value": str(cwe_id)})

        f = make_finding(
            issue_key=issue_key,
            title=str(name),
            severity=sev,
            tool="nuclei",
            category=category,
            asset={"type": "web", "host": context.get("target_host", ""), "url": str(matched)},
            description=truncate(redact_text(str(desc)), 500),
            evidence=truncate(redact_text("; ".join(evidence_parts)), 500),
            remediation_summary=truncate(redact_text(str(info.get("remediation") or info.get("reference") or "")), 500),
            vuln_identifiers=vuln_ids if vuln_ids else None,
            tags=sorted(tag_set)[:10] if tag_set else None,
        )

        # Stash tool-specific rule_id for fallback issue_key resolution
        f["_tool_rule_id"] = template_id

        findings.append(f)

    return findings
