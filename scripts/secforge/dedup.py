"""SecForge v2 dedup engine — Level 2 cross-tool deduplication.

Groups findings by fingerprint. When multiple tools report the same
finding (same fingerprint), merges into one finding with sources[] array.

Merge rules (locked):
- severity: take max
- confidence: take max
- primary tool: by priority list (ZAP > Nuclei > Wapiti > Nikto > built-in)
- sources[]: preserves per-tool evidence
- evidence: primary tool's evidence at top level

Level 1 (same-tool) dedup is handled in parsers (emit one finding per issue).
Level 3 (cross-scan) dedup is handled by the state module.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from secforge.schema import severity_max, confidence_max

# Tool priority for selecting primary (higher = preferred as primary).
_TOOL_PRIORITY: Dict[str, int] = {
    "zap": 100,
    "nuclei": 90,
    "wapiti": 80,
    "nikto": 70,
    "dalfox": 65,
    "xsstrike": 65,
    "sqlmap": 60,
    "commix": 55,
    "testssl": 50,
    "sslscan": 45,
    "nmap": 40,
    "ffuf": 35,
    "whatweb": 30,
    "ssh-audit": 30,
    "trivy": 25,
    "trufflehog": 20,
    "gitleaks": 20,
    "hydra": 15,
    "netexec": 15,
    "osv-scanner": 15,
    "pip-audit": 15,
    "wafw00f": 10,
    "check-email-dns": 10,
    "check-mysql": 10,
    "stripe-check": 10,
    "secforge-builtin": 5,
}

# Max evidence length for merged findings.
_MAX_EVIDENCE = 1000


def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Level 2 cross-tool dedup. Groups by fingerprint, merges duplicates.

    Findings MUST have 'fingerprint' set before calling this.
    Returns deduped list with sources[] on merged findings.
    """
    by_fp: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        fp = f.get("fingerprint", "")
        if not fp:
            # No fingerprint — can't dedup, keep as-is
            by_fp.setdefault("_no_fp_" + str(id(f)), []).append(f)
            continue
        by_fp.setdefault(fp, []).append(f)

    result: List[Dict[str, Any]] = []
    for fp, group in by_fp.items():
        if len(group) == 1:
            f = group[0]
            # Single finding — add sources[] with just itself
            if not f.get("sources"):
                f["sources"] = [_make_source(f)]
            result.append(f)
        else:
            merged = _merge_group(group)
            result.append(merged)

    return result


def _merge_group(group: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge a group of findings with the same fingerprint.

    Picks primary by tool priority. Takes max severity/confidence.
    Builds sources[] from all tools.
    """
    # Sort by tool priority (highest first)
    sorted_group = sorted(group, key=lambda f: _TOOL_PRIORITY.get(f.get("tool", ""), 0), reverse=True)
    primary = sorted_group[0]

    # Deep copy primary to avoid mutating input
    merged = dict(primary)

    # Take max severity and confidence across all tools
    for f in sorted_group[1:]:
        merged["severity"] = severity_max(
            merged.get("severity", "info"),
            f.get("severity", "info"),
        )
        merged["confidence"] = confidence_max(
            merged.get("confidence", "possible"),
            f.get("confidence", "possible"),
        )

    # Build sources[] from all tools
    sources = []
    seen_tools = set()
    for f in sorted_group:
        tool = f.get("tool", "")
        if tool and tool not in seen_tools:
            sources.append(_make_source(f))
            seen_tools.add(tool)
    merged["sources"] = sources

    # Build also_found_by (tools other than primary)
    primary_tool = merged.get("tool", "")
    merged["also_found_by"] = sorted([
        s["tool"] for s in sources if s["tool"] != primary_tool
    ])

    # Fill missing optional fields from secondary findings
    for attr in ("description", "evidence", "remediation"):
        if not merged.get(attr):
            for f in sorted_group:
                val = f.get(attr)
                if val:
                    if isinstance(val, dict):
                        merged[attr] = val
                    else:
                        merged[attr] = str(val)
                    break

    return merged


def _make_source(f: Dict[str, Any]) -> Dict[str, Any]:
    """Create a source entry from a finding."""
    evidence = f.get("evidence", "")
    if isinstance(evidence, str) and len(evidence) > _MAX_EVIDENCE:
        evidence = evidence[:_MAX_EVIDENCE - 3] + "..."
    return {
        "tool": f.get("tool", ""),
        "evidence": evidence,
    }
