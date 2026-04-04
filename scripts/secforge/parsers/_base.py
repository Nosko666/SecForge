"""Shared parser utilities for SecForge v2 parsers.

Extracted from merge-reports.py for reuse across all tool parsers.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def safe_read_text(path: Path) -> str:
    """Read a file with fallback encoding handling."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        try:
            return path.read_text(errors="replace")
        except Exception:
            return ""


def load_json_file(path: Path) -> Optional[Any]:
    """Load and parse a JSON file. Returns None on failure."""
    raw = safe_read_text(path).strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def iter_jsonl(path: Path) -> Iterable[Any]:
    """Iterate over JSON Lines file, yielding one parsed object per line."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except Exception:
        return


def make_finding(
    *,
    issue_key: str,
    title: str,
    severity: str,
    confidence: str = "confirmed",
    tool: str,
    category: str,
    asset_type: str = "web",
    asset: Optional[Dict[str, Any]] = None,
    location: Optional[Dict[str, Any]] = None,
    description: str = "",
    evidence: str = "",
    remediation_summary: str = "",
    vuln_identifiers: Optional[List[Dict[str, str]]] = None,
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create a v2 finding dict with mandatory fields.

    Parsers call this to emit findings. id and fingerprint are set later
    by the pipeline (after issue_key resolution and fingerprint computation).
    """
    f: Dict[str, Any] = {
        "id": "",  # Set by pipeline after sort
        "fingerprint": "",  # Set by fingerprint engine
        "issue_key": issue_key,
        "title": title,
        "normalized_title": "",  # Set by enrichment from catalog
        "severity": severity.lower(),
        "confidence": confidence.lower(),
        "tool": tool,
        "category": category,
        "asset": asset or {"type": asset_type},
    }
    if location:
        f["location"] = location
    if description:
        f["description"] = description
    if evidence:
        f["evidence"] = evidence
    if remediation_summary:
        f["remediation"] = {"summary": remediation_summary}
    if vuln_identifiers:
        f["vuln"] = {"identifiers": vuln_identifiers}
    if tags:
        f["tags"] = tags
    return f
