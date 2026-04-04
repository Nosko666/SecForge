"""SecForge v2 parser: ffuf (webapp/ffuf.json)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import redact_text, truncate


@register("webapp/ffuf.json")
def parse_ffuf(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []
    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    urls: List[str] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        status = r.get("status")
        if url and status and str(status).isdigit():
            urls.append(f"{url} ({status})")
        if len(urls) >= 50:
            break

    if not urls:
        return []

    return [make_finding(
        issue_key="discovery.paths_found",
        title="Content discovery results (ffuf)",
        severity="info",
        tool="ffuf",
        category="discovery",
        asset={"type": "web", "host": context.get("target_host", ""), "url": context.get("target_url", "")},
        description="ffuf discovered paths that returned non-404 responses.",
        evidence=truncate(redact_text("\n".join(urls)), 800),
        remediation_summary="Review discovered paths and ensure sensitive endpoints are protected.",
    )]
