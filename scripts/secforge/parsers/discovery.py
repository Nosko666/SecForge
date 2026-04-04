"""SecForge v2 parsers: Subfinder + httpx (discovery/attack surface)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Set

from secforge.parsers import register
from secforge.parsers._base import iter_jsonl, make_finding
from secforge.normalize import truncate


@register("emaildns/subfinder.jsonl")
def parse_subfinder(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    hosts: Set[str] = set()
    for obj in iter_jsonl(fpath):
        if isinstance(obj, dict):
            h = obj.get("host")
            if h:
                hosts.add(str(h))
    if not hosts:
        return []
    sample = sorted(hosts)[:50]
    return [make_finding(
        issue_key="discovery.subdomains_found",
        title="Subdomains discovered",
        severity="info",
        tool="subfinder",
        category="discovery",
        asset={"type": "web", "host": context.get("target_host", "")},
        description="Subfinder discovered subdomains that may include forgotten staging/dev environments.",
        evidence=truncate("\n".join(sample), 900),
        remediation_summary="Inventory and secure all discovered subdomains; decommission unused hosts.",
    )]


@register("emaildns/httpx.jsonl")
def parse_httpx(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    alive: List[str] = []
    for obj in iter_jsonl(fpath):
        if not isinstance(obj, dict):
            continue
        url = obj.get("url")
        status = obj.get("status_code") or obj.get("status-code") or obj.get("statusCode")
        if url:
            if status is not None and str(status).isdigit():
                alive.append(f"{url} ({status})")
            else:
                alive.append(str(url))
        if len(alive) >= 50:
            break
    if not alive:
        return []
    return [make_finding(
        issue_key="discovery.live_hosts_found",
        title="Live hosts discovered (httpx)",
        severity="info",
        tool="httpx",
        category="discovery",
        asset={"type": "web", "host": context.get("target_host", "")},
        description="httpx probed discovered hosts for responsive HTTP(S) services.",
        evidence=truncate("\n".join(alive), 900),
        remediation_summary="Review exposed services on discovered hosts; ensure consistent security controls.",
    )]
