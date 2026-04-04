"""SecForge v2 parser: Masscan (network/masscan.json)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Set

from secforge.parsers import register
from secforge.parsers._base import load_json_file, iter_jsonl, make_finding


@register("network/masscan.json")
def parse_masscan(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    ports: Set[str] = set()

    if isinstance(data, list):
        for obj in data:
            if isinstance(obj, dict) and "ports" in obj:
                for p in obj.get("ports", []) or []:
                    if isinstance(p, dict) and "port" in p:
                        ports.add(str(p["port"]))
    else:
        for obj in iter_jsonl(fpath):
            if isinstance(obj, dict) and "ports" in obj:
                for p in obj.get("ports", []) or []:
                    if isinstance(p, dict) and "port" in p:
                        ports.add(str(p["port"]))

    if not ports:
        return []

    port_list = ", ".join(sorted(ports, key=lambda x: int(x) if x.isdigit() else 0)[:100])
    return [make_finding(
        issue_key="network.open_port",
        title="Open ports discovered (masscan)",
        severity="info",
        tool="masscan",
        category="network",
        asset={"type": "host", "host": context.get("target_host", "")},
        description="Masscan reported open TCP ports on the target.",
        evidence=f"Ports: {port_list}",
        remediation_summary="Confirm exposed services are required; restrict with firewall rules where appropriate.",
    )]
