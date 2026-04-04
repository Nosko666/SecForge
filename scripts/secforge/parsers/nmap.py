"""SecForge v2 parser: Nmap XML output (network/nmap.xml)."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import safe_read_text, make_finding
from secforge.normalize import truncate


@register("network/nmap.xml")
def parse_nmap_xml(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(safe_read_text(fpath))
    except Exception:
        return []

    target_host = context.get("target_host", "")
    open_ports: List[str] = []

    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for p in ports_el.findall("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = p.get("portid") or ""
            proto = p.get("protocol") or ""
            service = p.find("service")
            svc = ""
            if service is not None:
                parts = [service.get("name") or "", service.get("product") or "", service.get("version") or ""]
                svc = " ".join([x for x in parts if x]).strip()
            entry = f"{proto}/{portid}"
            if svc:
                entry += f" ({svc})"
            open_ports.append(entry)

    if not open_ports:
        return []

    return [make_finding(
        issue_key="network.open_port",
        title="Open ports discovered (nmap)",
        severity="info",
        tool="nmap",
        category="network",
        asset={"type": "host", "host": target_host},
        description="Nmap reported open ports/services on the target.",
        evidence=truncate("\n".join(open_ports[:100]), 900),
        remediation_summary="Confirm exposed services are required, patched, and firewalled appropriately.",
    )]
