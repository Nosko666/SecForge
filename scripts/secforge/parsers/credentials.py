"""SecForge v2 parsers: Hydra + NetExec (credential testing)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import safe_read_text, make_finding
from secforge.normalize import redact_text, truncate


@register("passwords/hydra.txt")
def parse_hydra(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    text = safe_read_text(fpath)
    if not text:
        return []
    hits = []
    for line in text.splitlines():
        if "login:" in line.lower() and "password:" in line.lower():
            line = redact_text(line)
            line = re.sub(r"(?i)(password:\s*)(\S+)", r"\1[REDACTED]", line)
            hits.append(line.strip())
            if len(hits) >= 20:
                break
    if not hits:
        return []
    return [make_finding(
        issue_key="auth.credentials_found",
        title="Valid credentials found (hydra)",
        severity="critical",
        tool="hydra",
        category="auth",
        asset={"type": "host", "host": context.get("target_host", ""), "protocol": "ssh"},
        description="Hydra reported at least one valid credential. Passwords are redacted.",
        evidence=truncate("\n".join(hits), 900),
        remediation_summary="Disable password auth if possible, rotate credentials, and enforce MFA/keys + rate limiting.",
    )]


@register("passwords/netexec.txt")
def parse_netexec(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    text = safe_read_text(fpath)
    if not text:
        return []
    hits = []
    for line in text.splitlines():
        if "pwn3d" in line.lower() or ("[+]" in line and "ssh" in line.lower()):
            line = redact_text(line)
            line = re.sub(r"(?i)(password|pass)\s*[:=]\s*\S+", r"\1=[REDACTED]", line)
            hits.append(line.strip())
            if len(hits) >= 20:
                break
    if not hits:
        return []
    return [make_finding(
        issue_key="auth.credentials_found",
        title="Valid credentials found (netexec)",
        severity="critical",
        tool="netexec",
        category="auth",
        asset={"type": "host", "host": context.get("target_host", ""), "protocol": "ssh"},
        description="NetExec reported at least one successful authentication. Passwords are redacted.",
        evidence=truncate("\n".join(hits), 900),
        remediation_summary="Rotate credentials, restrict SSH access, and prefer key-based auth + MFA.",
    )]
