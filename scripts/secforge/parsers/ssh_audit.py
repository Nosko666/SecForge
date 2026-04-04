"""SecForge v2 parser: ssh-audit (hardening/ssh-audit.json or network/ssh-audit.json)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import normalize_severity_v2, redact_text, truncate


def _parse_ssh_audit_impl(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []

    target_host = context.get("target_host", "")
    issues = []
    for key in ("issues", "recommendations", "warnings"):
        v = data.get(key)
        if isinstance(v, list):
            issues = v
            break

    findings: List[Dict[str, Any]] = []
    if isinstance(issues, list) and issues:
        for item in issues[:200]:
            if not isinstance(item, dict):
                continue
            text = item.get("text") or item.get("message") or item.get("description") or ""
            level = item.get("level") or item.get("severity") or item.get("risk") or ""
            sev = normalize_severity_v2(level, "info")
            findings.append(make_finding(
                issue_key="network.ssh_weak_config",
                title="SSH configuration issue",
                severity=sev,
                tool="ssh-audit",
                category="hardening",
                asset={"type": "host", "host": target_host, "port": 22, "protocol": "ssh"},
                description=truncate(redact_text(str(text)), 800),
                remediation_summary="Review sshd configuration, disable weak algorithms, and prefer modern ciphers/MACs.",
            ))
        return findings

    # Fallback: report exists but format unknown
    return [make_finding(
        issue_key="network.ssh_weak_config",
        title="ssh-audit report available",
        severity="info",
        tool="ssh-audit",
        category="hardening",
        asset={"type": "host", "host": target_host, "port": 22, "protocol": "ssh"},
        description="ssh-audit JSON report was generated but could not be parsed into individual findings.",
        evidence=f"File: {fpath.name}",
    )]


@register("hardening/ssh-audit.json")
def parse_ssh_audit_hardening(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _parse_ssh_audit_impl(fpath, context)


@register("network/ssh-audit.json")
def parse_ssh_audit_network(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _parse_ssh_audit_impl(fpath, context)
