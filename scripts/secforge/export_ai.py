"""SecForge v2 AI export module — 5 markdown export modes.

Modes:
  1. quick-fix  — one finding at a time (--finding SF-###)
  2. fix-pack   — one cluster/pack (--pack FP-xxx or cluster_id)
  3. full-plan  — all packs prioritized
  4. patch      — designed for AI to edit code/config (--pack)
  5. explain    — plain English for vibecoders (--finding SF-###)

Output: markdown to stdout by default. --out <path> for file.
Session resolution: latest-$USER → latest → --session/--in.
Front-matter header on every export (10 fields).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def export(
    mode: str,
    findings_data: Dict[str, Any],
    finding_id: Optional[str] = None,
    pack_id: Optional[str] = None,
    detail: str = "operator",
    system_info: Optional[str] = None,
    stack_hints: Optional[str] = None,
) -> str:
    """Generate markdown export for the given mode.

    Returns markdown string (print to stdout or save to file).
    """
    if mode == "quick-fix":
        return _export_quick_fix(findings_data, finding_id, detail)
    if mode == "fix-pack":
        return _export_fix_pack(findings_data, pack_id, detail, system_info, stack_hints)
    if mode == "full-plan":
        return _export_full_plan(findings_data, detail, system_info, stack_hints)
    if mode == "patch":
        return _export_patch(findings_data, pack_id, system_info, stack_hints)
    if mode == "explain":
        return _export_explain(findings_data, finding_id)
    return f"Unknown export mode: {mode}"


def _front_matter(mode: str, data: Dict[str, Any],
                  system_info: Optional[str] = None,
                  stack_hints: Optional[str] = None,
                  detail_level: str = "operator") -> str:
    """Standard front-matter header for every export (10 fields)."""
    target = data.get("target", "unknown")
    scan_date = data.get("scan_date", "")
    profile = data.get("scan_profile", "")

    lines = [
        "---",
        "secforge_export: true",
        f"mode: {mode}",
        f"target: {target}",
        f"scan_date: {scan_date}",
        f"scan_profile: {profile}",
        f"detail_level: {detail_level}",
    ]
    if system_info:
        lines.append(f"system: {system_info}")
    if stack_hints:
        lines.append(f"stack_hints: {stack_hints}")
    lines.extend([
        "role: You are a security remediation assistant. The user is not a security expert.",
        "safety: Do not apply changes without explicit user approval. Back up configs before editing. Verify after every change. If unsure, explain the risk and ask.",
        "---",
        "",
    ])
    return "\n".join(lines)


def _find_finding(data: Dict[str, Any], finding_id: str) -> Optional[Dict[str, Any]]:
    """Find a finding by SF-### ID."""
    for f in data.get("findings", []):
        if f.get("id") == finding_id:
            return f
    return None


def _find_pack(data: Dict[str, Any], pack_id: str) -> Optional[Dict[str, Any]]:
    """Find a fix pack by FP-xxx or cluster_id."""
    # Normalize: accept both FP-xxx and xxx
    normalized = pack_id if pack_id.startswith("FP-") else f"FP-{pack_id}"
    for p in data.get("fix_packs", []):
        if p.get("fix_pack_id") == normalized:
            return p
    return None


# --- Mode implementations ---

def _export_quick_fix(data: Dict[str, Any], finding_id: Optional[str],
                      detail: str) -> str:
    if not finding_id:
        return "Error: --finding SF-### required for quick-fix mode."
    f = _find_finding(data, finding_id)
    if not f:
        return f"Error: finding {finding_id} not found."

    md = _front_matter("quick-fix", data, detail_level=detail)
    md += f"## SecForge Fix: {f.get('title', '')} ({finding_id})\n\n"
    md += f"**Severity:** {f.get('severity', '?')} | "
    md += f"**Confidence:** {f.get('confidence', '?')} | "
    md += f"**Found by:** {f.get('tool', '?')}"
    afb = f.get("also_found_by", [])
    if afb:
        md += f", {', '.join(afb)}"
    md += "\n\n"

    md += "### What's wrong\n"
    md += f"{f.get('description', f.get('title', ''))}\n\n"

    evidence = f.get("evidence", "")
    if evidence:
        md += "### Evidence\n"
        md += f"{evidence}\n\n"

    # Fix location
    rem = f.get("remediation", {})
    if isinstance(rem, dict):
        locs = rem.get("fix_locations", [])
        if locs:
            md += "### Likely fix location\n"
            for loc in locs[:3]:
                surface = loc.get("surface", "?")
                path = loc.get("path") or "(detect with --inspect)"
                md += f"- **{surface}**: {path}\n"
            md += "\n"

        summary = rem.get("summary", "")
        if summary:
            md += "### Suggested fix\n"
            md += f"{summary}\n\n"

    # Verification
    verifications = f.get("verification", [])
    if verifications:
        md += "### Verify\n"
        for v in verifications:
            if isinstance(v, dict):
                md += f"```\n{v.get('command', '')}\n```\n"
                md += f"Expected: {v.get('explain', '')}\n\n"

    return md


def _export_fix_pack(data: Dict[str, Any], pack_id: Optional[str],
                     detail: str, system_info: Optional[str],
                     stack_hints: Optional[str]) -> str:
    if not pack_id:
        return "Error: --pack required for fix-pack mode."
    pack = _find_pack(data, pack_id)
    if not pack:
        return f"Error: fix pack {pack_id} not found."

    md = _front_matter("fix-pack", data, system_info, stack_hints, detail_level=detail)
    md += f"## Fix Pack: {pack.get('title', '')} ({pack.get('fix_pack_id', '')})\n\n"
    md += f"**Priority:** {pack.get('priority_label', '?')} (score {pack.get('priority_score', '?')}) | "
    md += f"**Findings:** {pack.get('total', 0)} | "
    md += f"**Difficulty:** {pack.get('remediation_difficulty', '?')}\n\n"

    md += "### Why it matters\n"
    md += f"{pack.get('why_it_matters', pack.get('description', ''))}\n\n"

    md += "### Findings in this pack\n"
    for fid in pack.get("finding_ids", []):
        f = _find_finding(data, fid)
        if f:
            md += f"- **{fid}** [{f.get('severity', '?')}]: {f.get('title', '')}\n"
    md += "\n"

    md += "### Fix direction\n"
    for step in pack.get("proposed_fix_direction", []):
        md += f"- {step}\n"
    md += "\n"

    if detail != "beginner":
        surfaces = pack.get("candidate_fix_surfaces", [])
        if surfaces:
            md += f"### Fix surfaces\n{', '.join(surfaces)}\n\n"

    warnings = pack.get("breakage_warnings", "")
    if warnings:
        md += "### What might break\n"
        md += f"{warnings}\n\n"

    md += "### Verify after fixing\n"
    md += f"```\nsecforge verify --pack {pack.get('fix_pack_id', '')} --run\n```\n\n"

    return md


def _export_full_plan(data: Dict[str, Any], detail: str,
                      system_info: Optional[str],
                      stack_hints: Optional[str]) -> str:
    md = _front_matter("full-plan", data, system_info, stack_hints, detail_level=detail)
    summary = data.get("summary", {})
    counts = summary.get("severity_counts", {})

    md += "## SecForge Full Remediation Plan\n\n"
    md += f"**Total findings:** {summary.get('total_findings', 0)} | "
    md += f"**Fix packs:** {summary.get('total_fix_packs', 0)}\n\n"
    md += f"Severity: {counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
    md += f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low, {counts.get('info', 0)} info\n\n"

    # Critical callouts
    callouts = summary.get("critical_callouts", [])
    if callouts:
        md += "### Critical findings (fix immediately)\n"
        for c in callouts:
            md += f"- **{c.get('id', '?')}**: {c.get('title', '')}\n"
        md += "\n"

    md += "### Fix packs (by priority)\n\n"
    for i, pack in enumerate(data.get("fix_packs", []), 1):
        sev = pack.get("severity", "?")
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(sev, "")
        md += f"{i}. {emoji} **{pack.get('title', '')}** — {pack.get('total', 0)} findings "
        md += f"(priority: {pack.get('priority_label', '?')}, score: {pack.get('priority_score', '?')})\n"
        md += f"   {pack.get('description', '')}\n"
        md += f"   → `secforge export --mode fix-pack --pack {pack.get('fix_pack_id', '')}`\n\n"

    md += "---\n"
    md += "Start with #1. Fix, verify, rescan. Use `secforge diff` to track progress.\n"

    return md


def _export_patch(data: Dict[str, Any], pack_id: Optional[str],
                  system_info: Optional[str],
                  stack_hints: Optional[str]) -> str:
    if not pack_id:
        return "Error: --pack required for patch mode."
    pack = _find_pack(data, pack_id)
    if not pack:
        return f"Error: fix pack {pack_id} not found."

    md = _front_matter("patch", data, system_info, stack_hints, detail_level="operator")
    md += f"## Patch Request: {pack.get('title', '')} ({pack.get('fix_pack_id', '')})\n\n"
    md += "Generate exact config/code changes for each finding below.\n"
    md += "For each change: show the diff, explain the impact, and provide a verification command.\n\n"

    for fid in pack.get("finding_ids", []):
        f = _find_finding(data, fid)
        if not f:
            continue
        md += f"### {fid}: {f.get('title', '')}\n"
        md += f"- Severity: {f.get('severity', '?')}\n"
        rem = f.get("remediation", {})
        if isinstance(rem, dict):
            locs = rem.get("fix_locations", [])
            for loc in locs[:2]:
                path = loc.get("path") or loc.get("surface", "?")
                md += f"- Fix at: {path}\n"
        md += f"- Evidence: {f.get('evidence', '(none)')[:200]}\n\n"

    md += "### Safety gates\n"
    for gate in pack.get("safety_gates", []):
        md += f"- {gate}\n"
    md += "\n"

    md += "### Rollback if something breaks\n"
    rollback = pack.get("rollback", {})
    if isinstance(rollback, dict):
        for step in rollback.get("restore_steps", []):
            md += f"- {step}\n"

    return md


def _export_explain(data: Dict[str, Any], finding_id: Optional[str]) -> str:
    if not finding_id:
        return "Error: --finding SF-### required for explain mode."
    f = _find_finding(data, finding_id)
    if not f:
        return f"Error: finding {finding_id} not found."

    md = _front_matter("explain", data)
    md += f"## What is {finding_id}?\n\n"
    md += f"**{f.get('title', '')}**\n\n"
    md += f"{f.get('description', 'No description available.')}\n\n"

    md += "### Should I worry?\n"
    sev = f.get("severity", "info")
    if sev in ("critical", "high"):
        md += "**Yes.** This is a serious security issue that should be fixed as soon as possible.\n\n"
    elif sev == "medium":
        md += "**Probably.** This is a moderate security issue. Fix it soon, but it's not an emergency.\n\n"
    elif sev == "low":
        md += "**Not urgently.** This is a low-risk issue. Good to fix when you have time.\n\n"
    else:
        md += "**Not really.** This is informational — good to know but not a security risk.\n\n"

    evidence = f.get("evidence", "")
    if evidence:
        md += "### What was found\n"
        md += f"{evidence[:300]}\n\n"

    rem = f.get("remediation", {})
    if isinstance(rem, dict) and rem.get("summary"):
        md += "### How to fix it\n"
        md += f"{rem['summary']}\n\n"

    md += f"For the full fix: `secforge export --mode quick-fix --finding {finding_id}`\n"

    return md


# --- Session resolution ---

def resolve_session(reports_dir: Path, session_spec: Optional[str] = None) -> Optional[Path]:
    """Resolve which findings.json to read.

    Priority: --session spec → latest-$USER → latest → None.
    """
    if session_spec:
        # Direct session ID or path
        p = Path(session_spec)
        if p.is_file():
            return p
        if p.is_dir():
            return p / "findings.json"
        # Try as session ID under reports_dir
        sp = reports_dir / session_spec / "findings.json"
        if sp.exists():
            return sp

    # latest-$USER
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    if user:
        user_latest = reports_dir / f"latest-{user}"
        if user_latest.exists():
            target = user_latest.resolve()
            fj = target / "findings.json" if target.is_dir() else target
            if fj.exists():
                return fj

    # Global latest
    latest = reports_dir / "latest"
    if latest.exists():
        target = latest.resolve()
        fj = target / "findings.json" if target.is_dir() else target
        if fj.exists():
            return fj

    return None


def load_findings(path: Path) -> Dict[str, Any]:
    """Load and parse findings.json."""
    return json.loads(path.read_text(encoding="utf-8"))
