"""SecForge v2 issue_key resolver.

Parsers own tool→issue_key mapping (using tool-specific IDs).
This module provides:
  - validate(issue_key) — is this key in the catalog?
  - fallback(tool, rule_id, title) — stable key for unmapped findings
  - enrich(issue_key) — returns catalog metadata (cluster_id, normalized_title, etc.)
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional


class IssueKeyResolver:
    """Loads catalog/issue_keys.json and provides validation, fallback, and enrichment."""

    def __init__(self, catalog_dir: Optional[Path] = None):
        self._catalog: Dict[str, Dict[str, Any]] = {}
        if catalog_dir is not None:
            self._load(catalog_dir)

    def _load(self, catalog_dir: Path) -> None:
        ik_path = catalog_dir / "issue_keys.json"
        if not ik_path.exists():
            return
        try:
            raw = json.loads(ik_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._catalog = {k: v for k, v in raw.items()
                                 if k != "_meta" and isinstance(v, dict)}
        except Exception:
            pass

    def validate(self, issue_key: str) -> bool:
        """Is this issue_key in the catalog?"""
        return issue_key in self._catalog

    def fallback(self, tool: str, rule_id: Optional[str] = None,
                 title: Optional[str] = None) -> str:
        """Generate a stable issue_key for unmapped findings.

        Prefers unknown.<tool>.<rule_id> when a tool-specific stable ID exists.
        Last resort: unknown.<tool>.<sha256(title)[:8]>.
        """
        tool_slug = _slugify(tool or "unknown")
        if rule_id:
            rid = _slugify(rule_id)
            if rid:
                return f"unknown.{tool_slug}.{rid}"
        # Last resort — hash of title (can change if tool rewrites title text)
        title_str = (title or "untitled").strip().lower()
        title_hash = hashlib.sha256(title_str.encode("utf-8")).hexdigest()[:8]
        return f"unknown.{tool_slug}.{title_hash}"

    def enrich(self, issue_key: str) -> Dict[str, Any]:
        """Return catalog metadata for an issue_key.

        Returns dict with: cluster_id, normalized_title, category, fingerprint_type.
        For unknown keys, returns defaults.
        """
        if issue_key in self._catalog:
            return dict(self._catalog[issue_key])
        # Unknown key — derive defaults from the key itself
        return {
            "cluster_id": "other",
            "normalized_title": issue_key.replace(".", " ").replace("_", " "),
            "category": _prefix(issue_key) or "misconfig",
            "fingerprint_type": "web_server_level",
        }

    @property
    def catalog_size(self) -> int:
        return len(self._catalog)


def _slugify(text: str, max_len: int = 40) -> str:
    """Convert text to a safe slug (lowercase, alphanumeric + dots + hyphens)."""
    s = text.strip().lower()
    s = re.sub(r"[^a-z0-9._-]", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:max_len] if s else "unknown"


def _prefix(issue_key: str) -> str:
    """Extract the prefix before the first dot."""
    if "." in issue_key:
        return issue_key.split(".")[0]
    return ""
