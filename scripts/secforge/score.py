"""SecForge v2 priority scoring engine — 7 weighted factors.

Computes priority_score (0-100), priority_label, priority_reason,
and priority_breakdown per finding. Pack-level = max of member scores.

Loads defaults from catalog/priority_weights.json.
Merges /opt/secforge/config/priority-weights.json if present (user overrides).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


# Label thresholds (from catalog, overridable)
_DEFAULT_LABELS = {
    "critical": {"min": 90},
    "high": {"min": 70},
    "medium": {"min": 40},
    "low": {"min": 1},
}


class PriorityScorer:
    """7-factor priority scoring with tunable weights."""

    def __init__(self, catalog_dir: Optional[Path] = None,
                 config_dir: Optional[Path] = None):
        self._weights: Dict[str, Any] = {}
        self._labels = dict(_DEFAULT_LABELS)
        if catalog_dir is not None:
            self._load(catalog_dir, config_dir)

    def _load(self, catalog_dir: Path, config_dir: Optional[Path] = None) -> None:
        # Load defaults
        pw_path = catalog_dir / "priority_weights.json"
        if pw_path.exists():
            try:
                raw = json.loads(pw_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._weights = {k: v for k, v in raw.items() if k != "_meta"}
                    if "labels" in raw:
                        self._labels = raw["labels"]
            except Exception:
                pass

        # Merge user overrides
        if config_dir is not None:
            override_path = config_dir / "priority-weights.json"
            if override_path.exists():
                try:
                    overrides = json.loads(override_path.read_text(encoding="utf-8"))
                    if isinstance(overrides, dict):
                        for k, v in overrides.items():
                            if k != "_meta" and isinstance(v, dict):
                                if k in self._weights and isinstance(self._weights[k], dict):
                                    self._weights[k].update(v)
                                else:
                                    self._weights[k] = v
                except Exception:
                    pass

    def score_finding(self, f: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a finding with priority_score, priority_label, priority_reason, priority_breakdown."""
        breakdown = {
            "severity": self._score_severity(f),
            "internet_exposure": self._score_exposure(f),
            "confidence": self._score_confidence(f),
            "ease_of_fix": self._score_ease(f),
            "multi_tool": self._score_multi_tool(f),
            "blast_radius": self._score_blast_radius(f),
            "age": self._score_age(f),
        }
        total = sum(breakdown.values())
        total = max(0, min(100, total))

        label = "low"
        for lbl in ("critical", "high", "medium", "low"):
            if total >= self._labels.get(lbl, {}).get("min", 0):
                label = lbl
                break

        # Build human reason
        top_factors = sorted(breakdown.items(), key=lambda x: -x[1])[:3]
        reason_parts = []
        for factor, pts in top_factors:
            if pts > 0:
                reason_parts.append(f"{factor.replace('_', ' ')}={pts}")
        reason = " + ".join(reason_parts) if reason_parts else "minimal risk"

        f["priority_score"] = total
        f["priority_label"] = label
        f["priority_reason"] = reason
        f["priority_breakdown"] = breakdown
        return f

    def score_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score all findings in place."""
        for f in findings:
            self.score_finding(f)
        return findings

    def score_pack(self, pack: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Score a fix pack as max of its member findings' scores."""
        max_score = 0
        max_label = "low"
        max_reason = ""
        for f in findings:
            score = f.get("priority_score", 0)
            if score > max_score:
                max_score = score
                max_label = f.get("priority_label", "low")
                max_reason = f.get("priority_reason", "")
        pack["priority_score"] = max_score
        pack["priority_label"] = max_label
        pack["priority_reason"] = max_reason
        return pack

    # --- Factor scoring ---

    def _get_values(self, factor: str) -> Dict[str, int]:
        w = self._weights.get(factor, {})
        return w.get("values", {}) if isinstance(w, dict) else {}

    def _score_severity(self, f: Dict[str, Any]) -> int:
        vals = self._get_values("severity")
        sev = (f.get("severity") or "info").lower()
        return vals.get(sev, 2)

    def _score_exposure(self, f: Dict[str, Any]) -> int:
        """Pure string/IP matching, never DNS resolution."""
        vals = self._get_values("internet_exposure")
        asset = f.get("asset") or {}
        host = (asset.get("host") or "").lower().strip()

        if not host or host in ("localhost", "127.0.0.1", "::1", "this_server"):
            return vals.get("localhost", 2)

        # RFC1918 check
        if (host.startswith("10.") or
            host.startswith("192.168.") or
            any(host.startswith(f"172.{i}.") for i in range(16, 32))):
            return vals.get("internal", 8)

        # Private domain suffixes
        if host.endswith((".local", ".internal", ".lan", ".home")):
            return vals.get("internal", 8)

        return vals.get("public", 20)

    def _score_confidence(self, f: Dict[str, Any]) -> int:
        vals = self._get_values("confidence")
        conf = (f.get("confidence") or "possible").lower()
        return vals.get(conf, 4)

    def _score_ease(self, f: Dict[str, Any]) -> int:
        """From remediation.difficulty or cluster default."""
        vals = self._get_values("ease_of_fix")
        rem = f.get("remediation")
        if isinstance(rem, dict):
            diff = (rem.get("difficulty") or "unknown").lower()
            return vals.get(diff, 5)
        return vals.get("unknown", 5)

    def _score_multi_tool(self, f: Dict[str, Any]) -> int:
        vals = self._get_values("multi_tool")
        sources = f.get("sources", [])
        also = f.get("also_found_by", [])
        tool_count = max(len(sources), len(also) + 1)
        if tool_count >= 3:
            return vals.get("3+", 8)
        if tool_count == 2:
            return vals.get("2", 5)
        return vals.get("1", 2)

    def _score_blast_radius(self, f: Dict[str, Any]) -> int:
        vals = self._get_values("blast_radius")
        fp_type = f.get("_fingerprint_type", "")
        if fp_type in ("web_server_level", "host_level", "config_level"):
            return vals.get("server_wide", 7)
        if fp_type in ("web_endpoint_level",):
            return vals.get("single_endpoint", 1)
        # Infer from issue_key
        ik = f.get("issue_key", "")
        prefix = ik.split(".")[0] if "." in ik else ""
        if prefix in ("headers", "tls", "hardening", "dns", "network"):
            return vals.get("server_wide", 7)
        if prefix in ("xss", "sqli", "injection"):
            return vals.get("single_endpoint", 1)
        return vals.get("multi_endpoint", 4)

    def _score_age(self, f: Dict[str, Any]) -> int:
        """Age scoring. For new scans without history, returns 'fresh'."""
        vals = self._get_values("age")
        status = f.get("status", "new")
        if status == "reopened":
            return vals.get("fresh", 1) + vals.get("reopened_bonus", 3)
        # Without state DB connection, default to fresh
        return vals.get("fresh", 1)
