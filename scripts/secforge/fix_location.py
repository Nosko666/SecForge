"""SecForge v2 fix location inference — baseline (catalog-driven).

Assigns remediation.fix_locations[] to each finding based on the
cluster's candidate_fix_surfaces from catalog/clusters.json.

Baseline confidence is always "medium" or "low" (never "high").
"high" is reserved for --inspect mode where local files are found.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class FixLocationInference:
    """Baseline fix location inference from catalog."""

    def __init__(self, catalog_dir: Optional[Path] = None):
        self._clusters: Dict[str, Dict[str, Any]] = {}
        if catalog_dir is not None:
            self._load(catalog_dir)

    def _load(self, catalog_dir: Path) -> None:
        cl_path = catalog_dir / "clusters.json"
        if not cl_path.exists():
            return
        try:
            raw = json.loads(cl_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._clusters = {k: v for k, v in raw.items()
                                  if k != "_meta" and isinstance(v, dict)}
        except Exception:
            pass

    def assign_fix_locations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add remediation.fix_locations[] to each finding (baseline, catalog-only)."""
        for f in findings:
            cluster_id = f.get("cluster_id", "other")
            meta = self._clusters.get(cluster_id, {})
            surfaces = meta.get("candidate_fix_surfaces", [])
            difficulty = meta.get("remediation_difficulty", "unknown")

            if not surfaces:
                continue

            fix_locs = []
            for surface in surfaces[:3]:  # Top 3 candidates
                fix_locs.append({
                    "surface": surface,
                    "path": None,       # Populated by --inspect (Step 15)
                    "hint": None,       # Populated by --inspect
                    "confidence": "medium",  # Baseline is always medium
                })

            # Ensure remediation dict exists
            if not isinstance(f.get("remediation"), dict):
                f["remediation"] = {}
            f["remediation"]["fix_locations"] = fix_locs
            if difficulty != "unknown":
                f["remediation"]["difficulty"] = difficulty

        return findings
