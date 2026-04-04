"""SecForge v2 clustering engine — deterministic, catalog-driven.

Groups findings by cluster_id (from issue_key → catalog → cluster mapping).
Builds explicit clusters[] array for findings.json output.

Ordering: severity desc → total desc → cluster_id. "other" always last.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from secforge.schema import SEVERITY_ORDER

# v2 uses lowercase severities; build a lowercase lookup
_SEV_ORDER = {k.lower(): v for k, v in SEVERITY_ORDER.items()}


class ClusterEngine:
    """Deterministic clustering from catalog/clusters.json."""

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

    def assign_clusters(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Set cluster_id on each finding. Returns the same list (mutated)."""
        for f in findings:
            cid = f.get("cluster_id")
            if not cid or cid == "other":
                # Try to get cluster_id from enriched metadata
                # (set by pipeline after IssueKeyResolver.enrich())
                cid = f.get("_enriched_cluster_id", "other")
            f["cluster_id"] = cid if cid in self._clusters else "other"
        return findings

    def build_cluster_objects(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build explicit clusters[] array from findings.

        Each cluster: cluster_id, title, description, severity (max),
        severity_summary, total, finding_ids, finding_fingerprints.
        Sorted: severity desc → total desc → cluster_id. "other" last.
        """
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            cid = f.get("cluster_id", "other")
            groups.setdefault(cid, []).append(f)

        clusters: List[Dict[str, Any]] = []
        for cid, group in groups.items():
            meta = self._clusters.get(cid, {})
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            max_sev = "info"
            fids: List[str] = []
            fps: List[str] = []

            for f in group:
                s = f.get("severity", "info")
                sev_counts[s] = sev_counts.get(s, 0) + 1
                if _SEV_ORDER.get(s, 0) > _SEV_ORDER.get(max_sev, 0):
                    max_sev = s
                fid = f.get("id", "")
                if fid:
                    fids.append(fid)
                fp = f.get("fingerprint", "")
                if fp and fp not in fps:
                    fps.append(fp)

            clusters.append({
                "cluster_id": cid,
                "title": meta.get("title", cid.replace("-", " ").title()),
                "description": meta.get("description", ""),
                "severity": max_sev,
                "severity_summary": sev_counts,
                "total": len(group),
                "finding_ids": fids,
                "finding_fingerprints": fps,
            })

        # Sort: severity desc, total desc, cluster_id alpha. "other" always last.
        def sort_key(c: Dict[str, Any]):
            is_other = 1 if c["cluster_id"] == "other" else 0
            sev_rank = -_SEV_ORDER.get(c["severity"], 0)
            return (is_other, sev_rank, -c["total"], c["cluster_id"])

        clusters.sort(key=sort_key)
        return clusters

    def get_cluster_meta(self, cluster_id: str) -> Dict[str, Any]:
        """Get cluster metadata (title, description, fix surfaces, difficulty)."""
        return dict(self._clusters.get(cluster_id, {}))
