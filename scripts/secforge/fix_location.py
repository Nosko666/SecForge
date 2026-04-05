"""SecForge v2 fix location inference — baseline + --inspect refined.

Assigns remediation.fix_locations[] to each finding based on the
cluster's candidate_fix_surfaces from catalog/clusters.json.

Baseline confidence is always "medium" or "low" (never "high").
"high" is reserved for --inspect mode where local files are actually found.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


# Allowlisted paths to auto-read for --inspect (read-only, safe)
_INSPECT_PATHS: Dict[str, List[str]] = {
    "nginx": [
        "/etc/nginx/nginx.conf",
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/conf.d/default.conf",
    ],
    "apache": [
        "/etc/apache2/apache2.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/etc/httpd/conf/httpd.conf",
    ],
    "ssh-config": [
        "/etc/ssh/sshd_config",
        "/etc/ssh/sshd_config.d/",
    ],
    "firewall": [
        "/etc/ufw/ufw.conf",
    ],
    "sysctl": [
        "/etc/sysctl.conf",
        "/etc/sysctl.d/",
    ],
}

# Patterns to search for per cluster (surface → grep pattern)
_INSPECT_PATTERNS: Dict[str, Dict[str, str]] = {
    "http-header-hardening": {
        "nginx": "add_header|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options",
        "apache": "Header set|Header always set|Content-Security-Policy",
    },
    "tls-hardening": {
        "nginx": "ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers",
        "apache": "SSLProtocol|SSLCipherSuite",
    },
    "server-hardening": {
        "ssh-config": "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication",
    },
}


class FixLocationInference:
    """Baseline + refined fix location inference."""

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

    def assign_fix_locations(self, findings: List[Dict[str, Any]],
                             inspect: bool = False) -> List[Dict[str, Any]]:
        """Add remediation.fix_locations[] to each finding.

        If inspect=True, also probe allowlisted local files for matches.
        """
        for f in findings:
            cluster_id = f.get("cluster_id", "other")
            meta = self._clusters.get(cluster_id, {})
            surfaces = meta.get("candidate_fix_surfaces", [])
            difficulty = meta.get("remediation_difficulty", "unknown")

            if not surfaces:
                continue

            fix_locs = []
            for surface in surfaces[:3]:
                loc: Dict[str, Any] = {
                    "surface": surface,
                    "path": None,
                    "hint": None,
                    "confidence": "medium",
                }

                if inspect:
                    resolved = self._inspect_surface(surface, cluster_id)
                    if resolved:
                        loc["path"] = resolved["path"]
                        loc["hint"] = resolved.get("hint")
                        loc["confidence"] = "high"

                fix_locs.append(loc)

            if not isinstance(f.get("remediation"), dict):
                f["remediation"] = {}
            f["remediation"]["fix_locations"] = fix_locs
            if difficulty != "unknown":
                f["remediation"]["difficulty"] = difficulty

        return findings

    def _inspect_surface(self, surface: str, cluster_id: str) -> Optional[Dict[str, str]]:
        """Probe allowlisted local files for a surface. Returns {path, hint} or None."""
        paths = _INSPECT_PATHS.get(surface, [])
        pattern = (_INSPECT_PATTERNS.get(cluster_id, {}).get(surface) or "")

        for p in paths:
            pp = Path(p)
            if pp.is_dir():
                # Check files in directory
                try:
                    for child in sorted(pp.iterdir()):
                        if child.is_file() and child.stat().st_size < 1_000_000:
                            match = self._search_file(child, pattern)
                            if match:
                                return match
                except PermissionError:
                    continue
            elif pp.is_file():
                try:
                    if pp.stat().st_size < 1_000_000:
                        match = self._search_file(pp, pattern)
                        if match:
                            return match
                        # File exists but no pattern match → still useful
                        return {"path": str(pp), "hint": "file exists, review manually"}
                except PermissionError:
                    continue

        return None

    def _search_file(self, fpath: Path, pattern: str) -> Optional[Dict[str, str]]:
        """Search a file for pattern. Returns {path, hint} if found."""
        if not pattern:
            if fpath.exists():
                return {"path": str(fpath), "hint": "file exists, review manually"}
            return None
        try:
            import re
            text = fpath.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pattern, line, re.IGNORECASE):
                    snippet = line.strip()[:80]
                    return {"path": str(fpath), "hint": f"line {i}: {snippet}"}
        except Exception:
            pass
        return None
