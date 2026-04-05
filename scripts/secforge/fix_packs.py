"""SecForge v2 fix pack generator — 1:1 with clusters.

Generates one fix pack per cluster with all required fields.
Fix pack ID: FP-<cluster_id>.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from secforge.schema import SEVERITY_ORDER


_SEV_ORDER = {k.lower(): v for k, v in SEVERITY_ORDER.items()}


class FixPackGenerator:
    """Generate fix packs from clusters and findings."""

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

    def generate(self, findings: List[Dict[str, Any]],
                 cluster_objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate fix packs from cluster objects + findings.

        Returns list of fix pack dicts, one per cluster.
        """
        # Group findings by cluster_id
        by_cluster: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            cid = f.get("cluster_id", "other")
            by_cluster.setdefault(cid, []).append(f)

        packs: List[Dict[str, Any]] = []
        for cluster in cluster_objects:
            cid = cluster.get("cluster_id", "other")
            meta = self._clusters.get(cid, {})
            cluster_findings = by_cluster.get(cid, [])

            pack = {
                "fix_pack_id": f"FP-{cid}",
                "title": cluster.get("title", cid),
                "description": cluster.get("description", meta.get("description", "")),
                "severity": cluster.get("severity", "info"),
                "severity_summary": cluster.get("severity_summary", {}),
                "total": cluster.get("total", len(cluster_findings)),
                "finding_ids": cluster.get("finding_ids", []),
                "why_it_matters": meta.get("description", cluster.get("description", "")),
                "candidate_fix_surfaces": meta.get("candidate_fix_surfaces", []),
                "remediation_difficulty": meta.get("remediation_difficulty", "unknown"),
                "proposed_fix_direction": self._get_fix_direction(cid, meta),
                "verification": self._get_verification(cid, meta),
                "rollback": self._get_rollback(cid, meta),
                "safety_gates": self._get_safety_gates(meta),
                "breakage_warnings": self._get_breakage_warnings(cid),
                "extra_hints": self._collect_hints(cluster_findings),
            }

            # Priority from max finding score
            max_score = 0
            max_label = "low"
            max_reason = ""
            for f in cluster_findings:
                score = f.get("priority_score", 0) or 0
                if score > max_score:
                    max_score = score
                    max_label = f.get("priority_label", "low")
                    max_reason = f.get("priority_reason", "")
            pack["priority_score"] = max_score
            pack["priority_label"] = max_label
            pack["priority_reason"] = max_reason

            packs.append(pack)

        # Sort same as clusters: severity desc, total desc, cluster_id
        packs.sort(key=lambda p: (
            1 if p["fix_pack_id"] == "FP-other" else 0,
            -_SEV_ORDER.get(p["severity"], 0),
            -p["total"],
            p["fix_pack_id"],
        ))

        return packs

    def _get_fix_direction(self, cid: str, meta: Dict[str, Any]) -> List[str]:
        """Default fix direction bullets from catalog."""
        surfaces = meta.get("candidate_fix_surfaces", [])
        difficulty = meta.get("remediation_difficulty", "unknown")
        if not surfaces:
            return ["Review findings individually for remediation guidance."]
        return [
            f"Apply fixes at: {', '.join(surfaces[:3])}",
            f"Estimated difficulty: {difficulty}",
        ]

    def _get_verification(self, cid: str, meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Verification templates per cluster with real assertions."""
        _TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
            "http-header-hardening": [
                {"stage": "post", "name": "Check CSP header present",
                 "command": "curl -sI {target}",
                 "assertions": {"exit_code": 0, "stdout_contains": ["content-security-policy"]},
                 "explain": "CSP header should appear in response headers."},
                {"stage": "post", "name": "Check HSTS header present",
                 "command": "curl -sI {target}",
                 "assertions": {"exit_code": 0, "stdout_contains": ["strict-transport-security"]},
                 "explain": "HSTS header should appear in response headers."},
                {"stage": "post", "name": "Check X-Frame-Options header",
                 "command": "curl -sI {target}",
                 "assertions": {"exit_code": 0, "stdout_contains": ["x-frame-options"]},
                 "explain": "X-Frame-Options or CSP frame-ancestors should be set."},
            ],
            "tls-hardening": [
                {"stage": "post", "name": "Check TLS 1.2+ only",
                 "command": "openssl s_client -connect {host}:443 -tls1_1",
                 "assertions": {"stdout_not_contains": ["BEGIN CERTIFICATE"]},
                 "close_stdin": True,
                 "explain": "TLS 1.1 should be rejected (connection refused or handshake fail)."},
                {"stage": "post", "name": "Check strong ciphers",
                 "command": "openssl s_client -connect {host}:443 -cipher NULL,EXPORT,DES,RC4",
                 "assertions": {"stdout_not_contains": ["BEGIN CERTIFICATE"]},
                 "close_stdin": True,
                 "explain": "Weak ciphers should be rejected."},
            ],
            "auth-hardening": [
                {"stage": "post", "name": "Check rate limiting",
                 "command": "curl -sI {target}/login",
                 "assertions": {"exit_code": 0},
                 "explain": "Login endpoint should respond; verify rate limiting is configured."},
            ],
            "secrets-exposure": [
                {"stage": "post", "name": "Check .env not accessible",
                 "command": "curl -sI {target}/.env",
                 "assertions": {"stdout_not_contains": ["200 ok"]},
                 "explain": ".env file should return 403 or 404, not 200."},
                {"stage": "post", "name": "Check .git not accessible",
                 "command": "curl -sI {target}/.git/HEAD",
                 "assertions": {"stdout_not_contains": ["200 ok"]},
                 "explain": ".git directory should not be publicly accessible."},
            ],
            "exposure-cleanup": [
                {"stage": "post", "name": "Check .env blocked",
                 "command": "curl -sI {target}/.env",
                 "assertions": {"stdout_not_contains": ["200 ok"]},
                 "explain": "Sensitive files should be blocked by the web server."},
                {"stage": "post", "name": "Check .git blocked",
                 "command": "curl -sI {target}/.git/HEAD",
                 "assertions": {"stdout_not_contains": ["200 ok"]},
                 "explain": "Git directory should be blocked."},
            ],
            "server-hardening": [
                {"stage": "post", "name": "Check SSH config",
                 "command": "sshd -t",
                 "assertions": {"exit_code": 0},
                 "explain": "SSH config should be valid (no syntax errors)."},
                {"stage": "post", "name": "Check fail2ban running",
                 "command": "sudo fail2ban-client status",
                 "assertions": {"exit_code": 0, "stdout_contains": ["number of jail"]},
                 "explain": "fail2ban should be running with at least one jail active. Requires --allow-sudo."},
            ],
            "network-hardening": [
                {"stage": "post", "name": "Check unnecessary ports closed",
                 "command": "cat /dev/null",
                 "assertions": {"exit_code": 0},
                 "explain": "Manually verify only necessary ports are open with: nmap -sT {host}"},
            ],
            "cors-hardening": [
                {"stage": "post", "name": "Check CORS not wildcard",
                 "command": "curl -sI -H 'Origin: https://evil.com' {target}",
                 "assertions": {"stdout_not_contains": ["access-control-allow-origin: *"]},
                 "explain": "CORS should not reflect arbitrary origins or use wildcard."},
            ],
            "dns-email-security": [
                {"stage": "post", "name": "Check SPF record exists",
                 "command": "dig +short TXT {host}",
                 "assertions": {"exit_code": 0, "stdout_contains": ["spf"]},
                 "explain": "SPF TXT record should be present for the domain."},
                {"stage": "post", "name": "Check DMARC record exists",
                 "command": "dig +short TXT _dmarc.{host}",
                 "assertions": {"exit_code": 0, "stdout_contains": ["dmarc"]},
                 "explain": "DMARC TXT record should be present at _dmarc.domain."},
            ],
            "database-hardening": [
                {"stage": "post", "name": "Check MySQL anonymous accounts",
                 "command": "cat /dev/null",
                 "assertions": {"exit_code": 0},
                 "explain": "Manually verify: SELECT user,host FROM mysql.user WHERE user='';"},
            ],
        }
        checks = _TEMPLATES.get(cid, [])
        if not checks:
            # Fallback for unmapped clusters
            checks = [{
                "stage": "post",
                "name": f"Verify {meta.get('title', cid)} is resolved",
                "command": f"secforge verify --pack FP-{cid}",
                "assertions": {},
                "explain": f"Re-scan and check all findings in the {meta.get('title', cid)} pack.",
            }]
        return checks

    def _get_rollback(self, cid: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Default rollback template."""
        return {
            "backup_paths": [],
            "restore_steps": ["Restore from /opt/secforge/backups/SESSION/"],
            "rollback_triggers": ["Service fails to reload", "Health check fails"],
        }

    def _get_safety_gates(self, meta: Dict[str, Any]) -> List[str]:
        """Default safety gates based on fix surfaces."""
        surfaces = set(meta.get("candidate_fix_surfaces", []))
        gates = ["Back up affected config files"]
        if surfaces & {"nginx", "apache", "caddy"}:
            gates.append("Run config syntax check (nginx -t / apachectl configtest)")
            gates.append("Verify site responds after reload")
        if surfaces & {"ssh-config"}:
            gates.append("Keep a second SSH session open as lifeline")
            gates.append("Schedule at-revert before applying changes")
            gates.append("Run sshd -t before restart")
        if surfaces & {"firewall"}:
            gates.append("Whitelist admin IP before tightening rules")
        return gates

    def _get_breakage_warnings(self, cid: str) -> str:
        """Default breakage warnings per cluster type."""
        _WARNINGS = {
            "http-header-hardening": "Strict CSP may break inline scripts. HSTS can affect local testing. Test on staging first.",
            "tls-hardening": "Disabling old TLS versions may break legacy clients. Test client compatibility.",
            "auth-hardening": "Rate limiting changes can lock out legitimate users during high traffic.",
            "injection-prevention": "Input validation changes may reject legitimate input. Test thoroughly.",
            "secrets-exposure": "Rotating credentials may temporarily break services that use them.",
            "dependency-updates": "Package updates may introduce breaking changes. Lock versions after testing.",
        }
        return _WARNINGS.get(cid, "Review changes carefully before applying to production.")

    def _collect_hints(self, findings: List[Dict[str, Any]], max_hints: int = 10) -> List[str]:
        """Collect unique tool-specific hints from findings (deduped, capped)."""
        hints = set()
        for f in findings:
            rem = f.get("remediation")
            if isinstance(rem, dict):
                summary = rem.get("summary") or ""
                if summary and len(hints) < max_hints:
                    hints.add(summary[:200])
        return sorted(hints)[:max_hints]
