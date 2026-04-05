"""SecForge v2 SQLite state manager.

Persistent finding tracking across scans: new/existing/fixed/reopened.
DB at /opt/secforge/state/secforge.db (root:secforge 0660, dir 3770).
PK: (project_id, fingerprint) — prevents cross-project collisions.

Root-safety: checks os.geteuid() and skips DB writes if running as root.
Conservative gating: only marks fixed if finding.tool is in tools_succeeded.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class StateDB:
    """SQLite state manager for persistent finding tracking."""

    def __init__(self, db_path: Optional[Path] = None, allow_root: bool = False):
        self._db_path = db_path or Path("/opt/secforge/state/secforge.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._is_root = os.geteuid() == 0 and not allow_root

    def open(self) -> bool:
        """Open the database. Returns False if root (skip writes) or file not accessible."""
        if self._is_root:
            import sys
            print("[secforge] WARN: Running as root — skipping state DB writes.", file=sys.stderr)
            return False  # Root never writes to state DB
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._ensure_schema()
            return True
        except Exception:
            self._conn = None
            return False

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def _ensure_schema(self) -> None:
        if not self._conn:
            return
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                display_name TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                project_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                asset_type TEXT,
                host TEXT,
                port INTEGER,
                endpoint TEXT,
                parameter TEXT,
                package_name TEXT,
                issue_key TEXT,
                status TEXT DEFAULT 'new',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                fixed_at TEXT,
                reopened_count INTEGER DEFAULT 0,
                ignore_reason TEXT,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                normalized_title TEXT,
                tool TEXT,
                category TEXT,
                cluster_id TEXT,
                PRIMARY KEY (project_id, fingerprint)
            );

            CREATE TABLE IF NOT EXISTS finding_scans (
                fingerprint TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                sf_id TEXT,
                issue_key TEXT,
                normalized_title TEXT,
                severity TEXT,
                confidence TEXT,
                priority_score INTEGER,
                cluster_id TEXT,
                tool TEXT,
                status_at_scan TEXT,
                proof_line TEXT,
                scan_date TEXT NOT NULL,
                PRIMARY KEY (fingerprint, scan_id, project_id)
            );

            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                profile TEXT,
                tools_run TEXT,
                tools_failed TEXT,
                total_findings INTEGER,
                summary_json TEXT,
                session_path TEXT
            );

            CREATE TABLE IF NOT EXISTS verification_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                project_id TEXT NOT NULL,
                scan_id TEXT,
                run_date TEXT NOT NULL,
                stage TEXT NOT NULL,
                command TEXT,
                result TEXT NOT NULL,
                output_snippet TEXT
            );

            CREATE TABLE IF NOT EXISTS finding_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                project_id TEXT NOT NULL,
                note_type TEXT NOT NULL,
                note_text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(project_id, status);
            CREATE INDEX IF NOT EXISTS idx_finding_scans_scan ON finding_scans(scan_id);
        """)

    def ensure_project(self, project_id: str, display_name: Optional[str] = None) -> None:
        if not self._conn:
            return
        self._conn.execute(
            "INSERT OR IGNORE INTO projects (project_id, display_name, created_at) VALUES (?, ?, ?)",
            (project_id, display_name or project_id, _utc_now())
        )
        self._conn.commit()

    def record_scan(self, scan_id: str, project_id: str, target: str,
                    scan_date: str, profile: str = "",
                    tools_run: Optional[List[str]] = None,
                    tools_failed: Optional[List[str]] = None,
                    total_findings: int = 0,
                    summary_json: str = "",
                    session_path: str = "") -> None:
        if not self._conn:
            return
        self._conn.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, project_id, target, scan_date, profile, tools_run, tools_failed,
                total_findings, summary_json, session_path)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, project_id, target, scan_date, profile,
             json.dumps(tools_run or []), json.dumps(tools_failed or []),
             total_findings, summary_json, session_path)
        )
        self._conn.commit()

    def upsert_findings(self, findings: List[Dict[str, Any]],
                        project_id: str, scan_id: str,
                        tools_succeeded: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
        """Upsert findings into state DB. Sets status (new/existing/fixed/reopened).

        Returns the findings list with status updated.
        """
        if not self._conn:
            return findings

        now = _utc_now()
        current_fps = set()

        for f in findings:
            fp = f.get("fingerprint", "")
            if not fp:
                continue
            current_fps.add(fp)

            # Check if exists
            row = self._conn.execute(
                "SELECT status, first_seen, reopened_count FROM findings WHERE project_id=? AND fingerprint=?",
                (project_id, fp)
            ).fetchone()

            if row is None:
                # New finding
                f["status"] = "new"
                f["first_seen"] = now
                f["last_seen"] = now
                self._conn.execute(
                    """INSERT INTO findings (project_id, fingerprint, asset_type, host, issue_key,
                       status, first_seen, last_seen, severity, confidence, normalized_title,
                       tool, category, cluster_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (project_id, fp,
                     (f.get("asset") or {}).get("type", ""),
                     (f.get("asset") or {}).get("host", ""),
                     f.get("issue_key", ""),
                     "new", now, now,
                     f.get("severity", "info"),
                     f.get("confidence", "possible"),
                     f.get("normalized_title", ""),
                     f.get("tool", ""),
                     f.get("category", ""),
                     f.get("cluster_id", "other"))
                )
            else:
                old_status = row["status"]
                if old_status == "fixed":
                    # Reopened
                    f["status"] = "reopened"
                    reopen_count = (row["reopened_count"] or 0) + 1
                    self._conn.execute(
                        """UPDATE findings SET status='reopened', last_seen=?, reopened_count=?,
                           severity=?, confidence=?, tool=?, cluster_id=?
                           WHERE project_id=? AND fingerprint=?""",
                        (now, reopen_count,
                         f.get("severity", "info"), f.get("confidence", "possible"),
                         f.get("tool", ""), f.get("cluster_id", "other"),
                         project_id, fp)
                    )
                elif old_status in ("ignored", "accepted_risk", "false_positive"):
                    # Preserve manual intent — don't overwrite with "existing"
                    f["status"] = old_status
                    f["first_seen"] = row["first_seen"]
                    self._conn.execute(
                        """UPDATE findings SET last_seen=?,
                           severity=?, confidence=?, tool=?, cluster_id=?
                           WHERE project_id=? AND fingerprint=?""",
                        (now, f.get("severity", "info"), f.get("confidence", "possible"),
                         f.get("tool", ""), f.get("cluster_id", "other"),
                         project_id, fp)
                    )
                else:
                    # Existing (new/existing/reopened → existing)
                    f["status"] = "existing"
                    f["first_seen"] = row["first_seen"]
                    self._conn.execute(
                        """UPDATE findings SET status='existing', last_seen=?,
                           severity=?, confidence=?, tool=?, cluster_id=?
                           WHERE project_id=? AND fingerprint=?""",
                        (now, f.get("severity", "info"), f.get("confidence", "possible"),
                         f.get("tool", ""), f.get("cluster_id", "other"),
                         project_id, fp)
                    )

            # Record in finding_scans
            self._conn.execute(
                """INSERT OR REPLACE INTO finding_scans
                   (fingerprint, scan_id, project_id, sf_id, issue_key, normalized_title,
                    severity, confidence, priority_score, cluster_id, tool, status_at_scan,
                    proof_line, scan_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (fp, scan_id, project_id,
                 f.get("id", ""), f.get("issue_key", ""), f.get("normalized_title", ""),
                 f.get("severity", ""), f.get("confidence", ""),
                 f.get("priority_score"), f.get("cluster_id", ""),
                 f.get("tool", ""), f.get("status", ""),
                 (f.get("evidence") or "")[:500],  # proof_line
                 now)
            )

        # Mark findings as fixed if ANY of their historically-detecting tools succeeded
        # but the fingerprint is missing from the current scan.
        # This prevents cross-tool findings from being stuck "existing" just because
        # the primary tool didn't run — any tool that ever detected it can clear it.
        if tools_succeeded:
            existing_rows = self._conn.execute(
                "SELECT fingerprint, tool, status FROM findings WHERE project_id=? AND status IN ('new','existing','reopened')",
                (project_id,)
            ).fetchall()

            for row in existing_rows:
                fp = row["fingerprint"]
                if fp not in current_fps:
                    # Check primary tool first
                    primary_tool = row["tool"] or ""
                    if primary_tool in tools_succeeded:
                        self._conn.execute(
                            "UPDATE findings SET status='fixed', fixed_at=? WHERE project_id=? AND fingerprint=?",
                            (now, project_id, fp)
                        )
                        continue
                    # Check all historical detecting tools from finding_scans
                    hist_tools = self._conn.execute(
                        "SELECT DISTINCT tool FROM finding_scans WHERE fingerprint=? AND project_id=? AND tool != ''",
                        (fp, project_id)
                    ).fetchall()
                    for ht in hist_tools:
                        if (ht["tool"] or "") in tools_succeeded:
                            self._conn.execute(
                                "UPDATE findings SET status='fixed', fixed_at=? WHERE project_id=? AND fingerprint=?",
                                (now, project_id, fp)
                            )
                            break

        self._conn.commit()
        return findings

    def get_findings(self, project_id: str,
                     status: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._conn:
            return []
        if status:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE project_id=? AND status=?",
                (project_id, status)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE project_id=?",
                (project_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_finding_history(self, project_id: str, fingerprint: str) -> List[Dict[str, Any]]:
        """Get full scan history for one finding."""
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM finding_scans WHERE project_id=? AND fingerprint=? ORDER BY scan_date DESC",
            (project_id, fingerprint)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_diff(self, project_id: str, scan_id: str) -> Dict[str, List[Dict[str, Any]]]:
        """Compare scan_id against the previous scan: new, fixed, reopened, existing."""
        if not self._conn:
            return {"new": [], "fixed": [], "reopened": [], "existing": []}

        # Get ordered scans to find the previous one
        scans = self._conn.execute(
            "SELECT scan_id FROM scans WHERE project_id=? ORDER BY scan_date DESC",
            (project_id,)
        ).fetchall()
        scan_ids = [r["scan_id"] for r in scans]

        # Fingerprints in current scan
        current_fps = set()
        current_rows = self._conn.execute(
            "SELECT * FROM finding_scans WHERE project_id=? AND scan_id=?",
            (project_id, scan_id)
        ).fetchall()
        current_map = {}
        for r in current_rows:
            current_fps.add(r["fingerprint"])
            current_map[r["fingerprint"]] = dict(r)

        # Fingerprints in previous scan (if any)
        prev_fps: set = set()
        prev_scan_id = ""
        if scan_id in scan_ids:
            idx = scan_ids.index(scan_id)
            if idx + 1 < len(scan_ids):
                prev_scan_id = scan_ids[idx + 1]
        if prev_scan_id:
            prev_rows = self._conn.execute(
                "SELECT fingerprint FROM finding_scans WHERE project_id=? AND scan_id=?",
                (project_id, prev_scan_id)
            ).fetchall()
            prev_fps = {r["fingerprint"] for r in prev_rows}

        result: Dict[str, List[Dict[str, Any]]] = {
            "new": [], "fixed": [], "reopened": [], "existing": [],
        }
        # New: in current but not in previous
        for fp in current_fps - prev_fps:
            result["new"].append(current_map.get(fp, {"fingerprint": fp}))
        # Fixed: in previous but not in current (check findings table status)
        for fp in prev_fps - current_fps:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE project_id=? AND fingerprint=?",
                (project_id, fp)
            ).fetchone()
            if row:
                result["fixed"].append(dict(row))
        # Existing/reopened: in both
        for fp in current_fps & prev_fps:
            entry = current_map.get(fp, {"fingerprint": fp})
            status = entry.get("status_at_scan", "existing")
            if status == "reopened":
                result["reopened"].append(entry)
            else:
                result["existing"].append(entry)

        return result

    def get_regressions(self, project_id: str, min_reopened: int = 2) -> List[Dict[str, Any]]:
        """Findings that have been reopened multiple times."""
        if not self._conn:
            return []
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE project_id=? AND reopened_count >= ? ORDER BY reopened_count DESC",
            (project_id, min_reopened)
        ).fetchall()
        return [dict(r) for r in rows]

    def set_finding_status(self, project_id: str, fingerprint: str,
                           status: str, reason: str = "") -> bool:
        """Set finding status (ignored/accepted_risk/false_positive) with note."""
        if not self._conn:
            return False
        now = _utc_now()
        self._conn.execute(
            "UPDATE findings SET status=?, ignore_reason=? WHERE project_id=? AND fingerprint=?",
            (status, reason, project_id, fingerprint)
        )
        if reason:
            self._conn.execute(
                "INSERT INTO finding_notes (fingerprint, project_id, note_type, note_text, created_at) VALUES (?, ?, ?, ?, ?)",
                (fingerprint, project_id, status, reason, now)
            )
        self._conn.commit()
        return True

    def purge_before(self, project_id: str, before_date: str,
                     delete_reports: bool = False) -> Dict[str, int]:
        """Delete scan history older than before_date. Returns counts."""
        if not self._conn:
            return {"scans_deleted": 0, "finding_scans_deleted": 0}

        # Get old scan IDs
        old_scans = self._conn.execute(
            "SELECT scan_id, session_path FROM scans WHERE project_id=? AND scan_date < ?",
            (project_id, before_date)
        ).fetchall()
        scan_ids = [r["scan_id"] for r in old_scans]

        fs_deleted = 0
        for sid in scan_ids:
            self._conn.execute("DELETE FROM finding_scans WHERE scan_id=? AND project_id=?", (sid, project_id))
            fs_deleted += self._conn.execute("SELECT changes()").fetchone()[0]

        self._conn.execute(
            "DELETE FROM scans WHERE project_id=? AND scan_date < ?",
            (project_id, before_date)
        )
        scans_deleted = self._conn.execute("SELECT changes()").fetchone()[0]
        self._conn.commit()

        if delete_reports:
            import shutil
            for r in old_scans:
                sp = r["session_path"]
                if sp and Path(sp).is_dir():
                    try:
                        shutil.rmtree(sp)
                    except Exception:
                        pass

        return {"scans_deleted": scans_deleted, "finding_scans_deleted": fs_deleted}

    def resolve_finding(self, project_id: str, sf_id: str) -> Optional[str]:
        """Resolve SF-### ID to fingerprint via finding_scans."""
        if not self._conn:
            return None
        row = self._conn.execute(
            "SELECT fingerprint FROM finding_scans WHERE project_id=? AND sf_id=? ORDER BY scan_date DESC LIMIT 1",
            (project_id, sf_id)
        ).fetchone()
        return row["fingerprint"] if row else None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()
