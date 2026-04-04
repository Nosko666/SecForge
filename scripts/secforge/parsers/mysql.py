"""SecForge v2 parser: check-mysql.sh (database/mysql.json)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import redact_text, truncate

import json


@register("database/mysql.json")
def parse_mysql(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []
    if data.get("status") != "ok":
        return [make_finding(
            issue_key="database.anonymous_accounts",  # generic DB key
            title="MySQL checks not run",
            severity="info",
            tool="check-mysql",
            category="database",
            asset={"type": "host", "host": "this_server"},
            description=str(data.get("error", "unknown error")),
            evidence=truncate(redact_text(json.dumps(data, indent=2, sort_keys=True)), 500),
        )]

    checks = data.get("checks", {}) if isinstance(data.get("checks"), dict) else {}
    findings: List[Dict[str, Any]] = []

    _CHECKS = [
        ("anonymous_accounts_count", "database.anonymous_accounts", "MySQL anonymous accounts present",
         "high", "Anonymous MySQL accounts increase risk of unauthorized access.",
         "Remove anonymous accounts and run mysql_secure_installation if appropriate."),
        ("remote_root_accounts_count", "database.remote_root", "MySQL remote root access enabled",
         "critical", "Root accounts accessible from non-local hosts are a high-risk configuration.",
         "Restrict root to localhost and use least-privileged accounts for apps."),
        ("users_without_password_count", "database.no_password_users", "MySQL users without passwords detected",
         "critical", "Database users without passwords can allow unauthorized access.",
         "Set strong passwords for all MySQL users and disable unused accounts."),
        ("test_databases_count", "database.test_db_present", "MySQL test databases present",
         "medium", "Default test databases are often unnecessary and can increase attack surface.",
         "Remove test databases unless explicitly needed."),
        ("non_root_super_priv_count", "database.super_priv", "MySQL non-root users with SUPER-like privileges",
         "high", "SUPER/SYSTEM_USER privileges can allow powerful actions and bypass controls.",
         "Review privileges and remove SUPER-like privileges from non-admin accounts."),
    ]

    for field, ik, title, sev, desc, rem in _CHECKS:
        val = checks.get(field)
        if isinstance(val, int) and val > 0:
            findings.append(make_finding(
                issue_key=ik, title=title, severity=sev,
                tool="check-mysql", category="database",
                asset={"type": "host", "host": "this_server"},
                description=desc,
                evidence=f"{field}: {val}",
                remediation_summary=rem,
            ))

    # SSL check
    rst = checks.get("require_secure_transport")
    if isinstance(rst, str) and rst.lower() in ("off", "0", "false"):
        findings.append(make_finding(
            issue_key="database.no_ssl_required",
            title="MySQL does not require secure transport",
            severity="medium",
            tool="check-mysql",
            category="database",
            asset={"type": "host", "host": "this_server"},
            description="Without require_secure_transport, clients can connect without TLS.",
            evidence=f"require_secure_transport={rst}",
            remediation_summary="Enable require_secure_transport and configure TLS for MySQL clients/servers.",
        ))

    return findings
