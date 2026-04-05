"""SecForge v2 verification runner.

Runs allowlisted safe commands to verify findings/fixes.
Structured assertions: exit_code, stdout_contains, stdout_not_contains.
Results to SQLite verification_runs table + session verify/results.json.

Safe command allowlist (default, no --run flag needed):
  curl -sI, openssl s_client, sshd -t, nginx -t, apachectl configtest,
  systemctl is-active, dig, grep, cat

Noisy commands (require --allow-noisy): nmap -sT, testssl.sh

Sudo commands (require hardening fix surface + explicit approval):
  ufw status, systemctl is-active, fail2ban-client status, sshd -t, iptables -L -n
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


_SAFE_COMMANDS = {
    "curl", "openssl", "sshd", "nginx", "apachectl",
    "systemctl", "dig", "grep", "cat",
}

_NOISY_COMMANDS = {"nmap", "testssl.sh"}

_SUDO_ALLOWLIST = {
    "ufw status", "systemctl is-active", "fail2ban-client status",
    "sshd -t", "iptables -L",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class VerificationResult:
    """Result of one verification check."""
    name: str
    stage: str
    command: str
    passed: bool
    actual_output: str = ""
    explain: str = ""


def is_safe_command(command: str, allow_noisy: bool = False,
                    allow_sudo: bool = False) -> bool:
    """Check if a command is in the safe allowlist.

    Sudo-prefixed commands are checked against _SUDO_ALLOWLIST when allow_sudo=True.
    """
    if not command:
        return False
    parts = command.strip().split()
    first_word = parts[0].split("/")[-1]

    # Handle sudo-prefixed commands
    if first_word == "sudo" and len(parts) > 1:
        if not allow_sudo:
            return False
        # The command after "sudo" must match an allowlisted entry exactly, OR be
        # the allowlisted entry followed by safe positional arguments (a space).
        # "sudo ufw status" matches "ufw status" — exact.
        # "sudo systemctl is-active nginx" matches "systemctl is-active" + arg "nginx".
        # "sudo ufw disable" does NOT match "ufw status" — different subcommand.
        # "sudo iptables -L -F" does NOT match "iptables -L" — "-F" starts with dash (flag).
        rest = " ".join(p.split("/")[-1] if i == 0 else p for i, p in enumerate(parts[1:]))
        for allowed in _SUDO_ALLOWLIST:
            if rest == allowed:
                return True
            # Allow extra positional args (not flags) after the allowlisted prefix
            if rest.startswith(allowed + " "):
                extra = rest[len(allowed) + 1:]
                # Reject if any extra token starts with "-" (flag injection)
                if not any(t.startswith("-") for t in extra.split()):
                    return True
        return False

    if first_word in _SAFE_COMMANDS:
        return True
    if allow_noisy and first_word in _NOISY_COMMANDS:
        return True
    return False


def _substitute_placeholders(command: str, context: Dict[str, str]) -> str:
    """Replace {target}, {host} etc. in command templates with actual values."""
    for key, val in context.items():
        command = command.replace("{" + key + "}", val)
    return command


def run_verification(
    checks: List[Dict[str, Any]],
    stage_filter: Optional[str] = None,
    execute: bool = False,
    allow_noisy: bool = False,
    allow_sudo: bool = False,
    timeout: int = 30,
    context: Optional[Dict[str, str]] = None,
) -> List[VerificationResult]:
    """Run verification checks and return results.

    If execute=False, just returns the checks as suggested commands (no execution).
    If execute=True, runs allowlisted commands and evaluates assertions.
    allow_sudo: permit sudo-prefixed commands from _SUDO_ALLOWLIST.
    context: placeholder values like {"target": "https://example.com", "host": "example.com"}
    """
    results: List[VerificationResult] = []
    ctx = context or {}

    for check in checks:
        if not isinstance(check, dict):
            continue
        check_stage = check.get("stage", "post")
        # "both" means no filter; otherwise exact match
        if stage_filter and stage_filter != "both" and check_stage != stage_filter:
            continue

        name = check.get("name", "Unnamed check")
        command = _substitute_placeholders(check.get("command", ""), ctx)
        assertions = check.get("assertions", {})
        explain = check.get("explain", "")
        close_stdin = check.get("close_stdin", False)

        if not execute:
            results.append(VerificationResult(
                name=name, stage=check_stage, command=command,
                passed=False, explain=f"Suggested: {explain}",
            ))
            continue

        if not is_safe_command(command, allow_noisy=allow_noisy, allow_sudo=allow_sudo):
            results.append(VerificationResult(
                name=name, stage=check_stage, command=command,
                passed=False, explain=f"Command not in safe allowlist: {command.split()[0] if command else '(empty)'}",
            ))
            continue

        # Execute the command (no shell=True — use shlex.split for safety)
        try:
            cmd_args = shlex.split(command)
            stdin_arg = subprocess.DEVNULL if close_stdin else None
            proc = subprocess.run(
                cmd_args, capture_output=True, text=True,
                timeout=timeout, stdin=stdin_arg,
            )
            actual = proc.stdout + proc.stderr
            passed = _evaluate_assertions(proc.returncode, actual, assertions)
            results.append(VerificationResult(
                name=name, stage=check_stage, command=command,
                passed=passed, actual_output=actual[:500],
                explain=explain,
            ))
        except subprocess.TimeoutExpired:
            results.append(VerificationResult(
                name=name, stage=check_stage, command=command,
                passed=False, actual_output=f"Timed out after {timeout}s",
                explain=explain,
            ))
        except Exception as e:
            results.append(VerificationResult(
                name=name, stage=check_stage, command=command,
                passed=False, actual_output=str(e)[:500],
                explain=explain,
            ))

    return results


def _evaluate_assertions(exit_code: int, output: str, assertions: Dict[str, Any]) -> bool:
    """Evaluate structured assertions against command output."""
    if not assertions:
        return exit_code == 0  # Default: pass if exit code is 0

    # Check exit_code
    expected_exit = assertions.get("exit_code")
    if expected_exit is not None and exit_code != expected_exit:
        return False

    # Check stdout_contains (case-insensitive)
    stdout_contains = assertions.get("stdout_contains", [])
    if isinstance(stdout_contains, list):
        output_lower = output.lower()
        for pattern in stdout_contains:
            if str(pattern).lower() not in output_lower:
                return False

    # Check stdout_not_contains (case-insensitive)
    stdout_not_contains = assertions.get("stdout_not_contains", [])
    if isinstance(stdout_not_contains, list):
        output_lower = output.lower()
        for pattern in stdout_not_contains:
            if str(pattern).lower() in output_lower:
                return False

    return True


def write_results(results: List[VerificationResult], session_dir: Path,
                  fingerprint: str = "", project_id: str = "",
                  scan_id: str = "") -> Path:
    """Write verification results to session verify/results.json and state DB."""
    verify_dir = session_dir / "verify"
    verify_dir.mkdir(exist_ok=True)
    out_path = verify_dir / "results.json"

    now = _utc_now()
    data = {
        "run_date": now,
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "results": [
            {
                "name": r.name,
                "stage": r.stage,
                "command": r.command,
                "passed": r.passed,
                "actual_output": r.actual_output[:500] if r.actual_output else "",
                "explain": r.explain,
            }
            for r in results
        ],
    }

    out_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    # Write to verification_runs table (best-effort)
    if fingerprint and project_id:
        try:
            from secforge.state import StateDB
            state = StateDB()
            if state.open():
                conn = state._conn
                if conn:
                    for r in results:
                        conn.execute(
                            """INSERT INTO verification_runs
                               (fingerprint, project_id, scan_id, run_date, stage, command, result, output_snippet)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                            (fingerprint, project_id, scan_id, now,
                             r.stage, r.command,
                             "pass" if r.passed else "fail",
                             (r.actual_output or "")[:500])
                        )
                    conn.commit()
                state.close()
        except Exception:
            pass  # Best-effort

    return out_path
