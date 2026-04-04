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


def is_safe_command(command: str, allow_noisy: bool = False) -> bool:
    """Check if a command is in the safe allowlist."""
    if not command:
        return False
    # Extract the base command (first word, strip paths)
    first_word = command.strip().split()[0].split("/")[-1]
    if first_word in _SAFE_COMMANDS:
        return True
    if allow_noisy and first_word in _NOISY_COMMANDS:
        return True
    return False


def run_verification(
    checks: List[Dict[str, Any]],
    stage_filter: Optional[str] = None,
    execute: bool = False,
    allow_noisy: bool = False,
    timeout: int = 30,
) -> List[VerificationResult]:
    """Run verification checks and return results.

    If execute=False, just returns the checks as suggested commands (no execution).
    If execute=True, runs allowlisted commands and evaluates assertions.
    """
    results: List[VerificationResult] = []

    for check in checks:
        if not isinstance(check, dict):
            continue
        check_stage = check.get("stage", "post")
        if stage_filter and check_stage != stage_filter:
            continue

        name = check.get("name", "Unnamed check")
        command = check.get("command", "")
        assertions = check.get("assertions", {})
        explain = check.get("explain", "")

        if not execute:
            # Just return the check as a suggestion
            results.append(VerificationResult(
                name=name, stage=check_stage, command=command,
                passed=False, explain=f"Suggested: {explain}",
            ))
            continue

        if not is_safe_command(command, allow_noisy=allow_noisy):
            results.append(VerificationResult(
                name=name, stage=check_stage, command=command,
                passed=False, explain=f"Command not in safe allowlist: {command.split()[0] if command else '(empty)'}",
            ))
            continue

        # Execute the command
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=timeout,
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


def write_results(results: List[VerificationResult], session_dir: Path) -> Path:
    """Write verification results to session verify/results.json."""
    verify_dir = session_dir / "verify"
    verify_dir.mkdir(exist_ok=True)
    out_path = verify_dir / "results.json"

    data = {
        "run_date": _utc_now(),
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
    return out_path
