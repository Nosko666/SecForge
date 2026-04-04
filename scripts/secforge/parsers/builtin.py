"""SecForge v2 parser: built-in curl checks (webapp/builtin.json).

Parses the output of scan-all.sh's sf_builtin_web_checks() function.
Checks: .git/.env exposure, HTTP methods, cookie flags, clickjacking.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import redact_text, truncate


@register("webapp/builtin.json")
def parse_builtin(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []

    target_url = context.get("target_url", "")
    base = target_url or ""
    findings: List[Dict[str, Any]] = []

    git_code = str(data.get("git_head_http_code", "000"))
    env_code = str(data.get("env_http_code", "000"))
    methods = data.get("http_methods", {}) if isinstance(data.get("http_methods"), dict) else {}
    trace_code = str(methods.get("trace_http_code", "000"))
    put_code = str(methods.get("put_http_code", "000"))
    delete_code = str(methods.get("delete_http_code", "000"))

    cookies = data.get("cookies", {}) if isinstance(data.get("cookies"), dict) else {}
    cookies_total = int(cookies.get("set_cookie_headers", 0) or 0)
    miss_secure = int(cookies.get("missing_secure", 0) or 0)
    miss_httponly = int(cookies.get("missing_httponly", 0) or 0)
    miss_samesite = int(cookies.get("missing_samesite", 0) or 0)

    def _exposed(code: str) -> bool:
        return code.isdigit() and int(code) in (200, 301, 302, 307, 308, 401, 403)

    if _exposed(git_code):
        findings.append(make_finding(
            issue_key="exposure.git_directory",
            title="Exposed .git directory",
            severity="high",
            tool="secforge-builtin",
            category="exposure",
            asset={"type": "web", "host": context.get("target_host", ""), "url": base},
            description="The server responded to /.git/HEAD. Exposing a .git directory can leak source code and secrets.",
            evidence=f"HTTP code: {git_code}",
            remediation_summary="Block access to /.git/ via web server config and ensure deployment excludes .git.",
        ))

    if _exposed(env_code):
        findings.append(make_finding(
            issue_key="exposure.env_file",
            title="Exposed .env file",
            severity="high",
            tool="secforge-builtin",
            category="exposure",
            asset={"type": "web", "host": context.get("target_host", ""), "url": base},
            description="The server responded to /.env. Environment files often contain secrets (DB passwords, API keys).",
            evidence=f"HTTP code: {env_code}",
            remediation_summary="Block access to /.env and ensure environment files are not served by the web server.",
        ))

    if trace_code.isdigit() and int(trace_code) == 200:
        findings.append(make_finding(
            issue_key="misconfig.http_trace_enabled",
            title="HTTP TRACE method enabled",
            severity="medium",
            tool="secforge-builtin",
            category="misconfig",
            asset={"type": "web", "host": context.get("target_host", ""), "url": base},
            description="TRACE is rarely needed and can be abused in some contexts.",
            evidence=f"TRACE / returned HTTP {trace_code}",
            remediation_summary="Disable TRACE on the web server (Apache/Nginx) unless explicitly required.",
        ))

    for code, method, ik in [(put_code, "PUT", "misconfig.http_put_enabled"),
                              (delete_code, "DELETE", "misconfig.http_delete_enabled")]:
        if code.isdigit() and int(code) not in (404, 405):
            findings.append(make_finding(
                issue_key=ik,
                title=f"Unexpected HTTP method allowed: {method}",
                severity="medium",
                tool="secforge-builtin",
                category="misconfig",
                asset={"type": "web", "host": context.get("target_host", ""), "url": base},
                description=f"The server responded with {code} to {method} /. This may indicate risky method handling.",
                evidence=f"{method} / returned HTTP {code}",
                remediation_summary=f"Restrict {method} to the minimal set of routes that require it; return 405 otherwise.",
            ))

    if cookies_total > 0 and miss_secure > 0:
        findings.append(make_finding(
            issue_key="cookies.missing_secure",
            title="Cookies missing Secure flag",
            severity="medium",
            tool="secforge-builtin",
            category="cookies",
            asset={"type": "web", "host": context.get("target_host", ""), "url": base},
            description="Cookies without Secure can be sent over HTTP, increasing session hijack risk.",
            evidence=f"Set-Cookie headers: {cookies_total}. Missing Secure: {miss_secure}.",
            remediation_summary="Set the Secure flag on session/auth cookies and enforce HTTPS site-wide.",
        ))

    if cookies_total > 0 and miss_httponly > 0:
        findings.append(make_finding(
            issue_key="cookies.missing_httponly",
            title="Cookies missing HttpOnly flag",
            severity="medium",
            tool="secforge-builtin",
            category="cookies",
            asset={"type": "web", "host": context.get("target_host", ""), "url": base},
            description="Cookies without HttpOnly are accessible to JavaScript and can be stolen via XSS.",
            evidence=f"Set-Cookie headers: {cookies_total}. Missing HttpOnly: {miss_httponly}.",
            remediation_summary="Set HttpOnly on session/auth cookies.",
        ))

    if cookies_total > 0 and miss_samesite > 0:
        findings.append(make_finding(
            issue_key="cookies.missing_samesite",
            title="Cookies missing SameSite attribute",
            severity="low",
            tool="secforge-builtin",
            category="cookies",
            asset={"type": "web", "host": context.get("target_host", ""), "url": base},
            description="SameSite helps reduce CSRF and cross-site leakage for cookies.",
            evidence=f"Set-Cookie headers: {cookies_total}. Missing SameSite: {miss_samesite}.",
            remediation_summary="Set SameSite=Lax (or Strict where possible) for session/auth cookies.",
        ))

    # Clickjacking
    clickjacking = data.get("clickjacking", {}) if isinstance(data.get("clickjacking"), dict) else {}
    if not clickjacking.get("protected", False):
        findings.append(make_finding(
            issue_key="misconfig.missing_clickjacking_protection",
            title="Missing clickjacking protection",
            severity="medium",
            tool="secforge-builtin",
            category="misconfig",
            asset={"type": "web", "host": context.get("target_host", ""), "url": base},
            description="Missing X-Frame-Options or CSP frame-ancestors can allow clickjacking.",
            evidence="No X-Frame-Options header and no CSP frame-ancestors directive detected on /.",
            remediation_summary="Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors.",
        ))

    return findings
