#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def truncate(text: str, max_len: int = 800) -> str:
    text = text or ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


_REDACTIONS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(?i)\b(sk|pk)_(live|test)_[0-9a-zA-Z]{16,}\b"), "[REDACTED_STRIPE_KEY]"),
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "[REDACTED_JWT]"),
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"(?i)(password\s*[:=]\s*)([^\s,;]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(secret\s*[:=]\s*)([^\s,;]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token\s*[:=]\s*)([^\s,;]+)"), r"\1[REDACTED]"),
    (re.compile(r"\b[0-9a-fA-F]{40,}\b"), "[REDACTED_HEX]"),
]


def redact_text(text: str) -> str:
    if not text:
        return ""
    out = text
    for pat, repl in _REDACTIONS:
        out = pat.sub(repl, out)
    return out


def normalize_severity(sev: Any, default: str = "INFO") -> str:
    if sev is None:
        return default
    if isinstance(sev, (int, float)):
        # Best-effort: treat high numeric as higher severity.
        if sev >= 9:
            return "CRITICAL"
        if sev >= 7:
            return "HIGH"
        if sev >= 4:
            return "MEDIUM"
        return "LOW"
    s = str(sev).strip().upper()
    if s in ("CRIT", "CRITICAL"):
        return "CRITICAL"
    if s in ("HIGH",):
        return "HIGH"
    if s in ("MED", "MEDIUM"):
        return "MEDIUM"
    if s in ("LOW",):
        return "LOW"
    if s in ("INFO", "INFORMATIONAL", "NOTE"):
        return "INFO"
    if s in ("WARN", "WARNING"):
        return "MEDIUM"
    return default


def severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    url = url.replace("\r", "")
    url = url.rstrip("/")
    return url


def normalize_title(title: str) -> str:
    t = (title or "").strip().lower()
    t = re.sub(r"\s+", " ", t)
    # Canonicalize common header/misconfig phrasing so cross-tool dedupe works.
    if "content-security-policy" in t or "csp" in t:
        return "missing content-security-policy header"
    if ".env" in t:
        return "exposed .env file"
    if ".git" in t:
        return "exposed .git directory"
    if "x-frame-options" in t or "frame-ancestors" in t or "clickjack" in t:
        return "missing clickjacking protection"
    if "trace method" in t or "http trace" in t:
        return "http trace method enabled"
    return t


def infer_cwe_owasp(category: str, title: str) -> Tuple[str, str]:
    cat = (category or "").lower()
    t = (title or "").lower()

    def mk(cwe: str, owasp: str) -> Tuple[str, str]:
        return (cwe, owasp)

    if "sql" in t and "inject" in t:
        return mk("CWE-89", "A03:2021-Injection")
    if "xss" in t or "cross-site scripting" in t:
        return mk("CWE-79", "A03:2021-Injection")
    if "command" in t and "inject" in t:
        return mk("CWE-77", "A03:2021-Injection")
    if "ssrf" in t or "server-side request forgery" in t:
        return mk("CWE-918", "A10:2021-Server-Side Request Forgery (SSRF)")
    if "content-security-policy" in t or "csp" in t:
        return mk("CWE-16", "A05:2021-Security Misconfiguration")
    if ".env" in t or ".git" in t or "exposed" in t and ("config" in t or "file" in t or "directory" in t):
        return mk("CWE-200", "A05:2021-Security Misconfiguration")
    if "cookie" in t and "httponly" in t:
        return mk("CWE-1004", "A07:2021-Identification and Authentication Failures")
    if "cookie" in t and "secure" in t:
        return mk("CWE-614", "A07:2021-Identification and Authentication Failures")
    if "tls" in t or "ssl" in t or "cipher" in t or cat == "tls":
        return mk("CWE-327", "A02:2021-Cryptographic Failures")
    if cat in ("secrets", "credentials"):
        return mk("CWE-798", "A07:2021-Identification and Authentication Failures")
    if cat in ("dependency", "dependencies"):
        return mk("", "A06:2021-Vulnerable and Outdated Components")
    return ("", "")


@dataclass
class Finding:
    severity: str
    tool: str
    category: str
    title: str
    url: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    status: str = "open"
    also_found_by: Set[str] = field(default_factory=set)

    def dedupe_key(self) -> str:
        return f"{(self.category or '').strip().lower()}|{normalize_url(self.url).lower()}|{normalize_title(self.title)}"

    def to_json(self) -> Dict[str, Any]:
        cwe, owasp = self.cwe, self.owasp
        if not cwe or not owasp:
            inferred_cwe, inferred_owasp = infer_cwe_owasp(self.category, self.title)
            cwe = cwe or inferred_cwe
            owasp = owasp or inferred_owasp

        also = sorted({t for t in self.also_found_by if t and t != self.tool})
        return {
            "severity": self.severity,
            "tool": self.tool,
            "also_found_by": also,
            "category": self.category,
            "title": self.title,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": cwe,
            "owasp": owasp,
            "status": self.status,
        }


def safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        try:
            return path.read_text(errors="replace")
        except Exception:
            return ""


def load_json_file(path: Path) -> Optional[Any]:
    raw = safe_read_text(path).strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def iter_jsonl(path: Path) -> Iterable[Any]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except Exception:
        return


def parse_builtin(path: Path, target_url: str) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []

    findings: List[Finding] = []
    base = target_url or ""

    git_code = str(data.get("git_head_http_code", "000"))
    env_code = str(data.get("env_http_code", "000"))
    methods = data.get("http_methods", {}) if isinstance(data.get("http_methods", {}), dict) else {}
    trace_code = str(methods.get("trace_http_code", "000"))
    put_code = str(methods.get("put_http_code", "000"))
    delete_code = str(methods.get("delete_http_code", "000"))

    cookies = data.get("cookies", {}) if isinstance(data.get("cookies", {}), dict) else {}
    cookies_total = int(cookies.get("set_cookie_headers", 0) or 0)
    miss_secure = int(cookies.get("missing_secure", 0) or 0)
    miss_httponly = int(cookies.get("missing_httponly", 0) or 0)
    miss_samesite = int(cookies.get("missing_samesite", 0) or 0)

    clickjacking = data.get("clickjacking", {}) if isinstance(data.get("clickjacking", {}), dict) else {}
    click_protected = bool(clickjacking.get("protected", False))

    def is_probably_exposed(code: str) -> bool:
        # Treat 200/3xx/401/403 as "something is there".
        return code.isdigit() and int(code) in (200, 301, 302, 307, 308, 401, 403)

    if is_probably_exposed(git_code):
        findings.append(
            Finding(
                severity="HIGH",
                tool="secforge-builtin",
                category="exposure",
                title="Exposed .git directory",
                url=f"{base.rstrip('/')}/.git/HEAD" if base else "",
                description="The server responded to /.git/HEAD. Exposing a .git directory can leak source code and secrets.",
                evidence=f"HTTP code: {git_code}",
                remediation="Block access to /.git/ via web server config and ensure deployment excludes .git.",
            )
        )

    if is_probably_exposed(env_code):
        findings.append(
            Finding(
                severity="HIGH",
                tool="secforge-builtin",
                category="exposure",
                title="Exposed .env file",
                url=f"{base.rstrip('/')}/.env" if base else "",
                description="The server responded to /.env. Environment files often contain secrets (DB passwords, API keys).",
                evidence=f"HTTP code: {env_code}",
                remediation="Block access to /.env and ensure environment files are not served by the web server.",
            )
        )

    if trace_code.isdigit() and int(trace_code) == 200:
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="secforge-builtin",
                category="http-methods",
                title="HTTP TRACE method enabled",
                url=base,
                description="TRACE is rarely needed and can be abused in some contexts.",
                evidence=f"TRACE / returned HTTP {trace_code}",
                remediation="Disable TRACE on the web server (Apache/Nginx) unless explicitly required.",
            )
        )

    for code, method in [(put_code, "PUT"), (delete_code, "DELETE")]:
        if code.isdigit() and int(code) not in (404, 405):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    tool="secforge-builtin",
                    category="http-methods",
                    title=f"Unexpected HTTP method allowed: {method}",
                    url=base,
                    description=f"The server responded with {code} to {method} /. This may indicate risky method handling.",
                    evidence=f"{method} / returned HTTP {code}",
                    remediation=f"Restrict {method} to the minimal set of routes that require it; return 405 otherwise.",
                )
            )

    if cookies_total > 0 and miss_secure > 0:
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="secforge-builtin",
                category="cookies",
                title="Cookies missing Secure flag",
                url=base,
                description="Cookies without Secure can be sent over HTTP, increasing session hijack risk.",
                evidence=f"Set-Cookie headers: {cookies_total}. Missing Secure: {miss_secure}.",
                remediation="Set the Secure flag on session/auth cookies and enforce HTTPS site-wide.",
            )
        )

    if cookies_total > 0 and miss_httponly > 0:
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="secforge-builtin",
                category="cookies",
                title="Cookies missing HttpOnly flag",
                url=base,
                description="Cookies without HttpOnly are accessible to JavaScript and can be stolen via XSS.",
                evidence=f"Set-Cookie headers: {cookies_total}. Missing HttpOnly: {miss_httponly}.",
                remediation="Set HttpOnly on session/auth cookies.",
            )
        )

    if cookies_total > 0 and miss_samesite > 0:
        findings.append(
            Finding(
                severity="LOW",
                tool="secforge-builtin",
                category="cookies",
                title="Cookies missing SameSite attribute",
                url=base,
                description="SameSite helps reduce CSRF and cross-site leakage for cookies.",
                evidence=f"Set-Cookie headers: {cookies_total}. Missing SameSite: {miss_samesite}.",
                remediation="Set SameSite=Lax (or Strict where possible) for session/auth cookies.",
            )
        )

    if not click_protected:
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="secforge-builtin",
                category="headers",
                title="Missing clickjacking protection",
                url=base,
                description="Missing X-Frame-Options or CSP frame-ancestors can allow clickjacking.",
                evidence="No X-Frame-Options header and no CSP frame-ancestors directive detected on /.",
                remediation="Set X-Frame-Options: DENY (or SAMEORIGIN) and/or CSP frame-ancestors.",
            )
        )

    return findings


def parse_emaildns(path: Path, target_host: str) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []

    checks = data.get("checks", {}) if isinstance(data.get("checks", {}), dict) else {}
    findings: List[Finding] = []

    spf = checks.get("spf", {}) if isinstance(checks.get("spf", {}), dict) else {}
    if not spf.get("present", False):
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="check-email-dns",
                category="email-dns",
                title="Missing SPF record",
                url=f"dns://{target_host}",
                description="SPF helps prevent sender spoofing for your domain.",
                remediation="Add an SPF TXT record for your outbound mail providers and use -all where feasible.",
            )
        )
    else:
        all_mech = str(spf.get("all_mechanism", "unknown"))
        if all_mech and all_mech != "-all":
            findings.append(
                Finding(
                    severity="LOW",
                    tool="check-email-dns",
                    category="email-dns",
                    title="SPF policy is not strict (-all)",
                    url=f"dns://{target_host}",
                    description="Using ~all/?all/+all can weaken spoofing protection.",
                    evidence=f"SPF all-mechanism: {all_mech}",
                    remediation="Prefer -all once your SPF record is correct and stable.",
                )
            )

    dmarc = checks.get("dmarc", {}) if isinstance(checks.get("dmarc", {}), dict) else {}
    if not dmarc.get("present", False):
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="check-email-dns",
                category="email-dns",
                title="Missing DMARC record",
                url=f"dns://{target_host}",
                description="DMARC enforces alignment and improves spoofing protection and reporting.",
                remediation="Add a DMARC TXT record at _dmarc.<domain> with p=reject where feasible.",
            )
        )
    else:
        policy = str(dmarc.get("policy", "unknown"))
        if policy and policy != "reject":
            findings.append(
                Finding(
                    severity="LOW",
                    tool="check-email-dns",
                    category="email-dns",
                    title="DMARC policy is not enforcing (p=reject)",
                    url=f"dns://{target_host}",
                    description="DMARC policies like p=none provide monitoring but do not block spoofing attempts.",
                    evidence=f"DMARC policy: {policy}",
                    remediation="Move to p=quarantine then p=reject after validating alignment.",
                )
            )

    dkim = checks.get("dkim", {}) if isinstance(checks.get("dkim", {}), dict) else {}
    if not dkim.get("present", False):
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="check-email-dns",
                category="email-dns",
                title="DKIM selector not found (common selectors)",
                url=f"dns://{target_host}",
                description="DKIM helps authenticate emails. This check only tests common selectors.",
                evidence="No DKIM TXT record found for common selectors (default, selector1, google, etc.).",
                remediation="Ensure your mail provider publishes DKIM records and document the selector used.",
            )
        )

    dnssec = checks.get("dnssec", {}) if isinstance(checks.get("dnssec", {}), dict) else {}
    enabled = str(dnssec.get("enabled", "unknown")).lower()
    if enabled == "false":
        findings.append(
            Finding(
                severity="INFO",
                tool="check-email-dns",
                category="email-dns",
                title="DNSSEC not detected",
                url=f"dns://{target_host}",
                description="DNSSEC helps protect DNS integrity for your domain. Not all environments support it.",
                remediation="Enable DNSSEC at your DNS provider if supported.",
            )
        )

    zone = checks.get("zone_transfer", {}) if isinstance(checks.get("zone_transfer", {}), dict) else {}
    if zone.get("allowed", False):
        ns = str(zone.get("allowed_ns", "") or "")
        findings.append(
            Finding(
                severity="CRITICAL",
                tool="check-email-dns",
                category="dns",
                title="DNS zone transfer (AXFR) allowed",
                url=f"dns://{target_host}",
                description="Allowing AXFR can leak full DNS zone contents (hosts, subdomains, internal structure).",
                evidence=f"AXFR succeeded against NS: {ns}" if ns else "AXFR succeeded.",
                remediation="Disable public AXFR; restrict transfers to authorized secondary name servers only.",
            )
        )

    return findings


def parse_mysql(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []
    if data.get("status") != "ok":
        return [
            Finding(
                severity="INFO",
                tool="check-mysql",
                category="database",
                title="MySQL checks not run",
                url="local://mysql",
                description=str(data.get("error", "unknown error")),
                evidence=truncate(redact_text(json.dumps(data, indent=2, sort_keys=True)), 500),
            )
        ]

    checks = data.get("checks", {}) if isinstance(data.get("checks", {}), dict) else {}
    findings: List[Finding] = []

    anon = checks.get("anonymous_accounts_count")
    if isinstance(anon, int) and anon > 0:
        findings.append(
            Finding(
                severity="HIGH",
                tool="check-mysql",
                category="database",
                title="MySQL anonymous accounts present",
                url="local://mysql",
                description="Anonymous MySQL accounts increase risk of unauthorized access.",
                evidence=f"Anonymous accounts count: {anon}",
                remediation="Remove anonymous accounts and run mysql_secure_installation if appropriate.",
            )
        )

    remote_root = checks.get("remote_root_accounts_count")
    if isinstance(remote_root, int) and remote_root > 0:
        findings.append(
            Finding(
                severity="CRITICAL",
                tool="check-mysql",
                category="database",
                title="MySQL remote root access enabled",
                url="local://mysql",
                description="Root accounts accessible from non-local hosts are a high-risk configuration.",
                evidence=f"Remote root accounts count: {remote_root}",
                remediation="Restrict root to localhost and use least-privileged accounts for apps.",
            )
        )

    no_pass = checks.get("users_without_password_count")
    if isinstance(no_pass, int) and no_pass > 0:
        findings.append(
            Finding(
                severity="CRITICAL",
                tool="check-mysql",
                category="database",
                title="MySQL users without passwords detected",
                url="local://mysql",
                description="Database users without passwords can allow unauthorized access.",
                evidence=f"Users without passwords count: {no_pass}",
                remediation="Set strong passwords for all MySQL users and disable unused accounts.",
            )
        )

    test_db = checks.get("test_databases_count")
    if isinstance(test_db, int) and test_db > 0:
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="check-mysql",
                category="database",
                title="MySQL test databases present",
                url="local://mysql",
                description="Default test databases are often unnecessary and can increase attack surface.",
                evidence=f"Test databases count: {test_db}",
                remediation="Remove test databases unless explicitly needed.",
            )
        )

    rst = checks.get("require_secure_transport")
    if isinstance(rst, str) and rst and rst.lower() in ("off", "0", "false"):
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="check-mysql",
                category="database",
                title="MySQL does not require secure transport",
                url="local://mysql",
                description="Without require_secure_transport, clients can connect without TLS.",
                evidence=f"require_secure_transport={rst}",
                remediation="Enable require_secure_transport and configure TLS for MySQL clients/servers.",
            )
        )

    super_non_root = checks.get("non_root_super_priv_count")
    if isinstance(super_non_root, int) and super_non_root > 0:
        findings.append(
            Finding(
                severity="HIGH",
                tool="check-mysql",
                category="database",
                title="MySQL non-root users with SUPER-like privileges detected",
                url="local://mysql",
                description="SUPER/SYSTEM_USER privileges can allow powerful actions and bypass controls.",
                evidence=f"Non-root SUPER-like privileged users count: {super_non_root}",
                remediation="Review privileges and remove SUPER-like privileges from non-admin accounts.",
            )
        )

    return findings


def parse_nuclei(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_NUCLEI", "2000"))
    for obj in iter_jsonl(path):
        if len(findings) >= max_items:
            break
        if not isinstance(obj, dict):
            continue
        info = obj.get("info", {}) if isinstance(obj.get("info", {}), dict) else {}
        sev = normalize_severity(info.get("severity") or obj.get("severity"), "INFO")
        template_id = obj.get("template-id") or obj.get("templateID") or obj.get("template") or ""
        name = info.get("name") or template_id or "Nuclei finding"
        matched = obj.get("matched-at") or obj.get("matchedAt") or obj.get("host") or obj.get("url") or ""
        desc = info.get("description") or ""
        tags = info.get("tags")
        category = "webapp"
        if isinstance(tags, str):
            # Tag heuristics (e.g., "csp,misconfig")
            tag_set = {t.strip().lower() for t in tags.split(",") if t.strip()}
            if "misconfig" in tag_set:
                category = "misconfig"
            if "ssl" in tag_set or "tls" in tag_set:
                category = "tls"
            if "cve" in tag_set or "cves" in tag_set:
                category = "cve"
            if "xss" in tag_set:
                category = "xss"
            if "sqli" in tag_set or "sql" in tag_set:
                category = "sql-injection"
        elif isinstance(tags, list):
            tag_set = {str(t).strip().lower() for t in tags if str(t).strip()}
            if "misconfig" in tag_set:
                category = "misconfig"
            if "ssl" in tag_set or "tls" in tag_set:
                category = "tls"
            if "cve" in tag_set or "cves" in tag_set:
                category = "cve"
            if "xss" in tag_set:
                category = "xss"
            if "sqli" in tag_set or "sql" in tag_set:
                category = "sql-injection"

        evidence_parts = []
        if template_id:
            evidence_parts.append(f"template_id={template_id}")
        matcher = obj.get("matcher-name") or obj.get("matcherName")
        if matcher:
            evidence_parts.append(f"matcher={matcher}")
        extracted = obj.get("extracted-results") or obj.get("extractedResults")
        if isinstance(extracted, list) and extracted:
            evidence_parts.append("extracted=" + ", ".join([str(x) for x in extracted[:5]]))
        evidence = truncate(redact_text("; ".join(evidence_parts)), 500)

        findings.append(
            Finding(
                severity=sev,
                tool="nuclei",
                category=category,
                title=str(name),
                url=str(matched),
                description=truncate(redact_text(str(desc)), 500),
                evidence=evidence,
                remediation=truncate(redact_text(str(info.get("remediation") or info.get("reference") or "")), 500),
            )
        )
    return findings


def parse_zap(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []
    alerts = data.get("alerts", [])
    if not isinstance(alerts, list):
        return []

    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_ZAP", "2000"))
    for a in alerts:
        if len(findings) >= max_items:
            break
        if not isinstance(a, dict):
            continue
        risk = a.get("risk") or a.get("riskdesc") or a.get("riskDesc") or ""
        sev = normalize_severity(risk, "INFO")
        title = a.get("alert") or a.get("name") or "ZAP alert"
        url = a.get("url") or ""
        desc = a.get("desc") or a.get("description") or ""
        solution = a.get("solution") or ""
        evidence = a.get("evidence") or ""
        param = a.get("param") or ""
        attack = a.get("attack") or ""

        cweid = str(a.get("cweid") or a.get("cweId") or "")
        cwe = ""
        if cweid.isdigit() and int(cweid) > 0:
            cwe = f"CWE-{int(cweid)}"

        ev_parts = []
        if param:
            ev_parts.append(f"param={param}")
        if attack:
            ev_parts.append(f"attack={truncate(str(attack), 120)}")
        if evidence:
            ev_parts.append(f"evidence={truncate(str(evidence), 200)}")

        findings.append(
            Finding(
                severity=sev,
                tool="zap",
                category="webapp",
                title=str(title),
                url=str(url),
                description=truncate(redact_text(str(desc)), 600),
                evidence=truncate(redact_text("; ".join(ev_parts)), 500),
                remediation=truncate(redact_text(str(solution)), 600),
                cwe=cwe,
            )
        )
    return findings


def parse_ffuf(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []
    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    # Summarize to keep findings readable.
    urls: List[str] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        url = r.get("url")
        status = r.get("status")
        if url and status and str(status).isdigit():
            urls.append(f"{url} ({status})")
        if len(urls) >= 50:
            break

    if not urls:
        return []

    return [
        Finding(
            severity="INFO",
            tool="ffuf",
            category="discovery",
            title="Content discovery results (ffuf)",
            url="",
            description="ffuf discovered paths that returned non-404 responses.",
            evidence=truncate(redact_text("\n".join(urls)), 800),
            remediation="Review discovered paths and ensure sensitive endpoints are protected.",
        )
    ]


def parse_nmap_xml(path: Path, target_host: str) -> List[Finding]:
    try:
        root = ET.fromstring(safe_read_text(path))
    except Exception:
        return []

    open_ports: List[str] = []
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for p in ports.findall("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = p.get("portid") or ""
            proto = p.get("protocol") or ""
            service = p.find("service")
            svc = ""
            if service is not None:
                name = service.get("name") or ""
                product = service.get("product") or ""
                version = service.get("version") or ""
                extra = " ".join([x for x in [name, product, version] if x]).strip()
                svc = extra
            entry = f"{proto}/{portid}"
            if svc:
                entry += f" ({svc})"
            open_ports.append(entry)

    if not open_ports:
        return []

    return [
        Finding(
            severity="INFO",
            tool="nmap",
            category="network",
            title="Open ports discovered (nmap)",
            url=f"host://{target_host}",
            description="Nmap reported open ports/services on the target.",
            evidence=truncate("\n".join(open_ports[:100]), 900),
            remediation="Confirm exposed services are required, patched, and firewalled appropriately.",
        )
    ]


def parse_masscan(path: Path, target_host: str) -> List[Finding]:
    data = load_json_file(path)
    ports: Set[str] = set()

    # masscan -oJ can be either JSON list or JSONL-ish; attempt both.
    if isinstance(data, list):
        for obj in data:
            if isinstance(obj, dict) and "ports" in obj:
                for p in obj.get("ports", []) or []:
                    if isinstance(p, dict) and "port" in p:
                        ports.add(str(p.get("port")))
    else:
        for obj in iter_jsonl(path):
            if isinstance(obj, dict) and "ports" in obj:
                for p in obj.get("ports", []) or []:
                    if isinstance(p, dict) and "port" in p:
                        ports.add(str(p.get("port")))

    if not ports:
        return []

    port_list = ", ".join(sorted(ports, key=lambda x: int(x) if x.isdigit() else 0)[:100])
    return [
        Finding(
            severity="INFO",
            tool="masscan",
            category="network",
            title="Open ports discovered (masscan)",
            url=f"host://{target_host}",
            description="Masscan reported open TCP ports on the target.",
            evidence=f"Ports: {port_list}",
            remediation="Confirm exposed services are required; restrict with firewall rules where appropriate.",
        )
    ]


def parse_ssh_audit(path: Path, target_host: str) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []

    issues = []
    for key in ("issues", "recommendations", "warnings"):
        v = data.get(key)
        if isinstance(v, list):
            issues = v
            break

    findings: List[Finding] = []
    if isinstance(issues, list) and issues:
        for item in issues[:200]:
            if not isinstance(item, dict):
                continue
            text = item.get("text") or item.get("message") or item.get("description") or ""
            level = item.get("level") or item.get("severity") or item.get("risk") or ""
            sev = normalize_severity(level, "INFO")
            findings.append(
                Finding(
                    severity=sev,
                    tool="ssh-audit",
                    category="ssh",
                    title="SSH configuration issue",
                    url=f"ssh://{target_host}",
                    description=truncate(redact_text(str(text)), 800),
                    remediation="Review sshd configuration, disable weak algorithms, and prefer modern ciphers/MACs.",
                )
            )
        return findings

    # Fallback: report exists but format is unknown.
    return [
        Finding(
            severity="INFO",
            tool="ssh-audit",
            category="ssh",
            title="ssh-audit report available",
            url=f"ssh://{target_host}",
            description="ssh-audit JSON report was generated but could not be parsed into individual findings.",
            evidence=f"File: {path.name}",
        )
    ]


def parse_trivy_rootfs(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if data is None:
        return []

    results: List[Dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("Results"), list):
        results = [r for r in data.get("Results", []) if isinstance(r, dict)]
    elif isinstance(data, list):
        results = [r for r in data if isinstance(r, dict)]

    vulns: List[Dict[str, Any]] = []
    for r in results:
        vs = r.get("Vulnerabilities")
        if isinstance(vs, list):
            vulns.extend([v for v in vs if isinstance(v, dict)])

    if not vulns:
        return []

    max_per_sev = int(os.environ.get("SECFORGE_MAX_FINDINGS_TRIVY", "200"))
    emitted = 0
    findings: List[Finding] = []

    def vul_key(v: Dict[str, Any]) -> str:
        return str(v.get("VulnerabilityID") or "") + "|" + str(v.get("PkgName") or "")

    seen: Set[str] = set()
    for v in sorted(vulns, key=lambda x: SEVERITY_ORDER.get(normalize_severity(x.get("Severity"), "LOW"), 0), reverse=True):
        if emitted >= max_per_sev:
            break
        k = vul_key(v)
        if k in seen:
            continue
        seen.add(k)

        sev = normalize_severity(v.get("Severity"), "LOW")
        if SEVERITY_ORDER.get(sev, 0) < SEVERITY_ORDER["HIGH"]:
            continue  # keep output manageable; lower severities summarized below

        vid = str(v.get("VulnerabilityID") or "VULN")
        pkg = str(v.get("PkgName") or "")
        installed = str(v.get("InstalledVersion") or "")
        fixed = str(v.get("FixedVersion") or "")
        title = str(v.get("Title") or vid)
        primary = str(v.get("PrimaryURL") or "")
        desc = str(v.get("Description") or "")

        evidence = []
        if pkg:
            evidence.append(f"package={pkg}")
        if installed:
            evidence.append(f"installed={installed}")
        if fixed:
            evidence.append(f"fixed={fixed}")
        if primary:
            evidence.append(f"ref={primary}")

        findings.append(
            Finding(
                severity=sev,
                tool="trivy",
                category="vulnerability",
                title=f"OS vulnerability: {title}",
                url="local://rootfs",
                description=truncate(redact_text(desc), 700),
                evidence=truncate(redact_text("; ".join(evidence)), 700),
                remediation="Update the affected package(s) and rebuild/patch the host as appropriate.",
            )
        )
        emitted += 1

    # Summary for the rest
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "INFO": 0}
    for v in vulns:
        sev = normalize_severity(v.get("Severity"), "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1

    findings.append(
        Finding(
            severity="INFO",
            tool="trivy",
            category="vulnerability",
            title="Trivy rootfs vulnerability summary",
            url="local://rootfs",
            description="Trivy reported OS package vulnerabilities on the filesystem.",
            evidence=f"Counts: CRITICAL={counts.get('CRITICAL',0)}, HIGH={counts.get('HIGH',0)}, MEDIUM={counts.get('MEDIUM',0)}, LOW={counts.get('LOW',0)}",
            remediation="Prioritize CRITICAL/HIGH updates first; consider unattended upgrades and regular patching.",
        )
    )
    return findings


def parse_gitleaks(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, list):
        return []
    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_GITLEAKS", "500"))

    for item in data:
        if len(findings) >= max_items:
            break
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID") or item.get("rule") or ""
        desc = item.get("Description") or item.get("description") or ""
        file_path = item.get("File") or item.get("file") or ""
        start = item.get("StartLine") or item.get("startLine") or ""
        evidence = f"{file_path}:{start} rule={rule}"
        findings.append(
            Finding(
                severity="HIGH",
                tool="gitleaks",
                category="secrets",
                title="Secret detected (gitleaks)",
                url=str(file_path),
                description=truncate(redact_text(str(desc)), 600),
                evidence=truncate(redact_text(evidence), 600),
                remediation="Rotate the exposed credential, remove it from the repo history, and use a secrets manager.",
            )
        )
    return findings


def parse_trufflehog(path: Path) -> List[Finding]:
    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_TRUFFLEHOG", "500"))

    for obj in iter_jsonl(path):
        if len(findings) >= max_items:
            break
        if not isinstance(obj, dict):
            continue
        detector = obj.get("DetectorName") or obj.get("Detector") or "Secret"
        source = obj.get("SourceMetadata") or {}
        file_path = ""
        line = ""
        try:
            if isinstance(source, dict):
                d = source.get("Data") or {}
                if isinstance(d, dict):
                    fs = d.get("Filesystem") or d.get("filesystem") or {}
                    if isinstance(fs, dict):
                        file_path = fs.get("file") or fs.get("path") or ""
                        line = fs.get("line") or ""
        except Exception:
            pass

        evidence = f"{file_path}:{line}" if file_path else ""
        findings.append(
            Finding(
                severity="HIGH",
                tool="trufflehog",
                category="secrets",
                title=f"Secret detected: {detector}",
                url=str(file_path),
                description="TruffleHog detected a potential secret. Secret values are intentionally redacted.",
                evidence=truncate(redact_text(evidence), 500),
                remediation="Verify the finding, rotate credentials, and remove secrets from code + history.",
            )
        )
    return findings


def parse_osv(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []

    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_OSV", "500"))

    for r in results:
        if len(findings) >= max_items:
            break
        if not isinstance(r, dict):
            continue
        pkgs = r.get("packages") or []
        vulns = r.get("vulnerabilities") or []
        pkg_names = []
        if isinstance(pkgs, list):
            for p in pkgs:
                if isinstance(p, dict):
                    name = p.get("name")
                    if name:
                        pkg_names.append(str(name))
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if len(findings) >= max_items:
                break
            if not isinstance(v, dict):
                continue
            vid = v.get("id") or "OSV"
            summary = v.get("summary") or ""
            details = v.get("details") or ""
            severity_score = None
            sev_list = v.get("severity")
            if isinstance(sev_list, list) and sev_list:
                # OSV uses objects like {"type": "CVSS_V3", "score": "9.8"}
                try:
                    severity_score = float(sev_list[0].get("score"))  # type: ignore
                except Exception:
                    severity_score = None
            sev = normalize_severity(severity_score, "MEDIUM")
            evidence = ""
            if pkg_names:
                evidence = "packages=" + ", ".join(pkg_names[:10])
            findings.append(
                Finding(
                    severity=sev,
                    tool="osv-scanner",
                    category="dependency",
                    title=f"Dependency vulnerability: {vid}",
                    url="",
                    description=truncate(redact_text(summary or details), 800),
                    evidence=truncate(redact_text(evidence), 700),
                    remediation="Update affected dependencies to non-vulnerable versions.",
                )
            )
    return findings


def parse_pip_audit(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, list):
        return []
    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_PIP_AUDIT", "500"))
    for dep in data:
        if len(findings) >= max_items:
            break
        if not isinstance(dep, dict):
            continue
        name = dep.get("name") or ""
        vulns = dep.get("vulns") or []
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if len(findings) >= max_items:
                break
            if not isinstance(v, dict):
                continue
            vid = v.get("id") or "VULN"
            desc = v.get("description") or ""
            fixed = v.get("fix_versions") or v.get("fix_versions", [])
            evidence = f"package={name}"
            if isinstance(fixed, list) and fixed:
                evidence += f" fixed_versions={','.join([str(x) for x in fixed[:5]])}"
            findings.append(
                Finding(
                    severity="MEDIUM",
                    tool="pip-audit",
                    category="dependency",
                    title=f"Python dependency vulnerability: {vid}",
                    url="",
                    description=truncate(redact_text(str(desc)), 700),
                    evidence=truncate(redact_text(evidence), 700),
                    remediation="Upgrade the vulnerable Python package to a fixed version.",
                )
            )
    return findings


def parse_hydra(path: Path, target_host: str) -> List[Finding]:
    text = safe_read_text(path)
    if not text:
        return []
    hits = []
    for line in text.splitlines():
        if "login:" in line.lower() and "password:" in line.lower():
            # Example: [22][ssh] host: x  login: user  password: pass
            line = redact_text(line)
            line = re.sub(r"(?i)(password:\s*)(\S+)", r"\1[REDACTED]", line)
            hits.append(line.strip())
            if len(hits) >= 20:
                break
    if not hits:
        return []
    return [
        Finding(
            severity="CRITICAL",
            tool="hydra",
            category="credentials",
            title="Valid credentials found (hydra)",
            url=f"ssh://{target_host}",
            description="Hydra reported at least one valid credential. Passwords are redacted.",
            evidence=truncate("\n".join(hits), 900),
            remediation="Disable password auth if possible, rotate credentials, and enforce MFA/keys + rate limiting.",
        )
    ]


def parse_netexec(path: Path, target_host: str) -> List[Finding]:
    text = safe_read_text(path)
    if not text:
        return []
    hits = []
    for line in text.splitlines():
        # NetExec often marks successes with [+] or "Pwn3d!" etc.
        if "pwn3d" in line.lower() or ("[+]" in line and "ssh" in line.lower()):
            line = redact_text(line)
            line = re.sub(r"(?i)(password|pass)\s*[:=]\s*\S+", r"\1=[REDACTED]", line)
            hits.append(line.strip())
            if len(hits) >= 20:
                break
    if not hits:
        return []
    return [
        Finding(
            severity="CRITICAL",
            tool="netexec",
            category="credentials",
            title="Valid credentials found (netexec)",
            url=f"ssh://{target_host}",
            description="NetExec reported at least one successful authentication. Passwords are redacted.",
            evidence=truncate("\n".join(hits), 900),
            remediation="Rotate credentials, restrict SSH access, and prefer key-based auth + MFA.",
        )
    ]


def parse_subfinder_jsonl(path: Path, target_host: str) -> List[Finding]:
    hosts: Set[str] = set()
    for obj in iter_jsonl(path):
        if isinstance(obj, dict):
            h = obj.get("host")
            if h:
                hosts.add(str(h))
    if not hosts:
        return []
    sample = sorted(hosts)[:50]
    return [
        Finding(
            severity="INFO",
            tool="subfinder",
            category="discovery",
            title="Subdomains discovered",
            url=f"dns://{target_host}",
            description="Subfinder discovered subdomains that may include forgotten staging/dev environments.",
            evidence=truncate("\n".join(sample), 900),
            remediation="Inventory and secure all discovered subdomains; decommission unused hosts.",
        )
    ]


def parse_httpx_jsonl(path: Path, target_host: str) -> List[Finding]:
    alive: List[str] = []
    for obj in iter_jsonl(path):
        if not isinstance(obj, dict):
            continue
        url = obj.get("url")
        status = obj.get("status_code") or obj.get("status-code") or obj.get("statusCode")
        if url:
            if status is not None and str(status).isdigit():
                alive.append(f"{url} ({status})")
            else:
                alive.append(str(url))
        if len(alive) >= 50:
            break
    if not alive:
        return []
    return [
        Finding(
            severity="INFO",
            tool="httpx",
            category="discovery",
            title="Live hosts discovered (httpx)",
            url=f"dns://{target_host}",
            description="httpx probed discovered hosts for responsive HTTP(S) services.",
            evidence=truncate("\n".join(alive), 900),
            remediation="Review exposed services on discovered hosts; ensure consistent security controls.",
        )
    ]


def parse_wafw00f_text(path: Path, target_url: str) -> List[Finding]:
    text = safe_read_text(path)
    if not text:
        return []
    waf = ""
    for line in text.splitlines():
        if "is behind" in line.lower() or "waf" in line.lower() and "detected" in line.lower():
            waf = line.strip()
            break
    if not waf:
        waf = "wafw00f output present (no WAF line detected)."
    return [
        Finding(
            severity="INFO",
            tool="wafw00f",
            category="waf",
            title="WAF detection result",
            url=target_url,
            description="A WAF can block/scatter scanner traffic and cause false negatives; tune scan intensity accordingly.",
            evidence=truncate(redact_text(waf), 800),
            remediation="If a WAF is present, use safe scan rates and validate findings with manual checks.",
        )
    ]


def parse_wapiti(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulnerabilities", {})
    if not isinstance(vulns, dict):
        return []
    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_WAPITI", "500"))

    for vuln_type, items in vulns.items():
        if not isinstance(items, list):
            continue
        for it in items:
            if len(findings) >= max_items:
                break
            if not isinstance(it, dict):
                continue
            url = it.get("url") or it.get("path") or ""
            title = f"Wapiti: {vuln_type}"
            info = it.get("info") or it.get("description") or ""
            evidence = it.get("parameter") or it.get("method") or ""
            findings.append(
                Finding(
                    severity="MEDIUM",
                    tool="wapiti",
                    category="webapp",
                    title=title,
                    url=str(url),
                    description=truncate(redact_text(str(info)), 700),
                    evidence=truncate(redact_text(str(evidence)), 500),
                    remediation="Investigate Wapiti findings and remediate per the vulnerability type.",
                )
            )
    return findings


def parse_dalfox(path: Path) -> List[Finding]:
    raw = safe_read_text(path).strip()
    if not raw:
        return []
    items: List[Any] = []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            # dalfox may wrap results
            if isinstance(parsed.get("result"), list):
                items = parsed.get("result")  # type: ignore
            elif isinstance(parsed.get("results"), list):
                items = parsed.get("results")  # type: ignore
            else:
                items = [parsed]
    except Exception:
        # JSONL fallback
        items = list(iter_jsonl(path))

    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_DALFOX", "500"))
    for it in items:
        if len(findings) >= max_items:
            break
        if not isinstance(it, dict):
            continue
        typ = str(it.get("type") or it.get("vuln") or "xss").lower()
        url = it.get("url") or it.get("target") or ""
        poc = it.get("poc") or it.get("payload") or ""
        severity = "HIGH" if "found" in typ or "poc" in typ else "MEDIUM"
        findings.append(
            Finding(
                severity=severity,
                tool="dalfox",
                category="xss",
                title="XSS finding (dalfox)",
                url=str(url),
                description="Dalfox reported a potential XSS vector.",
                evidence=truncate(redact_text(str(poc)), 400),
                remediation="Apply output encoding, validate input, and deploy a strict CSP where appropriate.",
            )
        )
    return findings


def parse_nikto(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if data is None:
        return []

    items: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        # Common format: {"vulnerabilities":[...]} or {"nikto":[{"item":[...]}]}
        if isinstance(data.get("vulnerabilities"), list):
            items = [x for x in data.get("vulnerabilities", []) if isinstance(x, dict)]  # type: ignore
        elif isinstance(data.get("nikto"), list):
            for n in data.get("nikto", []):  # type: ignore
                if isinstance(n, dict) and isinstance(n.get("item"), list):
                    items.extend([x for x in n.get("item", []) if isinstance(x, dict)])  # type: ignore
    elif isinstance(data, list):
        items = [x for x in data if isinstance(x, dict)]

    if not items:
        return []

    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_NIKTO", "500"))
    for it in items:
        if len(findings) >= max_items:
            break
        msg = it.get("msg") or it.get("description") or it.get("message") or ""
        url = it.get("url") or it.get("uri") or ""
        osvdb = it.get("osvdb") or ""
        evidence = []
        if osvdb:
            evidence.append(f"osvdb={osvdb}")
        if it.get("id"):
            evidence.append(f"id={it.get('id')}")
        findings.append(
            Finding(
                severity="MEDIUM",
                tool="nikto",
                category="webapp",
                title="Web server issue (nikto)",
                url=str(url),
                description=truncate(redact_text(str(msg)), 800),
                evidence=truncate(redact_text("; ".join(evidence)), 400),
                remediation="Review Nikto findings and harden server configuration accordingly.",
            )
        )
    return findings


def parse_testssl(path: Path, target_host: str) -> List[Finding]:
    data = load_json_file(path)
    if data is None:
        return []

    # testssl.sh JSON formats vary by version. Try to normalize to a list of dict entries.
    entries: List[Dict[str, Any]] = []
    if isinstance(data, list):
        entries = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        for key in ("scanResult", "scanresult", "findings", "results"):
            v = data.get(key)
            if isinstance(v, list):
                entries = [x for x in v if isinstance(x, dict)]
                break
        if not entries:
            entries = [data]

    findings: List[Finding] = []
    max_items = int(os.environ.get("SECFORGE_MAX_FINDINGS_TESTSSL", "500"))

    for e in entries:
        if len(findings) >= max_items:
            break
        sev = normalize_severity(e.get("severity") or e.get("severity_value") or e.get("severityValue"), "INFO")
        finding = e.get("finding") or e.get("id") or e.get("title") or ""
        if not finding:
            continue
        fid = str(e.get("id") or "").strip()
        evidence = str(e.get("finding") or "").strip()
        if fid:
            title = f"TLS/SSL finding: {fid}"
        else:
            title = "TLS/SSL finding"
        # Only emit actionable severities; INFO entries can be very noisy.
        if SEVERITY_ORDER.get(sev, 0) < SEVERITY_ORDER["LOW"]:
            continue
        findings.append(
            Finding(
                severity=sev,
                tool="testssl",
                category="tls",
                title=title,
                url=f"tls://{target_host}",
                description=truncate(redact_text(str(finding)), 900),
                evidence=truncate(redact_text(str(evidence)), 900),
                remediation="Disable insecure protocols/ciphers and enable modern TLS configuration.",
            )
        )

    return findings


def parse_whatweb(path: Path, target_url: str) -> List[Finding]:
    raw = safe_read_text(path).strip()
    if not raw:
        return []

    objs: List[Any] = []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            objs = parsed
        else:
            objs = [parsed]
    except Exception:
        objs = list(iter_jsonl(path))

    # Try to extract plugin names.
    plugins: Set[str] = set()
    for obj in objs[:5]:
        if not isinstance(obj, dict):
            continue
        p = obj.get("plugins")
        if isinstance(p, dict):
            for k in p.keys():
                if k:
                    plugins.add(str(k))

    if not plugins:
        return []

    sample = ", ".join(sorted(plugins)[:40])
    return [
        Finding(
            severity="INFO",
            tool="whatweb",
            category="fingerprinting",
            title="Technology fingerprint (WhatWeb)",
            url=target_url,
            description="WhatWeb identified technologies/plugins. This is informational but helps threat modeling and patching.",
            evidence=truncate(sample, 800),
            remediation="Ensure detected components are expected and kept up to date.",
        )
    ]


def parse_interactsh(path: Path, target_host: str) -> List[Finding]:
    # Interactsh outputs can be JSON/JSONL; count events only to avoid storing callback payloads.
    count = 0
    data = load_json_file(path)
    if isinstance(data, list):
        count = len(data)
    elif isinstance(data, dict):
        # Some formats wrap events.
        for k in ("data", "events", "interactions"):
            v = data.get(k)
            if isinstance(v, list):
                count = len(v)
                break
    else:
        for _ in iter_jsonl(path):
            count += 1
            if count >= 10000:
                break

    if count <= 0:
        return []

    return [
        Finding(
            severity="HIGH",
            tool="interactsh",
            category="oob",
            title="Out-of-band (OOB) callbacks observed",
            url=f"host://{target_host}",
            description="Interactsh observed at least one callback during the scan. This can indicate blind SSRF/XSS/SQLi/command injection.",
            evidence=f"Callbacks observed: {count} (details intentionally not stored).",
            remediation="Correlate callback timestamps with scan runs and investigate the endpoints/tools that triggered them.",
        )
    ]


def parse_corscanner(path: Path) -> List[Finding]:
    data = load_json_file(path)
    if data is None:
        return []

    # CORScanner formats vary; best-effort: surface any risky '*' / reflective origins.
    findings: List[Finding] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v)
                else:
                    ks = str(k).lower()
                    vs = str(v)
                    if "access-control-allow-origin" in ks and vs.strip() in ("*", "null"):
                        findings.append(
                            Finding(
                                severity="HIGH",
                                tool="corscanner",
                                category="cors",
                                title="CORS misconfiguration (permissive ACAO)",
                                url="",
                                description="CORS allowing '*' or 'null' can enable cross-site data access depending on credentials and headers.",
                                evidence=f"{k}: {vs}",
                                remediation="Restrict Access-Control-Allow-Origin to trusted origins; avoid wildcard with credentials.",
                            )
                        )
        elif isinstance(obj, list):
            for x in obj:
                walk(x)

    walk(data)

    # Deduplicate within tool output.
    dedup: Dict[str, Finding] = {}
    for f in findings:
        dedup[f.dedupe_key()] = f
    return list(dedup.values())


def collect_tools_and_findings(session_dir: Path) -> Tuple[Set[str], List[Finding], Dict[str, Any]]:
    tools_run: Set[str] = set()
    findings: List[Finding] = []

    preflight_path = session_dir / "preflight.json"
    preflight: Dict[str, Any] = {}
    if preflight_path.exists():
        pf = load_json_file(preflight_path)
        if isinstance(pf, dict):
            preflight = pf

    target_host = str(preflight.get("target_host") or "")
    target_url = str(preflight.get("target_url") or preflight.get("target_full_url") or "")
    if not target_host:
        target_host = str(preflight.get("target_input") or "")

    # Walk all files but only parse known outputs.
    for root, dirs, files in os.walk(session_dir, followlinks=False):
        root_path = Path(root)
        for fname in files:
            fpath = root_path / fname
            try:
                if fpath.is_symlink():
                    continue
            except Exception:
                continue

            rel = str(fpath.relative_to(session_dir)).replace("\\", "/")

            def add(tool: str, new: List[Finding]) -> None:
                if tool:
                    tools_run.add(tool)
                for f in new:
                    # Final defense-in-depth redaction on any user-facing text.
                    f.title = redact_text(f.title)
                    f.description = redact_text(f.description)
                    f.evidence = redact_text(f.evidence)
                    f.remediation = redact_text(f.remediation)
                    findings.append(f)

            if rel == "webapp/builtin.json":
                add("secforge-builtin", parse_builtin(fpath, target_url))
            elif rel == "emaildns/emaildns.json":
                add("check-email-dns", parse_emaildns(fpath, target_host))
            elif rel == "database/mysql.json":
                add("check-mysql", parse_mysql(fpath))
            elif rel == "webapp/nuclei.json":
                add("nuclei", parse_nuclei(fpath))
            elif rel == "webapp/zap.json":
                add("zap", parse_zap(fpath))
            elif rel == "webapp/ffuf.json":
                add("ffuf", parse_ffuf(fpath))
            elif rel == "network/nmap.xml":
                add("nmap", parse_nmap_xml(fpath, target_host))
            elif rel == "network/masscan.json":
                add("masscan", parse_masscan(fpath, target_host))
            elif rel == "network/ssh-audit.json":
                add("ssh-audit", parse_ssh_audit(fpath, target_host))
            elif rel == "hardening/trivy-rootfs.json":
                add("trivy", parse_trivy_rootfs(fpath))
            elif rel == "secrets/gitleaks.json":
                add("gitleaks", parse_gitleaks(fpath))
            elif rel == "secrets/trufflehog.json":
                add("trufflehog", parse_trufflehog(fpath))
            elif rel == "dependencies/osv.json":
                add("osv-scanner", parse_osv(fpath))
            elif rel == "dependencies/pip-audit.json":
                add("pip-audit", parse_pip_audit(fpath))
            elif rel == "passwords/hydra.txt":
                add("hydra", parse_hydra(fpath, target_host))
            elif rel == "passwords/netexec.txt":
                add("netexec", parse_netexec(fpath, target_host))
            elif rel == "emaildns/subfinder.jsonl":
                add("subfinder", parse_subfinder_jsonl(fpath, target_host))
            elif rel == "emaildns/httpx.jsonl":
                add("httpx", parse_httpx_jsonl(fpath, target_host))
            elif rel == "webapp/wafw00f.txt":
                add("wafw00f", parse_wafw00f_text(fpath, target_url))
            elif rel == "webapp/wapiti.json":
                add("wapiti", parse_wapiti(fpath))
            elif rel == "webapp/dalfox.json":
                add("dalfox", parse_dalfox(fpath))
            elif rel == "webapp/nikto.json":
                add("nikto", parse_nikto(fpath))
            elif rel == "webapp/whatweb.json":
                add("whatweb", parse_whatweb(fpath, target_url))
            elif rel == "ssl/testssl.json":
                add("testssl", parse_testssl(fpath, target_host))
            elif rel == "api/interactsh.json":
                add("interactsh", parse_interactsh(fpath, target_host))
            elif rel == "webapp/corscanner.json":
                add("corscanner", parse_corscanner(fpath))

    return tools_run, findings, preflight


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    by_key: Dict[str, Finding] = {}
    for f in findings:
        k = f.dedupe_key()
        if k not in by_key:
            by_key[k] = f
            continue
        cur = by_key[k]
        if f.tool != cur.tool:
            cur.also_found_by.add(f.tool)
        cur.also_found_by.update(f.also_found_by)
        cur.severity = severity_max(cur.severity, f.severity)
        # Fill missing fields from secondary findings.
        for attr in ("url", "description", "evidence", "remediation", "cwe", "owasp"):
            if not getattr(cur, attr) and getattr(f, attr):
                setattr(cur, attr, getattr(f, attr))
    return list(by_key.values())


def compute_summary(findings: List[Finding]) -> Dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = f.severity.upper()
        if s == "CRITICAL":
            summary["critical"] += 1
        elif s == "HIGH":
            summary["high"] += 1
        elif s == "MEDIUM":
            summary["medium"] += 1
        elif s == "LOW":
            summary["low"] += 1
        else:
            summary["info"] += 1
    return summary


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity.upper(), 0),
            (f.category or ""),
            (f.title or ""),
            (f.url or ""),
            (f.tool or ""),
        ),
    )


def write_findings_json(session_dir: Path, tools_run: Set[str], findings: List[Finding], preflight: Dict[str, Any]) -> Path:
    out_path = session_dir / "findings.json"

    scan_date = str(preflight.get("timestamp_utc") or preflight.get("timestamp") or "") or utc_now_iso()
    target = str(preflight.get("target_host") or preflight.get("target_input") or "")
    profile = str(preflight.get("profile") or "")

    sorted_findings = sort_findings(findings)
    summary = compute_summary(sorted_findings)

    # Assign deterministic IDs after sorting.
    out_findings = []
    for idx, f in enumerate(sorted_findings, start=1):
        fid = f"SF-{idx:03d}"
        payload = f.to_json()
        payload["id"] = fid
        out_findings.append(payload)

    out = {
        "scan_date": scan_date,
        "target": target,
        "scan_profile": profile,
        "tools_run": sorted(t for t in tools_run if t),
        "summary": summary,
        "findings": out_findings,
    }

    out_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


def try_export_sarif(session_dir: Path, findings_json: Path) -> None:
    export_script = Path(__file__).with_name("export-sarif.py")
    if not export_script.exists():
        return
    try:
        # Run as a subprocess so SARIF logic remains independently usable.
        import subprocess  # noqa: S404

        subprocess.run(
            [sys.executable, str(export_script), str(findings_json)],
            cwd=str(session_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge SecForge tool reports into findings.json (and optional findings.sarif).")
    parser.add_argument("session_dir", help="Path to /opt/secforge/reports/<SESSION>/")
    args = parser.parse_args()

    session_dir = Path(args.session_dir).expanduser().resolve()
    if not session_dir.exists() or not session_dir.is_dir():
        print(f"ERROR: session_dir not found: {session_dir}", file=sys.stderr)
        return 2

    tools_run, findings, preflight = collect_tools_and_findings(session_dir)
    merged = dedupe_findings(findings)
    findings_json = write_findings_json(session_dir, tools_run, merged, preflight)
    try_export_sarif(session_dir, findings_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

