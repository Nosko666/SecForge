"""SecForge v2 normalization, redaction, and utility functions.

Extracted from merge-reports.py for reuse across the v2 pipeline.
All functions preserve their original signatures for v1 compatibility.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


# --- Severity ---

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 0,
}


def normalize_severity(sev: Any, default: str = "INFO") -> str:
    """Map any severity representation to CRITICAL/HIGH/MEDIUM/LOW/INFO."""
    if sev is None:
        return default
    if isinstance(sev, (int, float)):
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
    """Return the higher severity."""
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


# --- v2 lowercase severity helpers ---

def normalize_severity_v2(sev: Any, default: str = "info") -> str:
    """Like normalize_severity but returns lowercase (v2 enum)."""
    return normalize_severity(sev, default.upper()).lower()


def severity_max_v2(a: str, b: str) -> str:
    """Return the higher severity (v2 lowercase)."""
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return a if order.get(a, 0) >= order.get(b, 0) else b


# --- Text normalization ---

def truncate(text: str, max_len: int = 800) -> str:
    text = text or ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    url = url.replace("\r", "")
    url = url.rstrip("/")
    return url


def normalize_title(title: str) -> str:
    """Canonicalize common issue titles for cross-tool dedup (v1 style)."""
    t = (title or "").strip().lower()
    t = re.sub(r"\s+", " ", t)
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


# --- Redaction ---

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


# --- CWE/OWASP inference ---

def infer_cwe_owasp(category: str, title: str) -> Tuple[str, str]:
    """Infer CWE and OWASP category from finding category/title."""
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
    if ".env" in t or ".git" in t or ("exposed" in t and ("config" in t or "file" in t or "directory" in t)):
        return mk("CWE-200", "A05:2021-Security Misconfiguration")
    if "cookie" in t and "httponly" in t:
        return mk("CWE-1004", "A07:2021-Identification and Authentication Failures")
    if "cookie" in t and "secure" in t:
        return mk("CWE-614", "A07:2021-Identification and Authentication Failures")
    if "tls" in t or "ssl" in t or "cipher" in t or cat == "tls":
        return mk("CWE-327", "A02:2021-Cryptographic Failures")
    if cat in ("secrets", "credentials"):
        return mk("CWE-798", "A07:2021-Identification and Authentication Failures")
    if cat in ("dependency", "dependencies", "deps"):
        return mk("", "A06:2021-Vulnerable and Outdated Components")
    return ("", "")


# --- Timestamps ---

def utc_now_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
