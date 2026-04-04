"""SecForge v2 fingerprint engine.

Computes stable SHA-256[:32] fingerprints using type-specific canonical strings.
Requires issue_key to be set on the finding before computing.

6 asset types, 7 canonical string templates.
Normalization rules per plan: host lowercased, default ports omitted,
endpoint case preserved, parameter lowercased, missing → empty string.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional

# Default ports per protocol — omitted from canonical string.
_DEFAULT_PORTS = {
    "https": 443,
    "http": 80,
    "ssh": 22,
    "ftp": 21,
}


def compute_fingerprint(finding: Dict[str, Any]) -> str:
    """Compute a stable 32-char hex fingerprint for a finding.

    The finding MUST have 'issue_key' set before calling this.
    Returns SHA-256[:32] (128-bit, 32 hex chars).
    """
    canonical = _canonical_string(finding)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _canonical_string(finding: Dict[str, Any]) -> str:
    """Build the canonical string based on asset type and fingerprint_type."""
    asset = finding.get("asset") or {}
    if isinstance(asset, dict):
        asset_type = asset.get("type", "web")
    else:
        asset_type = "web"

    issue_key = finding.get("issue_key", "")
    fp_type = finding.get("_fingerprint_type", "")

    # Determine canonical template from fingerprint_type hint or asset_type
    if fp_type == "web_endpoint_level" or (
        asset_type == "web" and _is_endpoint_level(issue_key)
    ):
        return _canonical_web_endpoint(finding)
    if fp_type == "web_server_level" or asset_type == "web":
        return _canonical_web_server(finding)
    if asset_type == "host":
        return _canonical_host(finding)
    if asset_type == "package":
        return _canonical_package(finding)
    if asset_type == "code":
        return _canonical_code(finding)
    if asset_type == "apk":
        return _canonical_apk(finding)
    if asset_type == "config":
        return _canonical_config(finding)
    # Fallback
    return _canonical_web_server(finding)


def _is_endpoint_level(issue_key: str) -> bool:
    """Check if the issue_key implies endpoint-level fingerprinting."""
    prefix = issue_key.split(".")[0] if "." in issue_key else ""
    return prefix in ("xss", "sqli", "injection", "auth")


# --- Canonical string templates ---

def _canonical_web_server(f: Dict[str, Any]) -> str:
    """web|host|port|protocol|||issue_key (server-level, no endpoint)."""
    a = f.get("asset") or {}
    host = _norm_host(a.get("host", ""))
    port = _norm_port(a.get("port"), a.get("protocol", "https"))
    proto = (a.get("protocol") or "https").lower().strip()
    ik = f.get("issue_key", "")
    return f"web|{host}|{port}|{proto}|||{ik}"


def _canonical_web_endpoint(f: Dict[str, Any]) -> str:
    """web|host|port|protocol|endpoint|parameter|issue_key."""
    a = f.get("asset") or {}
    loc = f.get("location") or {}
    if isinstance(loc, dict):
        endpoint = _norm_endpoint(loc.get("endpoint", ""))
        parameter = (loc.get("parameter") or "").lower().strip()
    else:
        endpoint = ""
        parameter = ""
    host = _norm_host(a.get("host", ""))
    port = _norm_port(a.get("port"), a.get("protocol", "https"))
    proto = (a.get("protocol") or "https").lower().strip()
    ik = f.get("issue_key", "")
    return f"web|{host}|{port}|{proto}|{endpoint}|{parameter}|{ik}"


def _canonical_host(f: Dict[str, Any]) -> str:
    """host|host|port|protocol|issue_key."""
    a = f.get("asset") or {}
    host = _norm_host(a.get("host", ""))
    port = _norm_port(a.get("port"), a.get("protocol", ""))
    proto = (a.get("protocol") or "").lower().strip()
    ik = f.get("issue_key", "")
    return f"host|{host}|{port}|{proto}|{ik}"


def _canonical_package(f: Dict[str, Any]) -> str:
    """package|name|version|ecosystem|vuln_id|issue_key."""
    a = f.get("asset") or {}
    name = (a.get("package") or "").strip()  # Case preserved
    version = (a.get("package_version") or "").strip()
    ecosystem = (a.get("ecosystem") or "").lower().strip()
    # Extract vuln_id from vuln.identifiers if present
    vuln_id = _extract_vuln_id(f)
    ik = f.get("issue_key", "")
    return f"package|{name}|{version}|{ecosystem}|{vuln_id}|{ik}"


def _canonical_code(f: Dict[str, Any]) -> str:
    """code|file_path|line|issue_key."""
    loc = f.get("location") or {}
    if isinstance(loc, dict):
        fp = (loc.get("file_path") or "").strip()  # Case preserved
        line = str(loc.get("line") or "")
    else:
        fp = ""
        line = ""
    ik = f.get("issue_key", "")
    return f"code|{fp}|{line}|{ik}"


def _canonical_apk(f: Dict[str, Any]) -> str:
    """apk|package_name|issue_key."""
    a = f.get("asset") or {}
    pkg = (a.get("apk") or a.get("package") or "").strip()
    ik = f.get("issue_key", "")
    return f"apk|{pkg}|{ik}"


def _canonical_config(f: Dict[str, Any]) -> str:
    """config|host|service|file_path|issue_key."""
    a = f.get("asset") or {}
    loc = f.get("location") or {}
    host = _norm_host(a.get("host", ""))
    service = (a.get("service") or "").lower().strip()
    fp = ""
    if isinstance(loc, dict):
        fp = (loc.get("file_path") or "").strip()
    ik = f.get("issue_key", "")
    return f"config|{host}|{service}|{fp}|{ik}"


# --- Normalization helpers ---

def _norm_host(host: Optional[str]) -> str:
    """Lowercase, strip trailing dots."""
    return (host or "").lower().strip().rstrip(".")


def _norm_port(port: Any, protocol: str = "") -> str:
    """Omit default ports (443/https, 80/http, 22/ssh). Return empty string if default."""
    if port is None:
        return ""
    try:
        p = int(port)
    except (ValueError, TypeError):
        return ""
    proto = (protocol or "").lower().strip()
    default = _DEFAULT_PORTS.get(proto)
    if default is not None and p == default:
        return ""
    return str(p)


def _norm_endpoint(endpoint: Optional[str]) -> str:
    """Case preserved, trailing slash stripped, query params excluded."""
    ep = (endpoint or "").strip()
    if "?" in ep:
        ep = ep.split("?")[0]
    return ep.rstrip("/")


def _extract_vuln_id(f: Dict[str, Any]) -> str:
    """Extract the first CVE/GHSA/OSV identifier for package fingerprinting."""
    vuln = f.get("vuln")
    if not isinstance(vuln, dict):
        return ""
    identifiers = vuln.get("identifiers")
    if not isinstance(identifiers, list):
        return ""
    for ident in identifiers:
        if isinstance(ident, dict):
            itype = (ident.get("type") or "").upper()
            if itype in ("CVE", "GHSA", "OSV"):
                return ident.get("value", "")
    return ""
