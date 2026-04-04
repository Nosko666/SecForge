"""SecForge v2 Finding schema — the canonical data model.

10 mandatory fields per finding. Nested objects for optional detail.
6 asset types. Strict enums. No v1 backward compatibility needed.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# --- Enums (strict, lowercase) ---

SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER: Dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

CONFIDENCE_VALUES = ("confirmed", "likely", "possible")
CONFIDENCE_ORDER: Dict[str, int] = {
    "confirmed": 3,
    "likely": 2,
    "possible": 1,
}

CATEGORY_VALUES = (
    "headers", "tls", "xss", "sqli", "injection", "secrets", "auth",
    "cors", "misconfig", "deps", "network", "dns", "cookies", "payment",
    "hardening", "mobile", "exposure", "discovery", "database", "compliance",
)

ASSET_TYPES = ("web", "host", "package", "code", "apk", "config")

FINGERPRINT_TYPES = (
    "web_server_level",
    "web_endpoint_level",
    "host_level",
    "package_level",
    "code_level",
    "apk_level",
    "config_level",
)

STATUS_VALUES = (
    "new", "existing", "fixed", "reopened",
    "ignored", "accepted_risk", "false_positive",
)


# --- Nested object schemas ---

@dataclass
class Asset:
    """What is affected. At minimum {type: "..."}."""
    type: str  # One of ASSET_TYPES
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    url: Optional[str] = None
    package: Optional[str] = None
    package_version: Optional[str] = None
    ecosystem: Optional[str] = None
    apk: Optional[str] = None
    service: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type}
        for k in ("host", "port", "protocol", "url", "package", "package_version",
                   "ecosystem", "apk", "service"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Asset":
        if not isinstance(d, dict):
            return cls(type="web")
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Location:
    """Where it was found (optional — omit absent fields)."""
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        for k in ("endpoint", "parameter", "file_path", "line"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Location":
        if not isinstance(d, dict):
            return cls()
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class VulnIdentifier:
    """One vulnerability identifier (CWE, CVE, OWASP, GHSA, etc.)."""
    type: str   # "CWE", "CVE", "OWASP", "GHSA", etc.
    value: str  # "CWE-89", "CVE-2024-12345", etc.

    def to_dict(self) -> Dict[str, str]:
        return {"type": self.type, "value": self.value}


@dataclass
class CVSS:
    """CVSS scoring (optional)."""
    score: Optional[float] = None
    vector: Optional[str] = None
    version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.score is not None:
            d["score"] = self.score
        if self.vector is not None:
            d["vector"] = self.vector
        if self.version is not None:
            d["version"] = self.version
        return d


@dataclass
class VulnInfo:
    """Vulnerability identifiers and scoring."""
    identifiers: List[VulnIdentifier] = field(default_factory=list)
    cvss: Optional[CVSS] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.identifiers:
            d["identifiers"] = [i.to_dict() for i in self.identifiers]
        if self.cvss is not None:
            cvss_d = self.cvss.to_dict()
            if cvss_d:
                d["cvss"] = cvss_d
        return d


@dataclass
class FixLocation:
    """One candidate fix location."""
    surface: str               # "nginx", "app-middleware", "ssh", etc.
    path: Optional[str] = None       # "/etc/nginx/sites-enabled/default"
    hint: Optional[str] = None       # "server block, line 42"
    confidence: str = "medium"       # "high", "medium", "low"

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"surface": self.surface, "confidence": self.confidence}
        if self.path is not None:
            d["path"] = self.path
        if self.hint is not None:
            d["hint"] = self.hint
        return d


@dataclass
class Remediation:
    """Fix guidance (optional section)."""
    summary: Optional[str] = None
    difficulty: Optional[str] = None  # "easy", "medium", "hard"
    fix_locations: List[FixLocation] = field(default_factory=list)
    steps: Optional[List[str]] = None
    rollback: Optional[str] = None
    risks: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.summary is not None:
            d["summary"] = self.summary
        if self.difficulty is not None:
            d["difficulty"] = self.difficulty
        if self.fix_locations:
            d["fix_locations"] = [fl.to_dict() for fl in self.fix_locations]
        if self.steps:
            d["steps"] = self.steps
        if self.rollback is not None:
            d["rollback"] = self.rollback
        if self.risks is not None:
            d["risks"] = self.risks
        return d


@dataclass
class VerificationAssertion:
    """Structured assertion for auto PASS/FAIL."""
    exit_code: Optional[int] = None
    stdout_contains: Optional[List[str]] = None
    stdout_not_contains: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.exit_code is not None:
            d["exit_code"] = self.exit_code
        if self.stdout_contains:
            d["stdout_contains"] = self.stdout_contains
        if self.stdout_not_contains:
            d["stdout_not_contains"] = self.stdout_not_contains
        return d


@dataclass
class VerificationEntry:
    """One verification check (pre or post fix)."""
    stage: str         # "pre" or "post"
    name: str          # "Check CSP header is present"
    command: str       # "curl -sI https://{host} | grep ..."
    assertions: Optional[VerificationAssertion] = None
    explain: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "stage": self.stage,
            "name": self.name,
            "command": self.command,
        }
        if self.assertions is not None:
            d["assertions"] = self.assertions.to_dict()
        if self.explain is not None:
            d["explain"] = self.explain
        return d


@dataclass
class Source:
    """Per-tool evidence from dedup merge."""
    tool: str
    evidence: str = ""
    raw_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"tool": self.tool, "evidence": self.evidence}
        if self.raw_path is not None:
            d["raw_path"] = self.raw_path
        return d


# --- Priority ---

@dataclass
class PriorityBreakdown:
    """Per-factor scores for explainability."""
    severity: int = 0
    internet_exposure: int = 0
    confidence: int = 0
    ease_of_fix: int = 0
    multi_tool: int = 0
    blast_radius: int = 0
    age: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "severity": self.severity,
            "internet_exposure": self.internet_exposure,
            "confidence": self.confidence,
            "ease_of_fix": self.ease_of_fix,
            "multi_tool": self.multi_tool,
            "blast_radius": self.blast_radius,
            "age": self.age,
        }


# --- The v2 Finding ---

@dataclass
class FindingV2:
    """The canonical v2 finding. 10 mandatory fields + optional nested sections."""

    # --- 10 MANDATORY fields ---
    id: str                    # Per-scan human ID (SF-001)
    fingerprint: str           # Stable SHA-256[:32]
    issue_key: str             # Machine-stable (headers.missing_csp)
    title: str                 # Original tool title
    normalized_title: str      # Canonical from catalog
    severity: str              # critical|high|medium|low|info
    confidence: str            # confirmed|likely|possible
    tool: str                  # Primary tool name
    category: str              # Fixed enum (20 values)
    asset: Asset               # At minimum {type: "..."}

    # --- Optional fields ---
    also_found_by: List[str] = field(default_factory=list)
    sources: List[Source] = field(default_factory=list)
    location: Optional[Location] = None
    vuln: Optional[VulnInfo] = None
    tags: List[str] = field(default_factory=list)
    description: str = ""
    evidence: str = ""
    remediation: Optional[Remediation] = None
    verification: List[VerificationEntry] = field(default_factory=list)
    first_seen: Optional[str] = None    # UTC ISO-8601
    last_seen: Optional[str] = None     # UTC ISO-8601
    status: str = "new"
    cluster_id: str = "other"
    related_findings: List[str] = field(default_factory=list)  # fingerprints

    # --- Priority (set by scoring engine) ---
    priority_score: Optional[int] = None
    priority_label: Optional[str] = None
    priority_reason: Optional[str] = None
    priority_breakdown: Optional[PriorityBreakdown] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON-compatible dict. Omits None/empty optional fields."""
        d: Dict[str, Any] = {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "issue_key": self.issue_key,
            "title": self.title,
            "normalized_title": self.normalized_title,
            "severity": self.severity,
            "confidence": self.confidence,
            "tool": self.tool,
            "category": self.category,
            "asset": self.asset.to_dict(),
        }

        if self.also_found_by:
            d["also_found_by"] = self.also_found_by
        if self.sources:
            d["sources"] = [s.to_dict() for s in self.sources]
        if self.location is not None:
            loc = self.location.to_dict()
            if loc:
                d["location"] = loc
        if self.vuln is not None:
            vuln_d = self.vuln.to_dict()
            if vuln_d:
                d["vuln"] = vuln_d
        if self.tags:
            d["tags"] = self.tags
        if self.description:
            d["description"] = self.description
        if self.evidence:
            d["evidence"] = self.evidence
        if self.remediation is not None:
            rem = self.remediation.to_dict()
            if rem:
                d["remediation"] = rem
        if self.verification:
            d["verification"] = [v.to_dict() for v in self.verification]
        if self.first_seen is not None:
            d["first_seen"] = self.first_seen
        if self.last_seen is not None:
            d["last_seen"] = self.last_seen
        if self.status != "new":
            d["status"] = self.status
        if self.cluster_id != "other":
            d["cluster_id"] = self.cluster_id
        if self.related_findings:
            d["related_findings"] = self.related_findings
        if self.priority_score is not None:
            d["priority_score"] = self.priority_score
        if self.priority_label is not None:
            d["priority_label"] = self.priority_label
        if self.priority_reason is not None:
            d["priority_reason"] = self.priority_reason
        if self.priority_breakdown is not None:
            d["priority_breakdown"] = self.priority_breakdown.to_dict()

        return d


# --- Validation ---

_MANDATORY_KEYS = (
    "id", "fingerprint", "issue_key", "title", "normalized_title",
    "severity", "confidence", "tool", "category", "asset",
)


def validate_finding(d: Dict[str, Any]) -> bool:
    """Check that a dict has all 10 mandatory fields with valid values."""
    if not isinstance(d, dict):
        return False
    for k in _MANDATORY_KEYS:
        if k not in d:
            return False
    if not isinstance(d.get("asset"), dict) or "type" not in d["asset"]:
        return False
    if d.get("severity", "").lower() not in SEVERITY_VALUES:
        return False
    if d.get("confidence", "").lower() not in CONFIDENCE_VALUES:
        return False
    if d["asset"]["type"] not in ASSET_TYPES:
        return False
    return True


def severity_max(a: str, b: str) -> str:
    """Return the higher severity."""
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def confidence_max(a: str, b: str) -> str:
    """Return the higher confidence."""
    return a if CONFIDENCE_ORDER.get(a, 0) >= CONFIDENCE_ORDER.get(b, 0) else b


# --- v1 compatibility shim ---

def to_v1_dict(v2: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a v2 finding dict to v1-compatible dict for merge-reports.py shim."""
    d = {
        "id": v2.get("id", ""),
        "severity": (v2.get("severity") or "INFO").upper(),
        "tool": v2.get("tool", ""),
        "also_found_by": v2.get("also_found_by", []),
        "category": v2.get("category", ""),
        "title": v2.get("title", ""),
        "url": "",
        "description": v2.get("description", ""),
        "evidence": v2.get("evidence", ""),
        "remediation": "",
        "cwe": "",
        "owasp": "",
        "status": v2.get("status", "open"),
    }
    # Extract URL from asset
    asset = v2.get("asset", {})
    if isinstance(asset, dict):
        d["url"] = asset.get("url") or asset.get("host") or ""
    # Extract remediation summary
    rem = v2.get("remediation")
    if isinstance(rem, dict):
        d["remediation"] = rem.get("summary") or ""
    # Extract CWE/OWASP from vuln identifiers
    vuln = v2.get("vuln")
    if isinstance(vuln, dict):
        for ident in vuln.get("identifiers", []):
            if isinstance(ident, dict):
                if ident.get("type") == "CWE" and not d["cwe"]:
                    d["cwe"] = ident.get("value", "")
                if ident.get("type") == "OWASP" and not d["owasp"]:
                    d["owasp"] = ident.get("value", "")
    return d
