"""SecForge v2 parser: check-email-dns.sh (emaildns/emaildns.json)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding


@register("emaildns/emaildns.json")
def parse_emaildns(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []

    checks = data.get("checks", {}) if isinstance(data.get("checks"), dict) else {}
    target_host = context.get("target_host", "")
    findings: List[Dict[str, Any]] = []

    # SPF
    spf = checks.get("spf", {}) if isinstance(checks.get("spf"), dict) else {}
    if not spf.get("present", False):
        findings.append(make_finding(
            issue_key="dns.missing_spf", title="Missing SPF record", severity="medium",
            tool="check-email-dns", category="dns",
            asset={"type": "web", "host": target_host},
            description="SPF helps prevent sender spoofing for your domain.",
            remediation_summary="Add an SPF TXT record for your outbound mail providers and use -all where feasible.",
        ))
    else:
        all_mech = str(spf.get("all_mechanism", "unknown"))
        if all_mech and all_mech != "-all":
            findings.append(make_finding(
                issue_key="dns.spf_not_strict", title="SPF policy is not strict (-all)", severity="low",
                tool="check-email-dns", category="dns",
                asset={"type": "web", "host": target_host},
                description="Using ~all/?all/+all can weaken spoofing protection.",
                evidence=f"SPF all-mechanism: {all_mech}",
                remediation_summary="Prefer -all once your SPF record is correct and stable.",
            ))

    # DMARC
    dmarc = checks.get("dmarc", {}) if isinstance(checks.get("dmarc"), dict) else {}
    if not dmarc.get("present", False):
        findings.append(make_finding(
            issue_key="dns.missing_dmarc", title="Missing DMARC record", severity="medium",
            tool="check-email-dns", category="dns",
            asset={"type": "web", "host": target_host},
            description="DMARC enforces alignment and improves spoofing protection and reporting.",
            remediation_summary="Add a DMARC TXT record at _dmarc.<domain> with p=reject where feasible.",
        ))
    else:
        policy = str(dmarc.get("policy", "unknown"))
        if policy and policy != "reject":
            findings.append(make_finding(
                issue_key="dns.dmarc_not_enforcing", title="DMARC policy is not enforcing (p=reject)", severity="low",
                tool="check-email-dns", category="dns",
                asset={"type": "web", "host": target_host},
                evidence=f"DMARC policy: {policy}",
                remediation_summary="Move to p=quarantine then p=reject after validating alignment.",
            ))

    # DKIM
    dkim = checks.get("dkim", {}) if isinstance(checks.get("dkim"), dict) else {}
    if not dkim.get("present", False):
        findings.append(make_finding(
            issue_key="dns.missing_dkim", title="DKIM selector not found (common selectors)", severity="medium",
            tool="check-email-dns", category="dns",
            asset={"type": "web", "host": target_host},
            description="DKIM helps authenticate emails. This check only tests common selectors.",
            remediation_summary="Ensure your mail provider publishes DKIM records and document the selector used.",
        ))

    # DNSSEC
    dnssec = checks.get("dnssec", {}) if isinstance(checks.get("dnssec"), dict) else {}
    if str(dnssec.get("enabled", "unknown")).lower() == "false":
        findings.append(make_finding(
            issue_key="dns.missing_dnssec", title="DNSSEC not detected", severity="info",
            tool="check-email-dns", category="dns",
            asset={"type": "web", "host": target_host},
            description="DNSSEC helps protect DNS integrity. Not all environments support it.",
            remediation_summary="Enable DNSSEC at your DNS provider if supported.",
        ))

    # Zone transfer
    zone = checks.get("zone_transfer", {}) if isinstance(checks.get("zone_transfer"), dict) else {}
    if zone.get("allowed", False):
        ns = str(zone.get("allowed_ns", "") or "")
        findings.append(make_finding(
            issue_key="dns.zone_transfer_allowed", title="DNS zone transfer (AXFR) allowed", severity="critical",
            tool="check-email-dns", category="dns",
            asset={"type": "web", "host": target_host},
            description="Allowing AXFR can leak full DNS zone contents (hosts, subdomains, internal structure).",
            evidence=f"AXFR succeeded against NS: {ns}" if ns else "AXFR succeeded.",
            remediation_summary="Disable public AXFR; restrict transfers to authorized secondary name servers only.",
        ))

    return findings
