"""SecForge v2 parser: stripe-check.py (compliance/stripe-check.json)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from secforge.parsers import register
from secforge.parsers._base import load_json_file, make_finding
from secforge.normalize import truncate


_CHECK_TO_FINDING = {
    "https_enforced": ("payment.https_not_enforced", "HTTPS not enforced for payment pages", "high"),
    "mixed_content": ("payment.https_not_enforced", "Mixed content on payment pages", "high"),
    "stripe_js_official_only": ("payment.third_party_scripts", "Stripe.js loaded from non-official source", "high"),
    "raw_card_fields": ("payment.raw_card_fields", "Raw card input fields detected in HTML", "critical"),
    "csp_present": ("payment.missing_csp_on_checkout", "Missing CSP on payment pages", "high"),
    "csp_blocks_unsafe_inline": ("headers.csp_unsafe_inline", "CSP allows unsafe-inline on payment pages", "high"),
    "no_card_number_patterns": ("payment.raw_card_fields", "Card number patterns detected in page source", "critical"),
    "sri_on_external_scripts": ("payment.missing_sri", "External scripts missing SRI on payment pages", "medium"),
    "clickjacking_protection": ("misconfig.missing_clickjacking_protection", "Missing clickjacking protection on payment pages", "medium"),
    "no_third_party_scripts_on_payment_pages": ("payment.third_party_scripts", "Third-party scripts on payment pages", "medium"),
}


@register("compliance/stripe-check.json")
def parse_stripe_check(fpath: Path, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = load_json_file(fpath)
    if not isinstance(data, dict):
        return []

    target_url = context.get("target_url", "")
    status = data.get("status", "")

    if status != "ok":
        return [make_finding(
            issue_key="payment.raw_card_fields",
            title="Stripe/payment check did not run successfully",
            severity="info",
            tool="stripe-check",
            category="payment",
            asset={"type": "web", "host": context.get("target_host", ""), "url": target_url},
            description="The stripe-check script returned an error status.",
            evidence=truncate(str(data.get("errors", [])), 500),
        )]

    checks = data.get("checks", {})
    if not isinstance(checks, dict):
        return []

    findings: List[Dict[str, Any]] = []
    for check_name, check_data in checks.items():
        if not isinstance(check_data, dict):
            continue
        passed = check_data.get("pass", True)
        if passed:
            continue

        mapping = _CHECK_TO_FINDING.get(check_name)
        if not mapping:
            continue
        ik, title, sev = mapping

        evidence_data = check_data.get("evidence", {})
        evidence_str = ""
        if isinstance(evidence_data, dict):
            # Summarize evidence
            for k, v in evidence_data.items():
                if v and v != [] and v != {}:
                    evidence_str += f"{k}: {truncate(str(v), 200)}; "
        evidence_str = evidence_str.rstrip("; ")

        findings.append(make_finding(
            issue_key=ik,
            title=title,
            severity=sev,
            tool="stripe-check",
            category="payment",
            asset={"type": "web", "host": context.get("target_host", ""), "url": target_url},
            description=f"Payment security check '{check_name}' failed.",
            evidence=truncate(evidence_str, 800),
        ))

    return findings
