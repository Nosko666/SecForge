#!/usr/bin/env bash
set -euo pipefail

umask 022

domain_raw="${1:-}"
if [[ -z "${domain_raw}" ]]; then
  echo "Usage: ${0##*/} <domain>" >&2
  exit 2
fi

domain="${domain_raw}"
domain="${domain#http://}"
domain="${domain#https://}"
domain="${domain%%/*}"
domain="${domain%%:*}"

if ! command -v dig >/dev/null 2>&1; then
  echo "dig not found (install dnsutils)." >&2
  exit 1
fi

now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

txt_clean() {
  tr -d '"' | tr '\n' ' ' | sed 's/  */ /g' | sed 's/^ *//; s/ *$//'
}

spf_txt="$(dig +short TXT "${domain}" 2>/dev/null | txt_clean | grep -oiE 'v=spf1[^ ]*.*' | head -n1 || true)"
dmarc_txt="$(dig +short TXT "_dmarc.${domain}" 2>/dev/null | txt_clean | grep -oiE 'v=dmarc1[^ ]*.*' | head -n1 || true)"
tls_rpt_txt="$(dig +short TXT "_smtp._tls.${domain}" 2>/dev/null | txt_clean | grep -oiE 'v=tlsrptv1[^ ]*.*' | head -n1 || true)"

spf_all="unknown"
if [[ -n "${spf_txt}" ]]; then
  if grep -qi -- " -all" <<<"${spf_txt}"; then spf_all="-all"; fi
  if grep -qi -- " ~all" <<<"${spf_txt}"; then spf_all="~all"; fi
  if grep -qi -- " ?all" <<<"${spf_txt}"; then spf_all="?all"; fi
  if grep -qi -- " +all" <<<"${spf_txt}"; then spf_all="+all"; fi
fi

dmarc_policy="unknown"
if [[ -n "${dmarc_txt}" ]]; then
  dmarc_policy="$(grep -oiE 'p=(none|quarantine|reject)' <<<"${dmarc_txt}" | head -n1 | cut -d= -f2 || true)"
  dmarc_policy="${dmarc_policy:-unknown}"
fi

dnssec_enabled="unknown"
if dig +dnssec "${domain}" A +noall +answer 2>/dev/null | grep -q "RRSIG"; then
  dnssec_enabled="true"
else
  dnssec_enabled="false"
fi

dkim_selectors_found=()
common_selectors=(default selector1 selector2 google mail s1 s2 s2048 k1 k2)
for sel in "${common_selectors[@]}"; do
  rec="$(dig +short TXT "${sel}._domainkey.${domain}" 2>/dev/null | txt_clean | grep -oiE 'v=dkim1[^ ]*.*' | head -n1 || true)"
  if [[ -n "${rec}" ]]; then
    dkim_selectors_found+=("${sel}")
  fi
done

mta_sts_txt="$(dig +short TXT "_mta-sts.${domain}" 2>/dev/null | txt_clean | grep -oiE 'v=stsv1[^ ]*.*' | head -n1 || true)"
mta_sts_txt_present="false"
[[ -n "${mta_sts_txt}" ]] && mta_sts_txt_present="true"

mta_sts_policy_url="https://mta-sts.${domain}/.well-known/mta-sts.txt"
mta_sts_policy_present="false"
if command -v curl >/dev/null 2>&1; then
  if curl -fsS --max-time 10 "${mta_sts_policy_url}" 2>/dev/null | grep -qi '^version:\s*STSv1'; then
    mta_sts_policy_present="true"
  fi
fi

ns_records=()
while IFS= read -r ns; do
  ns="${ns%.}"
  [[ -n "${ns}" ]] && ns_records+=("${ns}")
done < <(dig +short NS "${domain}" 2>/dev/null || true)

zone_transfer_attempted="false"
zone_transfer_allowed="false"
zone_transfer_ns=""
if [[ "${#ns_records[@]}" -gt 0 ]]; then
  zone_transfer_attempted="true"
  for ns in "${ns_records[@]}"; do
    # Do not capture AXFR contents; only check for success via stats.
    out="$(dig @"${ns}" "${domain}" AXFR +time=2 +tries=1 +noall +comments +stats 2>/dev/null || true)"
    if grep -q "XFR size" <<<"${out}"; then
      zone_transfer_allowed="true"
      zone_transfer_ns="${ns}"
      break
    fi
  done
fi

SF_NOW="${now}" \
SF_DOMAIN="${domain}" \
SF_SPF_TXT="${spf_txt}" \
SF_SPF_ALL="${spf_all}" \
SF_DMARC_TXT="${dmarc_txt}" \
SF_DMARC_POLICY="${dmarc_policy}" \
SF_DKIM_SELECTORS_CHECKED="${common_selectors[*]}" \
SF_DKIM_SELECTORS_FOUND="${dkim_selectors_found[*]}" \
SF_DNSSEC_ENABLED="${dnssec_enabled}" \
SF_MTA_STS_TXT_PRESENT="${mta_sts_txt_present}" \
SF_MTA_STS_TXT="${mta_sts_txt}" \
SF_MTA_STS_POLICY_URL="${mta_sts_policy_url}" \
SF_MTA_STS_POLICY_PRESENT="${mta_sts_policy_present}" \
SF_TLS_RPT_TXT="${tls_rpt_txt}" \
SF_NS_RECORDS="${ns_records[*]}" \
SF_ZONE_TRANSFER_ATTEMPTED="${zone_transfer_attempted}" \
SF_ZONE_TRANSFER_ALLOWED="${zone_transfer_allowed}" \
SF_ZONE_TRANSFER_NS="${zone_transfer_ns}" \
python3 - <<'PY'
import json
import os


def split_words(s: str):
  return [x for x in (s or "").split() if x]


spf_txt = os.environ.get("SF_SPF_TXT", "")
dmarc_txt = os.environ.get("SF_DMARC_TXT", "")
tls_rpt_txt = os.environ.get("SF_TLS_RPT_TXT", "")

data = {
  "timestamp_utc": os.environ.get("SF_NOW", ""),
  "domain": os.environ.get("SF_DOMAIN", ""),
  "checks": {
    "spf": {
      "present": bool(spf_txt),
      "record": spf_txt,
      "all_mechanism": os.environ.get("SF_SPF_ALL", "unknown"),
      "recommended": "-all",
    },
    "dmarc": {
      "present": bool(dmarc_txt),
      "record": dmarc_txt,
      "policy": os.environ.get("SF_DMARC_POLICY", "unknown"),
      "recommended": "reject",
    },
    "dkim": {
      "selectors_checked": split_words(os.environ.get("SF_DKIM_SELECTORS_CHECKED", "")),
      "selectors_found": split_words(os.environ.get("SF_DKIM_SELECTORS_FOUND", "")),
      "present": len(split_words(os.environ.get("SF_DKIM_SELECTORS_FOUND", ""))) > 0,
    },
    "dnssec": {
      "enabled": os.environ.get("SF_DNSSEC_ENABLED", "unknown"),
    },
    "mta_sts": {
      "txt_present": os.environ.get("SF_MTA_STS_TXT_PRESENT", "false") == "true",
      "txt_record": os.environ.get("SF_MTA_STS_TXT", ""),
      "policy_url": os.environ.get("SF_MTA_STS_POLICY_URL", ""),
      "policy_present": os.environ.get("SF_MTA_STS_POLICY_PRESENT", "false") == "true",
    },
    "tls_rpt": {
      "present": bool(tls_rpt_txt),
      "record": tls_rpt_txt,
    },
    "zone_transfer": {
      "attempted": os.environ.get("SF_ZONE_TRANSFER_ATTEMPTED", "false") == "true",
      "allowed": os.environ.get("SF_ZONE_TRANSFER_ALLOWED", "false") == "true",
      "allowed_ns": os.environ.get("SF_ZONE_TRANSFER_NS", ""),
      "ns_records": split_words(os.environ.get("SF_NS_RECORDS", "")),
    },
  },
}

print(json.dumps(data, indent=2, sort_keys=True))
PY
