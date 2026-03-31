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

python3 - <<PY
import json
data = {
  "timestamp_utc": ${now!r},
  "domain": ${domain!r},
  "checks": {
    "spf": {
      "present": bool(${spf_txt!r}),
      "record": ${spf_txt!r},
      "all_mechanism": ${spf_all!r},
      "recommended": "-all",
    },
    "dmarc": {
      "present": bool(${dmarc_txt!r}),
      "record": ${dmarc_txt!r},
      "policy": ${dmarc_policy!r},
      "recommended": "reject",
    },
    "dkim": {
      "selectors_checked": ${common_selectors!r},
      "selectors_found": ${dkim_selectors_found!r},
      "present": len(${dkim_selectors_found!r}) > 0,
    },
    "dnssec": {
      "enabled": ${dnssec_enabled!r},
    },
    "mta_sts": {
      "txt_present": ${mta_sts_txt_present!r} == "true",
      "txt_record": ${mta_sts_txt!r},
      "policy_url": ${mta_sts_policy_url!r},
      "policy_present": ${mta_sts_policy_present!r} == "true",
    },
    "tls_rpt": {
      "present": bool(${tls_rpt_txt!r}),
      "record": ${tls_rpt_txt!r},
    },
  },
}
print(json.dumps(data, indent=2, sort_keys=True))
PY

