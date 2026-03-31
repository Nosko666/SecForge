#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SECFORGE_ROOT="${SECFORGE_ROOT:-$DEFAULT_ROOT}"
SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE:-${SECFORGE_ROOT}/config/secforge.conf}"

# Optional inputs for local code scans (secrets/dependencies).
SECFORGE_CODE_PATH="${SECFORGE_CODE_PATH:-}"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

sf_tool() {
  local name="$1"
  if [[ -x "${SECFORGE_ROOT}/bin/${name}" ]]; then
    printf '%s' "${SECFORGE_ROOT}/bin/${name}"
    return 0
  fi
  if command -v "${name}" >/dev/null 2>&1; then
    command -v "${name}"
    return 0
  fi
  return 1
}

sf_run() {
  local timeout_s="$1"
  local stdout_path="$2"
  shift 2
  local err_path="${stdout_path}.err"

  mkdir -p "$(dirname -- "${stdout_path}")"

  sf_log "Running: $*"
  if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status --kill-after=10s "${timeout_s}" "$@" >"${stdout_path}" 2>"${err_path}" || true
  else
    "$@" >"${stdout_path}" 2>"${err_path}" || true
  fi
}

sf_sleep_ms() {
  local ms="$1"
  python3 - <<PY
import time
time.sleep(${ms}/1000)
PY
}

sf_circuit_breaker_check() {
  local url="$1"
  local threshold_s="$2"
  local cooldown_s="$3"
  [[ -z "${url}" ]] && return 0

  local t
  t="$(curl -fsS -o /dev/null --connect-timeout 5 --max-time 15 -w "%{time_total}\n" "${url}" 2>/dev/null || echo "")"
  [[ -z "${t}" ]] && return 0

  if awk -v t="${t}" -v th="${threshold_s}" 'BEGIN{exit !(t>th)}'; then
    sf_warn "Circuit breaker: target responding slowly (${t}s > ${threshold_s}s). Pausing ${cooldown_s}s..."
    sleep "${cooldown_s}"
  fi
}

sf_builtin_web_checks() {
  local base_url="$1"
  local out_json="$2"
  local delay_ms="$3"

  local git_head_code env_code trace_code put_code delete_code
  git_head_code="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code}" "${base_url}/.git/HEAD" 2>/dev/null || echo "000")"
  sf_sleep_ms "${delay_ms}"
  env_code="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code}" "${base_url}/.env" 2>/dev/null || echo "000")"
  sf_sleep_ms "${delay_ms}"

  trace_code="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code}" -X TRACE "${base_url}/" 2>/dev/null || echo "000")"
  sf_sleep_ms "${delay_ms}"
  put_code="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code}" -X PUT "${base_url}/" 2>/dev/null || echo "000")"
  sf_sleep_ms "${delay_ms}"
  delete_code="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code}" -X DELETE "${base_url}/" 2>/dev/null || echo "000")"

  # Cookie flags (best-effort)
  local headers cookies_total cookies_missing_secure cookies_missing_httponly cookies_missing_samesite
  headers="$(curl -sS -I --max-time 10 "${base_url}/" 2>/dev/null || true)"
  cookies_total="$(grep -ic '^set-cookie:' <<<"${headers}" || true)"
  cookies_missing_secure="$(grep -i '^set-cookie:' <<<"${headers}" | grep -vic ';\s*secure' || true)"
  cookies_missing_httponly="$(grep -i '^set-cookie:' <<<"${headers}" | grep -vic ';\s*httponly' || true)"
  cookies_missing_samesite="$(grep -i '^set-cookie:' <<<"${headers}" | grep -vic ';\s*samesite=' || true)"

  python3 - <<PY
import json
data = {
  "git_head_http_code": ${git_head_code!r},
  "env_http_code": ${env_code!r},
  "http_methods": {
    "trace_http_code": ${trace_code!r},
    "put_http_code": ${put_code!r},
    "delete_http_code": ${delete_code!r},
  },
  "cookies": {
    "set_cookie_headers": int(${cookies_total!r}),
    "missing_secure": int(${cookies_missing_secure!r}),
    "missing_httponly": int(${cookies_missing_httponly!r}),
    "missing_samesite": int(${cookies_missing_samesite!r}),
  },
}
with open(${out_json!r}, "w", encoding="utf-8") as f:
  json.dump(data, f, indent=2, sort_keys=True)
PY
}

sf_tier2_opt_in() {
  cat >&2 <<'EOF'
Tier 2 tools send real attack payloads (SQLi/XSS/command injection) to test vulnerabilities.
On production, this can slow your app, fill logs, trigger bans, and (if vulnerable) affect data.
EOF
  sf_ask_tty_yes "Type YES to run Tier 2 active tests (or anything else to skip):" "YES"
}

main() {
  local target="${1:-}"
  if [[ -z "${target}" ]]; then
    sf_die "Usage: ${0##*/} <domain|url|this_server> [code_path_optional]"
  fi
  if [[ -n "${2:-}" ]]; then
    SECFORGE_CODE_PATH="$2"
  fi

  # shellcheck disable=SC1090
  source <("${SCRIPT_DIR}/preflight.sh" --target "${target}" --profile "all" --require-tools "curl,jq")

  local timeout_web timeout_portscan timeout_hardening delay_ms threshold cooldown
  timeout_web="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_WEB_SECONDS" || true)"
  timeout_portscan="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_PORTSCAN_SECONDS" || true)"
  timeout_hardening="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_HARDENING_SECONDS" || true)"
  delay_ms="${SECFORGE_SCAN_DELAY_MS:-200}"
  threshold="${SECFORGE_CIRCUIT_BREAKER_THRESHOLD_SECONDS:-10}"
  cooldown="${SECFORGE_CIRCUIT_BREAKER_COOLDOWN_SECONDS:-30}"
  timeout_web="${timeout_web:-600}"
  timeout_portscan="${timeout_portscan:-1800}"
  timeout_hardening="${timeout_hardening:-1800}"

  sf_log "Session: ${SECFORGE_SESSION_ID}"
  sf_log "Reports: ${SECFORGE_SESSION_DIR}"

  # ---------------------------
  # Tier 1 (default)
  # ---------------------------
  if [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    sf_circuit_breaker_check "${SECFORGE_TARGET_URL}" "${threshold}" "${cooldown}"

    if sf_tool wafw00f >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/wafw00f.txt" "$(sf_tool wafw00f)" "${SECFORGE_TARGET_URL}"
    fi

    if sf_tool whatweb >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/whatweb.log" "$(sf_tool whatweb)" "${SECFORGE_TARGET_URL}" "--log-json=${SECFORGE_SESSION_DIR}/webapp/whatweb.json"
    fi

    if sf_tool nuclei >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/nuclei.log" "$(sf_tool nuclei)" -u "${SECFORGE_TARGET_URL}" -json-export "${SECFORGE_SESSION_DIR}/webapp/nuclei.json"
    fi

    if sf_tool ffuf >/dev/null 2>&1 && [[ -r "${SECFORGE_ROOT}/wordlists/directories.txt" ]]; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/ffuf.log" "$(sf_tool ffuf)" -u "${SECFORGE_TARGET_URL%/}/FUZZ" -w "${SECFORGE_ROOT}/wordlists/directories.txt" -o "${SECFORGE_SESSION_DIR}/webapp/ffuf.json" -of json
    fi

    if sf_tool nikto >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/nikto.log" "$(sf_tool nikto)" -h "${SECFORGE_TARGET_URL}" -Format json -output "${SECFORGE_SESSION_DIR}/webapp/nikto.json"
    fi

    if sf_tool observatory >/dev/null 2>&1; then
      # CLI syntax varies; try common forms.
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/observatory.json" "$(sf_tool observatory)" --format json "${SECFORGE_TARGET_URL}" || true
      if [[ ! -s "${SECFORGE_SESSION_DIR}/ssl/observatory.json" ]]; then
        sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/observatory.json" "$(sf_tool observatory)" scan --format json "${SECFORGE_TARGET_URL}" || true
      fi
    fi

    if sf_tool testssl.sh >/dev/null 2>&1; then
      local ssl_target="${SECFORGE_TARGET_HOST}"
      if [[ -n "${SECFORGE_TARGET_PORT}" ]]; then
        ssl_target="${ssl_target}:${SECFORGE_TARGET_PORT}"
      fi
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/testssl.log" "$(sf_tool testssl.sh)" --jsonfile "${SECFORGE_SESSION_DIR}/ssl/testssl.json" "${ssl_target}"
    fi

    if sf_tool sslscan >/dev/null 2>&1; then
      local ssl_target="${SECFORGE_TARGET_HOST}"
      if [[ -n "${SECFORGE_TARGET_PORT}" ]]; then
        ssl_target="${ssl_target}:${SECFORGE_TARGET_PORT}"
      fi
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/sslscan.log" "$(sf_tool sslscan)" --xml="${SECFORGE_SESSION_DIR}/ssl/sslscan.xml" "${ssl_target}"
    fi

    # Built-in curl checks (zero-dependency, high value).
    sf_builtin_web_checks "${SECFORGE_TARGET_URL%/}" "${SECFORGE_SESSION_DIR}/webapp/builtin.json" "${delay_ms}"

    if [[ -r "${SCRIPT_DIR}/check-email-dns.sh" ]]; then
      chmod +x "${SCRIPT_DIR}/check-email-dns.sh" 2>/dev/null || true
      sf_run 60 "${SECFORGE_SESSION_DIR}/emaildns/emaildns.json" "${SCRIPT_DIR}/check-email-dns.sh" "${SECFORGE_TARGET_HOST}"
    fi

    if sf_tool subfinder >/dev/null 2>&1; then
      sf_run 120 "${SECFORGE_SESSION_DIR}/emaildns/subfinder.jsonl" "$(sf_tool subfinder)" -d "${SECFORGE_TARGET_HOST}" -silent -json
      # Probe discovered hosts (limit to first 200).
      if sf_tool httpx >/dev/null 2>&1; then
        awk -F'"host":' '{print $2}' "${SECFORGE_SESSION_DIR}/emaildns/subfinder.jsonl" 2>/dev/null | sed 's/[^A-Za-z0-9._-].*$//' | grep -E '^[A-Za-z0-9._-]+$' | head -n 200 >"${SECFORGE_SESSION_DIR}/emaildns/subdomains.txt" || true
        if [[ -s "${SECFORGE_SESSION_DIR}/emaildns/subdomains.txt" ]]; then
          sf_run 300 "${SECFORGE_SESSION_DIR}/emaildns/httpx.jsonl" "$(sf_tool httpx)" -l "${SECFORGE_SESSION_DIR}/emaildns/subdomains.txt" -silent -json
        fi
      fi
    fi

    if sf_tool nmap >/dev/null 2>&1; then
      local nmap_timing nmap_top
      nmap_timing="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "NMAP_TIMING" || true)"
      nmap_top="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "NMAP_TOP_PORTS" || true)"
      nmap_timing="${nmap_timing:--T3}"
      nmap_top="${nmap_top:-1000}"

      sf_run "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/nmap.log" "$(sf_tool nmap)" ${nmap_timing} -sV -sC --top-ports "${nmap_top}" -oX "${SECFORGE_SESSION_DIR}/network/nmap.xml" "${SECFORGE_TARGET_HOST}"
    fi

    if sf_tool masscan >/dev/null 2>&1; then
      local sudo_policy
      sudo_policy="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "ALLOW_SUDO_TOOLS" || true)"
      sudo_policy="${sudo_policy:-ask}"
      if [[ "${EUID}" -eq 0 ]]; then
        sf_run "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/masscan.log" "$(sf_tool masscan)" "${SECFORGE_TARGET_HOST}" -p0-65535 --rate=1000 -oJ "${SECFORGE_SESSION_DIR}/network/masscan.json"
      elif [[ "${sudo_policy}" == "never" ]]; then
        sf_warn "Skipping masscan (requires root; ALLOW_SUDO_TOOLS=never)."
      else
        if sf_ask_tty_yes "Masscan needs sudo (raw sockets). Type YES to run it now:" "YES"; then
          sf_run "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/masscan.log" sudo "$(sf_tool masscan)" "${SECFORGE_TARGET_HOST}" -p0-65535 --rate=1000 -oJ "${SECFORGE_SESSION_DIR}/network/masscan.json"
        else
          sf_log "Skipping masscan."
        fi
      fi
    fi
  fi

  # Local system audit (Tier 1, read-only).
  if sf_tool lynis >/dev/null 2>&1; then
    sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/lynis.stdout" "$(sf_tool lynis)" audit system --no-colors --logfile "${SECFORGE_SESSION_DIR}/hardening/lynis.log" --report-file "${SECFORGE_SESSION_DIR}/hardening/lynis.dat"
  fi

  if sf_tool clamscan >/dev/null 2>&1; then
    # Scoped scan by default; full / scan is opt-in.
    sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/clamav.stdout" "$(sf_tool clamscan)" -r /home /var/www /tmp /opt --log="${SECFORGE_SESSION_DIR}/hardening/clamav.log" --exclude-dir="^/proc" --exclude-dir="^/sys" || true
  fi

  if sf_tool rkhunter >/dev/null 2>&1; then
    sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/rkhunter.stdout" "$(sf_tool rkhunter)" --check --skip-keypress --logfile "${SECFORGE_SESSION_DIR}/hardening/rkhunter.log"
  fi

  if sf_tool aide >/dev/null 2>&1; then
    sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/aide.log" "$(sf_tool aide)" --check
  fi

  if sf_tool aureport >/dev/null 2>&1; then
    sf_run 60 "${SECFORGE_SESSION_DIR}/hardening/audit-summary.log" "$(sf_tool aureport)" --summary
  fi

  if sf_tool debsums >/dev/null 2>&1; then
    sf_run 600 "${SECFORGE_SESSION_DIR}/hardening/debsums.log" "$(sf_tool debsums)" -s
  fi

  if [[ -r "${SCRIPT_DIR}/check-mysql.sh" ]]; then
    chmod +x "${SCRIPT_DIR}/check-mysql.sh" 2>/dev/null || true
    sf_run 60 "${SECFORGE_SESSION_DIR}/database/mysql.json" "${SCRIPT_DIR}/check-mysql.sh"
  fi

  # Optional codebase scans.
  if [[ -n "${SECFORGE_CODE_PATH}" ]]; then
    if sf_tool trufflehog >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/secrets/trufflehog.json" "$(sf_tool trufflehog)" filesystem "${SECFORGE_CODE_PATH}" --json
    fi
    if sf_tool gitleaks >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/secrets/gitleaks.log" "$(sf_tool gitleaks)" detect --source "${SECFORGE_CODE_PATH}" --report-path "${SECFORGE_SESSION_DIR}/secrets/gitleaks.json" --report-format json
    fi
    if sf_tool osv-scanner >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/dependencies/osv.json" "$(sf_tool osv-scanner)" --json "${SECFORGE_CODE_PATH}"
    fi
    if sf_tool pip-audit >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/dependencies/pip-audit.json" "$(sf_tool pip-audit)" --format json
    fi
  fi

  # ---------------------------
  # Tier 2 (explicit opt-in)
  # ---------------------------
  if [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    if sf_tier2_opt_in; then
      if sf_tool sqlmap >/dev/null 2>&1; then
        mkdir -p "${SECFORGE_SESSION_DIR}/webapp/sqlmap"
        sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/sqlmap/sqlmap.log" "$(sf_tool sqlmap)" -u "${SECFORGE_TARGET_URL}" --batch --forms --crawl=3 --output-dir="${SECFORGE_SESSION_DIR}/webapp/sqlmap"
      fi

      if sf_tool dalfox >/dev/null 2>&1; then
        sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/dalfox.log" "$(sf_tool dalfox)" url "${SECFORGE_TARGET_URL}" -o "${SECFORGE_SESSION_DIR}/webapp/dalfox.json" --format json
      fi

      if sf_tool xsstrike >/dev/null 2>&1; then
        sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/xsstrike.log" "$(sf_tool xsstrike)" -u "${SECFORGE_TARGET_URL}" --crawl || true
      fi

      if sf_tool commix >/dev/null 2>&1; then
        mkdir -p "${SECFORGE_SESSION_DIR}/webapp/commix"
        sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/commix.log" "$(sf_tool commix)" --url="${SECFORGE_TARGET_URL}" --batch --output-dir="${SECFORGE_SESSION_DIR}/webapp/commix"
      fi
    else
      sf_log "Tier 2 skipped."
    fi
  fi

  if [[ -r "${SCRIPT_DIR}/merge-reports.py" ]]; then
    sf_log "Merging reports..."
    python3 "${SCRIPT_DIR}/merge-reports.py" "${SECFORGE_SESSION_DIR}" || sf_warn "merge-reports.py failed (continuing)."
  else
    sf_warn "merge-reports.py not available yet (Phase 4)."
  fi

  sf_log "Full scan complete."
  sf_log "Session folder: ${SECFORGE_SESSION_DIR}"
}

main "$@"
