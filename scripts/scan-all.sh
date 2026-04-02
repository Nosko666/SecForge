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

INTERACTSH_PID=""
ZAP_PID=""
ZAP_API_BASE=""
ZAP_STARTED="0"

sf_kill_pid() {
  local pid="${1:-}"
  [[ -z "${pid}" ]] && return 0
  if kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    sleep 1
    kill -9 "${pid}" 2>/dev/null || true
  fi
}

sf_cleanup_bg() {
  set +e

  if [[ "${ZAP_STARTED}" == "1" && -n "${ZAP_API_BASE}" ]] && command -v curl >/dev/null 2>&1; then
    curl -fsS "${ZAP_API_BASE}/JSON/core/action/shutdown/" >/dev/null 2>&1 || true
  fi

  sf_kill_pid "${INTERACTSH_PID}"
  sf_kill_pid "${ZAP_PID}"
}

trap sf_cleanup_bg EXIT

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
  # Validate numeric to prevent injection; fall back to 200ms.
  if ! [[ "${ms}" =~ ^[0-9]+$ ]]; then
    ms=200
  fi
  sleep "$(awk -v ms="${ms}" 'BEGIN{printf "%.3f", ms/1000}')"
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
  headers="$({ curl -sS -I --max-time 10 "${base_url}/" 2>/dev/null || true; } | tr -d '\r')"
  cookies_total="$(grep -ic '^set-cookie:' <<<"${headers}" || true)"
  cookies_missing_secure="$(grep -i '^set-cookie:' <<<"${headers}" | grep -vic ';\s*secure' || true)"
  cookies_missing_httponly="$(grep -i '^set-cookie:' <<<"${headers}" | grep -vic ';\s*httponly' || true)"
  cookies_missing_samesite="$(grep -i '^set-cookie:' <<<"${headers}" | grep -vic ';\s*samesite=' || true)"

  # Clickjacking protection (best-effort)
  local xfo_present csp_frame_ancestors_present clickjacking_protected
  xfo_present="false"
  csp_frame_ancestors_present="false"
  clickjacking_protected="false"
  if grep -qi '^x-frame-options:' <<<"${headers}"; then
    xfo_present="true"
    clickjacking_protected="true"
  fi
  if grep -qi '^content-security-policy:.*frame-ancestors' <<<"${headers}"; then
    csp_frame_ancestors_present="true"
    clickjacking_protected="true"
  fi

  # Basic SSRF probes (lightweight, non-destructive). We only record status/latency.
  local probe ssrf_url_code ssrf_url_time ssrf_dest_code ssrf_dest_time ssrf_next_code ssrf_next_time
  probe="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code} %{time_total}" "${base_url%/}/?url=http://127.0.0.1:9" 2>/dev/null || echo "000 0")"
  read -r ssrf_url_code ssrf_url_time <<<"${probe}" || true
  sf_sleep_ms "${delay_ms}"
  probe="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code} %{time_total}" "${base_url%/}/?dest=http://127.0.0.1:9" 2>/dev/null || echo "000 0")"
  read -r ssrf_dest_code ssrf_dest_time <<<"${probe}" || true
  sf_sleep_ms "${delay_ms}"
  probe="$(curl -sS -o /dev/null --max-time 10 -w "%{http_code} %{time_total}" "${base_url%/}/?next=http://127.0.0.1:9" 2>/dev/null || echo "000 0")"
  read -r ssrf_next_code ssrf_next_time <<<"${probe}" || true

  SF_GIT_HEAD_CODE="${git_head_code}" \
  SF_ENV_CODE="${env_code}" \
  SF_TRACE_CODE="${trace_code}" \
  SF_PUT_CODE="${put_code}" \
  SF_DELETE_CODE="${delete_code}" \
  SF_COOKIES_TOTAL="${cookies_total}" \
  SF_COOKIES_NO_SECURE="${cookies_missing_secure}" \
  SF_COOKIES_NO_HTTPONLY="${cookies_missing_httponly}" \
  SF_COOKIES_NO_SAMESITE="${cookies_missing_samesite}" \
  SF_XFO_PRESENT="${xfo_present}" \
  SF_CSP_FRAME_ANCESTORS_PRESENT="${csp_frame_ancestors_present}" \
  SF_CLICKJACKING_PROTECTED="${clickjacking_protected}" \
  SF_SSRF_URL_CODE="${ssrf_url_code:-000}" \
  SF_SSRF_URL_TIME="${ssrf_url_time:-0}" \
  SF_SSRF_DEST_CODE="${ssrf_dest_code:-000}" \
  SF_SSRF_DEST_TIME="${ssrf_dest_time:-0}" \
  SF_SSRF_NEXT_CODE="${ssrf_next_code:-000}" \
  SF_SSRF_NEXT_TIME="${ssrf_next_time:-0}" \
  SF_OUT_JSON="${out_json}" \
  python3 - <<'PY'
import json
import os


def int_or_zero(s):
  try:
    return int(s)
  except Exception:
    return 0


data = {
  "git_head_http_code": os.environ.get("SF_GIT_HEAD_CODE", "000"),
  "env_http_code": os.environ.get("SF_ENV_CODE", "000"),
  "http_methods": {
    "trace_http_code": os.environ.get("SF_TRACE_CODE", "000"),
    "put_http_code": os.environ.get("SF_PUT_CODE", "000"),
    "delete_http_code": os.environ.get("SF_DELETE_CODE", "000"),
  },
  "cookies": {
    "set_cookie_headers": int_or_zero(os.environ.get("SF_COOKIES_TOTAL", "0")),
    "missing_secure": int_or_zero(os.environ.get("SF_COOKIES_NO_SECURE", "0")),
    "missing_httponly": int_or_zero(os.environ.get("SF_COOKIES_NO_HTTPONLY", "0")),
    "missing_samesite": int_or_zero(os.environ.get("SF_COOKIES_NO_SAMESITE", "0")),
  },
  "clickjacking": {
    "protected": os.environ.get("SF_CLICKJACKING_PROTECTED", "false") == "true",
    "x_frame_options_present": os.environ.get("SF_XFO_PRESENT", "false") == "true",
    "csp_frame_ancestors_present": os.environ.get("SF_CSP_FRAME_ANCESTORS_PRESENT", "false") == "true",
  },
  "ssrf_probes": {
    "url_param": {
      "http_code": os.environ.get("SF_SSRF_URL_CODE", "000"),
      "latency_seconds": os.environ.get("SF_SSRF_URL_TIME", "0"),
    },
    "dest_param": {
      "http_code": os.environ.get("SF_SSRF_DEST_CODE", "000"),
      "latency_seconds": os.environ.get("SF_SSRF_DEST_TIME", "0"),
    },
    "next_param": {
      "http_code": os.environ.get("SF_SSRF_NEXT_CODE", "000"),
      "latency_seconds": os.environ.get("SF_SSRF_NEXT_TIME", "0"),
    },
  },
}

out_path = os.environ.get("SF_OUT_JSON", "")
if out_path:
  with open(out_path, "w", encoding="utf-8") as f:
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

sf_zap_active_scan() {
  local target_url="$1"
  local out_json="$2"
  local log_path="$3"
  local max_wait_s="$4"

  [[ -z "${target_url}" ]] && return 0

  if ! command -v curl >/dev/null 2>&1; then
    sf_warn "Skipping ZAP: curl not available."
    return 0
  fi

  local zap_bin
  if ! zap_bin="$(sf_tool zap.sh 2>/dev/null)"; then
    sf_warn "Skipping ZAP: zap.sh not found."
    return 0
  fi

  mkdir -p "$(dirname -- "${out_json}")" "$(dirname -- "${log_path}")"

  local api_base="http://127.0.0.1:8080"
  ZAP_API_BASE="${api_base}"

  if curl -fsS "${api_base}/JSON/core/view/version/" >/dev/null 2>&1; then
    sf_log "ZAP API already reachable at ${api_base} (reusing existing instance)."
    ZAP_STARTED="0"
  else
    sf_log "Starting ZAP daemon..."
    "${zap_bin}" -daemon -host 127.0.0.1 -port 8080 \
      -config api.disablekey=true \
      -config api.addrs.addr.name=127.0.0.1 \
      -config api.addrs.addr.regex=false >>"${log_path}" 2>&1 &
    ZAP_PID=$!
    ZAP_STARTED="1"

    local i
    for i in $(seq 1 60); do
      if curl -fsS "${api_base}/JSON/core/view/version/" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done

    if ! curl -fsS "${api_base}/JSON/core/view/version/" >/dev/null 2>&1; then
      sf_warn "ZAP daemon did not start (skipping ZAP active scan)."
      return 0
    fi
  fi

  curl -fsS --get "${api_base}/JSON/core/action/accessUrl/" --data-urlencode "url=${target_url}" >/dev/null 2>>"${log_path}" || true

  local spider_budget ascan_budget
  spider_budget=$((max_wait_s / 3))
  [[ "${spider_budget}" -lt 120 ]] && spider_budget=120
  ascan_budget=$((max_wait_s - spider_budget))
  [[ "${ascan_budget}" -lt 300 ]] && ascan_budget=300

  local spider_id spider_resp
  spider_resp="$(curl -fsS --get "${api_base}/JSON/spider/action/scan/" \
    --data-urlencode "url=${target_url}" \
    --data-urlencode "recurse=true" \
    --data-urlencode "subtreeOnly=true" 2>>"${log_path}" || echo "")"
  spider_id="$(python3 -c 'import json,sys; j=json.loads(sys.stdin.read() or "{}"); print(j.get("scan",""))' <<<"${spider_resp}" 2>/dev/null || echo "")"

  if [[ -n "${spider_id}" ]]; then
    local spider_deadline
    spider_deadline=$(( $(date +%s) + spider_budget ))
    while :; do
      local status_resp status
      status_resp="$(curl -fsS --get "${api_base}/JSON/spider/view/status/" --data-urlencode "scanId=${spider_id}" 2>>"${log_path}" || echo "")"
      status="$(python3 -c 'import json,sys; j=json.loads(sys.stdin.read() or "{}"); print(j.get("status",""))' <<<"${status_resp}" 2>/dev/null || echo "")"
      [[ "${status}" == "100" ]] && break
      [[ "$(date +%s)" -ge "${spider_deadline}" ]] && { sf_warn "ZAP spider timed out."; break; }
      sleep 2
    done
  fi

  local ascan_id ascan_resp
  ascan_resp="$(curl -fsS --get "${api_base}/JSON/ascan/action/scan/" \
    --data-urlencode "url=${target_url}" \
    --data-urlencode "recurse=true" 2>>"${log_path}" || echo "")"
  ascan_id="$(python3 -c 'import json,sys; j=json.loads(sys.stdin.read() or "{}"); print(j.get("scan",""))' <<<"${ascan_resp}" 2>/dev/null || echo "")"

  if [[ -n "${ascan_id}" ]]; then
    local ascan_deadline
    ascan_deadline=$(( $(date +%s) + ascan_budget ))
    while :; do
      local status_resp status
      status_resp="$(curl -fsS --get "${api_base}/JSON/ascan/view/status/" --data-urlencode "scanId=${ascan_id}" 2>>"${log_path}" || echo "")"
      status="$(python3 -c 'import json,sys; j=json.loads(sys.stdin.read() or "{}"); print(j.get("status",""))' <<<"${status_resp}" 2>/dev/null || echo "")"
      [[ "${status}" == "100" ]] && break
      [[ "$(date +%s)" -ge "${ascan_deadline}" ]] && { sf_warn "ZAP active scan timed out."; break; }
      sleep 5
    done
  fi

  curl -fsS --get "${api_base}/JSON/core/view/alerts/" \
    --data-urlencode "baseurl=${target_url}" \
    --data-urlencode "start=0" \
    --data-urlencode "count=999999" >"${out_json}" 2>>"${log_path}" || true

  if [[ "${ZAP_STARTED}" == "1" ]]; then
    curl -fsS "${api_base}/JSON/core/action/shutdown/" >/dev/null 2>>"${log_path}" || true
    wait "${ZAP_PID}" 2>/dev/null || true
    ZAP_PID=""
    ZAP_STARTED="0"
    ZAP_API_BASE=""
  fi
}

main() {
  local target="${1:-}"
  if [[ -z "${target}" ]]; then
    sf_die "Usage: ${0##*/} <domain|url|this_server> [code_path_optional]"
  fi
  if [[ -n "${2:-}" ]]; then
    SECFORGE_CODE_PATH="$2"
  fi

  # Preflight exports session vars (safe: tempfile, not process substitution).
  local _pf_tmp
  _pf_tmp="$(mktemp /tmp/secforge-preflight.XXXXXX)"
  if ! "${SCRIPT_DIR}/preflight.sh" --target "${target}" --profile "all" --require-tools "curl,jq" >"${_pf_tmp}"; then
    rm -f "${_pf_tmp}"
    sf_die "Preflight failed. Check errors above."
  fi
  if [[ ! -s "${_pf_tmp}" ]]; then
    rm -f "${_pf_tmp}"
    sf_die "Preflight produced no output (likely a bug)."
  fi
  # shellcheck disable=SC1090
  source "${_pf_tmp}"
  rm -f "${_pf_tmp}"
  [[ -n "${SECFORGE_SESSION_DIR:-}" ]] || sf_die "Preflight did not set SECFORGE_SESSION_DIR."

  local timeout_web timeout_portscan timeout_hardening timeout_zap delay_ms threshold cooldown
  timeout_web="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_WEB_SECONDS" || true)"
  timeout_portscan="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_PORTSCAN_SECONDS" || true)"
  timeout_hardening="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_HARDENING_SECONDS" || true)"
  timeout_zap="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_ZAP_SECONDS" || true)"
  delay_ms="${SECFORGE_SCAN_DELAY_MS:-200}"
  threshold="${SECFORGE_CIRCUIT_BREAKER_THRESHOLD_SECONDS:-10}"
  cooldown="${SECFORGE_CIRCUIT_BREAKER_COOLDOWN_SECONDS:-30}"
  timeout_web="${timeout_web:-600}"
  timeout_portscan="${timeout_portscan:-1800}"
  timeout_hardening="${timeout_hardening:-1800}"
  timeout_zap="${timeout_zap:-1800}"

  sf_log "Session: ${SECFORGE_SESSION_ID}"
  sf_log "Reports: ${SECFORGE_SESSION_DIR}"

  # ---------------------------
  # Tier 1 (default)
  # ---------------------------
  if [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    if [[ -z "${INTERACTSH_PID}" ]] && sf_tool interactsh-client >/dev/null 2>&1; then
      sf_log "Starting interactsh-client (OOB callbacks)..."
      "$(sf_tool interactsh-client)" -json -o "${SECFORGE_SESSION_DIR}/api/interactsh.json" >"${SECFORGE_SESSION_DIR}/api/interactsh.log" 2>"${SECFORGE_SESSION_DIR}/api/interactsh.log.err" &
      INTERACTSH_PID=$!
    fi

    sf_circuit_breaker_check "${SECFORGE_TARGET_URL}" "${threshold}" "${cooldown}"

    if sf_tool wafw00f >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json" "$(sf_tool wafw00f)" "${SECFORGE_TARGET_URL}" -f json -o "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json"
    fi

    if sf_tool whatweb >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/whatweb.log" "$(sf_tool whatweb)" "${SECFORGE_TARGET_URL}" "--log-json=${SECFORGE_SESSION_DIR}/webapp/whatweb.json"
    fi

    if sf_tool corscanner >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/corscanner.log" "$(sf_tool corscanner)" -u "${SECFORGE_TARGET_URL}" -o "${SECFORGE_SESSION_DIR}/webapp/corscanner.json"
    fi

    if sf_tool nuclei >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/nuclei.log" "$(sf_tool nuclei)" -u "${SECFORGE_TARGET_URL}" -json-export "${SECFORGE_SESSION_DIR}/webapp/nuclei.json"
    fi

    sf_circuit_breaker_check "${SECFORGE_TARGET_URL}" "${threshold}" "${cooldown}"

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
        jq -r '.host // empty' "${SECFORGE_SESSION_DIR}/emaildns/subfinder.jsonl" 2>/dev/null | grep -E '^[A-Za-z0-9._-]+$' | sort -u | head -n 200 >"${SECFORGE_SESSION_DIR}/emaildns/subdomains.txt" || true
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
      if ! [[ "${nmap_timing}" =~ ^-T[0-5]$ ]]; then
        sf_warn "Invalid NMAP_TIMING '${nmap_timing}'; defaulting to -T3."
        nmap_timing="-T3"
      fi

      sf_run "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/nmap.log" "$(sf_tool nmap)" "${nmap_timing}" -sV -sC --top-ports "${nmap_top}" -oX "${SECFORGE_SESSION_DIR}/network/nmap.xml" "${SECFORGE_TARGET_HOST}"
    fi

    if sf_tool ssh-audit >/dev/null 2>&1; then
      sf_run 60 "${SECFORGE_SESSION_DIR}/hardening/ssh-audit.json" "$(sf_tool ssh-audit)" --json "${SECFORGE_TARGET_HOST}"
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

  if sf_tool systemd-analyze >/dev/null 2>&1; then
    sf_run 120 "${SECFORGE_SESSION_DIR}/hardening/systemd-security.txt" "$(sf_tool systemd-analyze)" security
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

  if sf_tool trivy >/dev/null 2>&1; then
    local sudo_policy
    sudo_policy="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "ALLOW_SUDO_TOOLS" || true)"
    sudo_policy="${sudo_policy:-ask}"

    if [[ "${EUID}" -eq 0 ]]; then
      sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.log" "$(sf_tool trivy)" rootfs --format json --output "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.json" /
    elif [[ "${sudo_policy}" == "always" ]]; then
      sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.log" sudo "$(sf_tool trivy)" rootfs --format json --output "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.json" /
    elif [[ "${sudo_policy}" == "ask" ]]; then
      if sf_ask_tty_yes "Trivy rootfs can be more complete with sudo. Type YES to run with sudo:" "YES"; then
        sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.log" sudo "$(sf_tool trivy)" rootfs --format json --output "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.json" /
      else
        sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.log" "$(sf_tool trivy)" rootfs --format json --output "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.json" /
      fi
    else
      sf_run "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.log" "$(sf_tool trivy)" rootfs --format json --output "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.json" /
    fi
  fi

  if [[ -r "${SCRIPT_DIR}/check-mysql.sh" ]]; then
    chmod +x "${SCRIPT_DIR}/check-mysql.sh" 2>/dev/null || true
    sf_run 60 "${SECFORGE_SESSION_DIR}/database/mysql.json" "${SCRIPT_DIR}/check-mysql.sh"
  fi

  # Optional codebase scans.
  if [[ -n "${SECFORGE_CODE_PATH}" ]]; then
    if sf_tool trufflehog >/dev/null 2>&1; then
      local _th_raw="${SECFORGE_SESSION_DIR}/secrets/.trufflehog-raw.jsonl"
      sf_run "${timeout_web}" "${_th_raw}" "$(sf_tool trufflehog)" filesystem "${SECFORGE_CODE_PATH}" --json
      if [[ -s "${_th_raw}" ]] && [[ -r "${SCRIPT_DIR}/sanitize-trufflehog.py" ]]; then
        python3 "${SCRIPT_DIR}/sanitize-trufflehog.py" "${_th_raw}" "${SECFORGE_SESSION_DIR}/secrets/trufflehog.json" 2>/dev/null || sf_warn "TruffleHog sanitization failed"
      fi
      rm -f "${_th_raw}" 2>/dev/null || true
    fi
    if sf_tool gitleaks >/dev/null 2>&1; then
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/secrets/gitleaks.log" "$(sf_tool gitleaks)" detect --source "${SECFORGE_CODE_PATH}" --redact --report-path "${SECFORGE_SESSION_DIR}/secrets/gitleaks.json" --report-format json
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
      sf_circuit_breaker_check "${SECFORGE_TARGET_URL}" "${threshold}" "${cooldown}"

      sf_zap_active_scan "${SECFORGE_TARGET_URL}" "${SECFORGE_SESSION_DIR}/webapp/zap.json" "${SECFORGE_SESSION_DIR}/webapp/zap.log" "${timeout_zap}"

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

      if sf_tool wapiti >/dev/null 2>&1; then
        sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/wapiti.log" "$(sf_tool wapiti)" -u "${SECFORGE_TARGET_URL}" -f json -o "${SECFORGE_SESSION_DIR}/webapp/wapiti.json"
      fi

      if sf_ask_tty_yes "Run SSH credential checks (Hydra/NetExec) against ${SECFORGE_TARGET_HOST}? Type YES to continue:" "YES"; then
        local pw_list ssh_user ssh_users_file
        pw_list="${SECFORGE_ROOT}/wordlists/passwords-top1000.txt"
        ssh_user="${SECFORGE_SSH_USER:-}"
        ssh_users_file="${SECFORGE_SSH_USERS_FILE:-}"

        if [[ ! -r "${pw_list}" ]]; then
          sf_warn "Password list missing: ${pw_list} (skipping Hydra/NetExec)."
        elif [[ -n "${ssh_user}" || ( -n "${ssh_users_file}" && -r "${ssh_users_file}" ) ]]; then
          if sf_tool hydra >/dev/null 2>&1; then
            if [[ -n "${ssh_user}" ]]; then
              sf_run 600 "${SECFORGE_SESSION_DIR}/passwords/hydra.txt" "$(sf_tool hydra)" -l "${ssh_user}" -P "${pw_list}" "${SECFORGE_TARGET_HOST}" ssh
            else
              sf_run 600 "${SECFORGE_SESSION_DIR}/passwords/hydra.txt" "$(sf_tool hydra)" -L "${ssh_users_file}" -P "${pw_list}" "${SECFORGE_TARGET_HOST}" ssh
            fi
          fi

          if sf_tool nxc >/dev/null 2>&1; then
            if [[ -n "${ssh_user}" ]]; then
              sf_run 600 "${SECFORGE_SESSION_DIR}/passwords/netexec.txt" "$(sf_tool nxc)" ssh "${SECFORGE_TARGET_HOST}" -u "${ssh_user}" -p "${pw_list}"
            else
              sf_run 600 "${SECFORGE_SESSION_DIR}/passwords/netexec.txt" "$(sf_tool nxc)" ssh "${SECFORGE_TARGET_HOST}" -u "${ssh_users_file}" -p "${pw_list}"
            fi
          fi
        else
          sf_warn "Set SECFORGE_SSH_USER or SECFORGE_SSH_USERS_FILE to enable Hydra/NetExec (skipping)."
        fi
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
