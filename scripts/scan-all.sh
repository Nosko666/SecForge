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
_SF_PF_TMP=""

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

  rm -f "${_SF_LOCK:-}"
  rm -f "${_SF_PF_TMP:-}"

  # Handle interactsh fallback FIRST (before manifest) — record failure + duration
  if [[ -n "${INTERACTSH_PID:-}" ]] && [[ "${_INTERACTSH_RECORDED:-0}" != "1" ]]; then
    # Compute duration BEFORE kill (sf_kill_pid sleeps + escalates, would pad duration)
    local _interactsh_cleanup_dur=0
    if [[ -n "${_INTERACTSH_START_TS:-}" ]] && [[ "${_INTERACTSH_START_TS}" -gt 0 ]]; then
      _interactsh_cleanup_dur=$(( $(date +%s) - _INTERACTSH_START_TS ))
    fi
    sf_kill_pid "${INTERACTSH_PID}"
    _SF_TOOLS_FAILED+=("interactsh")
    _SF_TOOL_DURATIONS+=("interactsh:${_interactsh_cleanup_dur}")
    sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"interactsh\",\"index\":${_INTERACTSH_INDEX:-0},\"error\":\"interrupted\"}"
    INTERACTSH_PID=""
    _INTERACTSH_RECORDED=1
  fi

  # Write partial manifest on early exit (now includes interactsh in tools_failed + duration)
  if [[ -n "${SECFORGE_SESSION_DIR:-}" ]] && [[ ! -f "${SECFORGE_SESSION_DIR:-}/scan_manifest.json" ]]; then
    SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]:-}")" \
    SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]:-}")" \
    SF_MANIFEST_TOOL_DURATIONS="$(IFS=,; echo "${_SF_TOOL_DURATIONS[*]:-}")" \
    SF_MANIFEST_PROFILE="${SECFORGE_STACK_PROFILE:-}" \
    SF_MANIFEST_TIER_MAX="${SECFORGE_TIER_MAX:-1}" \
    sf_write_manifest "${SECFORGE_SESSION_DIR}" "full" 2>/dev/null || true
  fi

  if [[ "${ZAP_STARTED}" == "1" && -n "${ZAP_API_BASE}" ]] && command -v curl >/dev/null 2>&1; then
    curl -fsS "${ZAP_API_BASE}/JSON/core/action/shutdown/" >/dev/null 2>&1 || true
  fi

  # INTERACTSH_PID already killed in fallback block above (cleared to "")
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

_SF_LAST_EXIT_CODE=0

sf_run() {
  local timeout_s="$1"
  local stdout_path="$2"
  shift 2
  local err_path="${stdout_path}.err"

  mkdir -p "$(dirname -- "${stdout_path}")"

  sf_log "Running: $*"
  _SF_LAST_EXIT_CODE=0
  if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status --kill-after=10s "${timeout_s}" "$@" >"${stdout_path}" 2>"${err_path}" || _SF_LAST_EXIT_CODE=$?
  else
    "$@" >"${stdout_path}" 2>"${err_path}" || _SF_LAST_EXIT_CODE=$?
  fi
}

# Manifest tracking arrays
_SF_TOOLS_RUN=()
_SF_TOOLS_FAILED=()
_SF_TOOL_DURATIONS=()
_sf_tool_index=0

sf_track_run() {
  # Usage: sf_track_run <tool_name> <check_file> <sf_run_args...>
  local tool_name="$1"
  local check_file="$2"
  shift 2
  local _stdout_path="$2"
  _SF_TOOLS_RUN+=("${tool_name}")
  ((_sf_tool_index++)) || true
  sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"${tool_name}\",\"index\":${_sf_tool_index}}"
  local _tool_start_ts="$(date +%s)"
  sf_run "$@"
  local _tool_end_ts="$(date +%s)"
  local _tool_dur=$(( _tool_end_ts - _tool_start_ts ))
  _SF_TOOL_DURATIONS+=("${tool_name}:${_tool_dur}")
  local _tool_failed=0
  if [[ "${_SF_LAST_EXIT_CODE}" -ge 124 ]]; then
    _SF_TOOLS_FAILED+=("${tool_name}")
    _tool_failed=1
  elif [[ ! -e "${check_file}" ]]; then
    _SF_TOOLS_FAILED+=("${tool_name}")
    _tool_failed=1
  elif [[ ! -s "${check_file}" ]]; then
    local _err_log="${_stdout_path}.err"
    if [[ -s "${_err_log}" ]] && grep -qiE '(error|exception|traceback|killed|timeout|segfault|panic|fatal)' "${_err_log}" 2>/dev/null; then
      _SF_TOOLS_FAILED+=("${tool_name}")
      _tool_failed=1
    fi
  fi
  if [[ "${_tool_failed}" -eq 1 ]]; then
    sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"${tool_name}\",\"index\":${_sf_tool_index},\"error\":\"exit ${_SF_LAST_EXIT_CODE}\"}"
  else
    sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"${tool_name}\",\"index\":${_sf_tool_index},\"duration\":${_tool_dur},\"findings\":0,\"status\":\"ok\"}"
  fi
}

sf_write_manifest() {
  local session_dir="$1"
  local scan_mode="${2:-full}"
  local scan_date
  scan_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "${session_dir}" "${scan_mode}" "${scan_date}" <<'PYEOF'
import json, sys, os
session_dir = sys.argv[1]
scan_mode = sys.argv[2]
scan_date = sys.argv[3]
tools_run = os.environ.get("SF_MANIFEST_TOOLS_RUN", "").split(",")
tools_failed = os.environ.get("SF_MANIFEST_TOOLS_FAILED", "").split(",")
tools_run = [t for t in tools_run if t]
tools_failed = [t for t in tools_failed if t]
# Parse tool durations ("tool:seconds,tool:seconds" → dict)
dur_raw = os.environ.get("SF_MANIFEST_TOOL_DURATIONS", "")
tool_durations = {}
for entry in dur_raw.split(","):
    entry = entry.strip()
    if ":" in entry:
        parts = entry.split(":", 1)
        try:
            tool_durations[parts[0]] = int(parts[1])
        except ValueError:
            pass
profile = os.environ.get("SF_MANIFEST_PROFILE", "")
tier_max_str = os.environ.get("SF_MANIFEST_TIER_MAX", "1")
try:
    tier_max_val = int(tier_max_str)
except ValueError:
    tier_max_val = 1
manifest = {
    "tools_run": sorted(set(tools_run)),
    "tools_failed": sorted(set(tools_failed)),
    "tool_durations": tool_durations,
    "scan_date": scan_date,
    "scan_mode": scan_mode,
    "profile": profile,
    "tier_max": tier_max_val,
}
out = os.path.join(session_dir, "scan_manifest.json")
with open(out, "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=False)
PYEOF
}

# sf_sleep_ms moved to _lib.sh

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

# sf_builtin_web_checks moved to _lib.sh

sf_tier2_opt_in() {
  # SECFORGE_ASSUME_YES bypasses the interactive prompt (for automated testing).
  if [[ "${SECFORGE_ASSUME_YES:-0}" == "1" ]]; then
    sf_warn "Tier 2 auto-approved (SECFORGE_ASSUME_YES=1)."
    return 0
  fi
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

  # Suggest tmux for long-running full scans (can take 30-60 minutes).
  if [[ -z "${TMUX:-}" ]] && [[ -z "${STY:-}" ]] && [[ "${SECFORGE_ASSUME_YES:-0}" != "1" ]]; then
    sf_warn "Full scans can take 30-60 minutes. Consider running inside tmux/screen to avoid SSH timeout."
    sf_warn "  Start with: tmux new -s secforge"
  fi

  # Preflight exports session vars (safe: tempfile, not process substitution).
  _SF_PF_TMP="$(mktemp /tmp/secforge-preflight.XXXXXX)"
  local _pf_tmp="${_SF_PF_TMP}"
  # Forward CLI flags to preflight (set as env vars by bin/secforge)
  local _pf_args=(--target "${target}" --scan-mode full --require-tools "curl,jq")
  [[ -n "${SECFORGE_STACK:-}" ]] && _pf_args+=(--stack "${SECFORGE_STACK}")
  [[ -n "${SECFORGE_SKIP:-}" ]] && _pf_args+=(--skip "${SECFORGE_SKIP}")
  [[ -n "${SECFORGE_TIER_OVERRIDE:-}" ]] && _pf_args+=(--tier "${SECFORGE_TIER_OVERRIDE}")
  [[ -n "${SECFORGE_CODE_PATH:-}" ]] && _pf_args+=(--code-path "${SECFORGE_CODE_PATH}")
  if ! "${SCRIPT_DIR}/preflight.sh" "${_pf_args[@]}" >"${_pf_tmp}"; then
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

  # No-parallel-scan guard
  _SF_LOCK="/tmp/secforge-scan.lock"
  if ! (set -C; echo $$ > "${_SF_LOCK}") 2>/dev/null; then
    sf_die "A scan is already running (lock: ${_SF_LOCK}). Wait for it to finish or remove the lock."
  fi

  # Dashboard status events
  SECFORGE_DASHBOARD_STATUS="/tmp/secforge-dashboard-${SECFORGE_SESSION_ID}.status"
  export SECFORGE_DASHBOARD_STATUS
  ln -sf "${SECFORGE_DASHBOARD_STATUS}" /tmp/secforge-dashboard-latest.status 2>/dev/null || true

  sf_emit_dashboard_event "{\"event\":\"scan_start\",\"target\":\"${SECFORGE_TARGET_HOST}\",\"profile\":\"${SECFORGE_STACK_PROFILE:-}\",\"scan_mode\":\"${SECFORGE_SCAN_MODE:-full}\",\"tools_total\":${SECFORGE_EST_TOOLS_TOTAL:-0},\"est_seconds\":${SECFORGE_EST_SECONDS:-0}}"

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

  # Show estimate before starting
  local _est_tools="${SECFORGE_EST_TOOLS_TOTAL:-0}"
  local _est_secs="${SECFORGE_EST_SECONDS:-0}"
  if [[ "${_est_tools}" -gt 0 ]]; then
    local _est_min=$(( _est_secs / 60 )) _est_rem=$(( _est_secs % 60 ))
    local _est_display
    if [[ "${_est_min}" -gt 0 ]]; then
      _est_display="~${_est_min}m ${_est_rem}s"
    else
      _est_display="~${_est_secs}s"
    fi
    local _est_qualifier=""
    if [[ -z "$(find "${SECFORGE_ROOT}/reports" -maxdepth 2 -name 'scan_manifest.json' -path "*${SECFORGE_TARGET_HOST}*" 2>/dev/null | head -1)" ]]; then
      _est_qualifier=" (first scan — rough estimate)"
    fi
    sf_log "${_est_tools} tools, ${_est_display}${_est_qualifier}"
  fi

  # ---------------------------
  # Tier 1 (default)
  # ---------------------------
  if [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    if sf_should_run_tool "interactsh" && [[ -z "${INTERACTSH_PID}" ]] && sf_tool interactsh-client >/dev/null 2>&1; then
      sf_log "Starting interactsh-client (OOB callbacks)..."
      ((_sf_tool_index++)) || true
      _INTERACTSH_INDEX="${_sf_tool_index}"
      _INTERACTSH_START_TS="$(date +%s)"
      _INTERACTSH_RECORDED=0
      sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"interactsh\",\"index\":${_sf_tool_index}}"
      "$(sf_tool interactsh-client)" -json -o "${SECFORGE_SESSION_DIR}/api/interactsh.json" >"${SECFORGE_SESSION_DIR}/api/interactsh.log" 2>"${SECFORGE_SESSION_DIR}/api/interactsh.log.err" &
      INTERACTSH_PID=$!
      _SF_TOOLS_RUN+=("interactsh")
    fi

    sf_circuit_breaker_check "${SECFORGE_TARGET_URL}" "${threshold}" "${cooldown}"

    if sf_should_run_tool "wafw00f" && sf_tool wafw00f >/dev/null 2>&1; then
      sf_track_run wafw00f "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/wafw00f.log" "$(sf_tool wafw00f)" "${SECFORGE_TARGET_URL}" -f json -o "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json"
    fi

    if sf_should_run_tool "whatweb" && sf_tool whatweb >/dev/null 2>&1; then
      sf_track_run whatweb "${SECFORGE_SESSION_DIR}/webapp/whatweb.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/whatweb.log" "$(sf_tool whatweb)" "${SECFORGE_TARGET_URL}" "--log-json=${SECFORGE_SESSION_DIR}/webapp/whatweb.json"
    fi

    if sf_should_run_tool "corscanner" && sf_tool corscanner >/dev/null 2>&1; then
      sf_track_run corscanner "${SECFORGE_SESSION_DIR}/webapp/corscanner.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/corscanner.log" "$(sf_tool corscanner)" -u "${SECFORGE_TARGET_URL}" -o "${SECFORGE_SESSION_DIR}/webapp/corscanner.json"
    fi

    if sf_should_run_tool "nuclei" && sf_tool nuclei >/dev/null 2>&1; then
      local _nuclei_tpl="${SECFORGE_ROOT}/tools/nuclei-templates"
      if [[ -d "${_nuclei_tpl}" ]]; then
        local _nuclei_extra_args=()
        if [[ -n "${SECFORGE_NUCLEI_TAGS:-}" ]] && [[ "${SECFORGE_SCAN_MODE:-quick}" == "quick" ]]; then
          _nuclei_extra_args+=(-tags "${SECFORGE_NUCLEI_TAGS}")
        elif [[ -n "${SECFORGE_NUCLEI_EXCLUDE_TAGS:-}" ]]; then
          _nuclei_extra_args+=(-etags "${SECFORGE_NUCLEI_EXCLUDE_TAGS}")
        fi
        sf_track_run nuclei "${SECFORGE_SESSION_DIR}/webapp/nuclei.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/nuclei.log" "$(sf_tool nuclei)" -duc -u "${SECFORGE_TARGET_URL}" -t "${_nuclei_tpl}" "${_nuclei_extra_args[@]}" -json-export "${SECFORGE_SESSION_DIR}/webapp/nuclei.json"
      else
        sf_warn "Nuclei templates not found at ${_nuclei_tpl}. Skipping nuclei (run installer to fetch templates)."
      fi
    fi

    sf_circuit_breaker_check "${SECFORGE_TARGET_URL}" "${threshold}" "${cooldown}"

    if sf_should_run_tool "ffuf" && sf_tool ffuf >/dev/null 2>&1 && [[ -r "${SECFORGE_ROOT}/wordlists/directories.txt" ]]; then
      sf_track_run ffuf "${SECFORGE_SESSION_DIR}/webapp/ffuf.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/ffuf.log" "$(sf_tool ffuf)" -u "${SECFORGE_TARGET_URL%/}/FUZZ" -w "${SECFORGE_ROOT}/wordlists/directories.txt" -o "${SECFORGE_SESSION_DIR}/webapp/ffuf.json" -of json
    fi

    if sf_should_run_tool "nikto" && sf_tool nikto >/dev/null 2>&1; then
      sf_track_run nikto "${SECFORGE_SESSION_DIR}/webapp/nikto.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/nikto.log" "$(sf_tool nikto)" -h "${SECFORGE_TARGET_URL}" -Format json -output "${SECFORGE_SESSION_DIR}/webapp/nikto.json"
    fi

    if sf_should_run_tool "observatory" && sf_tool observatory >/dev/null 2>&1; then
      _SF_TOOLS_RUN+=("observatory")
      ((_sf_tool_index++)) || true
      sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"observatory\",\"index\":${_sf_tool_index}}"
      local _observatory_start="$(date +%s)"
      sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/observatory.json" "$(sf_tool observatory)" --format json "${SECFORGE_TARGET_URL}" || true
      if [[ ! -s "${SECFORGE_SESSION_DIR}/ssl/observatory.json" ]]; then
        sf_run "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/observatory.json" "$(sf_tool observatory)" scan --format json "${SECFORGE_TARGET_URL}" || true
      fi
      local _observatory_dur=$(( $(date +%s) - _observatory_start ))
      _SF_TOOL_DURATIONS+=("observatory:${_observatory_dur}")
      if [[ ! -s "${SECFORGE_SESSION_DIR}/ssl/observatory.json" ]]; then
        _SF_TOOLS_FAILED+=("observatory")
        sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"observatory\",\"index\":${_sf_tool_index},\"error\":\"empty output\"}"
      else
        sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"observatory\",\"index\":${_sf_tool_index},\"duration\":${_observatory_dur},\"findings\":0,\"status\":\"ok\"}"
      fi
    fi

    if sf_should_run_tool "testssl" && sf_tool testssl.sh >/dev/null 2>&1; then
      local ssl_target="${SECFORGE_TARGET_HOST}"
      if [[ -n "${SECFORGE_TARGET_PORT}" ]]; then
        ssl_target="${ssl_target}:${SECFORGE_TARGET_PORT}"
      fi
      sf_track_run testssl "${SECFORGE_SESSION_DIR}/ssl/testssl.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/testssl.log" "$(sf_tool testssl.sh)" --jsonfile "${SECFORGE_SESSION_DIR}/ssl/testssl.json" "${ssl_target}"
    fi

    if sf_should_run_tool "sslscan" && sf_tool sslscan >/dev/null 2>&1; then
      local ssl_target="${SECFORGE_TARGET_HOST}"
      if [[ -n "${SECFORGE_TARGET_PORT}" ]]; then
        ssl_target="${ssl_target}:${SECFORGE_TARGET_PORT}"
      fi
      sf_track_run sslscan "${SECFORGE_SESSION_DIR}/ssl/sslscan.xml" "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/sslscan.log" "$(sf_tool sslscan)" --xml="${SECFORGE_SESSION_DIR}/ssl/sslscan.xml" "${ssl_target}"
    fi

    # Built-in curl checks (zero-dependency, high value).
    if sf_should_run_tool "secforge-builtin"; then
      _SF_TOOLS_RUN+=("secforge-builtin")
      ((_sf_tool_index++)) || true
      sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"secforge-builtin\",\"index\":${_sf_tool_index}}"
      local _builtin_start="$(date +%s)"
      sf_builtin_web_checks "${SECFORGE_TARGET_URL%/}" "${SECFORGE_SESSION_DIR}/webapp/builtin.json" "${delay_ms}"
      local _builtin_dur=$(( $(date +%s) - _builtin_start ))
      _SF_TOOL_DURATIONS+=("secforge-builtin:${_builtin_dur}")
      if [[ ! -s "${SECFORGE_SESSION_DIR}/webapp/builtin.json" ]]; then
        _SF_TOOLS_FAILED+=("secforge-builtin")
        sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"secforge-builtin\",\"index\":${_sf_tool_index},\"error\":\"empty output\"}"
      else
        sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"secforge-builtin\",\"index\":${_sf_tool_index},\"duration\":${_builtin_dur},\"findings\":0,\"status\":\"ok\"}"
      fi
    fi

    if sf_should_run_tool "check-email-dns" && [[ -r "${SCRIPT_DIR}/check-email-dns.sh" ]]; then
      chmod +x "${SCRIPT_DIR}/check-email-dns.sh" 2>/dev/null || true
      sf_track_run check-email-dns "${SECFORGE_SESSION_DIR}/emaildns/emaildns.json" 60 "${SECFORGE_SESSION_DIR}/emaildns/emaildns.json" "${SCRIPT_DIR}/check-email-dns.sh" "${SECFORGE_TARGET_HOST}"
    fi

    if sf_should_run_tool "subfinder" && sf_tool subfinder >/dev/null 2>&1; then
      sf_track_run subfinder "${SECFORGE_SESSION_DIR}/emaildns/subfinder.jsonl" 120 "${SECFORGE_SESSION_DIR}/emaildns/subfinder.jsonl" "$(sf_tool subfinder)" -d "${SECFORGE_TARGET_HOST}" -silent -json
      # Probe discovered hosts (limit to first 200).
      if sf_should_run_tool "httpx" && sf_tool httpx >/dev/null 2>&1; then
        jq -r '.host // empty' "${SECFORGE_SESSION_DIR}/emaildns/subfinder.jsonl" 2>/dev/null | grep -E '^[A-Za-z0-9._-]+$' | sort -u | head -n 200 >"${SECFORGE_SESSION_DIR}/emaildns/subdomains.txt" || true
        if [[ -s "${SECFORGE_SESSION_DIR}/emaildns/subdomains.txt" ]]; then
          sf_track_run httpx "${SECFORGE_SESSION_DIR}/emaildns/httpx.jsonl" 300 "${SECFORGE_SESSION_DIR}/emaildns/httpx.jsonl" "$(sf_tool httpx)" -l "${SECFORGE_SESSION_DIR}/emaildns/subdomains.txt" -silent -json
        fi
      fi
    fi

    if sf_should_run_tool "nmap" && sf_tool nmap >/dev/null 2>&1; then
      local nmap_timing nmap_top
      nmap_timing="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "NMAP_TIMING" || true)"
      nmap_top="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "NMAP_TOP_PORTS" || true)"
      nmap_timing="${nmap_timing:--T3}"
      nmap_top="${nmap_top:-1000}"
      if ! [[ "${nmap_timing}" =~ ^-T[0-5]$ ]]; then
        sf_warn "Invalid NMAP_TIMING '${nmap_timing}'; defaulting to -T3."
        nmap_timing="-T3"
      fi

      sf_track_run nmap "${SECFORGE_SESSION_DIR}/network/nmap.xml" "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/nmap.log" "$(sf_tool nmap)" "${nmap_timing}" -sV -sC --top-ports "${nmap_top}" -oX "${SECFORGE_SESSION_DIR}/network/nmap.xml" "${SECFORGE_TARGET_HOST}"
    fi

    if sf_should_run_tool "ssh-audit" && sf_tool ssh-audit >/dev/null 2>&1; then
      sf_track_run ssh-audit "${SECFORGE_SESSION_DIR}/hardening/ssh-audit.json" 60 "${SECFORGE_SESSION_DIR}/hardening/ssh-audit.json" "$(sf_tool ssh-audit)" --json "${SECFORGE_TARGET_HOST}"
    fi

    if sf_should_run_tool "masscan" && sf_tool masscan >/dev/null 2>&1; then
      local sudo_policy
      sudo_policy="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "ALLOW_SUDO_TOOLS" || true)"
      sudo_policy="${sudo_policy:-ask}"
      _SF_TOOLS_RUN+=("masscan")
      ((_sf_tool_index++)) || true
      sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"masscan\",\"index\":${_sf_tool_index}}"
      local _masscan_start="$(date +%s)"
      if [[ "${EUID}" -eq 0 ]]; then
        sf_run "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/masscan.log" "$(sf_tool masscan)" "${SECFORGE_TARGET_HOST}" -p0-65535 --rate=1000 -oJ "${SECFORGE_SESSION_DIR}/network/masscan.json"
      elif [[ "${sudo_policy}" == "never" ]]; then
        sf_warn "Skipping masscan (requires root; ALLOW_SUDO_TOOLS=never)."
        _SF_TOOLS_FAILED+=("masscan")
        local _masscan_skipped=1
      else
        if sf_ask_tty_yes "Masscan needs sudo (raw sockets). Type YES to run it now:" "YES"; then
          sf_run "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/masscan.log" sudo "$(sf_tool masscan)" "${SECFORGE_TARGET_HOST}" -p0-65535 --rate=1000 -oJ "${SECFORGE_SESSION_DIR}/network/masscan.json"
        else
          sf_log "Skipping masscan."
          _SF_TOOLS_FAILED+=("masscan")
          local _masscan_skipped=1
        fi
      fi
      local _masscan_dur=$(( $(date +%s) - _masscan_start ))
      _SF_TOOL_DURATIONS+=("masscan:${_masscan_dur}")
      if [[ "${_masscan_skipped:-0}" == "1" ]]; then
        sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"masscan\",\"index\":${_sf_tool_index},\"error\":\"skipped (no sudo)\"}"
      elif [[ ! -s "${SECFORGE_SESSION_DIR}/network/masscan.json" ]]; then
        _SF_TOOLS_FAILED+=("masscan")
        sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"masscan\",\"index\":${_sf_tool_index},\"error\":\"empty output\"}"
      else
        sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"masscan\",\"index\":${_sf_tool_index},\"duration\":${_masscan_dur},\"findings\":0,\"status\":\"ok\"}"
      fi
    fi
  fi

  # Local system audit (Tier 1, read-only).
  if sf_should_run_tool "lynis" && sf_tool lynis >/dev/null 2>&1; then
    sf_track_run lynis "${SECFORGE_SESSION_DIR}/hardening/lynis.dat" "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/lynis.stdout" "$(sf_tool lynis)" audit system --no-colors --logfile "${SECFORGE_SESSION_DIR}/hardening/lynis.log" --report-file "${SECFORGE_SESSION_DIR}/hardening/lynis.dat"
  fi

  if sf_should_run_tool "systemd-analyze" && sf_tool systemd-analyze >/dev/null 2>&1; then
    sf_track_run systemd-analyze "${SECFORGE_SESSION_DIR}/hardening/systemd-security.txt" 120 "${SECFORGE_SESSION_DIR}/hardening/systemd-security.txt" "$(sf_tool systemd-analyze)" security
  fi

  if sf_should_run_tool "clamscan" && sf_tool clamscan >/dev/null 2>&1; then
    sf_track_run clamscan "${SECFORGE_SESSION_DIR}/hardening/clamav.log" "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/clamav.stdout" "$(sf_tool clamscan)" -r /home /var/www /tmp --log="${SECFORGE_SESSION_DIR}/hardening/clamav.log" --exclude-dir="^/proc" --exclude-dir="^/sys" --exclude-dir="^/opt/secforge" || true
  fi

  if sf_should_run_tool "rkhunter" && sf_tool rkhunter >/dev/null 2>&1; then
    sf_track_run rkhunter "${SECFORGE_SESSION_DIR}/hardening/rkhunter.log" "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/rkhunter.stdout" "$(sf_tool rkhunter)" --check --skip-keypress --logfile "${SECFORGE_SESSION_DIR}/hardening/rkhunter.log"
  fi

  if sf_should_run_tool "aide" && sf_tool aide >/dev/null 2>&1; then
    sf_track_run aide "${SECFORGE_SESSION_DIR}/hardening/aide.log" "${timeout_hardening}" "${SECFORGE_SESSION_DIR}/hardening/aide.log" "$(sf_tool aide)" --check
  fi

  if sf_should_run_tool "aureport" && sf_tool aureport >/dev/null 2>&1; then
    sf_track_run aureport "${SECFORGE_SESSION_DIR}/hardening/audit-summary.log" 60 "${SECFORGE_SESSION_DIR}/hardening/audit-summary.log" "$(sf_tool aureport)" --summary
  fi

  if sf_should_run_tool "debsums" && sf_tool debsums >/dev/null 2>&1; then
    sf_track_run debsums "${SECFORGE_SESSION_DIR}/hardening/debsums.log" 600 "${SECFORGE_SESSION_DIR}/hardening/debsums.log" "$(sf_tool debsums)" -s
  fi

  if sf_should_run_tool "trivy" && sf_tool trivy >/dev/null 2>&1; then
    local sudo_policy
    sudo_policy="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "ALLOW_SUDO_TOOLS" || true)"
    sudo_policy="${sudo_policy:-ask}"
    _SF_TOOLS_RUN+=("trivy")
    ((_sf_tool_index++)) || true
    sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"trivy\",\"index\":${_sf_tool_index}}"
    local _trivy_start="$(date +%s)"

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
    local _trivy_dur=$(( $(date +%s) - _trivy_start ))
    _SF_TOOL_DURATIONS+=("trivy:${_trivy_dur}")
    if [[ ! -s "${SECFORGE_SESSION_DIR}/hardening/trivy-rootfs.json" ]]; then
      _SF_TOOLS_FAILED+=("trivy")
      sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"trivy\",\"index\":${_sf_tool_index},\"error\":\"empty output\"}"
    else
      sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"trivy\",\"index\":${_sf_tool_index},\"duration\":${_trivy_dur},\"findings\":0,\"status\":\"ok\"}"
    fi
  fi

  # check-mysql: only for local targets with active MySQL service
  if sf_should_run_tool "check-mysql" && [[ "${SECFORGE_TARGET_HOST}" == "this_server" ]] && [[ -r "${SCRIPT_DIR}/check-mysql.sh" ]]; then
    if systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mariadb 2>/dev/null; then
      chmod +x "${SCRIPT_DIR}/check-mysql.sh" 2>/dev/null || true
      sf_track_run check-mysql "${SECFORGE_SESSION_DIR}/database/mysql.json" 60 "${SECFORGE_SESSION_DIR}/database/mysql.json" "${SCRIPT_DIR}/check-mysql.sh"
    fi
  fi

  # Optional codebase scans.
  if [[ -n "${SECFORGE_CODE_PATH}" ]]; then
    if sf_should_run_tool "trufflehog" && sf_tool trufflehog >/dev/null 2>&1; then
      _SF_TOOLS_RUN+=("trufflehog")
      ((_sf_tool_index++)) || true
      sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"trufflehog\",\"index\":${_sf_tool_index}}"
      local _trufflehog_start="$(date +%s)"
      local _th_raw
      _th_raw="$(mktemp /tmp/secforge-trufflehog-raw.XXXXXX)"
      chmod 0600 "${_th_raw}"
      sf_run "${timeout_web}" "${_th_raw}" "$(sf_tool trufflehog)" filesystem "${SECFORGE_CODE_PATH}" --json
      if [[ -s "${_th_raw}" ]] && [[ -r "${SCRIPT_DIR}/sanitize-trufflehog.py" ]]; then
        python3 "${SCRIPT_DIR}/sanitize-trufflehog.py" "${_th_raw}" "${SECFORGE_SESSION_DIR}/secrets/trufflehog.json" 2>/dev/null || sf_warn "TruffleHog sanitization failed"
      fi
      local _trufflehog_dur=$(( $(date +%s) - _trufflehog_start ))
      _SF_TOOL_DURATIONS+=("trufflehog:${_trufflehog_dur}")
      if [[ ! -s "${SECFORGE_SESSION_DIR}/secrets/trufflehog.json" ]]; then
        _SF_TOOLS_FAILED+=("trufflehog")
        sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"trufflehog\",\"index\":${_sf_tool_index},\"error\":\"empty output\"}"
      else
        sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"trufflehog\",\"index\":${_sf_tool_index},\"duration\":${_trufflehog_dur},\"findings\":0,\"status\":\"ok\"}"
      fi
      rm -f "${_th_raw}" "${_th_raw}.err" 2>/dev/null || true
    fi
    if sf_should_run_tool "gitleaks" && sf_tool gitleaks >/dev/null 2>&1; then
      sf_track_run gitleaks "${SECFORGE_SESSION_DIR}/secrets/gitleaks.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/secrets/gitleaks.log" "$(sf_tool gitleaks)" detect --source "${SECFORGE_CODE_PATH}" --redact --report-path "${SECFORGE_SESSION_DIR}/secrets/gitleaks.json" --report-format json
    fi
    if sf_should_run_tool "osv-scanner" && sf_tool osv-scanner >/dev/null 2>&1; then
      sf_track_run osv-scanner "${SECFORGE_SESSION_DIR}/dependencies/osv.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/dependencies/osv.json" "$(sf_tool osv-scanner)" --json "${SECFORGE_CODE_PATH}"
    fi
    if sf_should_run_tool "pip-audit" && sf_tool pip-audit >/dev/null 2>&1; then
      sf_track_run pip-audit "${SECFORGE_SESSION_DIR}/dependencies/pip-audit.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/dependencies/pip-audit.json" "$(sf_tool pip-audit)" --format json
    fi
  fi

  # ---------------------------
  # Tier 2 (explicit opt-in)
  # ---------------------------
  if [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    if [[ "${SECFORGE_TIER_MAX:-1}" -ge 2 ]]; then
      sf_emit_dashboard_event "{\"event\":\"tier2_prompt\",\"message\":\"Type YES in the main pane\"}"
      if sf_tier2_opt_in; then
        sf_emit_dashboard_event "{\"event\":\"tier2_approved\"}"
        sf_circuit_breaker_check "${SECFORGE_TARGET_URL}" "${threshold}" "${cooldown}"

        if sf_should_run_tool "zap"; then
          _SF_TOOLS_RUN+=("zap")
          ((_sf_tool_index++)) || true
          sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"zap\",\"index\":${_sf_tool_index}}"
          local _zap_start="$(date +%s)"
          sf_zap_active_scan "${SECFORGE_TARGET_URL}" "${SECFORGE_SESSION_DIR}/webapp/zap.json" "${SECFORGE_SESSION_DIR}/webapp/zap.log" "${timeout_zap}"
          local _zap_dur=$(( $(date +%s) - _zap_start ))
          _SF_TOOL_DURATIONS+=("zap:${_zap_dur}")
          if [[ ! -s "${SECFORGE_SESSION_DIR}/webapp/zap.json" ]]; then
            _SF_TOOLS_FAILED+=("zap")
            sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"zap\",\"index\":${_sf_tool_index},\"error\":\"empty output\"}"
          else
            sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"zap\",\"index\":${_sf_tool_index},\"duration\":${_zap_dur},\"findings\":0,\"status\":\"ok\"}"
          fi
        fi

        if sf_should_run_tool "sqlmap" && sf_tool sqlmap >/dev/null 2>&1; then
          mkdir -p "${SECFORGE_SESSION_DIR}/webapp/sqlmap"
          sf_track_run sqlmap "${SECFORGE_SESSION_DIR}/webapp/sqlmap/sqlmap.log" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/sqlmap/sqlmap.log" "$(sf_tool sqlmap)" -u "${SECFORGE_TARGET_URL}" --batch --forms --crawl=3 --output-dir="${SECFORGE_SESSION_DIR}/webapp/sqlmap"
        fi

        if sf_should_run_tool "dalfox" && sf_tool dalfox >/dev/null 2>&1; then
          sf_track_run dalfox "${SECFORGE_SESSION_DIR}/webapp/dalfox.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/dalfox.log" "$(sf_tool dalfox)" url "${SECFORGE_TARGET_URL}" -o "${SECFORGE_SESSION_DIR}/webapp/dalfox.json" --format json
        fi

        if sf_should_run_tool "xsstrike" && sf_tool xsstrike >/dev/null 2>&1; then
          sf_track_run xsstrike "${SECFORGE_SESSION_DIR}/webapp/xsstrike.log" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/xsstrike.log" "$(sf_tool xsstrike)" -u "${SECFORGE_TARGET_URL}" --crawl || true
        fi

        if sf_should_run_tool "commix" && sf_tool commix >/dev/null 2>&1; then
          mkdir -p "${SECFORGE_SESSION_DIR}/webapp/commix"
          sf_track_run commix "${SECFORGE_SESSION_DIR}/webapp/commix.log" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/commix.log" "$(sf_tool commix)" --url="${SECFORGE_TARGET_URL}" --batch --output-dir="${SECFORGE_SESSION_DIR}/webapp/commix"
        fi

        if sf_should_run_tool "wapiti" && sf_tool wapiti >/dev/null 2>&1; then
          sf_track_run wapiti "${SECFORGE_SESSION_DIR}/webapp/wapiti.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/wapiti.log" "$(sf_tool wapiti)" -u "${SECFORGE_TARGET_URL}" -f json -o "${SECFORGE_SESSION_DIR}/webapp/wapiti.json"
        fi

        if sf_should_run_tool "hydra" || sf_should_run_tool "netexec"; then
          if sf_ask_tty_yes "Run SSH credential checks (Hydra/NetExec) against ${SECFORGE_TARGET_HOST}? Type YES to continue:" "YES"; then
            local pw_list ssh_user ssh_users_file
            pw_list="${SECFORGE_ROOT}/wordlists/passwords-top1000.txt"
            ssh_user="${SECFORGE_SSH_USER:-}"
            ssh_users_file="${SECFORGE_SSH_USERS_FILE:-}"

            if [[ ! -r "${pw_list}" ]]; then
              sf_warn "Password list missing: ${pw_list} (skipping Hydra/NetExec)."
            elif [[ -n "${ssh_user}" || ( -n "${ssh_users_file}" && -r "${ssh_users_file}" ) ]]; then
              if sf_should_run_tool "hydra" && sf_tool hydra >/dev/null 2>&1; then
                if [[ -n "${ssh_user}" ]]; then
                  sf_track_run hydra "${SECFORGE_SESSION_DIR}/passwords/hydra.txt" 600 "${SECFORGE_SESSION_DIR}/passwords/hydra.txt" "$(sf_tool hydra)" -l "${ssh_user}" -P "${pw_list}" "${SECFORGE_TARGET_HOST}" ssh
                else
                  sf_track_run hydra "${SECFORGE_SESSION_DIR}/passwords/hydra.txt" 600 "${SECFORGE_SESSION_DIR}/passwords/hydra.txt" "$(sf_tool hydra)" -L "${ssh_users_file}" -P "${pw_list}" "${SECFORGE_TARGET_HOST}" ssh
                fi
              fi

              if sf_should_run_tool "netexec" && sf_tool nxc >/dev/null 2>&1; then
                if [[ -n "${ssh_user}" ]]; then
                  sf_track_run netexec "${SECFORGE_SESSION_DIR}/passwords/netexec.txt" 600 "${SECFORGE_SESSION_DIR}/passwords/netexec.txt" "$(sf_tool nxc)" ssh "${SECFORGE_TARGET_HOST}" -u "${ssh_user}" -p "${pw_list}"
                else
                  sf_track_run netexec "${SECFORGE_SESSION_DIR}/passwords/netexec.txt" 600 "${SECFORGE_SESSION_DIR}/passwords/netexec.txt" "$(sf_tool nxc)" ssh "${SECFORGE_TARGET_HOST}" -u "${ssh_users_file}" -p "${pw_list}"
                fi
              fi
            else
              sf_warn "Set SECFORGE_SSH_USER or SECFORGE_SSH_USERS_FILE to enable Hydra/NetExec (skipping)."
            fi
          fi
        fi
      else
        sf_emit_dashboard_event "{\"event\":\"tier2_skipped\"}"
        sf_log "Tier 2 skipped."
      fi
    else
      sf_log "Tier 2 skipped (TIER_MAX=${SECFORGE_TIER_MAX:-1})."
      sf_emit_dashboard_event "{\"event\":\"tier2_skipped\"}"
    fi
  fi

  # Gracefully close interactsh and record before manifest
  if [[ -n "${INTERACTSH_PID:-}" ]] && [[ "${_INTERACTSH_RECORDED:-0}" != "1" ]]; then
    sf_kill_pid "${INTERACTSH_PID}"
    local _interactsh_dur=$(( $(date +%s) - ${_INTERACTSH_START_TS:-0} ))
    _SF_TOOL_DURATIONS+=("interactsh:${_interactsh_dur}")
    sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"interactsh\",\"index\":${_INTERACTSH_INDEX:-0},\"duration\":${_interactsh_dur},\"findings\":0,\"status\":\"ok\"}"
    INTERACTSH_PID=""
    _INTERACTSH_RECORDED=1
  fi

  # Write scan manifest before merging
  SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]}")" \
  SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]}")" \
  SF_MANIFEST_TOOL_DURATIONS="$(IFS=,; echo "${_SF_TOOL_DURATIONS[*]}")" \
  SF_MANIFEST_PROFILE="${SECFORGE_STACK_PROFILE:-}" \
  SF_MANIFEST_TIER_MAX="${SECFORGE_TIER_MAX:-1}" \
  sf_write_manifest "${SECFORGE_SESSION_DIR}" "full"

  if [[ -r "${SCRIPT_DIR}/merge-reports.py" ]]; then
    sf_log "Merging reports..."
    python3 "${SCRIPT_DIR}/merge-reports.py" "${SECFORGE_SESSION_DIR}" || sf_warn "merge-reports.py failed (continuing)."
  else
    sf_warn "merge-reports.py not available yet (Phase 4)."
  fi

  # Emit scan_done with real finding counts from findings.json
  local _scan_done_json
  _scan_done_json="$(python3 - "${SECFORGE_SESSION_DIR}" "${SECONDS}" <<'PYSD'
import json, sys, os
session_dir = sys.argv[1]
duration = sys.argv[2]
fj = os.path.join(session_dir, "findings.json")
total = 0
sev = {}
if os.path.isfile(fj):
    try:
        with open(fj) as f:
            data = json.load(f)
        findings = data.get("findings", [])
        total = len(findings)
        for f in findings:
            s = f.get("severity", "info").lower()
            sev[s] = sev.get(s, 0) + 1
    except Exception:
        pass
severity_json = json.dumps(sev) if sev else "{}"
print(f'{{"event":"scan_done","duration":{duration},"total_findings":{total},"severity":{severity_json}}}')
PYSD
  )" 2>/dev/null || true
  if [[ -n "${_scan_done_json}" ]]; then
    sf_emit_dashboard_event "${_scan_done_json}"
  else
    sf_emit_dashboard_event "{\"event\":\"scan_done\",\"duration\":${SECONDS},\"total_findings\":0}"
  fi

  sf_log "Full scan complete."
  sf_log "Session folder: ${SECFORGE_SESSION_DIR}"
}

main "$@"
