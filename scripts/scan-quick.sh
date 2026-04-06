#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SECFORGE_ROOT="${SECFORGE_ROOT:-$DEFAULT_ROOT}"
SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE:-${SECFORGE_ROOT}/config/secforge.conf}"

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
  # A tool is marked "failed" if: exit code >= 124 (timeout/killed), output missing,
  # or empty output with crash indicators in stderr. Empty output alone = success.
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
  # 1. Exit code: 124=timeout, 125+=error, 126=cannot invoke, 127=not found, 128+N=signal
  if [[ "${_SF_LAST_EXIT_CODE}" -ge 124 ]]; then
    _SF_TOOLS_FAILED+=("${tool_name}")
    _tool_failed=1
  elif [[ ! -e "${check_file}" ]]; then
    # 2. Output file never created → crashed before writing
    _SF_TOOLS_FAILED+=("${tool_name}")
    _tool_failed=1
  elif [[ ! -s "${check_file}" ]]; then
    # 3. Empty output — check stderr for crash indicators (empty output alone is valid)
    local _err_log="${_stdout_path}.err"
    if [[ -s "${_err_log}" ]] && grep -qiE '(error|exception|traceback|killed|timeout|segfault|panic|fatal)' "${_err_log}" 2>/dev/null; then
      _SF_TOOLS_FAILED+=("${tool_name}")
      _tool_failed=1
    fi
    # else: empty output is valid (tool ran, found nothing)
  fi
  # Emit dashboard event
  if [[ "${_tool_failed}" -eq 1 ]]; then
    sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"${tool_name}\",\"index\":${_sf_tool_index},\"error\":\"exit ${_SF_LAST_EXIT_CODE}\"}"
  else
    sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"${tool_name}\",\"index\":${_sf_tool_index},\"duration\":${_tool_dur},\"findings\":0,\"status\":\"ok\"}"
  fi
}

sf_write_manifest() {
  local session_dir="$1"
  local scan_mode="${2:-quick}"
  local scan_date
  scan_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Build JSON with Python (safe for arbitrary tool names)
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

main() {
  local target="${1:-}"
  if [[ -z "${target}" ]]; then
    sf_die "Usage: ${0##*/} <domain|url|this_server>"
  fi

  # Preflight exports session vars (safe: tempfile, not process substitution).
  local _pf_tmp
  _pf_tmp="$(mktemp /tmp/secforge-preflight.XXXXXX)"
  trap '
    rm -f "${_pf_tmp:-}"
    rm -f "${_SF_LOCK:-}"
    # Write partial manifest on early exit (Ctrl+C, crash, etc.)
    if [[ -n "${SECFORGE_SESSION_DIR:-}" ]] && [[ ! -f "${SECFORGE_SESSION_DIR}/scan_manifest.json" ]]; then
      SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]:-}")" \
      SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]:-}")" \
      SF_MANIFEST_TOOL_DURATIONS="$(IFS=,; echo "${_SF_TOOL_DURATIONS[*]:-}")" \
      SF_MANIFEST_PROFILE="${SECFORGE_STACK_PROFILE:-}" \
      SF_MANIFEST_TIER_MAX="${SECFORGE_TIER_MAX:-1}" \
      sf_write_manifest "${SECFORGE_SESSION_DIR}" "quick" 2>/dev/null || true
    fi
  ' EXIT
  # Forward CLI flags to preflight (set as env vars by bin/secforge)
  local _pf_args=(--target "${target}" --scan-mode quick --require-tools "curl,jq")
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

  sf_emit_dashboard_event "{\"event\":\"scan_start\",\"target\":\"${SECFORGE_TARGET_HOST}\",\"profile\":\"${SECFORGE_STACK_PROFILE:-}\",\"scan_mode\":\"${SECFORGE_SCAN_MODE:-quick}\",\"tools_total\":${SECFORGE_EST_TOOLS_TOTAL:-0},\"est_seconds\":${SECFORGE_EST_SECONDS:-0}}"

  local timeout_web timeout_portscan
  timeout_web="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_WEB_SECONDS" || true)"
  timeout_portscan="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_PORTSCAN_SECONDS" || true)"
  timeout_web="${timeout_web:-600}"
  timeout_portscan="${timeout_portscan:-1800}"

  sf_log "Session: ${SECFORGE_SESSION_ID}"
  sf_log "Reports: ${SECFORGE_SESSION_DIR}"

  # Tier 1 only.
  if [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    if sf_should_run_tool "wafw00f" && sf_tool wafw00f >/dev/null 2>&1; then
      sf_track_run wafw00f "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/wafw00f.log" "$(sf_tool wafw00f)" "${SECFORGE_TARGET_URL}" -f json -o "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json"
    fi

    if sf_should_run_tool "whatweb" && sf_tool whatweb >/dev/null 2>&1; then
      sf_track_run whatweb "${SECFORGE_SESSION_DIR}/webapp/whatweb.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/whatweb.log" "$(sf_tool whatweb)" "${SECFORGE_TARGET_URL}" "--log-json=${SECFORGE_SESSION_DIR}/webapp/whatweb.json"
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
        sf_warn "Nuclei templates not found at ${_nuclei_tpl}. Skipping nuclei."
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

    if sf_should_run_tool "testssl" && sf_tool testssl.sh >/dev/null 2>&1; then
      local ssl_target="${SECFORGE_TARGET_HOST}"
      if [[ -n "${SECFORGE_TARGET_PORT}" ]]; then
        ssl_target="${ssl_target}:${SECFORGE_TARGET_PORT}"
      fi
      sf_track_run testssl "${SECFORGE_SESSION_DIR}/ssl/testssl.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/testssl.log" "$(sf_tool testssl.sh)" --jsonfile "${SECFORGE_SESSION_DIR}/ssl/testssl.json" "${ssl_target}"
    fi

    if sf_should_run_tool "check-email-dns" && [[ -r "${SCRIPT_DIR}/check-email-dns.sh" ]]; then
      chmod +x "${SCRIPT_DIR}/check-email-dns.sh" 2>/dev/null || true
      sf_track_run check-email-dns "${SECFORGE_SESSION_DIR}/emaildns/emaildns.json" 60 "${SECFORGE_SESSION_DIR}/emaildns/emaildns.json" "${SCRIPT_DIR}/check-email-dns.sh" "${SECFORGE_TARGET_HOST}"
    fi

    # Built-in web checks (zero-dep, ~5s, catches .env/.git/headers/cookies)
    if sf_should_run_tool "secforge-builtin" && [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
      _SF_TOOLS_RUN+=("secforge-builtin")
      ((_sf_tool_index++)) || true
      sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"secforge-builtin\",\"index\":${_sf_tool_index}}"
      local _builtin_start="$(date +%s)"
      sf_builtin_web_checks "${SECFORGE_TARGET_URL%/}" "${SECFORGE_SESSION_DIR}/webapp/builtin.json" "${SECFORGE_SCAN_DELAY_MS:-200}"
      local _builtin_dur=$(( $(date +%s) - _builtin_start ))
      _SF_TOOL_DURATIONS+=("secforge-builtin:${_builtin_dur}")
      if [[ ! -s "${SECFORGE_SESSION_DIR}/webapp/builtin.json" ]]; then
        _SF_TOOLS_FAILED+=("secforge-builtin")
        sf_emit_dashboard_event "{\"event\":\"tool_fail\",\"tool\":\"secforge-builtin\",\"index\":${_sf_tool_index},\"error\":\"empty output\"}"
      else
        sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"secforge-builtin\",\"index\":${_sf_tool_index},\"duration\":${_builtin_dur},\"findings\":0,\"status\":\"ok\"}"
      fi
    fi
  fi

  # Local Tier 1 hardening snapshot.
  if sf_should_run_tool "lynis" && sf_tool lynis >/dev/null 2>&1; then
    sf_track_run lynis "${SECFORGE_SESSION_DIR}/hardening/lynis.dat" "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/hardening/lynis.stdout" "$(sf_tool lynis)" audit system --no-colors --logfile "${SECFORGE_SESSION_DIR}/hardening/lynis.log" --report-file "${SECFORGE_SESSION_DIR}/hardening/lynis.dat"
  fi

  if sf_should_run_tool "ssh-audit" && sf_tool ssh-audit >/dev/null 2>&1 && [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    sf_track_run ssh-audit "${SECFORGE_SESSION_DIR}/hardening/ssh-audit.json" 60 "${SECFORGE_SESSION_DIR}/hardening/ssh-audit.json" "$(sf_tool ssh-audit)" --json "${SECFORGE_TARGET_HOST}" || true
  fi

  # Write scan manifest before merging
  SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]}")" \
  SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]}")" \
  SF_MANIFEST_TOOL_DURATIONS="$(IFS=,; echo "${_SF_TOOL_DURATIONS[*]}")" \
  SF_MANIFEST_PROFILE="${SECFORGE_STACK_PROFILE:-}" \
  SF_MANIFEST_TIER_MAX="${SECFORGE_TIER_MAX:-1}" \
  sf_write_manifest "${SECFORGE_SESSION_DIR}" "quick"

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

  sf_log "Quick scan complete."
  sf_log "Session folder: ${SECFORGE_SESSION_DIR}"
}

main "$@"
