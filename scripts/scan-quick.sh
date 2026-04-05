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

sf_track_run() {
  # Usage: sf_track_run <tool_name> <check_file> <sf_run_args...>
  # A tool is marked "failed" if: exit code >= 124 (timeout/killed), output missing,
  # or empty output with crash indicators in stderr. Empty output alone = success.
  local tool_name="$1"
  local check_file="$2"
  shift 2
  local _stdout_path="$2"
  _SF_TOOLS_RUN+=("${tool_name}")
  sf_run "$@"
  # 1. Exit code: 124=timeout, 125+=error, 126=cannot invoke, 127=not found, 128+N=signal
  if [[ "${_SF_LAST_EXIT_CODE}" -ge 124 ]]; then
    _SF_TOOLS_FAILED+=("${tool_name}")
  elif [[ ! -e "${check_file}" ]]; then
    # 2. Output file never created → crashed before writing
    _SF_TOOLS_FAILED+=("${tool_name}")
  elif [[ ! -s "${check_file}" ]]; then
    # 3. Empty output — check stderr for crash indicators (empty output alone is valid)
    local _err_log="${_stdout_path}.err"
    if [[ -s "${_err_log}" ]] && grep -qiE '(error|exception|traceback|killed|timeout|segfault|panic|fatal)' "${_err_log}" 2>/dev/null; then
      _SF_TOOLS_FAILED+=("${tool_name}")
    fi
    # else: empty output is valid (tool ran, found nothing)
  fi
}

sf_write_manifest() {
  local session_dir="$1"
  local profile="${2:-quick}"
  local scan_date
  scan_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Build JSON with Python (safe for arbitrary tool names)
  python3 - "${session_dir}" "${profile}" "${scan_date}" <<'PYEOF'
import json, sys, os
session_dir = sys.argv[1]
profile = sys.argv[2]
scan_date = sys.argv[3]
tools_run = os.environ.get("SF_MANIFEST_TOOLS_RUN", "").split(",")
tools_failed = os.environ.get("SF_MANIFEST_TOOLS_FAILED", "").split(",")
tools_run = [t for t in tools_run if t]
tools_failed = [t for t in tools_failed if t]
manifest = {
    "tools_run": sorted(set(tools_run)),
    "tools_failed": sorted(set(tools_failed)),
    "scan_date": scan_date,
    "profile": profile,
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
    # Write partial manifest on early exit (Ctrl+C, crash, etc.)
    if [[ -n "${SECFORGE_SESSION_DIR:-}" ]] && [[ ! -f "${SECFORGE_SESSION_DIR}/scan_manifest.json" ]]; then
      SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]:-}")" \
      SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]:-}")" \
      sf_write_manifest "${SECFORGE_SESSION_DIR}" "quick" 2>/dev/null || true
    fi
  ' EXIT
  if ! "${SCRIPT_DIR}/preflight.sh" --target "${target}" --profile "quick" --require-tools "curl,jq" >"${_pf_tmp}"; then
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

  local timeout_web timeout_portscan
  timeout_web="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_WEB_SECONDS" || true)"
  timeout_portscan="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "TIMEOUT_PORTSCAN_SECONDS" || true)"
  timeout_web="${timeout_web:-600}"
  timeout_portscan="${timeout_portscan:-1800}"

  sf_log "Session: ${SECFORGE_SESSION_ID}"
  sf_log "Reports: ${SECFORGE_SESSION_DIR}"

  # Tier 1 only.
  if [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    if sf_tool wafw00f >/dev/null 2>&1; then
      sf_track_run wafw00f "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/wafw00f.log" "$(sf_tool wafw00f)" "${SECFORGE_TARGET_URL}" -f json -o "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json"
    fi

    if sf_tool whatweb >/dev/null 2>&1; then
      sf_track_run whatweb "${SECFORGE_SESSION_DIR}/webapp/whatweb.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/whatweb.log" "$(sf_tool whatweb)" "${SECFORGE_TARGET_URL}" "--log-json=${SECFORGE_SESSION_DIR}/webapp/whatweb.json"
    fi

    if sf_tool nuclei >/dev/null 2>&1; then
      local _nuclei_tpl="${SECFORGE_ROOT}/tools/nuclei-templates"
      if [[ -d "${_nuclei_tpl}" ]]; then
        sf_track_run nuclei "${SECFORGE_SESSION_DIR}/webapp/nuclei.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/nuclei.log" "$(sf_tool nuclei)" -duc -u "${SECFORGE_TARGET_URL}" -t "${_nuclei_tpl}" -json-export "${SECFORGE_SESSION_DIR}/webapp/nuclei.json"
      else
        sf_warn "Nuclei templates not found at ${_nuclei_tpl}. Skipping nuclei."
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

      sf_track_run nmap "${SECFORGE_SESSION_DIR}/network/nmap.xml" "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/network/nmap.log" "$(sf_tool nmap)" "${nmap_timing}" -sV -sC --top-ports "${nmap_top}" -oX "${SECFORGE_SESSION_DIR}/network/nmap.xml" "${SECFORGE_TARGET_HOST}"
    fi

    if sf_tool testssl.sh >/dev/null 2>&1; then
      local ssl_target="${SECFORGE_TARGET_HOST}"
      if [[ -n "${SECFORGE_TARGET_PORT}" ]]; then
        ssl_target="${ssl_target}:${SECFORGE_TARGET_PORT}"
      fi
      sf_track_run testssl "${SECFORGE_SESSION_DIR}/ssl/testssl.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/ssl/testssl.log" "$(sf_tool testssl.sh)" --jsonfile "${SECFORGE_SESSION_DIR}/ssl/testssl.json" "${ssl_target}"
    fi

    if [[ -r "${SCRIPT_DIR}/check-email-dns.sh" ]]; then
      chmod +x "${SCRIPT_DIR}/check-email-dns.sh" 2>/dev/null || true
      sf_track_run emaildns "${SECFORGE_SESSION_DIR}/emaildns/emaildns.json" 60 "${SECFORGE_SESSION_DIR}/emaildns/emaildns.json" "${SCRIPT_DIR}/check-email-dns.sh" "${SECFORGE_TARGET_HOST}"
    fi
  fi

  # Local Tier 1 hardening snapshot.
  if sf_tool lynis >/dev/null 2>&1; then
    sf_track_run lynis "${SECFORGE_SESSION_DIR}/hardening/lynis.dat" "${timeout_portscan}" "${SECFORGE_SESSION_DIR}/hardening/lynis.stdout" "$(sf_tool lynis)" audit system --no-colors --logfile "${SECFORGE_SESSION_DIR}/hardening/lynis.log" --report-file "${SECFORGE_SESSION_DIR}/hardening/lynis.dat"
  fi

  if sf_tool ssh-audit >/dev/null 2>&1 && [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
    sf_track_run ssh-audit "${SECFORGE_SESSION_DIR}/hardening/ssh-audit.json" 60 "${SECFORGE_SESSION_DIR}/hardening/ssh-audit.json" "$(sf_tool ssh-audit)" --json "${SECFORGE_TARGET_HOST}" || true
  fi

  # Write scan manifest before merging
  SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]}")" \
  SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]}")" \
  sf_write_manifest "${SECFORGE_SESSION_DIR}" "quick"

  if [[ -r "${SCRIPT_DIR}/merge-reports.py" ]]; then
    sf_log "Merging reports..."
    python3 "${SCRIPT_DIR}/merge-reports.py" "${SECFORGE_SESSION_DIR}" || sf_warn "merge-reports.py failed (continuing)."
  else
    sf_warn "merge-reports.py not available yet (Phase 4)."
  fi

  sf_log "Quick scan complete."
  sf_log "Session folder: ${SECFORGE_SESSION_DIR}"
}

main "$@"
