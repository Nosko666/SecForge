#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SECFORGE_ROOT="${SECFORGE_ROOT:-$DEFAULT_ROOT}"
SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE:-${SECFORGE_ROOT}/config/secforge.conf}"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

sf_usage() {
  cat >&2 <<EOF
Usage:
  ${0##*/} --target <domain|url> [--profile <name>] [--require-tools <csv>] [--session-id <id>]

Outputs shell exports on stdout (safe to source), logs on stderr.
EOF
}

sf_parse_target() {
  local input="$1"
  python3 - "$input" <<'PY'
import json
import sys
from urllib.parse import urlparse

raw = sys.argv[1].strip()
if raw.lower() in ("this server", "this_server", "local", "localhost"):
    print(json.dumps({"raw": raw, "kind": "local", "url": "", "base_url": "", "host": "this_server", "port": ""}))
    raise SystemExit(0)

if not raw.startswith(("http://", "https://")):
    raw = "https://" + raw

u = urlparse(raw)
host = u.hostname or ""
port = str(u.port or "")

base_url = f"{u.scheme}://{u.netloc}" if host else raw

print(json.dumps({
  "raw": sys.argv[1],
  "kind": "url",
  "url": raw,
  "base_url": base_url,
  "host": host,
  "port": port,
}))
PY
}

sf_disclaimer_banner() {
  cat >&2 <<'EOF'
============================================================
 SecForge — Authorized Security Testing Only
 Only scan systems you own or have written permission to test.
============================================================
EOF
}

sf_require_authorization() {
  local target_key="$1"
  local auth_file="$2"

  sf_disclaimer_banner

  if [[ ! -e "${auth_file}" ]]; then
    sf_warn "Authorization cache missing: ${auth_file}"
    sf_warn "Run the installer again or create it (root) and ensure it's group-writable."
    return 1
  fi

  if grep -Fqx "${target_key}" "${auth_file}" 2>/dev/null; then
    return 0
  fi

  sf_warn "First time scanning: ${target_key}"
  sf_warn "To continue, you must confirm you own/are authorized to test this target."
  if ! sf_ask_tty_yes "Type YES to confirm authorization:" "YES"; then
    sf_die "Authorization not confirmed. Aborting."
  fi

  printf '%s\n' "${target_key}" >>"${auth_file}"
}

sf_dns_resolves() {
  local host="$1"
  if [[ "${host}" == "this_server" ]]; then
    return 0
  fi
  if sf_has_cmd getent; then
    getent ahosts "${host}" >/dev/null 2>&1 && return 0
  fi
  if sf_has_cmd dig; then
    dig +short "${host}" 2>/dev/null | head -n1 | grep -q . && return 0
  fi
  return 1
}

sf_http_baseline() {
  local url="$1"
  local timeout_s="${2:-10}"

  if [[ -z "${url}" ]]; then
    echo ""
    return 0
  fi

  # Return: "<http_code> <time_total>"
  curl -fsS -o /dev/null \
    --connect-timeout 5 \
    --max-time "${timeout_s}" \
    -w "%{http_code} %{time_total}\n" \
    "${url}" 2>/dev/null || true
}

sf_check_tools() {
  local csv="$1"
  local missing=()
  local tool

  if [[ -z "${csv}" ]]; then
    printf '%s' ""
    return 0
  fi

  IFS=',' read -r -a tools <<<"${csv}"
  for tool in "${tools[@]}"; do
    tool="${tool## }"
    tool="${tool%% }"
    [[ -z "${tool}" ]] && continue

    if [[ -x "${SECFORGE_ROOT}/bin/${tool}" ]]; then
      continue
    fi
    if command -v "${tool}" >/dev/null 2>&1; then
      continue
    fi
    missing+=("${tool}")
  done

  if [[ "${#missing[@]}" -gt 0 ]]; then
    printf '%s' "${missing[*]}"
  else
    printf '%s' ""
  fi
}

main() {
  local target="" profile="" require_tools="" session_id=""

  while [[ "${#}" -gt 0 ]]; do
    case "$1" in
      --target) target="${2:-}"; shift 2 ;;
      --profile) profile="${2:-}"; shift 2 ;;
      --require-tools) require_tools="${2:-}"; shift 2 ;;
      --session-id) session_id="${2:-}"; shift 2 ;;
      -h|--help) sf_usage; exit 0 ;;
      *) sf_warn "Unknown argument: $1"; sf_usage; exit 2 ;;
    esac
  done

  if [[ -z "${target}" ]]; then
    sf_usage
    exit 2
  fi

  local auth_file scan_delay_ms max_concurrent threshold cooldown
  auth_file="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "AUTHORIZED_TARGETS_FILE" || true)"
  auth_file="${auth_file:-${SECFORGE_ROOT}/config/.authorized_targets}"
  scan_delay_ms="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "SCAN_DELAY_MS" || true)"
  max_concurrent="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "MAX_CONCURRENT_TOOLS" || true)"
  threshold="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "CIRCUIT_BREAKER_THRESHOLD_SECONDS" || true)"
  cooldown="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "CIRCUIT_BREAKER_COOLDOWN_SECONDS" || true)"
  scan_delay_ms="${scan_delay_ms:-200}"
  max_concurrent="${max_concurrent:-3}"
  threshold="${threshold:-10}"
  cooldown="${cooldown:-30}"

  local parsed kind url base_url host port
  parsed="$(sf_parse_target "${target}")"
  kind="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["kind"])' <<<"${parsed}")"
  url="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["url"])' <<<"${parsed}")"
  base_url="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["base_url"])' <<<"${parsed}")"
  host="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["host"])' <<<"${parsed}")"
  port="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["port"])' <<<"${parsed}")"

  if [[ -z "${host}" ]]; then
    sf_die "Could not parse target host from: ${target}"
  fi

  sf_require_authorization "${host}" "${auth_file}"

  if ! sf_dns_resolves "${host}"; then
    sf_die "DNS resolution failed for ${host}."
  fi

  local baseline http_code latency_s
  baseline="$(sf_http_baseline "${base_url}")"
  http_code="$(awk '{print $1}' <<<"${baseline}" || true)"
  latency_s="$(awk '{print $2}' <<<"${baseline}" || true)"
  http_code="${http_code:-}"
  latency_s="${latency_s:-}"

  if [[ -n "${base_url}" && ( -z "${http_code}" || "${http_code}" == "000" ) ]]; then
    sf_warn "HTTP connectivity check failed for ${base_url}. Continuing, but web scanners may fail."
  fi

  if [[ -z "${session_id}" ]]; then
    local ts safe_host
    ts="$(date -u +'%Y-%m-%d_%H%M%S')"
    safe_host="$(printf '%s' "${host}" | tr -cd 'A-Za-z0-9._-' | sed 's/^\\.\\+//')"
    session_id="${ts}_${safe_host}"
  fi

  local reports_root session_dir
  reports_root="${SECFORGE_ROOT}/reports"
  session_dir="${reports_root}/${session_id}"

  mkdir -p "${session_dir}"
  mkdir -p \
    "${session_dir}/webapp" \
    "${session_dir}/api" \
    "${session_dir}/network" \
    "${session_dir}/ssl" \
    "${session_dir}/passwords" \
    "${session_dir}/secrets" \
    "${session_dir}/mobile" \
    "${session_dir}/compliance" \
    "${session_dir}/hardening" \
	    "${session_dir}/dependencies" \
	    "${session_dir}/emaildns" \
	    "${session_dir}/database" \
	    "${session_dir}/containers" \
	    "${session_dir}/iac" \
	    "${session_dir}/cloud"

  if [[ -d "${reports_root}" ]]; then
    # Global latest (may fail for non-root due to sticky bit — that's safe).
    (cd "${reports_root}" && ln -sfn "${session_id}" latest) >/dev/null 2>&1 || true
    # Per-user latest (always succeeds for the scan user).
    local _sf_user
    _sf_user="$(whoami 2>/dev/null || id -un 2>/dev/null || echo "uid$(id -u)")"
    _sf_user="$(printf '%s' "${_sf_user}" | tr -cd 'A-Za-z0-9._-')"
    if [[ -n "${_sf_user}" ]]; then
      (cd "${reports_root}" && ln -sfn "${session_id}" "latest-${_sf_user}") >/dev/null 2>&1 || true
    fi
  fi

  local missing_tools
  missing_tools="$(sf_check_tools "${require_tools}")"
  if [[ -n "${missing_tools}" ]]; then
    sf_warn "Missing required tools: ${missing_tools}"
  fi

  # Save a machine-readable snapshot.
  local now
  now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  SF_NOW="${now}" \
  SF_TARGET_INPUT="${target}" \
  SF_TARGET_KIND="${kind}" \
  SF_TARGET_URL="${base_url}" \
  SF_TARGET_FULL_URL="${url}" \
  SF_TARGET_HOST="${host}" \
  SF_TARGET_PORT="${port}" \
  SF_PROFILE="${profile}" \
  SF_HTTP_CODE="${http_code}" \
  SF_LATENCY_SECONDS="${latency_s}" \
  SF_SCAN_DELAY_MS="${scan_delay_ms}" \
  SF_MAX_CONCURRENT="${max_concurrent}" \
  SF_CB_THRESHOLD="${threshold}" \
  SF_CB_COOLDOWN="${cooldown}" \
  SF_MISSING_TOOLS="${missing_tools}" \
  SF_PREFLIGHT_PATH="${session_dir}/preflight.json" \
  python3 - <<'PY'
import json
import os

def int_or_none(s):
  try:
    return int(s)
  except Exception:
    return None

data = {
  "timestamp_utc": os.environ.get("SF_NOW", ""),
  "target_input": os.environ.get("SF_TARGET_INPUT", ""),
  "target_kind": os.environ.get("SF_TARGET_KIND", ""),
  "target_url": os.environ.get("SF_TARGET_URL", ""),
  "target_full_url": os.environ.get("SF_TARGET_FULL_URL", ""),
  "target_host": os.environ.get("SF_TARGET_HOST", ""),
  "target_port": os.environ.get("SF_TARGET_PORT", ""),
  "profile": os.environ.get("SF_PROFILE", ""),
  "baseline": {
    "http_code": os.environ.get("SF_HTTP_CODE", ""),
    "latency_seconds": os.environ.get("SF_LATENCY_SECONDS", ""),
  },
  "config": {
    "scan_delay_ms": int_or_none(os.environ.get("SF_SCAN_DELAY_MS", "")),
    "max_concurrent_tools": int_or_none(os.environ.get("SF_MAX_CONCURRENT", "")),
    "circuit_breaker_threshold_seconds": int_or_none(os.environ.get("SF_CB_THRESHOLD", "")),
    "circuit_breaker_cooldown_seconds": int_or_none(os.environ.get("SF_CB_COOLDOWN", "")),
  },
  "missing_required_tools": [t for t in os.environ.get("SF_MISSING_TOOLS", "").split() if t],
}

out_path = os.environ.get("SF_PREFLIGHT_PATH", "")
if out_path:
  with open(out_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True)
PY

  # Safe exports for callers (stdout only).
  # Use declare -p with an explicit allowlist to avoid shell injection.
  # Every variable MUST be set before declare -p is called.
  export SECFORGE_ROOT="${SECFORGE_ROOT}"
  export SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE}"
  export SECFORGE_SESSION_ID="${session_id}"
  export SECFORGE_SESSION_DIR="${session_dir}"
  export SECFORGE_TARGET_INPUT="${target}"
  export SECFORGE_TARGET_URL="${base_url}"
  export SECFORGE_TARGET_FULL_URL="${url}"
  export SECFORGE_TARGET_HOST="${host}"
  export SECFORGE_TARGET_PORT="${port}"
  export SECFORGE_SCAN_DELAY_MS="${scan_delay_ms}"
  export SECFORGE_MAX_CONCURRENT_TOOLS="${max_concurrent}"
  export SECFORGE_CIRCUIT_BREAKER_THRESHOLD_SECONDS="${threshold}"
  export SECFORGE_CIRCUIT_BREAKER_COOLDOWN_SECONDS="${cooldown}"
  export SECFORGE_MISSING_TOOLS="${missing_tools}"

  local _sf_var
  for _sf_var in \
    SECFORGE_ROOT SECFORGE_CONFIG_FILE SECFORGE_SESSION_ID SECFORGE_SESSION_DIR \
    SECFORGE_TARGET_INPUT SECFORGE_TARGET_URL SECFORGE_TARGET_FULL_URL \
    SECFORGE_TARGET_HOST SECFORGE_TARGET_PORT \
    SECFORGE_SCAN_DELAY_MS SECFORGE_MAX_CONCURRENT_TOOLS \
    SECFORGE_CIRCUIT_BREAKER_THRESHOLD_SECONDS SECFORGE_CIRCUIT_BREAKER_COOLDOWN_SECONDS \
    SECFORGE_MISSING_TOOLS; do
    declare -p "${_sf_var}" 2>/dev/null || true
  done
}

main "$@"
