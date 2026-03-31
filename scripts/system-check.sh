#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SECFORGE_ROOT="${SECFORGE_ROOT:-$DEFAULT_ROOT}"
SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE:-${SECFORGE_ROOT}/config/secforge.conf}"
SECFORGE_GROUP="${SECFORGE_GROUP:-secforge}"

# shellcheck source=/dev/null
if [[ -r "${SCRIPT_DIR}/_lib.sh" ]]; then
  . "${SCRIPT_DIR}/_lib.sh"
else
  sf_log() { printf '[secforge] %s\n' "$*"; }
  sf_warn() { printf '[secforge] WARN: %s\n' "$*" >&2; }
  sf_has_cmd() { command -v "$1" >/dev/null 2>&1; }
  sf_detect_arch() {
    case "$(uname -m)" in
      x86_64) printf 'amd64' ;;
      aarch64 | arm64) printf 'arm64' ;;
      *) printf 'unknown' ;;
    esac
  }
  sf_python_major_minor() { python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo ""; }
  sf_cfg_get_value() { return 1; }
fi

sf_safe_cmd_output() {
  local cmd="$1"
  shift || true
  if ! sf_has_cmd "${cmd}"; then
    return 0
  fi
  "${cmd}" "$@" 2>/dev/null | head -n 1 || true
}

sf_bytes_from_free() {
  if ! sf_has_cmd free; then
    echo ""
    return 0
  fi
  free -b 2>/dev/null | awk '/^Mem:/ {print $2" " $7; exit}' || true
}

sf_bytes_from_df() {
  local path="$1"
  if ! sf_has_cmd df; then
    echo ""
    return 0
  fi
  df -B1 "${path}" 2>/dev/null | awk 'NR==2 {print $2" " $4; exit}' || true
}

sf_dir_writable() {
  local dir_path="$1"
  if [[ ! -d "${dir_path}" ]]; then
    return 1
  fi
  if [[ ! -w "${dir_path}" ]]; then
    return 1
  fi
  local test_file="${dir_path}/.secforge_write_test.$$"
  ( : >"${test_file}" ) 2>/dev/null || return 1
  rm -f "${test_file}" >/dev/null 2>&1 || true
  return 0
}

main() {
  local now os_pretty os_id os_version
  now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  os_pretty=""
  os_id=""
  os_version=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    os_pretty="${PRETTY_NAME:-}"
    os_id="${ID:-}"
    os_version="${VERSION_ID:-}"
  fi

  local arch_norm arch_raw kernel
  arch_norm="$(sf_detect_arch)"
  arch_raw="$(uname -m 2>/dev/null || true)"
  kernel="$(uname -sr 2>/dev/null || true)"

  local python_ver python_mm node_ver npm_ver docker_ver docker_access go_ver git_rev
  python_ver="$(sf_safe_cmd_output python3 --version | sed 's/^Python //')"
  python_mm="$(sf_python_major_minor)"
  node_ver="$(sf_safe_cmd_output node --version | sed 's/^v//')"
  npm_ver="$(sf_safe_cmd_output npm --version)"
  docker_ver="$(sf_safe_cmd_output docker --version)"
  docker_access="unknown"
  if sf_has_cmd docker; then
    if docker ps >/dev/null 2>&1; then
      docker_access="ok"
    else
      docker_access="no_access"
    fi
  fi
  go_ver="$(sf_safe_cmd_output go version)"

  git_rev=""
  if sf_has_cmd git && [[ -d "${SECFORGE_ROOT}/.git" ]]; then
    git_rev="$(git -C "${SECFORGE_ROOT}" rev-parse --short HEAD 2>/dev/null || true)"
  fi

  local mem_bytes disk_bytes
  mem_bytes="$(sf_bytes_from_free)"
  disk_bytes="$(sf_bytes_from_df "${SECFORGE_ROOT}")"
  local mem_total mem_avail disk_total disk_avail
  mem_total=""
  mem_avail=""
  disk_total=""
  disk_avail=""
  if [[ -n "${mem_bytes}" ]]; then
    mem_total="$(awk '{print $1}' <<<"${mem_bytes}")"
    mem_avail="$(awk '{print $2}' <<<"${mem_bytes}")"
  fi
  if [[ -n "${disk_bytes}" ]]; then
    disk_total="$(awk '{print $1}' <<<"${disk_bytes}")"
    disk_avail="$(awk '{print $2}' <<<"${disk_bytes}")"
  fi

  local cfg_categories cfg_tools
  cfg_categories="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "INSTALLED_CATEGORIES" || true)"
  cfg_tools="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "INSTALLED_TOOLS" || true)"

  local in_group
  in_group="false"
  if id -nG 2>/dev/null | tr ' ' '\n' | grep -qx "${SECFORGE_GROUP}"; then
    in_group="true"
  fi

  local can_write_reports
  can_write_reports="false"
  if sf_dir_writable "${SECFORGE_ROOT}/reports"; then
    can_write_reports="true"
  fi

  SF_NOW="${now}" \
  SF_ROOT="${SECFORGE_ROOT}" \
  SF_CONFIG_FILE="${SECFORGE_CONFIG_FILE}" \
  SF_GIT_REV="${git_rev}" \
  SF_OS_PRETTY="${os_pretty}" \
  SF_OS_ID="${os_id}" \
  SF_OS_VERSION_ID="${os_version}" \
  SF_KERNEL="${kernel}" \
  SF_ARCH_RAW="${arch_raw}" \
  SF_ARCH_NORM="${arch_norm}" \
  SF_PYTHON_VER="${python_ver}" \
  SF_PYTHON_MM="${python_mm}" \
  SF_NODE_VER="${node_ver}" \
  SF_NPM_VER="${npm_ver}" \
  SF_DOCKER_VER="${docker_ver}" \
  SF_DOCKER_ACCESS="${docker_access}" \
  SF_GO_VER="${go_ver}" \
  SF_MEM_TOTAL="${mem_total}" \
  SF_MEM_AVAIL="${mem_avail}" \
  SF_DISK_TOTAL="${disk_total}" \
  SF_DISK_AVAIL="${disk_avail}" \
  SF_IN_GROUP="${in_group}" \
  SF_CAN_WRITE_REPORTS="${can_write_reports}" \
  SF_CATEGORIES="${cfg_categories}" \
  SF_TOOLS="${cfg_tools}" \
  python3 - <<'PY'
import json
import os

def int_or_none(s: str):
  try:
    return int(s)
  except Exception:
    return None

data = {
  "timestamp_utc": os.environ.get("SF_NOW", ""),
  "secforge_root": os.environ.get("SF_ROOT", ""),
  "secforge_config_file": os.environ.get("SF_CONFIG_FILE", ""),
  "git_rev": os.environ.get("SF_GIT_REV", ""),
  "os": {
    "pretty_name": os.environ.get("SF_OS_PRETTY", ""),
    "id": os.environ.get("SF_OS_ID", ""),
    "version_id": os.environ.get("SF_OS_VERSION_ID", ""),
    "kernel": os.environ.get("SF_KERNEL", ""),
  },
  "arch": {
    "raw": os.environ.get("SF_ARCH_RAW", ""),
    "normalized": os.environ.get("SF_ARCH_NORM", ""),
  },
  "versions": {
    "python3": os.environ.get("SF_PYTHON_VER", ""),
    "python3_major_minor": os.environ.get("SF_PYTHON_MM", ""),
    "node": os.environ.get("SF_NODE_VER", ""),
    "npm": os.environ.get("SF_NPM_VER", ""),
    "docker": os.environ.get("SF_DOCKER_VER", ""),
    "docker_access": os.environ.get("SF_DOCKER_ACCESS", "unknown"),
    "go": os.environ.get("SF_GO_VER", ""),
  },
  "resources": {
    "mem_total_bytes": int_or_none(os.environ.get("SF_MEM_TOTAL", "")),
    "mem_available_bytes": int_or_none(os.environ.get("SF_MEM_AVAIL", "")),
    "disk_total_bytes": int_or_none(os.environ.get("SF_DISK_TOTAL", "")),
    "disk_available_bytes": int_or_none(os.environ.get("SF_DISK_AVAIL", "")),
  },
  "permissions": {
    "in_secforge_group": os.environ.get("SF_IN_GROUP", "false") == "true",
    "can_write_reports": os.environ.get("SF_CAN_WRITE_REPORTS", "false") == "true",
  },
  "installed": {
    "categories": [c for c in os.environ.get("SF_CATEGORIES", "").split() if c],
    "tools": [t for t in os.environ.get("SF_TOOLS", "").split() if t],
  },
}
print(json.dumps(data, indent=2, sort_keys=True))
PY
}

main "$@"
