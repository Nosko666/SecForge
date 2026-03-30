#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_PROFILE="${SECFORGE_INSTALL_PROFILE:-full}" # full|essential

cfg_file="${SECFORGE_ROOT}/config/secforge.conf"

mark_tool_if_cmd_exists() {
  local tool_name="$1"
  local cmd_name="$2"
  if command -v "${cmd_name}" >/dev/null 2>&1; then
    sf_cfg_add_list_item "${cfg_file}" "INSTALLED_TOOLS" "${tool_name}"
    sf_ln_sf "$(command -v "${cmd_name}")" "${SECFORGE_ROOT}/bin/${cmd_name}"
  fi
}

main() {
  sf_need_root
  sf_require_ubuntu

  sf_log "Installing Category: Network Scanning (${SECFORGE_PROFILE})"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "network"

  mkdir -p "${SECFORGE_ROOT}/bin"

  if [[ "${SECFORGE_PROFILE}" == "essential" ]]; then
    sf_apt_install nmap
    mark_tool_if_cmd_exists "nmap" "nmap"
    return 0
  fi

  sf_apt_install nmap masscan netcat-openbsd
  mark_tool_if_cmd_exists "nmap" "nmap"
  mark_tool_if_cmd_exists "masscan" "masscan"
  mark_tool_if_cmd_exists "netcat" "nc"
}

main "$@"

