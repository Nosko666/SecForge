#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_VENV="${SECFORGE_VENV:-${SECFORGE_ROOT}/venv}"

cfg_file="${SECFORGE_ROOT}/config/secforge.conf"

mark_tool_if_present() {
  local tool_name="$1"
  local tool_path="$2"
  if [[ -e "${tool_path}" ]]; then
    sf_cfg_add_list_item "${cfg_file}" "INSTALLED_TOOLS" "${tool_name}"
  fi
}

main() {
  sf_need_root
  sf_require_ubuntu

  sf_log "Installing Category: Email/DNS Security"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "emaildns"

  mkdir -p "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  sf_apt_install dnsutils

  sf_install_github_release_binary "projectdiscovery/subfinder" "subfinder" "${SECFORGE_ROOT}/bin/subfinder" || sf_warn "Failed to install subfinder"
  mark_tool_if_present "subfinder" "${SECFORGE_ROOT}/bin/subfinder"

  sf_install_github_release_binary "projectdiscovery/httpx" "httpx" "${SECFORGE_ROOT}/bin/httpx" || sf_warn "Failed to install httpx"
  mark_tool_if_present "httpx" "${SECFORGE_ROOT}/bin/httpx"

  # dnsrecon is optional and upstream Python requirements can be strict; best-effort only.
  local py_ver
  py_ver="$(sf_python_major_minor)"
  if sf_version_ge "${py_ver}" "3.12"; then
    sf_install_venv_packages "${SECFORGE_VENV}" dnsrecon || sf_warn "Failed to install dnsrecon"
    if [[ -x "${SECFORGE_VENV}/bin/dnsrecon" ]]; then
      sf_ln_sf "${SECFORGE_VENV}/bin/dnsrecon" "${SECFORGE_ROOT}/bin/dnsrecon"
      mark_tool_if_present "dnsrecon" "${SECFORGE_ROOT}/bin/dnsrecon"
    fi
  else
    sf_warn "Skipping dnsrecon (optional; requires Python >= 3.12; found ${py_ver})."
  fi
}

main "$@"

