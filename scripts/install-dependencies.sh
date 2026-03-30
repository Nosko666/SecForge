#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_VENV="${SECFORGE_VENV:-${SECFORGE_ROOT}/venv}"
SECFORGE_PROFILE="${SECFORGE_INSTALL_PROFILE:-full}" # full|essential

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

  sf_log "Installing Category: Dependency & Supply Chain (${SECFORGE_PROFILE})"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "dependencies"

  mkdir -p "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  sf_install_github_release_binary "google/osv-scanner" "osv-scanner" "${SECFORGE_ROOT}/bin/osv-scanner" || sf_warn "Failed to install osv-scanner"
  mark_tool_if_present "osv-scanner" "${SECFORGE_ROOT}/bin/osv-scanner"

  if [[ "${SECFORGE_PROFILE}" == "essential" ]]; then
    return 0
  fi

  sf_install_venv_packages "${SECFORGE_VENV}" pip-audit || sf_warn "Failed to install pip-audit"
  if [[ -x "${SECFORGE_VENV}/bin/pip-audit" ]]; then
    sf_ln_sf "${SECFORGE_VENV}/bin/pip-audit" "${SECFORGE_ROOT}/bin/pip-audit"
  fi
  mark_tool_if_present "pip-audit" "${SECFORGE_ROOT}/bin/pip-audit"
}

main "$@"

