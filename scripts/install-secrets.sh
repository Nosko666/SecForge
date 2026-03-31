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

  sf_log "Installing Category: Secrets & Key Detection (${SECFORGE_PROFILE})"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "secrets"

  mkdir -p "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  sf_install_github_release_binary "trufflesecurity/trufflehog" "trufflehog" "${SECFORGE_ROOT}/bin/trufflehog" || sf_warn "Failed to install trufflehog"
  mark_tool_if_present "trufflehog" "${SECFORGE_ROOT}/bin/trufflehog"

  sf_install_github_release_binary "gitleaks/gitleaks" "gitleaks" "${SECFORGE_ROOT}/bin/gitleaks" || sf_warn "Failed to install gitleaks"
  mark_tool_if_present "gitleaks" "${SECFORGE_ROOT}/bin/gitleaks"

  if [[ "${SECFORGE_PROFILE}" == "essential" ]]; then
    return 0
  fi

  sf_install_venv_packages "${SECFORGE_VENV}" apkleaks || sf_warn "Failed to install apkleaks"
  if [[ -x "${SECFORGE_VENV}/bin/apkleaks" ]]; then
    sf_ln_sf "${SECFORGE_VENV}/bin/apkleaks" "${SECFORGE_ROOT}/bin/apkleaks"
  fi
  mark_tool_if_present "apkleaks" "${SECFORGE_ROOT}/bin/apkleaks"
}

main "$@"

