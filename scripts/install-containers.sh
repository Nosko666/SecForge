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

  sf_log "Installing Category: Containers / IaC / Cloud (optional)"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "containers"

  mkdir -p "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  sf_install_github_release_binary "aquasecurity/trivy" "trivy" "${SECFORGE_ROOT}/bin/trivy" || sf_warn "Failed to install trivy"
  mark_tool_if_present "trivy" "${SECFORGE_ROOT}/bin/trivy"

  local py_ver
  py_ver="$(sf_python_major_minor)"

  if sf_version_ge "${py_ver}" "3.9"; then
    sf_install_venv_packages "${SECFORGE_VENV}" checkov || sf_warn "Failed to install checkov (optional)"
    if [[ -x "${SECFORGE_VENV}/bin/checkov" ]]; then
      sf_ln_sf "${SECFORGE_VENV}/bin/checkov" "${SECFORGE_ROOT}/bin/checkov"
      mark_tool_if_present "checkov" "${SECFORGE_ROOT}/bin/checkov"
    fi

    # Prowler supports Python 3.9–3.12 (best-effort). Skip if outside range.
    if sf_version_ge "${py_ver}" "3.9" && sf_version_ge "3.12" "${py_ver}"; then
      sf_install_venv_packages "${SECFORGE_VENV}" prowler || sf_warn "Failed to install prowler (optional)"
      if [[ -x "${SECFORGE_VENV}/bin/prowler" ]]; then
        sf_ln_sf "${SECFORGE_VENV}/bin/prowler" "${SECFORGE_ROOT}/bin/prowler"
        mark_tool_if_present "prowler" "${SECFORGE_ROOT}/bin/prowler"
      fi
    else
      sf_warn "Skipping prowler (optional; supports Python 3.9–3.12; found ${py_ver})."
    fi
  else
    sf_warn "Skipping Checkov/Prowler (optional; require Python >= 3.9; found ${py_ver})."
  fi
}

main "$@"

