#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_VENV="${SECFORGE_VENV:-${SECFORGE_ROOT}/venv}"
SECFORGE_VULNAPI_REPO="${SECFORGE_VULNAPI_REPO:-cerberauth/vulnapi}"

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

  sf_log "Installing Category: API Security"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "api"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  # jwt_tool (git clone)
  sf_git_clone_or_update "https://github.com/ticarpi/jwt_tool.git" "${SECFORGE_ROOT}/tools/jwt_tool"
  if [[ -r "${SECFORGE_ROOT}/tools/jwt_tool/jwt_tool.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/jwt_tool" <<EOF
#!/usr/bin/env bash
exec "${SECFORGE_VENV}/bin/python" "${SECFORGE_ROOT}/tools/jwt_tool/jwt_tool.py" "\$@"
EOF
    chmod 0755 "${SECFORGE_ROOT}/bin/jwt_tool"
  fi
  mark_tool_if_present "jwt_tool" "${SECFORGE_ROOT}/bin/jwt_tool"

  # Install jwt_tool dependencies into venv (best-effort)
  if [[ -r "${SECFORGE_ROOT}/tools/jwt_tool/requirements.txt" ]]; then
    sf_install_venv_packages "${SECFORGE_VENV}" -r "${SECFORGE_ROOT}/tools/jwt_tool/requirements.txt" || sf_warn "jwt_tool dependency install failed (continuing)."
  fi

  # Kiterunner (kr)
  sf_install_github_release_binary "assetnote/kiterunner" "kr" "${SECFORGE_ROOT}/bin/kr" || sf_warn "Failed to install kiterunner (kr)"
  mark_tool_if_present "kiterunner" "${SECFORGE_ROOT}/bin/kr"

  # Interactsh client
  sf_install_github_release_binary "projectdiscovery/interactsh" "interactsh-client" "${SECFORGE_ROOT}/bin/interactsh-client" || sf_warn "Failed to install interactsh-client"
  mark_tool_if_present "interactsh-client" "${SECFORGE_ROOT}/bin/interactsh-client"

  # VulnAPI (default repo can be overridden via SECFORGE_VULNAPI_REPO)
  sf_install_github_release_binary "${SECFORGE_VULNAPI_REPO}" "vulnapi" "${SECFORGE_ROOT}/bin/vulnapi" || sf_warn "Failed to install vulnapi"
  mark_tool_if_present "vulnapi" "${SECFORGE_ROOT}/bin/vulnapi"
}

main "$@"
