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

  sf_log "Installing Category: Password & Auth Testing"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "passwords"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  sf_apt_install hydra john hashcat

  if command -v hydra >/dev/null 2>&1; then
    sf_ln_sf "$(command -v hydra)" "${SECFORGE_ROOT}/bin/hydra"
  fi
  mark_tool_if_present "hydra" "${SECFORGE_ROOT}/bin/hydra"

  if command -v john >/dev/null 2>&1; then
    sf_ln_sf "$(command -v john)" "${SECFORGE_ROOT}/bin/john"
  fi
  mark_tool_if_present "john" "${SECFORGE_ROOT}/bin/john"

  if command -v hashcat >/dev/null 2>&1; then
    sf_ln_sf "$(command -v hashcat)" "${SECFORGE_ROOT}/bin/hashcat"
  fi
  mark_tool_if_present "hashcat" "${SECFORGE_ROOT}/bin/hashcat"

  # NetExec (best-effort). Upstream packaging varies; we clone + try to install into the venv.
  sf_git_clone_or_update "https://github.com/Pennyw0rth/NetExec.git" "${SECFORGE_ROOT}/tools/netexec"
  if [[ -d "${SECFORGE_ROOT}/tools/netexec" ]]; then
    sf_log "Attempting to install NetExec into venv (best-effort)..."
    "${SECFORGE_VENV}/bin/pip" install -e "${SECFORGE_ROOT}/tools/netexec" >/dev/null 2>&1 || sf_warn "NetExec install failed; leaving repo in tools/netexec for manual setup."
  fi

  if [[ -x "${SECFORGE_VENV}/bin/nxc" ]]; then
    sf_ln_sf "${SECFORGE_VENV}/bin/nxc" "${SECFORGE_ROOT}/bin/nxc"
    mark_tool_if_present "netexec" "${SECFORGE_ROOT}/bin/nxc"
  elif command -v nxc >/dev/null 2>&1; then
    sf_ln_sf "$(command -v nxc)" "${SECFORGE_ROOT}/bin/nxc"
    mark_tool_if_present "netexec" "${SECFORGE_ROOT}/bin/nxc"
  else
    sf_warn "NetExec binary (nxc) not found after install attempt."
  fi
}

main "$@"

