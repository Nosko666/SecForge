#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"

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

  sf_log "Installing Category: Payment / PCI Compliance"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "compliance"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"

  # Lynis (git clone)
  sf_git_clone_or_update "https://github.com/CISOfy/lynis.git" "${SECFORGE_ROOT}/tools/lynis"
  if [[ -x "${SECFORGE_ROOT}/tools/lynis/lynis" ]]; then
    sf_ln_sf "${SECFORGE_ROOT}/tools/lynis/lynis" "${SECFORGE_ROOT}/bin/lynis"
  fi
  mark_tool_if_present "lynis" "${SECFORGE_ROOT}/bin/lynis"

  # OpenSCAP tooling (oscap)
  sf_apt_install openscap-scanner openscap-utils
  if command -v oscap >/dev/null 2>&1; then
    sf_ln_sf "$(command -v oscap)" "${SECFORGE_ROOT}/bin/oscap"
    mark_tool_if_present "oscap" "${SECFORGE_ROOT}/bin/oscap"
  else
    sf_warn "oscap not found after install; OpenSCAP checks may be unavailable."
  fi
}

main "$@"

