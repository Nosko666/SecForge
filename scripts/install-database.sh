#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"

cfg_file="${SECFORGE_ROOT}/config/secforge.conf"

main() {
  sf_need_root
  sf_require_ubuntu

  sf_log "Installing Category: Database Security (MySQL client)"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "database"

  mkdir -p "${SECFORGE_ROOT}/bin"
  sf_apt_install default-mysql-client

  if command -v mysql >/dev/null 2>&1; then
    sf_ln_sf "$(command -v mysql)" "${SECFORGE_ROOT}/bin/mysql"
    sf_cfg_add_list_item "${cfg_file}" "INSTALLED_TOOLS" "mysql-client"
  else
    sf_warn "mysql client not found after install."
  fi
}

main "$@"

