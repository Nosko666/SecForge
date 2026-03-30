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

install_observatory_cli() {
  local obs_dir="${SECFORGE_ROOT}/tools/observatory-cli"
  local wrapper="${SECFORGE_ROOT}/bin/observatory"

  if [[ -x "${wrapper}" ]]; then
    return 0
  fi

  sf_log "Installing Mozilla Observatory CLI locally..."
  sf_apt_install nodejs npm

  mkdir -p "${obs_dir}"

  if ! npm --version >/dev/null 2>&1; then
    sf_warn "npm not available; skipping Observatory CLI."
    return 1
  fi

  # Local install to keep everything under /opt/secforge.
  npm install --prefix "${obs_dir}" observatory-cli >/dev/null 2>&1 || {
    sf_warn "npm install observatory-cli failed; skipping."
    return 1
  }

  cat >"${wrapper}" <<EOF
#!/usr/bin/env bash
exec "${obs_dir}/node_modules/.bin/observatory" "\$@"
EOF
  chmod 0755 "${wrapper}"
}

main() {
  sf_need_root
  sf_require_ubuntu

  sf_log "Installing Category: SSL/TLS & Headers"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "ssl"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"

  sf_git_clone_or_update "https://github.com/drwetter/testssl.sh.git" "${SECFORGE_ROOT}/tools/testssl"
  if [[ -x "${SECFORGE_ROOT}/tools/testssl/testssl.sh" ]]; then
    sf_ln_sf "${SECFORGE_ROOT}/tools/testssl/testssl.sh" "${SECFORGE_ROOT}/bin/testssl.sh"
  fi
  mark_tool_if_present "testssl" "${SECFORGE_ROOT}/bin/testssl.sh"

  sf_apt_install sslscan
  if command -v sslscan >/dev/null 2>&1; then
    sf_ln_sf "$(command -v sslscan)" "${SECFORGE_ROOT}/bin/sslscan"
  fi
  mark_tool_if_present "sslscan" "${SECFORGE_ROOT}/bin/sslscan"

  install_observatory_cli || true
  mark_tool_if_present "observatory" "${SECFORGE_ROOT}/bin/observatory"
}

main "$@"

