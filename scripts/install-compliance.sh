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

  sf_log "Installing Category: Payment / PCI Compliance"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "compliance"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

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

  # Stripe/payment checker (SecForge script; runs inside venv)
  sf_install_venv_packages "${SECFORGE_VENV}" requests beautifulsoup4 || sf_warn "Failed to install stripe-check dependencies (requests, beautifulsoup4)"
  if [[ -r "${SECFORGE_ROOT}/scripts/stripe-check.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/stripe-check" <<EOF
#!/usr/bin/env bash
exec "${SECFORGE_VENV}/bin/python" "${SECFORGE_ROOT}/scripts/stripe-check.py" "\$@"
EOF
    chmod 0755 "${SECFORGE_ROOT}/bin/stripe-check"
    mark_tool_if_present "stripe-check" "${SECFORGE_ROOT}/bin/stripe-check"
  else
    sf_warn "Missing ${SECFORGE_ROOT}/scripts/stripe-check.py; stripe-check will be unavailable."
  fi
}

main "$@"
