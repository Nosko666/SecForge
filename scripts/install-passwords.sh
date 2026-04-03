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

  # NetExec: dedicated venv to avoid dependency conflicts with the shared venv.
  local nxc_venv="${SECFORGE_ROOT}/venvs/netexec"
  sf_git_clone_or_update "https://github.com/Pennyw0rth/NetExec.git" "${SECFORGE_ROOT}/tools/netexec"
  if [[ -d "${SECFORGE_ROOT}/tools/netexec" ]]; then
    sf_log "Installing NetExec into dedicated venv (best-effort)..."
    python3 -m venv "${nxc_venv}" 2>/dev/null || true
    if [[ -x "${nxc_venv}/bin/pip" ]]; then
      "${nxc_venv}/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
      "${nxc_venv}/bin/pip" install -e "${SECFORGE_ROOT}/tools/netexec" >/dev/null 2>&1 || sf_warn "NetExec install failed (best-effort; leaving repo for manual setup)."
    fi
  fi

  if [[ -x "${nxc_venv}/bin/nxc" ]]; then
    cat >"${SECFORGE_ROOT}/bin/nxc" <<EOF
#!/usr/bin/env bash
exec "${nxc_venv}/bin/nxc" "\$@"
EOF
    chmod 0755 "${SECFORGE_ROOT}/bin/nxc"
    mark_tool_if_present "netexec" "${SECFORGE_ROOT}/bin/nxc"
  elif command -v nxc >/dev/null 2>&1; then
    sf_ln_sf "$(command -v nxc)" "${SECFORGE_ROOT}/bin/nxc"
    mark_tool_if_present "netexec" "${SECFORGE_ROOT}/bin/nxc"
  else
    sf_warn "NetExec binary (nxc) not found after install attempt."
  fi
}

main "$@"

