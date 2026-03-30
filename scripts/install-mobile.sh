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

  sf_log "Installing Category: Mobile / APK Security"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "mobile"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  # APKDeepLens (git clone)
  sf_git_clone_or_update "https://github.com/d78ui98/APKDeepLens.git" "${SECFORGE_ROOT}/tools/apkdeeplens"
  if [[ -r "${SECFORGE_ROOT}/tools/apkdeeplens/APKDeepLens.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/apkdeeplens" <<EOF
#!/usr/bin/env bash
exec "${SECFORGE_VENV}/bin/python" "${SECFORGE_ROOT}/tools/apkdeeplens/APKDeepLens.py" "\$@"
EOF
    chmod 0755 "${SECFORGE_ROOT}/bin/apkdeeplens"
  fi
  mark_tool_if_present "apkdeeplens" "${SECFORGE_ROOT}/bin/apkdeeplens"

  # APKHunt (git clone + compile at install so Go isn't needed at runtime)
  sf_apt_install golang-go
  sf_git_clone_or_update "https://github.com/Cyber-Buddy/APKHunt.git" "${SECFORGE_ROOT}/tools/apkhunt"
  if [[ -d "${SECFORGE_ROOT}/tools/apkhunt" ]]; then
    sf_log "Building APKHunt binary..."
    if [[ -r "${SECFORGE_ROOT}/tools/apkhunt/apkhunt.go" ]]; then
      (cd "${SECFORGE_ROOT}/tools/apkhunt" && go build -o "${SECFORGE_ROOT}/bin/apkhunt" "./apkhunt.go") || sf_warn "APKHunt build failed"
    else
      (cd "${SECFORGE_ROOT}/tools/apkhunt" && go build -o "${SECFORGE_ROOT}/bin/apkhunt" ./...) || sf_warn "APKHunt build failed"
    fi
    chmod 0755 "${SECFORGE_ROOT}/bin/apkhunt" 2>/dev/null || true
  fi
  mark_tool_if_present "apkhunt" "${SECFORGE_ROOT}/bin/apkhunt"

  # APKLeaks is used in mobile audits; install it here as well (even if Secrets category isn't installed).
  sf_install_venv_packages "${SECFORGE_VENV}" apkleaks || sf_warn "Failed to install apkleaks"
  if [[ -x "${SECFORGE_VENV}/bin/apkleaks" ]]; then
    sf_ln_sf "${SECFORGE_VENV}/bin/apkleaks" "${SECFORGE_ROOT}/bin/apkleaks"
  fi
  mark_tool_if_present "apkleaks" "${SECFORGE_ROOT}/bin/apkleaks"

  # MobSF: Docker-only and optional
  if sf_has_cmd docker; then
    sf_warn "Docker detected. MobSF is optional and runs in Docker."
    if sf_ask_tty_yes "Type YES to pull the MobSF Docker image now (or anything else to skip):" "YES"; then
      docker pull opensecurity/mobile-security-framework-mobsf >/dev/null 2>&1 || sf_warn "MobSF docker pull failed (skipping)."
      sf_cfg_add_list_item "${cfg_file}" "INSTALLED_TOOLS" "mobsf"
    else
      sf_log "Skipping MobSF."
    fi
  else
    sf_warn "Docker not found. Skipping MobSF (mobile scanning via MobSF won't be available)."
  fi
}

main "$@"
