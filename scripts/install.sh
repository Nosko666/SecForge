#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_GROUP="${SECFORGE_GROUP:-secforge}"
SECFORGE_VENV="${SECFORGE_VENV:-${SECFORGE_ROOT}/venv}"

sf_print_menu() {
  cat <<'EOF'
╔══════════════════════════════════════════════╗
║          SecForge Installer v1.0             ║
║    AI-Guided Security Toolkit for Vibecoders ║
╠══════════════════════════════════════════════╣
║                                              ║
║  1) Install Everything (≈60 tools, ~7GB+)    ║
║  2) Essential Only (≈15 tools, ~2GB)         ║
║  3) Custom — Choose Categories               ║
║  4) Web App Scanning Only (≈12 tools)        ║
║  5) Server Hardening Only (≈10 tools)        ║
║  6) Mobile/APK Testing Only (3 tools)        ║
║  7) Payment/PCI Compliance Only (3 tools)    ║
║                                              ║
║  u) Update All Installed Tools               ║
║  s) Show Installed Tools & Versions          ║
║  0) Exit                                     ║
║                                              ║
╚══════════════════════════════════════════════╝
EOF
}

sf_run_installer_script() {
  local script_name="$1"
  shift || true

  local script_path="${SECFORGE_ROOT}/scripts/${script_name}"
  if [[ ! -r "${script_path}" ]]; then
    sf_die "Missing installer script: ${script_path}"
  fi

  chmod +x "${script_path}" 2>/dev/null || true
  "${script_path}" "$@"
}

sf_custom_category_menu() {
  cat <<'EOF'
Choose categories to install (space-separated):
  1) Web App Scanning         (install-webapp.sh)
  2) API Security             (install-api.sh)
  3) Network Scanning         (install-network.sh)
  4) SSL/TLS & Headers        (install-ssl.sh)
  5) Password & Auth Testing  (install-passwords.sh)
  6) Secrets & Key Detection  (install-secrets.sh)
  7) Mobile / APK             (install-mobile.sh)
  8) Payment / PCI Compliance (install-compliance.sh)
  9) Server Hardening         (install-hardening.sh)
 10) Dependencies / Supply    (install-dependencies.sh)
 12) Email/DNS Security       (install-emaildns.sh)
 13) Database Security        (install-database.sh)
 14) Containers/IaC/Cloud     (install-containers.sh)
EOF

  local selections
  selections="$(sf_prompt_tty "Enter numbers" "")"
  printf '\n'
  for sel in ${selections}; do
    case "${sel}" in
      1) sf_run_installer_script "install-webapp.sh" ;;
      2) sf_run_installer_script "install-api.sh" ;;
      3) sf_run_installer_script "install-network.sh" ;;
      4) sf_run_installer_script "install-ssl.sh" ;;
      5) sf_run_installer_script "install-passwords.sh" ;;
      6) sf_run_installer_script "install-secrets.sh" ;;
      7) sf_run_installer_script "install-mobile.sh" ;;
      8) sf_run_installer_script "install-compliance.sh" ;;
      9) sf_run_installer_script "install-hardening.sh" ;;
      10) sf_run_installer_script "install-dependencies.sh" ;;
      12) sf_run_installer_script "install-emaildns.sh" ;;
      13) sf_run_installer_script "install-database.sh" ;;
      14) sf_run_installer_script "install-containers.sh" ;;
      *) sf_warn "Unknown category selection: ${sel} (skipping)" ;;
    esac
  done
}

sf_show_versions() {
  sf_log "Installed tool entrypoints in ${SECFORGE_ROOT}/bin:"
  if [[ ! -d "${SECFORGE_ROOT}/bin" ]]; then
    sf_warn "Missing ${SECFORGE_ROOT}/bin."
    return 0
  fi

  ls -la "${SECFORGE_ROOT}/bin" || true

  sf_log "Versions (best-effort):"
  local tool
  for tool in nuclei nmap testssl.sh sslscan lynis ssh-audit wafw00f fail2ban-client clamscan rkhunter trufflehog gitleaks osv-scanner observatory; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
      printf '  - %-18s %s\n' "${tool}" "not found in PATH"
      continue
    fi
    local ver
    ver="$("${tool}" --version 2>/dev/null | head -n1 || true)"
    ver="${ver:-$("${tool}" -version 2>/dev/null | head -n1 || true)}"
    ver="${ver:-$("${tool}" version 2>/dev/null | head -n1 || true)}"
    ver="${ver:-unknown}"
    printf '  - %-18s %s\n' "${tool}" "${ver}"
  done
}

main() {
  sf_need_root
  sf_require_ubuntu

  sf_log "SecForge menu installer"
  sf_log "Install root: ${SECFORGE_ROOT}"

  sf_confirm_tty "Type YES to continue:" "YES"

  # Base dependencies used by installers (and by many tools).
  sf_apt_install ca-certificates curl jq git python3 python3-venv python3-pip tar
  export SECFORGE_APT_UPDATED="1"

  local invoking_user
  invoking_user="$(sf_get_invoking_user)"
  if [[ -z "${invoking_user}" ]]; then
    invoking_user="$(sf_prompt_tty "Username that will run scans" "")"
  fi
  if [[ -z "${invoking_user}" ]]; then
    sf_warn "Could not determine a non-root user for scans. You can add a user to the ${SECFORGE_GROUP} group later."
  else
    sf_log "Scan user: ${invoking_user}"
  fi

  sf_ensure_runtime_layout "${SECFORGE_ROOT}" "${SECFORGE_GROUP}"
  sf_ensure_config_files "${SECFORGE_ROOT}" "${SECFORGE_GROUP}"
  sf_ensure_profile_d_path "${SECFORGE_ROOT}"
  sf_add_user_to_group "${invoking_user}" "${SECFORGE_GROUP}"

  # Create venv early; category installers will add packages.
  sf_ensure_venv "${SECFORGE_VENV}"
  sf_download_wordlists "${SECFORGE_ROOT}"

  while true; do
    sf_print_menu
    local choice
    choice="$(sf_prompt_tty "Select an option" "0")"
    printf '\n'

    case "${choice}" in
      1)
        sf_run_installer_script "install-webapp.sh"
        sf_run_installer_script "install-api.sh"
        sf_run_installer_script "install-network.sh"
        sf_run_installer_script "install-ssl.sh"
        sf_run_installer_script "install-passwords.sh"
        sf_run_installer_script "install-secrets.sh"
        sf_run_installer_script "install-mobile.sh"
        sf_run_installer_script "install-compliance.sh"
        sf_run_installer_script "install-hardening.sh"
        sf_run_installer_script "install-dependencies.sh"
        sf_run_installer_script "install-emaildns.sh"
        sf_run_installer_script "install-database.sh"
        sf_run_installer_script "install-containers.sh"
        ;;
      2)
        SECFORGE_INSTALL_PROFILE="essential" sf_run_installer_script "install-webapp.sh"
        SECFORGE_INSTALL_PROFILE="essential" sf_run_installer_script "install-network.sh"
        SECFORGE_INSTALL_PROFILE="essential" sf_run_installer_script "install-ssl.sh"
        SECFORGE_INSTALL_PROFILE="essential" sf_run_installer_script "install-hardening.sh"
        SECFORGE_INSTALL_PROFILE="essential" sf_run_installer_script "install-secrets.sh"
        SECFORGE_INSTALL_PROFILE="essential" sf_run_installer_script "install-dependencies.sh"
        ;;
      3)
        sf_custom_category_menu
        ;;
      4)
        sf_run_installer_script "install-webapp.sh"
        sf_run_installer_script "install-api.sh"
        sf_run_installer_script "install-ssl.sh"
        ;;
      5)
        sf_run_installer_script "install-hardening.sh"
        sf_run_installer_script "install-network.sh"
        ;;
      6)
        sf_run_installer_script "install-mobile.sh"
        ;;
      7)
        sf_run_installer_script "install-compliance.sh"
        sf_run_installer_script "install-ssl.sh"
        ;;
      u|U)
        if [[ -r "${SECFORGE_ROOT}/scripts/update-all.sh" ]]; then
          chmod +x "${SECFORGE_ROOT}/scripts/update-all.sh" 2>/dev/null || true
          "${SECFORGE_ROOT}/scripts/update-all.sh"
        else
          sf_warn "Update script not available yet (Phase 5)."
        fi
        ;;
      s|S)
        sf_show_versions
        ;;
      0)
        sf_log "Exiting."
        exit 0
        ;;
      *)
        sf_warn "Invalid option: ${choice}"
        ;;
    esac

    printf '\n'
    sf_log "If scans fail to write reports, re-login so group membership applies: logout/login or: newgrp ${SECFORGE_GROUP}"
    printf '\n'
  done
}

main "$@"
