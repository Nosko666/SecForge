#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_VENV="${SECFORGE_VENV:-${SECFORGE_ROOT}/venv}"
SECFORGE_PROFILE="${SECFORGE_INSTALL_PROFILE:-full}" # full|essential

cfg_file="${SECFORGE_ROOT}/config/secforge.conf"

mark_tool_if_present() {
  local tool_name="$1"
  local tool_path="$2"
  if [[ -e "${tool_path}" ]]; then
    sf_cfg_add_list_item "${cfg_file}" "INSTALLED_TOOLS" "${tool_name}"
  fi
}

ensure_service_enabled() {
  local svc="$1"
  if ! sf_has_cmd systemctl; then
    sf_warn "systemctl not found; cannot enable ${svc}."
    return 0
  fi
  systemctl enable --now "${svc}" >/dev/null 2>&1 || sf_warn "Failed to enable ${svc} (continuing)."
}

init_etckeeper_baseline() {
  if ! command -v etckeeper >/dev/null 2>&1; then
    return 0
  fi

  sf_log "Initializing etckeeper baseline snapshot for /etc (helps rollback safety)..."

  if [[ ! -d /etc/.git ]]; then
    etckeeper init >/dev/null 2>&1 || sf_warn "etckeeper init failed (continuing)."
  fi

  if [[ -d /etc/.git ]]; then
    git -C /etc config user.name "SecForge" || true
    git -C /etc config user.email "secforge@localhost" || true
    etckeeper commit "SecForge baseline snapshot" >/dev/null 2>&1 || true
  fi
}

init_aide() {
  if ! command -v aide >/dev/null 2>&1; then
    return 0
  fi

  sf_log "Initializing AIDE database (may take a while)..."
  if command -v aideinit >/dev/null 2>&1; then
    aideinit >/dev/null 2>&1 || sf_warn "aideinit failed (continuing)."
  else
    aide --init >/dev/null 2>&1 || sf_warn "aide --init failed (continuing)."
  fi

  if [[ -f /var/lib/aide/aide.db.new.gz ]]; then
    mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz || true
  fi
}

init_clamav() {
  if ! command -v freshclam >/dev/null 2>&1; then
    return 0
  fi
  sf_log "Updating ClamAV signatures (freshclam)..."
  freshclam >/dev/null 2>&1 || sf_warn "freshclam failed (continuing)."
}

update_rkhunter() {
  if ! command -v rkhunter >/dev/null 2>&1; then
    return 0
  fi
  sf_log "Updating rkhunter definitions..."
  rkhunter --update >/dev/null 2>&1 || sf_warn "rkhunter --update failed (continuing)."
}

main() {
  sf_need_root
  sf_require_ubuntu

  sf_log "Installing Category: Server Hardening (${SECFORGE_PROFILE})"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "hardening"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"
  sf_ensure_venv "${SECFORGE_VENV}"

  sf_apt_install tmux at ufw fail2ban clamav clamav-freshclam rkhunter
  ensure_service_enabled atd
  ensure_service_enabled clamav-freshclam

  if command -v fail2ban-client >/dev/null 2>&1; then
    sf_ln_sf "$(command -v fail2ban-client)" "${SECFORGE_ROOT}/bin/fail2ban-client"
  fi
  mark_tool_if_present "fail2ban" "${SECFORGE_ROOT}/bin/fail2ban-client"

  if command -v clamscan >/dev/null 2>&1; then
    sf_ln_sf "$(command -v clamscan)" "${SECFORGE_ROOT}/bin/clamscan"
  fi
  mark_tool_if_present "clamav" "${SECFORGE_ROOT}/bin/clamscan"

  if command -v rkhunter >/dev/null 2>&1; then
    sf_ln_sf "$(command -v rkhunter)" "${SECFORGE_ROOT}/bin/rkhunter"
  fi
  mark_tool_if_present "rkhunter" "${SECFORGE_ROOT}/bin/rkhunter"

  # Lynis (git clone)
  sf_git_clone_or_update "https://github.com/CISOfy/lynis.git" "${SECFORGE_ROOT}/tools/lynis"
  if [[ -x "${SECFORGE_ROOT}/tools/lynis/lynis" ]]; then
    sf_ln_sf "${SECFORGE_ROOT}/tools/lynis/lynis" "${SECFORGE_ROOT}/bin/lynis"
  fi
  mark_tool_if_present "lynis" "${SECFORGE_ROOT}/bin/lynis"

  # ssh-audit (pip)
  sf_install_venv_packages "${SECFORGE_VENV}" ssh-audit || sf_warn "Failed to install ssh-audit"
  if [[ -x "${SECFORGE_VENV}/bin/ssh-audit" ]]; then
    sf_ln_sf "${SECFORGE_VENV}/bin/ssh-audit" "${SECFORGE_ROOT}/bin/ssh-audit"
  fi
  mark_tool_if_present "ssh-audit" "${SECFORGE_ROOT}/bin/ssh-audit"

  if [[ "${SECFORGE_PROFILE}" == "essential" ]]; then
    init_clamav
    update_rkhunter
    return 0
  fi

  # Additional hardening tools
  sf_apt_install aide auditd etckeeper debsums
  init_etckeeper_baseline
  init_aide
  init_clamav
  update_rkhunter

  if command -v aide >/dev/null 2>&1; then
    sf_ln_sf "$(command -v aide)" "${SECFORGE_ROOT}/bin/aide"
    mark_tool_if_present "aide" "${SECFORGE_ROOT}/bin/aide"
  fi

  if command -v aureport >/dev/null 2>&1; then
    sf_ln_sf "$(command -v aureport)" "${SECFORGE_ROOT}/bin/aureport"
    mark_tool_if_present "auditd" "${SECFORGE_ROOT}/bin/aureport"
  fi

  if command -v debsums >/dev/null 2>&1; then
    sf_ln_sf "$(command -v debsums)" "${SECFORGE_ROOT}/bin/debsums"
    mark_tool_if_present "debsums" "${SECFORGE_ROOT}/bin/debsums"
  fi
}

main "$@"
