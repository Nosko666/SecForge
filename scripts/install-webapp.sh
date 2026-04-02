#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_GROUP="${SECFORGE_GROUP:-secforge}"
SECFORGE_VENV="${SECFORGE_VENV:-${SECFORGE_ROOT}/venv}"
SECFORGE_PROFILE="${SECFORGE_INSTALL_PROFILE:-full}" # full|essential

cfg_file="${SECFORGE_ROOT}/config/secforge.conf"

install_zap() {
  local zap_dir="${SECFORGE_ROOT}/tools/zap"
  local zap_sh="${zap_dir}/zap.sh"

  if [[ -x "${zap_sh}" ]]; then
    return 0
  fi

  if ! sf_has_cmd jq; then
    sf_die "jq is required to install ZAP (GitHub API)."
  fi

  sf_log "Installing OWASP ZAP (tarball)..."
  sf_apt_install default-jre

  mkdir -p "${SECFORGE_ROOT}/tools"

  local tmp url archive extract_dir zap_extracted
  tmp="$(sf_mktemp_dir)"
  url="$(sf_github_latest_release_json "zaproxy/zaproxy" | jq -r '
    .assets[]
    | select(.name | test("Linux.*\\.tar\\.gz$"; "i"))
    | .browser_download_url
  ' | head -n1)"

  if [[ -z "${url}" || "${url}" == "null" ]]; then
    sf_warn "Could not find ZAP Linux tarball in latest release (skipping)."
    rm -rf "${tmp}"
    return 1
  fi

  archive="${tmp}/$(basename -- "${url}")"
  extract_dir="${tmp}/extract"

  sf_curl -o "${archive}" "${url}"
  mkdir -p "${extract_dir}"
  tar -xzf "${archive}" -C "${extract_dir}"

  zap_extracted="$(find "${extract_dir}" -maxdepth 2 -type f -name zap.sh -print | head -n1 || true)"
  if [[ -z "${zap_extracted}" ]]; then
    sf_warn "ZAP tarball extracted but zap.sh was not found (skipping)."
    rm -rf "${tmp}"
    return 1
  fi

  rm -rf "${zap_dir}"
  mkdir -p "${zap_dir}"
  # Move the whole extracted directory containing zap.sh into tools/zap
  mv "$(dirname -- "${zap_extracted}")"/* "${zap_dir}/"

  rm -rf "${tmp}"

  chmod +x "${zap_sh}" 2>/dev/null || true
  sf_ln_sf "${zap_sh}" "${SECFORGE_ROOT}/bin/zap.sh"
}

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

  sf_log "Installing Category: Web Application Scanning (${SECFORGE_PROFILE})"
  sf_cfg_add_list_item "${cfg_file}" "INSTALLED_CATEGORIES" "webapp"

  mkdir -p "${SECFORGE_ROOT}/tools" "${SECFORGE_ROOT}/bin"

  sf_ensure_venv "${SECFORGE_VENV}"

  install_zap || true
  mark_tool_if_present "zap" "${SECFORGE_ROOT}/bin/zap.sh"

  sf_install_github_release_binary "projectdiscovery/nuclei" "nuclei" "${SECFORGE_ROOT}/bin/nuclei" || sf_warn "Failed to install nuclei"
  mark_tool_if_present "nuclei" "${SECFORGE_ROOT}/bin/nuclei"

  # Fetch Nuclei templates (essential for scanning)
  if [[ -x "${SECFORGE_ROOT}/bin/nuclei" ]]; then
    sf_log "Updating Nuclei templates..."
    "${SECFORGE_ROOT}/bin/nuclei" -update-templates >/dev/null 2>&1 || sf_warn "Nuclei template update failed (scanning may have limited coverage)."
  fi

  sf_install_github_release_binary "ffuf/ffuf" "ffuf" "${SECFORGE_ROOT}/bin/ffuf" || sf_warn "Failed to install ffuf"
  mark_tool_if_present "ffuf" "${SECFORGE_ROOT}/bin/ffuf"

  local py_ver
  py_ver="$(sf_python_major_minor)"

  if sf_version_ge "${py_ver}" "3.10"; then
    sf_install_venv_packages "${SECFORGE_VENV}" wafw00f || sf_warn "Failed to install wafw00f"
    if [[ -x "${SECFORGE_VENV}/bin/wafw00f" ]]; then
      sf_ln_sf "${SECFORGE_VENV}/bin/wafw00f" "${SECFORGE_ROOT}/bin/wafw00f"
      mark_tool_if_present "wafw00f" "${SECFORGE_ROOT}/bin/wafw00f"
    fi
  else
    sf_warn "Skipping wafw00f (requires Python >= 3.10; found ${py_ver})."
  fi

  if [[ "${SECFORGE_PROFILE}" == "essential" ]]; then
    sf_log "Essential profile: skipping active scanners and heavier web tools."
    return 0
  fi

  sf_install_github_release_binary "hahwul/dalfox" "dalfox" "${SECFORGE_ROOT}/bin/dalfox" || sf_warn "Failed to install dalfox"
  mark_tool_if_present "dalfox" "${SECFORGE_ROOT}/bin/dalfox"

  sf_apt_install nikto ruby wapiti

  sf_git_clone_or_update "https://github.com/urbanadventurer/WhatWeb.git" "${SECFORGE_ROOT}/tools/whatweb"
  if [[ -x "${SECFORGE_ROOT}/tools/whatweb/whatweb" ]]; then
    sf_ln_sf "${SECFORGE_ROOT}/tools/whatweb/whatweb" "${SECFORGE_ROOT}/bin/whatweb"
  fi
  mark_tool_if_present "whatweb" "${SECFORGE_ROOT}/bin/whatweb"

  sf_git_clone_or_update "https://github.com/s0md3v/XSStrike.git" "${SECFORGE_ROOT}/tools/xsstrike"
  if [[ -r "${SECFORGE_ROOT}/tools/xsstrike/xsstrike.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/xsstrike" <<EOF
#!/usr/bin/env bash
exec "${SECFORGE_VENV}/bin/python" "${SECFORGE_ROOT}/tools/xsstrike/xsstrike.py" "\$@"
EOF
    chmod 0755 "${SECFORGE_ROOT}/bin/xsstrike"
  fi
  mark_tool_if_present "xsstrike" "${SECFORGE_ROOT}/bin/xsstrike"

  # Install XSStrike dependencies into venv (best-effort)
  if [[ -r "${SECFORGE_ROOT}/tools/xsstrike/requirements.txt" ]]; then
    sf_install_venv_packages "${SECFORGE_VENV}" -r "${SECFORGE_ROOT}/tools/xsstrike/requirements.txt" || sf_warn "XSStrike dependency install failed (continuing)."
  fi

  sf_git_clone_or_update "https://github.com/chenjj/CORScanner.git" "${SECFORGE_ROOT}/tools/corscanner"
  local cors_entry
  cors_entry="$(find "${SECFORGE_ROOT}/tools/corscanner" -maxdepth 2 -type f \( -iname '*cors*scanner*.py' -o -iname 'corscanner.py' -o -iname 'cors_scan.py' \) 2>/dev/null | head -n1 || true)"
  if [[ -n "${cors_entry}" ]]; then
    cat >"${SECFORGE_ROOT}/bin/corscanner" <<EOF
#!/usr/bin/env bash
exec "${SECFORGE_VENV}/bin/python" "${cors_entry}" "\$@"
EOF
    chmod 0755 "${SECFORGE_ROOT}/bin/corscanner"
  else
    sf_warn "CORScanner cloned but entrypoint not found; leaving in tools/ for manual use."
  fi
  mark_tool_if_present "corscanner" "${SECFORGE_ROOT}/bin/corscanner"

  # Install CORScanner dependencies into venv (best-effort)
  if [[ -r "${SECFORGE_ROOT}/tools/corscanner/requirements.txt" ]]; then
    sf_install_venv_packages "${SECFORGE_VENV}" -r "${SECFORGE_ROOT}/tools/corscanner/requirements.txt" || sf_warn "CORScanner dependency install failed (continuing)."
  fi

  sf_install_venv_packages "${SECFORGE_VENV}" sqlmap commix || sf_warn "Failed to install one or more pip web tools"
  if [[ -x "${SECFORGE_VENV}/bin/sqlmap" ]]; then
    sf_ln_sf "${SECFORGE_VENV}/bin/sqlmap" "${SECFORGE_ROOT}/bin/sqlmap"
  fi
  if [[ -x "${SECFORGE_VENV}/bin/commix" ]]; then
    sf_ln_sf "${SECFORGE_VENV}/bin/commix" "${SECFORGE_ROOT}/bin/commix"
  fi
  mark_tool_if_present "sqlmap" "${SECFORGE_ROOT}/bin/sqlmap"
  mark_tool_if_present "commix" "${SECFORGE_ROOT}/bin/commix"

  # Link Nikto/Wapiti if present (apt installs to system PATH; still expose via /opt/secforge/bin for consistency).
  if command -v nikto >/dev/null 2>&1; then
    sf_ln_sf "$(command -v nikto)" "${SECFORGE_ROOT}/bin/nikto"
  fi
  mark_tool_if_present "nikto" "${SECFORGE_ROOT}/bin/nikto"

  if command -v wapiti >/dev/null 2>&1; then
    sf_ln_sf "$(command -v wapiti)" "${SECFORGE_ROOT}/bin/wapiti"
  fi
  mark_tool_if_present "wapiti" "${SECFORGE_ROOT}/bin/wapiti"
}

main "$@"
