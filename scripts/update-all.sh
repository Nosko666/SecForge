#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE:-${SECFORGE_ROOT}/config/secforge.conf}"
SECFORGE_VENV="${SECFORGE_VENV:-${SECFORGE_ROOT}/venv}"

export PATH="${SECFORGE_ROOT}/bin:${PATH}"
export GIT_TERMINAL_PROMPT=0

sf_step() {
  local name="$1"
  shift
  sf_log "==> ${name}"
  set +e
  "$@"
  local rc=$?
  set -e
  if [[ "${rc}" -ne 0 ]]; then
    sf_warn "${name} failed (exit ${rc})"
  fi
  return 0
}

sf_cmd_first_line() {
  # Usage: sf_cmd_first_line <timeout_seconds> <cmd...>
  local timeout_s="$1"
  shift

  if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status --kill-after=2s "${timeout_s}" "$@" 2>/dev/null | head -n1 || true
  else
    "$@" 2>/dev/null | head -n1 || true
  fi
}

sf_tool_version() {
  # Best-effort version extraction. Never uses flags that could start a scan.
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf '%s' ""
    return 0
  fi

  local out
  out="$(sf_cmd_first_line 5 "${tool}" --version)"
  [[ -n "${out}" ]] && { printf '%s' "${out}"; return 0; }

  out="$(sf_cmd_first_line 5 "${tool}" -version)"
  [[ -n "${out}" ]] && { printf '%s' "${out}"; return 0; }

  out="$(sf_cmd_first_line 5 "${tool}" version)"
  [[ -n "${out}" ]] && { printf '%s' "${out}"; return 0; }

  out="$(sf_cmd_first_line 5 "${tool}" -V)"
  [[ -n "${out}" ]] && { printf '%s' "${out}"; return 0; }

  printf '%s' ""
}

sf_pkg_version() {
  local pkg="$1"
  dpkg-query -W -f='${Version}' "${pkg}" 2>/dev/null || true
}

sf_cfg_list_has() {
  local list="$1"
  local item="$2"
  [[ " ${list} " == *" ${item} "* ]]
}

sf_is_installed_tool() {
  local installed_tools="$1"
  local tool="$2"
  if sf_cfg_list_has "${installed_tools}" "${tool}"; then
    return 0
  fi
  [[ -x "${SECFORGE_ROOT}/bin/${tool}" ]]
}

sf_git_pull_ff_only() {
  local repo_dir="$1"
  if [[ ! -d "${repo_dir}/.git" ]]; then
    return 1
  fi
  git -C "${repo_dir}" -c core.hooksPath=/dev/null pull --ff-only
}

# Get verify_mode for a tool from the catalog. Defaults to sha256 if not set.
sf_get_tool_verify_mode() {
  local tool_id="$1"
  local tools_json="${SECFORGE_ROOT:-/opt/secforge}/catalog/tools.json"
  if [[ ! -f "${tools_json}" ]]; then
    printf '%s' "sha256"
    return 0
  fi
  python3 - "${tools_json}" "${tool_id}" <<'PY' 2>/dev/null || printf '%s' "sha256"
import json, sys
try:
    path = sys.argv[1]
    tool_id = sys.argv[2]
    with open(path) as fh:
        t = json.load(fh)
    mode = (t.get(tool_id, {}).get("verify") or {}).get("mode", "sha256")
    print(mode)
except Exception:
    print("sha256")
PY
}

sf_update_github_release_binary() {
  # Usage: sf_update_github_release_binary <repo> <expected_binary> <install_path> [tool_id]
  local repo="$1"
  local expected="$2"
  local install_path="$3"
  local tool_id="${4:-${expected}}"

  local tmp
  tmp="$(sf_mktemp_dir)"
  local tmp_bin="${tmp}/${expected}.new"

  local _verify_mode
  _verify_mode="$(sf_get_tool_verify_mode "${tool_id}")"

  if sf_install_github_release_binary "${repo}" "${expected}" "${tmp_bin}" "${_verify_mode}"; then
    if [[ -x "${tmp_bin}" ]]; then
      install -m 0755 "${tmp_bin}" "${install_path}"
      rm -rf "${tmp}"
      return 0
    fi
  fi

  rm -rf "${tmp}"
  return 1
}

update_zap_tarball() {
  local zap_dir="${SECFORGE_ROOT}/tools/zap"
  local zap_sh="${zap_dir}/zap.sh"

  if ! command -v jq >/dev/null 2>&1; then
    sf_warn "Skipping ZAP update (jq required)."
    return 1
  fi

  local tmp url archive extract_dir zap_extracted
  tmp="$(sf_mktemp_dir)"
  url="$(sf_github_latest_release_json "zaproxy/zaproxy" | jq -r '
    .assets[]
    | select(.name | test("Linux.*\\.tar\\.gz$"; "i"))
    | .browser_download_url
  ' | head -n1)"

  if [[ -z "${url}" || "${url}" == "null" ]]; then
    sf_warn "Could not find ZAP Linux tarball in latest release."
    rm -rf "${tmp}"
    return 1
  fi

  archive="${tmp}/$(basename -- "${url}")"
  extract_dir="${tmp}/extract"

  sf_curl -o "${archive}" "${url}"
  sf_extract_archive_to_dir "${archive}" "${extract_dir}"

  zap_extracted="$(find "${extract_dir}" -maxdepth 2 -type f -name zap.sh -print | head -n1 || true)"
  if [[ -z "${zap_extracted}" ]]; then
    sf_warn "ZAP tarball extracted but zap.sh was not found."
    rm -rf "${tmp}"
    return 1
  fi

  local new_dir="${tmp}/zap.new"
  mkdir -p "${new_dir}"
  mv "$(dirname -- "${zap_extracted}")"/* "${new_dir}/"

  # Swap directory.
  if [[ -d "${zap_dir}" ]]; then
    rm -rf "${zap_dir}.bak" 2>/dev/null || true
    mv "${zap_dir}" "${zap_dir}.bak"
  fi
  mv "${new_dir}" "${zap_dir}"

  rm -rf "${tmp}"
  chmod +x "${zap_sh}" 2>/dev/null || true
  sf_ln_sf "${zap_sh}" "${SECFORGE_ROOT}/bin/zap.sh"

  rm -rf "${zap_dir}.bak" 2>/dev/null || true
}

update_observatory_cli() {
  local obs_dir="${SECFORGE_ROOT}/tools/observatory-cli"
  if [[ ! -d "${obs_dir}" ]]; then
    return 1
  fi
  if ! command -v npm >/dev/null 2>&1; then
    return 1
  fi
  npm install --prefix "${obs_dir}" observatory-cli >/dev/null 2>&1
}

update_apkhunt_build() {
  local repo_dir="${SECFORGE_ROOT}/tools/apkhunt"
  local out_bin="${SECFORGE_ROOT}/bin/apkhunt"
  if [[ ! -d "${repo_dir}" ]]; then
    return 1
  fi
  if ! command -v go >/dev/null 2>&1; then
    sf_warn "Skipping APKHunt rebuild (go not installed)."
    return 1
  fi
  (cd "${repo_dir}" && go build -o "${out_bin}" ./...) || return 1
  chmod 0755 "${out_bin}" 2>/dev/null || true
}

update_netexec_editable() {
  local repo_dir="${SECFORGE_ROOT}/tools/netexec"
  local nxc_venv="${SECFORGE_ROOT}/venvs/netexec"
  if [[ ! -d "${repo_dir}" ]]; then
    return 1
  fi
  if [[ ! -x "${nxc_venv}/bin/pip" ]]; then
    sf_warn "NetExec dedicated venv missing at ${nxc_venv}; skipping update."
    return 1
  fi
  "${nxc_venv}/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
  "${nxc_venv}/bin/pip" install -e "${repo_dir}" >/dev/null 2>&1
}

main() {
  sf_need_root
  sf_require_ubuntu

  local log_file ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  log_file="${SECFORGE_ROOT}/logs/updates.log"
  mkdir -p "${SECFORGE_ROOT}/logs"
  chmod 0750 "${SECFORGE_ROOT}/logs" 2>/dev/null || true

  # Log everything.
  exec > >(tee -a "${log_file}") 2>&1

  sf_log "SecForge update-all.sh starting at ${ts}"
  sf_log "Root: ${SECFORGE_ROOT}"
  sf_log "Config: ${SECFORGE_CONFIG_FILE}"

  sf_confirm_tty "Type YES to update installed tools now:" "YES"

  local installed_tools installed_categories
  installed_tools="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "INSTALLED_TOOLS" || true)"
  installed_categories="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "INSTALLED_CATEGORIES" || true)"
  installed_tools="${installed_tools:-}"
  installed_categories="${installed_categories:-}"

  sf_log "Installed categories: ${installed_categories:-<unknown>}"
  sf_log "Installed tools: ${installed_tools:-<unknown>}"

  # 1) Update SecForge repo itself (best-effort).
  if [[ -d "${SECFORGE_ROOT}/.git" ]] && command -v git >/dev/null 2>&1; then
    local before after
    before="$(git -C "${SECFORGE_ROOT}" rev-parse --short HEAD 2>/dev/null || true)"
    sf_step "Updating SecForge repo (git pull --ff-only)" sf_git_pull_ff_only "${SECFORGE_ROOT}"
    after="$(git -C "${SECFORGE_ROOT}" rev-parse --short HEAD 2>/dev/null || true)"
    if [[ -n "${before}" || -n "${after}" ]]; then
      sf_log "SecForge repo: ${before:-unknown} -> ${after:-unknown}"
    fi
  fi

  # 2) apt upgrades (safe default: only-upgrade installed packages).
  local apt_strategy
  apt_strategy="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "APT_UPDATE_STRATEGY" || true)"
  apt_strategy="${apt_strategy:-only-upgrade}"

  sf_step "apt update" sf_apt_update

  if [[ "${apt_strategy}" == "full-upgrade" ]]; then
    sf_warn "APT_UPDATE_STRATEGY=full-upgrade can change many packages and may impact services."
    sf_confirm_tty "Type YES to run full apt-get upgrade:" "YES"
    sf_step "apt-get upgrade" apt-get upgrade -y
  else
    # Upgrade only packages SecForge uses, and only if already installed.
    local pkgs_all=(
      nmap masscan netcat-openbsd sslscan hydra john hashcat ufw clamav clamav-freshclam rkhunter
      fail2ban aide auditd wapiti openscap-scanner openscap-utils python3-pip python3-venv ruby
      default-jre nodejs npm dnsutils jq tmux at etckeeper debsums default-mysql-client nikto
    )
    local pkgs_installed=()
    local pkg
    for pkg in "${pkgs_all[@]}"; do
      if dpkg -s "${pkg}" >/dev/null 2>&1; then
        pkgs_installed+=("${pkg}")
      fi
    done

    if [[ "${#pkgs_installed[@]}" -gt 0 ]]; then
      local before_map after_map
      before_map=""
      for pkg in "${pkgs_installed[@]}"; do
        before_map+="${pkg}=$(sf_pkg_version "${pkg}") "
      done

      sf_step "apt-get install --only-upgrade (SecForge packages)" apt-get install -y --no-install-recommends --only-upgrade "${pkgs_installed[@]}"

      after_map=""
      for pkg in "${pkgs_installed[@]}"; do
        after_map+="${pkg}=$(sf_pkg_version "${pkg}") "
      done

      sf_log "APT versions (before): ${before_map}"
      sf_log "APT versions (after):  ${after_map}"
    else
      sf_log "No SecForge-related apt packages detected as installed; skipping only-upgrade step."
    fi
  fi

  # 3) Update git-cloned tools in /opt/secforge/tools
  if [[ -d "${SECFORGE_ROOT}/tools" ]] && command -v git >/dev/null 2>&1; then
    local repo_dir
    for repo_dir in "${SECFORGE_ROOT}/tools"/*; do
      [[ -d "${repo_dir}" ]] || continue
      [[ -d "${repo_dir}/.git" ]] || continue

      local name before after
      name="$(basename -- "${repo_dir}")"
      before="$(git -C "${repo_dir}" rev-parse --short HEAD 2>/dev/null || true)"
      sf_step "Updating tool repo ${name} (git pull --ff-only)" sf_git_pull_ff_only "${repo_dir}"
      after="$(git -C "${repo_dir}" rev-parse --short HEAD 2>/dev/null || true)"
      if [[ -n "${before}" || -n "${after}" ]]; then
        sf_log "  - ${name}: ${before:-unknown} -> ${after:-unknown}"
      fi
    done
  fi

  # 4) Update pip/venv tools (only those installed).
  if [[ -x "${SECFORGE_VENV}/bin/pip" ]]; then
    sf_step "Updating venv tooling (pip/setuptools/wheel)" "${SECFORGE_VENV}/bin/pip" install --upgrade pip setuptools wheel

    declare -A pip_map=(
      ["sqlmap"]="sqlmap"
      ["commix"]="commix"
      ["wafw00f"]="wafw00f"
      ["apkleaks"]="apkleaks"
      ["pip-audit"]="pip-audit"
      ["checkov"]="checkov"
      ["prowler"]="prowler"
    )

    local tool pkg before after
    for tool in "${!pip_map[@]}"; do
      pkg="${pip_map[$tool]}"
      if sf_is_installed_tool "${installed_tools}" "${tool}"; then
        before="$("${SECFORGE_VENV}/bin/pip" show "${pkg}" 2>/dev/null | awk -F': ' '$1=="Version"{print $2; exit}' || true)"
        sf_step "Updating pip package ${pkg} (venv)" "${SECFORGE_VENV}/bin/pip" install --upgrade "${pkg}"
        after="$("${SECFORGE_VENV}/bin/pip" show "${pkg}" 2>/dev/null | awk -F': ' '$1=="Version"{print $2; exit}' || true)"
        sf_log "  - ${pkg}: ${before:-unknown} -> ${after:-unknown}"
      fi
    done

    # stripe-check dependencies live in the venv as well.
    if sf_is_installed_tool "${installed_tools}" "stripe-check" || [[ -x "${SECFORGE_ROOT}/bin/stripe-check" ]]; then
      local spkg
      for spkg in requests beautifulsoup4; do
        before="$("${SECFORGE_VENV}/bin/pip" show "${spkg}" 2>/dev/null | awk -F': ' '$1=="Version"{print $2; exit}' || true)"
        sf_step "Updating pip package ${spkg} (venv)" "${SECFORGE_VENV}/bin/pip" install --upgrade "${spkg}"
        after="$("${SECFORGE_VENV}/bin/pip" show "${spkg}" 2>/dev/null | awk -F': ' '$1=="Version"{print $2; exit}' || true)"
        sf_log "  - ${spkg}: ${before:-unknown} -> ${after:-unknown}"
      done
    fi

    # NetExec is installed editable from a git clone (best-effort).
    if sf_cfg_list_has "${installed_tools}" "netexec" || [[ -x "${SECFORGE_ROOT}/bin/nxc" ]]; then
      sf_step "Refreshing NetExec editable install (venv)" update_netexec_editable
    fi
  else
    sf_warn "Venv not found at ${SECFORGE_VENV}; skipping pip updates."
  fi

  # 5) Update npm-local tools (observatory-cli).
  if sf_is_installed_tool "${installed_tools}" "observatory" || [[ -x "${SECFORGE_ROOT}/bin/observatory" ]]; then
    local before after
    before="$(sf_tool_version observatory)"
    sf_step "Updating Mozilla Observatory CLI (local npm install)" update_observatory_cli
    after="$(sf_tool_version observatory)"
    sf_log "observatory: ${before:-unknown} -> ${after:-unknown}"
  fi

  # 6) Update GitHub-release binaries (only those installed).
  if ! command -v jq >/dev/null 2>&1; then
    sf_warn "jq not found; skipping GitHub release binary updates."
  else
  declare -A gh_repo=(
    ["nuclei"]="projectdiscovery/nuclei"
    ["ffuf"]="ffuf/ffuf"
    ["dalfox"]="hahwul/dalfox"
    ["kr"]="assetnote/kiterunner"
    ["osv-scanner"]="google/osv-scanner"
    ["trufflehog"]="trufflesecurity/trufflehog"
    ["gitleaks"]="gitleaks/gitleaks"
    ["interactsh-client"]="projectdiscovery/interactsh"
    ["trivy"]="aquasecurity/trivy"
    ["vulnapi"]="${SECFORGE_VULNAPI_REPO:-cerberauth/vulnapi}"
  )
  declare -A gh_expected_bin=(
    ["nuclei"]="nuclei"
    ["ffuf"]="ffuf"
    ["dalfox"]="dalfox"
    ["kr"]="kr"
    ["osv-scanner"]="osv-scanner"
    ["trufflehog"]="trufflehog"
    ["gitleaks"]="gitleaks"
    ["interactsh-client"]="interactsh-client"
    ["trivy"]="trivy"
    ["vulnapi"]="vulnapi"
  )

  local tool before after repo expected bin_path
  for tool in "${!gh_repo[@]}"; do
    if sf_is_installed_tool "${installed_tools}" "${tool}" || command -v "${tool}" >/dev/null 2>&1; then
      repo="${gh_repo[$tool]}"
      expected="${gh_expected_bin[$tool]}"
      bin_path="${SECFORGE_ROOT}/bin/${tool}"
      if [[ "${tool}" == "kr" ]]; then
        bin_path="${SECFORGE_ROOT}/bin/kr"
      fi
      before="$(sf_tool_version "${tool}")"
      sf_step "Updating ${tool} (GitHub release)" sf_update_github_release_binary "${repo}" "${expected}" "${bin_path}" "${tool}"
      after="$(sf_tool_version "${tool}")"
      sf_log "${tool}: ${before:-unknown} -> ${after:-unknown}"
    fi
  done
  fi

  # 7) Special-case updates (ZAP tarball, APKHunt rebuild).
  if [[ -x "${SECFORGE_ROOT}/bin/zap.sh" ]]; then
    sf_step "Updating OWASP ZAP (tarball)" update_zap_tarball
  fi

  if sf_cfg_list_has "${installed_tools}" "apkhunt" || [[ -x "${SECFORGE_ROOT}/bin/apkhunt" ]]; then
    sf_step "Rebuilding APKHunt binary" update_apkhunt_build
  fi

  # 8) Signatures/templates (best-effort).
  # Nuclei templates are updated via the tools/* git-pull loop above (no root-HOME writes).
  if command -v freshclam >/dev/null 2>&1; then
    sf_step "Updating ClamAV signatures (freshclam)" freshclam
  fi
  if command -v rkhunter >/dev/null 2>&1; then
    sf_step "Updating rkhunter definitions" rkhunter --update
  fi

  # MobSF docker image update (optional).
  if sf_cfg_list_has "${installed_tools}" "mobsf" && command -v docker >/dev/null 2>&1; then
    sf_warn "MobSF runs via Docker. Pulling the latest image is optional."
    if sf_ask_tty_yes "Type YES to docker pull MobSF now (or anything else to skip):" "YES"; then
      sf_step "Pulling MobSF Docker image" docker pull opensecurity/mobile-security-framework-mobsf
    fi
  fi

  sf_log "Update complete. Log: ${log_file}"
}

main "$@"
