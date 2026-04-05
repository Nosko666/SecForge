#!/usr/bin/env bash
# SecForge bootstrap — minimal base installer.
# Sets up the directory layout, group, base deps, gum, and PATH.
# Does NOT install security tools (use install-tools.sh) or start tmux.
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
SECFORGE_GROUP="${SECFORGE_GROUP:-secforge}"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

# ---------------------------------------------------------------------------
# gum installer — pinned to v0.14.x
# ---------------------------------------------------------------------------
sf_install_gum() {
  local install_dir="${SECFORGE_ROOT}/bin"
  local gum_path="${install_dir}/gum"

  # Check if already installed with correct version
  if [[ -x "${gum_path}" ]]; then
    local current_ver
    current_ver="$("${gum_path}" --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0")"
    if sf_version_ge "${current_ver}" "0.14.0"; then
      sf_log "gum ${current_ver} already installed."
      return 0
    fi
  fi

  local arch gum_ver="0.14.5"
  arch="$(sf_detect_arch)"
  local arch_suffix
  case "${arch}" in
    amd64) arch_suffix="x86_64" ;;
    arm64) arch_suffix="arm64" ;;
  esac

  local url="https://github.com/charmbracelet/gum/releases/download/v${gum_ver}/gum_${gum_ver}_Linux_${arch_suffix}.tar.gz"
  local tmp
  tmp="$(sf_mktemp_dir)"
  sf_log "Installing gum v${gum_ver}..."
  sf_curl -o "${tmp}/gum.tar.gz" "${url}"
  sf_extract_archive_to_dir "${tmp}/gum.tar.gz" "${tmp}/extract"
  local found
  found="$(find "${tmp}/extract" -maxdepth 3 -type f -name "gum" -print | head -1)"
  if [[ -z "${found}" ]]; then
    sf_warn "Could not find gum binary in archive."
    rm -rf "${tmp}"
    return 1
  fi
  install -m 0755 "${found}" "${gum_path}"
  rm -rf "${tmp}"
  sf_log "gum v${gum_ver} installed to ${gum_path}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  sf_need_root

  sf_log "SecForge bootstrap starting..."
  sf_log "SECFORGE_ROOT=${SECFORGE_ROOT}"

  # 1. Create secforge group
  sf_log "Ensuring '${SECFORGE_GROUP}' group exists..."
  sf_ensure_group "${SECFORGE_GROUP}"

  # 2. Add invoking user to group
  local invoking_user
  invoking_user="$(sf_get_invoking_user)"
  if [[ -n "${invoking_user}" && "${invoking_user}" != "root" ]]; then
    sf_log "Adding user '${invoking_user}' to '${SECFORGE_GROUP}' group..."
    sf_add_user_to_group "${invoking_user}" "${SECFORGE_GROUP}"
  fi

  # 3. Create directory structure with correct ownership/permissions
  sf_log "Creating directory layout under ${SECFORGE_ROOT}..."
  mkdir -p "${SECFORGE_ROOT}"
  sf_ensure_runtime_layout "${SECFORGE_ROOT}" "${SECFORGE_GROUP}"

  # 4. Install base apt dependencies
  sf_log "Installing base dependencies..."
  sf_apt_install python3 python3-venv curl jq git tmux bc

  # 5. Install gum binary
  sf_log "Setting up gum..."
  sf_install_gum

  # 6. Add $SECFORGE_ROOT/bin to system PATH via /etc/profile.d
  sf_log "Configuring PATH..."
  sf_ensure_profile_d_path "${SECFORGE_ROOT}"

  # 7. Create config from example if missing
  sf_log "Checking configuration files..."
  sf_ensure_config_files "${SECFORGE_ROOT}" "${SECFORGE_GROUP}"

  # 8. Symlink bin/secforge if the CLI script exists in the repo
  local cli_source="${DEFAULT_ROOT}/bin/secforge"
  local cli_dest="${SECFORGE_ROOT}/bin/secforge"
  if [[ -f "${cli_source}" && "${cli_source}" != "${cli_dest}" ]]; then
    sf_log "Symlinking CLI: ${cli_dest} -> ${cli_source}"
    ln -sf "${cli_source}" "${cli_dest}"
    chmod +x "${cli_source}" 2>/dev/null || true
  elif [[ -f "${cli_dest}" ]]; then
    sf_log "CLI already present at ${cli_dest}"
  else
    sf_warn "CLI script not found at ${cli_source} — skipping symlink."
  fi

  # 9. Done — print next steps
  sf_log "Bootstrap complete!"
  cat <<'EOF'

SecForge bootstrap complete!

Next steps:
  1. Log out and back in (or run: source /etc/profile.d/secforge.sh)
  2. Run: secforge install --list    (see available tools)
  3. Run: secforge init              (configure your environment)
EOF
}

main "$@"
