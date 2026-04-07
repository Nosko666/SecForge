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
# gum installer — uses sf_install_github_release_binary (with SHA-256 verify)
# ---------------------------------------------------------------------------
# Note: this pulls the *latest* gum release and verifies it against the
# upstream gum_<version>_checksums.txt file that Charmbracelet publishes on
# every release. Version pinning is handled centrally in Task 4 (install.sh,
# update-all.sh, `secforge update`), not here.
#
# To bypass verification (NOT RECOMMENDED): SECFORGE_SKIP_CHECKSUMS=1
sf_install_gum() {
  local gum_path="${SECFORGE_ROOT}/bin/gum"

  if [[ -x "${gum_path}" ]]; then
    local current_ver
    current_ver="$("${gum_path}" --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0")"
    sf_log "gum ${current_ver} already installed at ${gum_path}."
    return 0
  fi

  sf_log "Installing gum (Charmbracelet TUI) with SHA-256 verification..."
  if ! sf_install_github_release_binary "charmbracelet/gum" "gum" "${gum_path}"; then
    sf_die "Failed to install gum. To bypass verification (NOT RECOMMENDED), set SECFORGE_SKIP_CHECKSUMS=1."
  fi
  sf_log "gum installed to ${gum_path}"
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
