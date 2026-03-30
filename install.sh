#!/usr/bin/env bash
set -euo pipefail

umask 022

SECFORGE_DEST="${SECFORGE_DEST:-/opt/secforge}"
SECFORGE_BRANCH="${SECFORGE_BRANCH:-main}"
SECFORGE_REPO_URL_DEFAULT="https://github.com/Nosko666/SecForge.git"
SECFORGE_REPO_URL="${SECFORGE_REPO_URL:-$SECFORGE_REPO_URL_DEFAULT}"

sf_log() { printf '[secforge] %s\n' "$*"; }
sf_warn() { printf '[secforge] WARN: %s\n' "$*" >&2; }
sf_die() { printf '[secforge] ERROR: %s\n' "$*" >&2; exit 1; }

sf_need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    sf_die "This installer must run as root. Try: curl -sSL ... | sudo bash"
  fi
}

sf_confirm_tty() {
  local prompt="$1"
  local expected="${2:-YES}"
  local reply=""

  if [[ "${SECFORGE_ASSUME_YES:-0}" == "1" ]]; then
    return 0
  fi

  if [[ ! -r /dev/tty ]]; then
    sf_die "No TTY available for confirmation. Re-run with SECFORGE_ASSUME_YES=1 to skip prompts."
  fi

  read -r -p "${prompt} " reply < /dev/tty || true
  if [[ "${reply}" != "${expected}" ]]; then
    sf_die "Aborted."
  fi
}

sf_require_ubuntu() {
  if [[ ! -r /etc/os-release ]]; then
    sf_die "Cannot detect OS version (/etc/os-release missing)."
  fi

  # shellcheck disable=SC1091
  . /etc/os-release

  if [[ "${ID:-}" != "ubuntu" ]]; then
    sf_die "Unsupported OS (expected Ubuntu). Detected: ${ID:-unknown}"
  fi

  local version_id="${VERSION_ID:-0}"
  # Require Ubuntu 20.04+
  if [[ "$(printf '%s\n' "20.04" "${version_id}" | sort -V | head -n1)" != "20.04" ]]; then
    sf_die "Unsupported Ubuntu version (${version_id}). Require 20.04+."
  fi
}

sf_ensure_git() {
  if command -v git >/dev/null 2>&1; then
    return 0
  fi

  sf_log "Installing git (required for SecForge install)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends ca-certificates git
}

sf_clone_or_update_repo() {
  local dest="$1"
  local branch="$2"
  local repo_url="$3"

  if [[ -e "${dest}" && ! -d "${dest}" ]]; then
    sf_die "${dest} exists and is not a directory."
  fi

  if [[ ! -d "${dest}" ]]; then
    sf_log "Cloning SecForge into ${dest}..."
    git clone --depth 1 --branch "${branch}" "${repo_url}" "${dest}"
    return 0
  fi

  if [[ ! -d "${dest}/.git" ]]; then
    sf_die "${dest} already exists but is not a git repo. Move it aside and re-run."
  fi

  sf_log "Updating existing SecForge checkout in ${dest}..."
  if ! git -C "${dest}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    sf_die "${dest} is not a valid git working tree."
  fi

  # Best-effort: keep origin pointed at the requested repo (supports forks via SECFORGE_REPO_URL).
  git -C "${dest}" remote set-url origin "${repo_url}" >/dev/null 2>&1 || true

  git -C "${dest}" fetch --depth 1 origin "${branch}"
  git -C "${dest}" checkout -q "${branch}"
  if ! git -C "${dest}" pull --ff-only origin "${branch}"; then
    sf_die "Could not fast-forward update ${dest}. Resolve local changes, then re-run."
  fi
}

main() {
  sf_need_root
  sf_require_ubuntu

  sf_log "SecForge bootstrap installer"
  sf_log "This will install packages (apt), create/update ${SECFORGE_DEST}, and run the menu installer."
  sf_confirm_tty "Type YES to continue:" "YES"

  sf_ensure_git
  sf_clone_or_update_repo "${SECFORGE_DEST}" "${SECFORGE_BRANCH}" "${SECFORGE_REPO_URL}"

  if [[ ! -r "${SECFORGE_DEST}/scripts/install.sh" ]]; then
    sf_die "Missing ${SECFORGE_DEST}/scripts/install.sh after clone. Repo may be incomplete."
  fi

  sf_log "Starting SecForge menu installer..."
  exec bash "${SECFORGE_DEST}/scripts/install.sh"
}

main "$@"

