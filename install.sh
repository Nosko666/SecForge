#!/usr/bin/env bash
set -euo pipefail

umask 022

SECFORGE_DEST="${SECFORGE_DEST:-/opt/secforge}"
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
  local ref="$2"
  local repo_url="$3"

  if [[ -e "${dest}" && ! -d "${dest}" ]]; then
    sf_die "${dest} exists and is not a directory."
  fi

  if [[ ! -d "${dest}" ]]; then
    sf_log "Cloning SecForge into ${dest}..."
    git clone "${repo_url}" "${dest}"
    git -C "${dest}" fetch --tags origin
    sf_log "Checking out ${ref}..."
    git -C "${dest}" checkout "${ref}" || sf_die "Ref '${ref}' not found in ${repo_url}"
    return 0
  fi

  if [[ ! -d "${dest}/.git" ]]; then
    sf_die "${dest} already exists but is not a git repo. Move it aside and re-run."
  fi

  sf_log "Updating existing SecForge checkout in ${dest}..."
  git -C "${dest}" remote set-url origin "${repo_url}" >/dev/null 2>&1 || true
  git -C "${dest}" fetch --tags origin
  sf_log "Checking out ${ref}..."
  git -C "${dest}" checkout "${ref}" || sf_die "Ref '${ref}' not found"
}

# Validate that a ref string is one of: v[0-9]*, "main", or 7+ char hex SHA
sf_validate_ref() {
  local ref="$1"
  if [[ -z "${ref}" ]]; then
    return 1
  fi
  if [[ "${ref}" == "main" ]]; then
    return 0
  fi
  if [[ "${ref}" =~ ^v[0-9][0-9a-zA-Z._+-]*$ ]]; then
    return 0
  fi
  if [[ "${ref}" =~ ^[0-9a-f]{7,40}$ ]]; then
    return 0
  fi
  return 1
}

# Resolve which git ref to use, based on env var, CLI flag, and existing checkout state.
# Args: $1 = dest dir
# Reads: SECFORGE_VERSION env var (or empty)
# Outputs: ref name on stdout
# Fails if no valid ref can be determined.
sf_resolve_version() {
  local dest="$1"
  local requested="${SECFORGE_VERSION:-}"

  # Explicit request wins
  if [[ -n "${requested}" ]]; then
    if ! sf_validate_ref "${requested}"; then
      sf_die "Invalid --version '${requested}'. Use a tag (v2.0.0), 'main', or a 7+ char commit SHA."
    fi
    printf '%s' "${requested}"
    return 0
  fi

  # Existing checkout: preserve current ref if it's valid
  if [[ -d "${dest}/.git" ]]; then
    local current_tag current_branch
    current_tag="$(git -C "${dest}" describe --tags --exact-match 2>/dev/null || true)"
    if [[ -n "${current_tag}" && "${current_tag}" == v[0-9]* ]]; then
      printf '%s' "${current_tag}"
      return 0
    fi
    current_branch="$(git -C "${dest}" symbolic-ref -q --short HEAD 2>/dev/null || true)"
    if [[ "${current_branch}" == "main" ]]; then
      printf '%s' "main"
      return 0
    fi
    if [[ -n "${current_branch}" ]]; then
      sf_die "Refusing to install from branch '${current_branch}'. Run with explicit --version v2.0.0 or --version main to proceed."
    fi
    # Detached HEAD on a non-tag commit
    local current_sha
    current_sha="$(git -C "${dest}" rev-parse HEAD 2>/dev/null || true)"
    if [[ -n "${current_sha}" ]]; then
      printf '%s' "${current_sha}"
      return 0
    fi
  fi

  # Fresh install: use latest tag from the remote
  local latest_tag
  latest_tag="$(git ls-remote --tags --refs "${SECFORGE_REPO_URL}" 'v[0-9]*' 2>/dev/null \
    | awk -F'/' '{print $NF}' | sort -V | tail -n1 || true)"
  if [[ -n "${latest_tag}" ]]; then
    printf '%s' "${latest_tag}"
    return 0
  fi

  sf_die "No tagged releases found. Use --version main to install from latest commit (NOT RECOMMENDED for production)."
}

main() {
  # Parse flags
  while [[ "${#}" -gt 0 ]]; do
    case "$1" in
      --version)
        export SECFORGE_VERSION="${2:-}"
        shift 2 ;;
      --help|-h)
        cat <<EOF
Usage: install.sh [options]

Options:
  --version <ref>     Git ref to install (tag like v2.0.0, 'main', or commit SHA)
                      Default: latest tag for fresh installs, current ref for existing
  --help              Show this help

Environment:
  SECFORGE_VERSION    Same as --version
  SECFORGE_DEST       Install destination (default: /opt/secforge)
  SECFORGE_REPO_URL   Git repo URL (default: github.com/Nosko666/SecForge.git)
EOF
        exit 0 ;;
      *)
        sf_die "Unknown flag: $1 (use --help)" ;;
    esac
  done

  sf_need_root
  sf_require_ubuntu

  sf_log "SecForge installer"
  sf_log "This will clone SecForge to ${SECFORGE_DEST} and run the bootstrap."
  sf_confirm_tty "Type YES to continue:" "YES"

  sf_ensure_git
  local _ref
  _ref="$(sf_resolve_version "${SECFORGE_DEST}")"
  sf_log "Installing SecForge ref: ${_ref}"
  sf_clone_or_update_repo "${SECFORGE_DEST}" "${_ref}" "${SECFORGE_REPO_URL}"

  if [[ ! -r "${SECFORGE_DEST}/scripts/bootstrap.sh" ]]; then
    sf_die "Missing ${SECFORGE_DEST}/scripts/bootstrap.sh after clone. Repo may be incomplete."
  fi

  sf_log "Running bootstrap..."
  export SECFORGE_ROOT="${SECFORGE_DEST}"
  bash "${SECFORGE_DEST}/scripts/bootstrap.sh"

  sf_log ""
  sf_log "Bootstrap complete. To install security tools:"
  sf_log "  secforge install --list    (see available tools)"
  sf_log "  secforge install --all     (install everything)"
  sf_log ""
  sf_log "Or let Claude/Codex handle it:"
  sf_log "  secforge init              (guided setup)"
}

main "$@"

