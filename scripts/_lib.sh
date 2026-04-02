#!/usr/bin/env bash

sf_log() { printf '[secforge] %s\n' "$*"; }
sf_warn() { printf '[secforge] WARN: %s\n' "$*" >&2; }
sf_die() { printf '[secforge] ERROR: %s\n' "$*" >&2; exit 1; }

sf_need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    sf_die "This script must run as root."
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

sf_prompt_tty() {
  local prompt="$1"
  local default_value="${2:-}"
  local reply=""

  if [[ ! -r /dev/tty ]]; then
    sf_die "No TTY available for input."
  fi

  if [[ -n "${default_value}" ]]; then
    read -r -p "${prompt} [${default_value}]: " reply < /dev/tty || true
    printf '%s' "${reply:-${default_value}}"
    return 0
  fi

  read -r -p "${prompt}: " reply < /dev/tty || true
  printf '%s' "${reply}"
}

sf_ask_tty_yes() {
  local prompt="$1"
  local expected="${2:-YES}"
  local reply=""

  if [[ "${SECFORGE_ASSUME_YES:-0}" == "1" ]]; then
    return 0
  fi

  if [[ ! -r /dev/tty ]]; then
    return 1
  fi

  read -r -p "${prompt} " reply < /dev/tty || true
  [[ "${reply}" == "${expected}" ]]
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
  if [[ "$(printf '%s\n' "20.04" "${version_id}" | sort -V | head -n1)" != "20.04" ]]; then
    sf_die "Unsupported Ubuntu version (${version_id}). Require 20.04+."
  fi
}

sf_has_cmd() { command -v "$1" >/dev/null 2>&1; }

sf_version_ge() {
  # Usage: sf_version_ge <have> <need>
  local have="$1"
  local need="$2"
  [[ "$(printf '%s\n' "${need}" "${have}" | sort -V | head -n1)" == "${need}" ]]
}

sf_python_major_minor() {
  python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
}

sf_detect_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
    x86_64) printf 'amd64' ;;
    aarch64 | arm64) printf 'arm64' ;;
    *) sf_die "Unsupported architecture: ${machine}" ;;
  esac
}

sf_apt_update() {
  if [[ "${SECFORGE_APT_UPDATED:-0}" == "1" ]]; then
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  SECFORGE_APT_UPDATED="1"
}

sf_apt_install() {
  sf_apt_update
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y --no-install-recommends "$@"
}

sf_git_clone_or_update() {
  local repo_url="$1"
  local dest_dir="$2"
  local branch="${3:-}"

  if [[ -d "${dest_dir}/.git" ]]; then
    sf_log "Updating ${dest_dir}..."
    git -C "${dest_dir}" fetch --depth 1 origin "${branch:-HEAD}" || true
    if [[ -n "${branch}" ]]; then
      git -C "${dest_dir}" checkout -q "${branch}" || true
      git -C "${dest_dir}" pull --ff-only origin "${branch}" || true
    else
      git -C "${dest_dir}" pull --ff-only || true
    fi
    return 0
  fi

  if [[ -e "${dest_dir}" && ! -d "${dest_dir}" ]]; then
    sf_warn "Skipping clone: ${dest_dir} exists and is not a directory."
    return 1
  fi

  sf_log "Cloning ${repo_url} into ${dest_dir}..."
  if [[ -n "${branch}" ]]; then
    git clone --depth 1 --branch "${branch}" "${repo_url}" "${dest_dir}"
  else
    git clone --depth 1 "${repo_url}" "${dest_dir}"
  fi
}

sf_ensure_group() {
  local group_name="$1"
  if getent group "${group_name}" >/dev/null 2>&1; then
    return 0
  fi
  groupadd --system "${group_name}"
}

sf_add_user_to_group() {
  local user="$1"
  local group="$2"

  if [[ -z "${user}" || "${user}" == "root" ]]; then
    return 0
  fi

  if id -nG "${user}" | tr ' ' '\n' | grep -qx "${group}"; then
    return 0
  fi

  usermod -aG "${group}" "${user}"
}

sf_get_invoking_user() {
  if [[ -n "${SUDO_USER:-}" ]]; then
    printf '%s' "${SUDO_USER}"
    return 0
  fi
  if sf_has_cmd logname; then
    logname 2>/dev/null || true
    return 0
  fi
  printf ''
}

sf_ensure_profile_d_path() {
  local secforge_root="$1"
  local profile_path="/etc/profile.d/secforge.sh"

  if [[ -r "${profile_path}" ]] && grep -Fqx "export PATH=\"${secforge_root}/bin:\$PATH\"" "${profile_path}"; then
    return 0
  fi

  cat >"${profile_path}" <<EOF
# Added by SecForge
if [ -d "${secforge_root}/bin" ]; then
  export PATH="${secforge_root}/bin:\$PATH"
fi
EOF
  chmod 0644 "${profile_path}"
}

sf_ensure_runtime_layout() {
  local secforge_root="$1"
  local group_name="$2"

  sf_ensure_group "${group_name}"

  mkdir -p \
    "${secforge_root}/reports" \
    "${secforge_root}/backups" \
    "${secforge_root}/tools" \
    "${secforge_root}/wordlists" \
    "${secforge_root}/bin" \
    "${secforge_root}/logs"

  # Keep code/scripts root-owned; allow non-root scans to write only where needed.
  chown root:root "${secforge_root}" "${secforge_root}/bin" "${secforge_root}/logs" 2>/dev/null || true
  chmod 0755 "${secforge_root}" "${secforge_root}/bin" 2>/dev/null || true
  chmod 0750 "${secforge_root}/logs" 2>/dev/null || true

  chown -R root:"${group_name}" "${secforge_root}/reports" "${secforge_root}/backups" 2>/dev/null || true
  chmod 3775 "${secforge_root}/reports"
  chmod 2750 "${secforge_root}/backups"

  chown -R root:root "${secforge_root}/tools" "${secforge_root}/wordlists" 2>/dev/null || true
  chmod 0755 "${secforge_root}/tools" "${secforge_root}/wordlists"
}

sf_ensure_config_files() {
  local secforge_root="$1"
  local group_name="$2"
  local example_cfg="${secforge_root}/config/secforge.conf.example"
  local cfg="${secforge_root}/config/secforge.conf"
  local auth_file="${secforge_root}/config/.authorized_targets"

  mkdir -p "${secforge_root}/config"
  chown root:"${group_name}" "${secforge_root}/config" 2>/dev/null || true
  chmod 2755 "${secforge_root}/config"

  if [[ ! -r "${example_cfg}" ]]; then
    sf_warn "Missing ${example_cfg}. Skipping config initialization."
    return 0
  fi

  if [[ ! -e "${cfg}" ]]; then
    sf_log "Creating runtime config ${cfg} from template..."
    cp "${example_cfg}" "${cfg}"
  fi
  chown root:"${group_name}" "${cfg}" 2>/dev/null || true
  chmod 0664 "${cfg}" 2>/dev/null || true

  if [[ ! -e "${auth_file}" ]]; then
    : >"${auth_file}"
  fi
  chown root:"${group_name}" "${auth_file}" 2>/dev/null || true
  chmod 0664 "${auth_file}" 2>/dev/null || true
}

sf_ensure_venv() {
  local venv_dir="$1"

  if [[ -x "${venv_dir}/bin/python" ]]; then
    return 0
  fi

  python3 -m venv "${venv_dir}"
  "${venv_dir}/bin/pip" install --upgrade pip setuptools wheel
}

sf_install_venv_packages() {
  local venv_dir="$1"
  shift

  if [[ ! -x "${venv_dir}/bin/pip" ]]; then
    sf_die "Missing venv at ${venv_dir}."
  fi

  "${venv_dir}/bin/pip" install --upgrade "$@"
}

sf_ln_sf() {
  local target="$1"
  local link_path="$2"
  mkdir -p "$(dirname -- "${link_path}")"
  ln -sf "${target}" "${link_path}"
}

sf_mktemp_dir() {
  mktemp -d -t secforge.XXXXXX
}

sf_curl() {
  curl -fsSL --retry 3 --retry-delay 1 "$@"
}

sf_github_latest_release_json() {
  local repo="$1"
  sf_curl "https://api.github.com/repos/${repo}/releases/latest"
}

sf_github_select_linux_asset_url() {
  local repo="$1"
  local arch="$2"
  local arch_re

  case "${arch}" in
    amd64) arch_re='(amd64|x86_64|x64|64bit|64-bit)' ;;
    arm64) arch_re='(arm64|aarch64)' ;;
    *) sf_die "Unsupported arch for GitHub asset selection: ${arch}" ;;
  esac

  # Prefer assets that look like actual binaries/archives, not checksums/SBOM/signatures/sources.
  sf_github_latest_release_json "${repo}" | jq -r --arg arch_re "${arch_re}" '
    .assets[]
    | select(.name | test("linux|Linux"; "i"))
    | select(.name | test($arch_re; "i"))
    | select(.name | test("sha256|checksum|checksums|sbom|signature|\\.sig$|\\.asc$|source|src|\\.txt$|\\.json$"; "i") | not)
    | .browser_download_url
  ' | head -n1
}

sf_extract_archive_to_dir() {
  local archive_path="$1"
  local dest_dir="$2"

  mkdir -p "${dest_dir}"

  # Use Python for both formats with path traversal protection (zip slip / tar traversal).
  python3 - "${archive_path}" "${dest_dir}" <<'PY'
import os, sys, tarfile, zipfile

archive = sys.argv[1]
dest = os.path.realpath(sys.argv[2])

def safe_path(member_name, dest_dir):
    target = os.path.realpath(os.path.join(dest_dir, member_name))
    if not target.startswith(dest_dir + os.sep) and target != dest_dir:
        raise ValueError(f"Path traversal detected: {member_name}")
    return target

if archive.endswith(('.tar.gz', '.tgz')):
    with tarfile.open(archive, 'r:gz') as tf:
        for m in tf.getmembers():
            safe_path(m.name, dest)
            if m.issym() or m.islnk():
                continue  # skip symlinks/hardlinks for safety
        for m in tf.getmembers():
            if m.issym() or m.islnk():
                continue
            safe_path(m.name, dest)
            tf.extract(m, dest, set_attrs=False)
elif archive.endswith('.zip'):
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            target = safe_path(info.filename, dest)
            # Skip symlinks in zip (external_attr check) and directory traversal
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            # Ensure parent dir exists and is not a symlink
            parent = os.path.dirname(target)
            os.makedirs(parent, exist_ok=True)
            if os.path.islink(parent):
                raise ValueError(f"Parent is a symlink: {parent}")
            with zf.open(info) as src, open(target, 'wb') as dst:
                import shutil
                shutil.copyfileobj(src, dst)
else:
    print(f"Unsupported archive: {archive}", file=sys.stderr)
    sys.exit(1)
PY
}

sf_install_github_release_binary() {
  local repo="$1"
  local expected_binary="$2"
  local install_path="$3"

  if [[ -x "${install_path}" ]]; then
    return 0
  fi

  if ! sf_has_cmd jq; then
    sf_die "jq is required for GitHub binary installs."
  fi

  local arch url tmp archive extract_dir found
  arch="$(sf_detect_arch)"
  url="$(sf_github_select_linux_asset_url "${repo}" "${arch}")"
  if [[ -z "${url}" || "${url}" == "null" ]]; then
    sf_warn "No suitable Linux ${arch} asset found for ${repo}."
    return 1
  fi

  tmp="$(sf_mktemp_dir)"
  archive="${tmp}/$(basename -- "${url}")"
  extract_dir="${tmp}/extract"

  sf_log "Downloading ${repo} release asset..."
  sf_curl -o "${archive}" "${url}"

  mkdir -p "$(dirname -- "${install_path}")"

  if [[ "${archive}" == *.tar.gz || "${archive}" == *.tgz || "${archive}" == *.zip ]]; then
    sf_extract_archive_to_dir "${archive}" "${extract_dir}"
    found="$(find "${extract_dir}" -maxdepth 4 -type f \( -name "${expected_binary}" \) -print | head -n1 || true)"
    if [[ -z "${found}" ]]; then
      found="$(find "${extract_dir}" -maxdepth 4 -type f -perm -111 -name "${expected_binary}*" | head -n1 || true)"
    fi
    if [[ -z "${found}" ]]; then
      sf_warn "Could not locate ${expected_binary} in ${repo} asset (skipping)."
      rm -rf "${tmp}"
      return 1
    fi
    install -m 0755 "${found}" "${install_path}"
  else
    install -m 0755 "${archive}" "${install_path}"
  fi

  rm -rf "${tmp}"
}

sf_download_wordlists() {
  local secforge_root="$1"
  local dst="${secforge_root}/wordlists"

  mkdir -p "${dst}"

  sf_log "Downloading curated wordlists (SecLists subset)..."

  # Note: keep names stable for scripts.
  sf_curl -o "${dst}/common.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" || sf_warn "Failed to download common.txt"
  sf_curl -o "${dst}/directories.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt" || sf_warn "Failed to download directories.txt"
  sf_curl -o "${dst}/passwords-top1000.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" || sf_warn "Failed to download passwords-top1000.txt"
  sf_curl -o "${dst}/api-routes.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" || sf_warn "Failed to download api-routes.txt"
}

sf_cfg_get_value() {
  local cfg_file="$1"
  local key="$2"

  if [[ ! -r "${cfg_file}" ]]; then
    return 1
  fi

  awk -F= -v k="${key}" '
    $1==k {
      v=$0
      sub(/^[^=]+=/, "", v)
      sub(/^"/, "", v)
      sub(/"$/, "", v)
      print v
      exit
    }
  ' "${cfg_file}"
}

sf_cfg_set_value() {
  local cfg_file="$1"
  local key="$2"
  local value="$3"

  # Validate key is safe (alphanumeric + underscore only).
  if ! [[ "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    sf_warn "sf_cfg_set_value: refusing unsafe key: ${key}"
    return 1
  fi

  # Reject values with newlines (prevents injection).
  # Note: bash strings cannot contain NUL bytes, so no NUL check is needed.
  if [[ "${value}" == *$'\n'* ]]; then
    sf_warn "sf_cfg_set_value: refusing value with newlines for key ${key}"
    return 1
  fi

  if [[ ! -e "${cfg_file}" ]]; then
    mkdir -p "$(dirname -- "${cfg_file}")"
    local example="${cfg_file}.example"
    if [[ -r "${example}" ]]; then
      cp "${example}" "${cfg_file}"
    else
      : >"${cfg_file}"
    fi
  fi

  # Use Python for safe key=value replacement (no sed injection risk).
  SF_CFG_FILE="${cfg_file}" SF_CFG_KEY="${key}" SF_CFG_VALUE="${value}" \
  python3 - <<'PY'
import os
cfg = os.environ["SF_CFG_FILE"]
key = os.environ["SF_CFG_KEY"]
val = os.environ["SF_CFG_VALUE"]
lines = []
found = False
try:
    with open(cfg, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
except FileNotFoundError:
    pass
out = []
for line in lines:
    stripped = line.rstrip("\n\r")
    if stripped.startswith(key + "="):
        out.append(f'{key}="{val}"\n')
        found = True
    else:
        out.append(line if line.endswith("\n") else line + "\n")
if not found:
    if out and not out[-1].endswith("\n"):
        out.append("\n")
    out.append(f'{key}="{val}"\n')
with open(cfg, "w", encoding="utf-8") as f:
    f.writelines(out)
PY
}

sf_cfg_add_list_item() {
  local cfg_file="$1"
  local key="$2"
  local item="$3"

  local cur
  cur="$(sf_cfg_get_value "${cfg_file}" "${key}" || true)"

  if [[ " ${cur} " == *" ${item} "* ]]; then
    return 0
  fi

  local next="${cur}"
  if [[ -n "${next}" ]]; then
    next="${next} ${item}"
  else
    next="${item}"
  fi

  sf_cfg_set_value "${cfg_file}" "${key}" "${next}"
}
