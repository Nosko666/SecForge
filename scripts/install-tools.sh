#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SECFORGE_ROOT="${SECFORGE_ROOT:-$DEFAULT_ROOT}"
SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE:-${SECFORGE_ROOT}/config/secforge.conf}"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

TOOLS_JSON="${SECFORGE_ROOT}/catalog/tools.json"

# ── Usage ────────────────────────────────────────────────────────────

usage() {
  cat >&2 <<EOF
Usage:
  ${0##*/} --list                   Show all tools with installed/available status
  ${0##*/} --all                    Install all non-builtin tools (requires root)
  ${0##*/} --from-selection <file>  Install tool IDs listed in file (requires root)
  ${0##*/} <tool> [tool...]         Install one or more tools by ID (requires root)

Aliases are normalized automatically (e.g. "testssl.sh" → "testssl").
EOF
}

# ── Alias normalization ──────────────────────────────────────────────
# Hardcoded known aliases + dynamic aliases from tools.json (via Python).

normalize_alias() {
  local input="$1"

  # Hardcoded aliases (fast path)
  case "${input}" in
    emaildns|email-dns|email|dns) printf 'check-email-dns'; return 0 ;;
    mysql)                        printf 'check-mysql';     return 0 ;;
    builtin)                      printf 'secforge-builtin'; return 0 ;;
    interactsh-client)            printf 'interactsh';      return 0 ;;
    jwt-tool|jwttool)             printf 'jwt_tool';        return 0 ;;
    nxc)                          printf 'netexec';         return 0 ;;
    stripe)                       printf 'stripe-check';    return 0 ;;
    testssl.sh)                   printf 'testssl';         return 0 ;;
  esac

  # Check if input is already a canonical tool ID by asking Python
  # (also checks aliases field in tools.json)
  SF_INPUT="${input}" SF_TOOLS_JSON="${TOOLS_JSON}" python3 - <<'PY'
import json, os, sys

inp = os.environ["SF_INPUT"]
tools_path = os.environ["SF_TOOLS_JSON"]

try:
    with open(tools_path, "r", encoding="utf-8") as f:
        catalog = json.load(f)
except Exception:
    # Can't read catalog; pass through unchanged
    print(inp, end="")
    sys.exit(0)

catalog.pop("_meta", None)

# Direct match on canonical ID
if inp in catalog:
    print(inp, end="")
    sys.exit(0)

# Search aliases field in each tool
for tool_id, tdata in catalog.items():
    aliases = tdata.get("aliases", [])
    if inp in aliases:
        print(tool_id, end="")
        sys.exit(0)

# No match found — pass through unchanged
print(inp, end="")
PY
}

# ── Installedness check (Python, reusable) ───────────────────────────
# Outputs "installed", "available", "missing", or "builtin" to stdout.

check_tool_status() {
  local tool_id="$1"

  SF_TOOL_ID="${tool_id}" SF_TOOLS_JSON="${TOOLS_JSON}" SF_ROOT="${SECFORGE_ROOT}" \
  python3 - <<'PY'
import json, os, shutil, sys

tool_id = os.environ["SF_TOOL_ID"]
tools_path = os.environ["SF_TOOLS_JSON"]
sf_root = os.environ["SF_ROOT"]

try:
    with open(tools_path, "r", encoding="utf-8") as f:
        catalog = json.load(f)
except Exception:
    print("unknown", end="")
    sys.exit(0)

catalog.pop("_meta", None)

tdata = catalog.get(tool_id)
if tdata is None:
    print("unknown", end="")
    sys.exit(0)

if tdata.get("install_method") == "builtin":
    # Builtins: check path/command but label as "builtin"
    check = tdata.get("check", {})
    check_path = check.get("path", "")
    check_cmd = check.get("command", "")
    ok = True
    if check_cmd:
        bin_path = os.path.join(sf_root, "bin", check_cmd)
        if not (os.path.isfile(bin_path) and os.access(bin_path, os.X_OK)) and shutil.which(check_cmd) is None:
            ok = False
    if check_path:
        full = os.path.join(sf_root, check_path) if not os.path.isabs(check_path) else check_path
        if not os.path.exists(full):
            ok = False
    # Check requires_commands
    for rc in tdata.get("requires_commands", []):
        bin_path = os.path.join(sf_root, "bin", rc)
        if not (os.path.isfile(bin_path) and os.access(bin_path, os.X_OK)) and shutil.which(rc) is None:
            ok = False
            break
    print("builtin" if ok else "missing", end="")
    sys.exit(0)


def cmd_exists(cmd):
    bin_path = os.path.join(sf_root, "bin", cmd)
    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return True
    return shutil.which(cmd) is not None


def path_exists(rel_path):
    full = os.path.join(sf_root, rel_path) if not os.path.isabs(rel_path) else rel_path
    return os.path.exists(full)


installed = True
check = tdata.get("check", {})
check_cmd = check.get("command", "")
check_path = check.get("path", "")

if check_cmd and not cmd_exists(check_cmd):
    installed = False
if check_path and not path_exists(check_path):
    installed = False

# Check depends_on
if installed:
    for dep_id in tdata.get("depends_on", []):
        dep_data = catalog.get(dep_id, {})
        dep_check = dep_data.get("check", {})
        dep_cmd = dep_check.get("command", "")
        dep_path = dep_check.get("path", "")
        if dep_cmd and not cmd_exists(dep_cmd):
            installed = False
            break
        if dep_path and not path_exists(dep_path):
            installed = False
            break

# Check requires_commands
if installed:
    for rc in tdata.get("requires_commands", []):
        if not cmd_exists(rc):
            installed = False
            break

if installed:
    print("installed", end="")
else:
    # Check if missing requires_commands → "missing" vs "available"
    missing_reqs = []
    for rc in tdata.get("requires_commands", []):
        if not cmd_exists(rc):
            missing_reqs.append(rc)
    if missing_reqs:
        print("missing", end="")
    else:
        print("available", end="")
PY
}

# ── --list: Show all tools with status ───────────────────────────────

do_list() {
  SF_TOOLS_JSON="${TOOLS_JSON}" SF_ROOT="${SECFORGE_ROOT}" \
  python3 - <<'PY'
import json, os, shutil, sys

tools_path = os.environ["SF_TOOLS_JSON"]
sf_root = os.environ["SF_ROOT"]

try:
    with open(tools_path, "r", encoding="utf-8") as f:
        catalog = json.load(f)
except Exception as e:
    print(f"[secforge] ERROR: Cannot read {tools_path}: {e}", file=sys.stderr)
    sys.exit(1)

catalog.pop("_meta", None)


def cmd_exists(cmd):
    bin_path = os.path.join(sf_root, "bin", cmd)
    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return True
    return shutil.which(cmd) is not None


def path_exists(rel_path):
    full = os.path.join(sf_root, rel_path) if not os.path.isabs(rel_path) else rel_path
    return os.path.exists(full)


def check_installed(tool_id, tdata):
    """Returns (status, missing_reqs)."""
    method = tdata.get("install_method", "")

    check = tdata.get("check", {})
    check_cmd = check.get("command", "")
    check_path = check.get("path", "")

    if method == "builtin":
        ok = True
        missing = []
        if check_cmd and not cmd_exists(check_cmd):
            ok = False
        if check_path and not path_exists(check_path):
            ok = False
        for rc in tdata.get("requires_commands", []):
            if not cmd_exists(rc):
                ok = False
                missing.append(rc)
        return ("BUILTIN" if ok else "MISSING", missing)

    installed = True
    if check_cmd and not cmd_exists(check_cmd):
        installed = False
    if check_path and not path_exists(check_path):
        installed = False

    # depends_on
    if installed:
        for dep_id in tdata.get("depends_on", []):
            dep_data = catalog.get(dep_id, {})
            dep_check = dep_data.get("check", {})
            dep_cmd = dep_check.get("command", "")
            dep_path = dep_check.get("path", "")
            if dep_cmd and not cmd_exists(dep_cmd):
                installed = False
                break
            if dep_path and not path_exists(dep_path):
                installed = False
                break

    # requires_commands
    missing_reqs = []
    if installed:
        for rc in tdata.get("requires_commands", []):
            if not cmd_exists(rc):
                installed = False
                missing_reqs.append(rc)

    if installed:
        return ("INSTALLED", [])

    # Distinguish "available" (can install) from "missing" (requires_commands absent)
    if missing_reqs:
        return ("MISSING", missing_reqs)
    return ("AVAILABLE", [])


# Compute max tool_id length for alignment
max_id_len = max(len(tid) for tid in catalog) if catalog else 10

# Sort by tier then name
sorted_tools = sorted(catalog.items(), key=lambda x: (x[1].get("tier", 99), x[0]))

counts = {"INSTALLED": 0, "AVAILABLE": 0, "MISSING": 0, "BUILTIN": 0}

for tool_id, tdata in sorted_tools:
    status, missing_reqs = check_installed(tool_id, tdata)
    counts[status] = counts.get(status, 0) + 1

    tier = tdata.get("tier", "?")
    desc = tdata.get("description", "")

    # Pad tool_id for alignment
    padded_id = tool_id.ljust(max_id_len)

    extra = ""
    if missing_reqs:
        extra = f" [requires: {', '.join(missing_reqs)}]"

    # Color-code status
    status_str = f"  {status:10s}"
    print(f"{status_str}{padded_id} — {desc} (Tier {tier}){extra}")

# Summary line
total = sum(counts.values())
print(f"\n  Total: {total} tools — "
      f"{counts['INSTALLED']} installed, "
      f"{counts['AVAILABLE']} available, "
      f"{counts['MISSING']} missing, "
      f"{counts['BUILTIN']} builtin")
PY
}

# ── Read tool metadata from tools.json ───────────────────────────────
# Outputs key=value pairs for bash to eval (safe — values are validated).

read_tool_meta() {
  local tool_id="$1"

  SF_TOOL_ID="${tool_id}" SF_TOOLS_JSON="${TOOLS_JSON}" SF_ROOT="${SECFORGE_ROOT}" \
  python3 - <<'PY'
import json, os, sys

tool_id = os.environ["SF_TOOL_ID"]
tools_path = os.environ["SF_TOOLS_JSON"]
sf_root = os.environ["SF_ROOT"]

try:
    with open(tools_path, "r", encoding="utf-8") as f:
        catalog = json.load(f)
except Exception as e:
    print(f"ERROR=cannot_read_catalog", end="")
    sys.exit(1)

catalog.pop("_meta", None)
tdata = catalog.get(tool_id)

if tdata is None:
    print("ERROR=unknown_tool")
    sys.exit(1)


def safe_val(s):
    """Escape for bash single-quote eval."""
    return str(s).replace("'", "'\\''")


method = tdata.get("install_method", "")
print(f"TOOL_TITLE='{safe_val(tdata.get('title', tool_id))}'")
print(f"TOOL_METHOD='{safe_val(method)}'")
print(f"TOOL_TIER='{safe_val(tdata.get('tier', 1))}'")

# apt
apt_pkgs = tdata.get("apt_packages", [])
print(f"TOOL_APT_PACKAGES='{safe_val(' '.join(apt_pkgs))}'")

# github_release
print(f"TOOL_REPO='{safe_val(tdata.get('repo', ''))}'")
print(f"TOOL_EXPECTED_BINARY='{safe_val(tdata.get('expected_binary', ''))}'")
print(f"TOOL_VERIFY_MODE='{safe_val((tdata.get('verify') or {}).get('mode', 'sha256'))}'")

# git_clone
print(f"TOOL_DEST_PATH='{safe_val(tdata.get('dest_path', ''))}'")

# pip_venv
pip_pkg = tdata.get("pip_package", "")
pip_pkgs_list = tdata.get("pip_packages", [])
if pip_pkg and not pip_pkgs_list:
    pip_pkgs_list = [pip_pkg]
print(f"TOOL_PIP_PACKAGES='{safe_val(' '.join(pip_pkgs_list))}'")

# npm_local
print(f"TOOL_NPM_PACKAGE='{safe_val(tdata.get('npm_package', ''))}'")
print(f"TOOL_NPM_DEST='{safe_val(tdata.get('dest_path', ''))}'")

# custom
print(f"TOOL_CUSTOM_FUNCTION='{safe_val(tdata.get('custom_function', ''))}'")

# check
check = tdata.get("check", {})
print(f"TOOL_CHECK_COMMAND='{safe_val(check.get('command', ''))}'")
print(f"TOOL_CHECK_PATH='{safe_val(check.get('path', ''))}'")

# depends_on
depends = tdata.get("depends_on", [])
print(f"TOOL_DEPENDS_ON='{safe_val(' '.join(depends))}'")

# requires_commands
req_cmds = tdata.get("requires_commands", [])
print(f"TOOL_REQUIRES_COMMANDS='{safe_val(' '.join(req_cmds))}'")

# custom install instructions (for custom method)
instructions = tdata.get("install", {}).get("instructions", "")
if not instructions:
    instructions = tdata.get("instructions", "")
print(f"TOOL_INSTRUCTIONS='{safe_val(instructions)}'")
PY
}

# ── Custom install functions ──────────────────────────────────────────
# Called by the "custom" install method dispatch. Each function is
# self-contained, using only _lib.sh helpers (already sourced).

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
  sf_extract_archive_to_dir "${archive}" "${extract_dir}"

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

install_xsstrike() {
  sf_git_clone_or_update "https://github.com/s0md3v/XSStrike.git" "${SECFORGE_ROOT}/tools/xsstrike"
  local venv="${SECFORGE_ROOT}/venv/xsstrike"
  sf_ensure_venv "${venv}"
  if [[ -r "${SECFORGE_ROOT}/tools/xsstrike/requirements.txt" ]]; then
    sf_install_venv_packages "${venv}" -r "${SECFORGE_ROOT}/tools/xsstrike/requirements.txt" || sf_warn "XSStrike deps failed (continuing)."
  fi
  if [[ -r "${SECFORGE_ROOT}/tools/xsstrike/xsstrike.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/xsstrike" <<XEOF
#!/usr/bin/env bash
exec "${venv}/bin/python" "${SECFORGE_ROOT}/tools/xsstrike/xsstrike.py" "\$@"
XEOF
    chmod 0755 "${SECFORGE_ROOT}/bin/xsstrike"
  fi
}

install_corscanner() {
  sf_git_clone_or_update "https://github.com/chenjj/CORScanner.git" "${SECFORGE_ROOT}/tools/corscanner"
  local venv="${SECFORGE_ROOT}/venv/corscanner"
  sf_ensure_venv "${venv}"
  if [[ -r "${SECFORGE_ROOT}/tools/corscanner/requirements.txt" ]]; then
    sf_install_venv_packages "${venv}" -r "${SECFORGE_ROOT}/tools/corscanner/requirements.txt" || sf_warn "CORScanner deps failed (continuing)."
  fi
  local cors_entry
  cors_entry="$(find "${SECFORGE_ROOT}/tools/corscanner" -maxdepth 2 -type f \( -iname '*cors*scanner*.py' -o -iname 'corscanner.py' -o -iname 'cors_scan.py' \) 2>/dev/null | head -n1 || true)"
  if [[ -n "${cors_entry}" ]]; then
    cat >"${SECFORGE_ROOT}/bin/corscanner" <<CEOF
#!/usr/bin/env bash
exec "${venv}/bin/python" "${cors_entry}" "\$@"
CEOF
    chmod 0755 "${SECFORGE_ROOT}/bin/corscanner"
  else
    sf_warn "CORScanner cloned but entrypoint not found; leaving in tools/ for manual use."
  fi
}

install_commix() {
  sf_git_clone_or_update "https://github.com/commixproject/commix.git" "${SECFORGE_ROOT}/tools/commix"
  if [[ -r "${SECFORGE_ROOT}/tools/commix/commix.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/commix" <<MEOF
#!/usr/bin/env bash
exec python3 "${SECFORGE_ROOT}/tools/commix/commix.py" "\$@"
MEOF
    chmod 0755 "${SECFORGE_ROOT}/bin/commix"
  fi
}

install_jwt_tool() {
  sf_git_clone_or_update "https://github.com/ticarpi/jwt_tool.git" "${SECFORGE_ROOT}/tools/jwt_tool"
  local venv="${SECFORGE_ROOT}/venv/jwt_tool"
  sf_ensure_venv "${venv}"
  if [[ -r "${SECFORGE_ROOT}/tools/jwt_tool/requirements.txt" ]]; then
    sf_install_venv_packages "${venv}" -r "${SECFORGE_ROOT}/tools/jwt_tool/requirements.txt" || sf_warn "jwt_tool deps failed (continuing)."
  fi
  if [[ -r "${SECFORGE_ROOT}/tools/jwt_tool/jwt_tool.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/jwt_tool" <<JEOF
#!/usr/bin/env bash
exec "${venv}/bin/python" "${SECFORGE_ROOT}/tools/jwt_tool/jwt_tool.py" "\$@"
JEOF
    chmod 0755 "${SECFORGE_ROOT}/bin/jwt_tool"
  fi
}

install_netexec() {
  sf_apt_install python3-dev build-essential libffi-dev libssl-dev
  local nxc_venv="${SECFORGE_ROOT}/venvs/netexec"
  sf_git_clone_or_update "https://github.com/Pennyw0rth/NetExec.git" "${SECFORGE_ROOT}/tools/netexec"
  if [[ -d "${SECFORGE_ROOT}/tools/netexec" ]]; then
    sf_log "Installing NetExec into dedicated venv (best-effort)..."
    python3 -m venv "${nxc_venv}" 2>/dev/null || true
    if [[ -x "${nxc_venv}/bin/pip" ]]; then
      "${nxc_venv}/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
      "${nxc_venv}/bin/pip" install -e "${SECFORGE_ROOT}/tools/netexec" >/dev/null 2>&1 || sf_warn "NetExec install failed (best-effort; leaving repo for manual setup)."
    fi
  fi

  if [[ -x "${nxc_venv}/bin/nxc" ]]; then
    cat >"${SECFORGE_ROOT}/bin/nxc" <<NEOF
#!/usr/bin/env bash
exec "${nxc_venv}/bin/nxc" "\$@"
NEOF
    chmod 0755 "${SECFORGE_ROOT}/bin/nxc"
  elif command -v nxc >/dev/null 2>&1; then
    sf_ln_sf "$(command -v nxc)" "${SECFORGE_ROOT}/bin/nxc"
  else
    sf_warn "NetExec binary (nxc) not found after install attempt."
  fi
}

install_apkdeeplens() {
  sf_git_clone_or_update "https://github.com/d78ui98/APKDeepLens.git" "${SECFORGE_ROOT}/tools/apkdeeplens"
  local venv="${SECFORGE_ROOT}/venv/apkdeeplens"
  sf_ensure_venv "${venv}"
  if [[ -r "${SECFORGE_ROOT}/tools/apkdeeplens/requirements.txt" ]]; then
    sf_install_venv_packages "${venv}" -r "${SECFORGE_ROOT}/tools/apkdeeplens/requirements.txt" || sf_warn "APKDeepLens deps failed (continuing)."
  fi
  if [[ -r "${SECFORGE_ROOT}/tools/apkdeeplens/APKDeepLens.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/apkdeeplens" <<AEOF
#!/usr/bin/env bash
exec "${venv}/bin/python" "${SECFORGE_ROOT}/tools/apkdeeplens/APKDeepLens.py" "\$@"
AEOF
    chmod 0755 "${SECFORGE_ROOT}/bin/apkdeeplens"
  fi
}

install_apkhunt() {
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
}

install_jadx() {
  sf_apt_install unzip
  local jadx_dir="${SECFORGE_ROOT}/tools/jadx"
  if [[ ! -x "${jadx_dir}/bin/jadx" ]]; then
    sf_log "Installing jadx (Java decompiler for APK analysis)..."
    if ! sf_has_cmd jq; then
      sf_die "jq is required to install jadx (GitHub API)."
    fi
    local jadx_tmp jadx_url
    jadx_tmp="$(sf_mktemp_dir)"
    jadx_url="$(sf_github_latest_release_json "skylot/jadx" | jq -r '
      [.assets[] | select(.name | test("jadx.*\\.zip$"; "i")) | select(.name | test("no-jre"; "i") | not)] | .[0].browser_download_url
    ')"
    if [[ -n "${jadx_url}" && "${jadx_url}" != "null" ]]; then
      sf_curl -o "${jadx_tmp}/jadx.zip" "${jadx_url}"
      mkdir -p "${jadx_dir}"
      unzip -q -o "${jadx_tmp}/jadx.zip" -d "${jadx_dir}"
      chmod +x "${jadx_dir}/bin/jadx" 2>/dev/null || true
      sf_ln_sf "${jadx_dir}/bin/jadx" "${SECFORGE_ROOT}/bin/jadx"
    else
      sf_warn "Could not find jadx release asset."
    fi
    rm -rf "${jadx_tmp}"
  else
    sf_ln_sf "${jadx_dir}/bin/jadx" "${SECFORGE_ROOT}/bin/jadx"
  fi
}

install_stripe_check() {
  local venv="${SECFORGE_ROOT}/venv/stripe-check"
  sf_ensure_venv "${venv}"
  sf_install_venv_packages "${venv}" requests beautifulsoup4 || sf_warn "Failed to install stripe-check dependencies (requests, beautifulsoup4)"
  if [[ -r "${SECFORGE_ROOT}/scripts/stripe-check.py" ]]; then
    cat >"${SECFORGE_ROOT}/bin/stripe-check" <<SEOF
#!/usr/bin/env bash
exec "${venv}/bin/python" "${SECFORGE_ROOT}/scripts/stripe-check.py" "\$@"
SEOF
    chmod 0755 "${SECFORGE_ROOT}/bin/stripe-check"
  else
    sf_warn "Missing ${SECFORGE_ROOT}/scripts/stripe-check.py; stripe-check will be unavailable."
  fi
}

install_wordlists() {
  sf_download_wordlists "${SECFORGE_ROOT}"
}

# ── Install a single tool ────────────────────────────────────────────

install_single_tool() {
  local tool_id="$1"
  local status

  status="$(check_tool_status "${tool_id}")"

  if [[ "${status}" == "unknown" ]]; then
    sf_warn "Unknown tool: ${tool_id}"
    sf_emit_dashboard_event "{\"event\":\"install_done\",\"tool\":\"${tool_id}\",\"status\":\"unknown\",\"duration\":0}"
    return 1
  fi

  if [[ "${status}" == "installed" || "${status}" == "builtin" ]]; then
    sf_log "${tool_id}: already installed."
    sf_emit_dashboard_event "{\"event\":\"install_done\",\"tool\":\"${tool_id}\",\"status\":\"skipped\",\"duration\":0}"
    return 0
  fi

  # Read metadata
  local meta
  meta="$(read_tool_meta "${tool_id}")"
  if [[ "${meta}" == *"ERROR="* ]]; then
    sf_warn "Cannot read metadata for ${tool_id}: ${meta}"
    return 1
  fi

  # Eval metadata into local variables
  local TOOL_TITLE="" TOOL_METHOD="" TOOL_TIER=""
  local TOOL_APT_PACKAGES="" TOOL_REPO="" TOOL_EXPECTED_BINARY=""
  local TOOL_DEST_PATH="" TOOL_PIP_PACKAGES=""
  local TOOL_NPM_PACKAGE="" TOOL_NPM_DEST=""
  local TOOL_CUSTOM_FUNCTION="" TOOL_INSTRUCTIONS=""
  local TOOL_CHECK_COMMAND="" TOOL_CHECK_PATH=""
  local TOOL_DEPENDS_ON="" TOOL_REQUIRES_COMMANDS=""
  local TOOL_VERIFY_MODE=""
  eval "${meta}"

  sf_log "Installing ${tool_id} (${TOOL_TITLE}) via ${TOOL_METHOD}..."
  local _install_start_ts
  _install_start_ts="$(date +%s)"

  # Handle depends_on first (one level deep)
  if [[ -n "${TOOL_DEPENDS_ON}" ]]; then
    local dep
    for dep in ${TOOL_DEPENDS_ON}; do
      local dep_status
      dep_status="$(check_tool_status "${dep}")"
      if [[ "${dep_status}" != "installed" && "${dep_status}" != "builtin" ]]; then
        sf_log "Installing dependency: ${dep}"
        install_single_tool "${dep}" || {
          sf_warn "Failed to install dependency ${dep} for ${tool_id}"
          return 1
        }
      fi
    done
  fi

  # Dispatch based on install method
  case "${TOOL_METHOD}" in
    builtin)
      sf_log "${tool_id}: builtin, nothing to install."
      ;;

    apt)
      if [[ -z "${TOOL_APT_PACKAGES}" ]]; then
        sf_warn "${tool_id}: No apt packages specified."
        return 1
      fi
      # shellcheck disable=SC2086
      sf_apt_install ${TOOL_APT_PACKAGES}
      ;;

    github_release)
      if [[ -z "${TOOL_REPO}" || -z "${TOOL_EXPECTED_BINARY}" ]]; then
        sf_warn "${tool_id}: Missing repo or expected_binary for github_release."
        return 1
      fi
      local install_path="${SECFORGE_ROOT}/bin/${TOOL_EXPECTED_BINARY}"
      sf_install_github_release_binary "${TOOL_REPO}" "${TOOL_EXPECTED_BINARY}" "${install_path}" "${TOOL_VERIFY_MODE:-sha256}"
      ;;

    git_clone)
      if [[ -z "${TOOL_REPO}" || -z "${TOOL_DEST_PATH}" ]]; then
        sf_warn "${tool_id}: Missing repo or dest_path for git_clone."
        return 1
      fi
      local full_dest="${SECFORGE_ROOT}/${TOOL_DEST_PATH}"
      local repo_url="https://github.com/${TOOL_REPO}.git"
      sf_git_clone_or_update "${repo_url}" "${full_dest}"

      # If there's an expected_binary, symlink it into bin/
      if [[ -n "${TOOL_EXPECTED_BINARY}" ]]; then
        # Look for the binary in the cloned directory
        local found_bin=""
        if [[ -x "${full_dest}/${TOOL_EXPECTED_BINARY}" ]]; then
          found_bin="${full_dest}/${TOOL_EXPECTED_BINARY}"
        elif [[ -x "${full_dest}/bin/${TOOL_EXPECTED_BINARY}" ]]; then
          found_bin="${full_dest}/bin/${TOOL_EXPECTED_BINARY}"
        else
          # Search for it
          found_bin="$(find "${full_dest}" -maxdepth 3 -name "${TOOL_EXPECTED_BINARY}" -type f 2>/dev/null | head -n1 || true)"
        fi
        if [[ -n "${found_bin}" ]]; then
          chmod +x "${found_bin}"
          sf_ln_sf "${found_bin}" "${SECFORGE_ROOT}/bin/${TOOL_EXPECTED_BINARY}"
        fi
      fi
      ;;

    pip_venv)
      if [[ -z "${TOOL_PIP_PACKAGES}" ]]; then
        sf_warn "${tool_id}: No pip packages specified."
        return 1
      fi
      local venv_dir="${SECFORGE_ROOT}/venv/${tool_id}"
      sf_ensure_venv "${venv_dir}"
      # shellcheck disable=SC2086
      sf_install_venv_packages "${venv_dir}" ${TOOL_PIP_PACKAGES}

      # Symlink the main command into bin/ if check.command is set
      if [[ -n "${TOOL_CHECK_COMMAND}" ]]; then
        local venv_bin="${venv_dir}/bin/${TOOL_CHECK_COMMAND}"
        if [[ -x "${venv_bin}" ]]; then
          sf_ln_sf "${venv_bin}" "${SECFORGE_ROOT}/bin/${TOOL_CHECK_COMMAND}"
        fi
      fi
      ;;

    npm_local)
      if [[ -z "${TOOL_NPM_PACKAGE}" ]]; then
        sf_warn "${tool_id}: No npm_package specified."
        return 1
      fi
      local npm_dest="${SECFORGE_ROOT}/${TOOL_NPM_DEST}"
      mkdir -p "${npm_dest}"

      # Initialize package.json if missing
      if [[ ! -f "${npm_dest}/package.json" ]]; then
        (cd "${npm_dest}" && npm init -y >/dev/null 2>&1)
      fi

      (cd "${npm_dest}" && npm install "${TOOL_NPM_PACKAGE}" >/dev/null 2>&1)

      # Symlink the binary into bin/ if check.command is set
      if [[ -n "${TOOL_CHECK_COMMAND}" ]]; then
        local npm_bin="${npm_dest}/node_modules/.bin/${TOOL_CHECK_COMMAND}"
        if [[ -x "${npm_bin}" ]]; then
          sf_ln_sf "${npm_bin}" "${SECFORGE_ROOT}/bin/${TOOL_CHECK_COMMAND}"
        fi
      fi
      ;;

    custom)
      if [[ -n "${TOOL_CUSTOM_FUNCTION}" ]]; then
        if declare -f "${TOOL_CUSTOM_FUNCTION}" >/dev/null 2>&1; then
          sf_log "${tool_id}: running custom installer (${TOOL_CUSTOM_FUNCTION})..."
          "${TOOL_CUSTOM_FUNCTION}"
        else
          sf_warn "Custom install function '${TOOL_CUSTOM_FUNCTION}' not found. Skipping."
          return 1
        fi
      else
        sf_log "${tool_id}: requires manual installation."
        if [[ -n "${TOOL_INSTRUCTIONS}" ]]; then
          sf_log "  Instructions: ${TOOL_INSTRUCTIONS}"
        fi
      fi
      ;;

    *)
      sf_warn "${tool_id}: Unknown install method '${TOOL_METHOD}'."
      return 1
      ;;
  esac

  # Verify installation succeeded
  local post_status
  post_status="$(check_tool_status "${tool_id}")"
  if [[ "${post_status}" == "installed" || "${post_status}" == "builtin" ]]; then
    # Update config
    sf_cfg_add_list_item "${SECFORGE_CONFIG_FILE}" "INSTALLED_TOOLS" "${tool_id}"
    local _install_dur=$(( $(date +%s) - _install_start_ts ))
    sf_emit_dashboard_event "{\"event\":\"install_done\",\"tool\":\"${tool_id}\",\"status\":\"ok\",\"duration\":${_install_dur}}"
    sf_log "${tool_id}: installed successfully."
    return 0
  else
    # For custom method, don't fail — just warn
    if [[ "${TOOL_METHOD}" == "custom" ]]; then
      sf_warn "${tool_id}: manual installation required. Could not verify."
      sf_emit_dashboard_event "{\"event\":\"install_done\",\"tool\":\"${tool_id}\",\"status\":\"manual\",\"duration\":0}"
      return 1
    fi
    local _install_dur_fail=$(( $(date +%s) - _install_start_ts ))
    sf_emit_dashboard_event "{\"event\":\"install_done\",\"tool\":\"${tool_id}\",\"status\":\"fail\",\"duration\":${_install_dur_fail}}"
    sf_warn "${tool_id}: installation completed but verification failed."
    return 1
  fi
}

# ── Dashboard status file for install flows ──────────────────────────
_sf_init_install_dashboard() {
  if [[ -z "${SECFORGE_DASHBOARD_STATUS:-}" ]]; then
    SECFORGE_DASHBOARD_STATUS="/tmp/secforge-dashboard-install-$$.status"
    export SECFORGE_DASHBOARD_STATUS
  fi
  ln -sf "${SECFORGE_DASHBOARD_STATUS}" /tmp/secforge-dashboard-latest.status 2>/dev/null || true
}

# ── --all: Install everything non-builtin ────────────────────────────

do_install_all() {
  sf_need_root
  _sf_init_install_dashboard

  local tool_ids
  tool_ids="$(SF_TOOLS_JSON="${TOOLS_JSON}" python3 - <<'PY'
import json, os, sys

tools_path = os.environ["SF_TOOLS_JSON"]

try:
    with open(tools_path, "r", encoding="utf-8") as f:
        catalog = json.load(f)
except Exception as e:
    print(f"", end="")
    sys.exit(1)

catalog.pop("_meta", None)

ids = []
for tool_id, tdata in sorted(catalog.items()):
    if tdata.get("install_method") != "builtin":
        ids.append(tool_id)

print(" ".join(ids), end="")
PY
)"

  if [[ -z "${tool_ids}" ]]; then
    sf_warn "No tools found in catalog."
    return 1
  fi

  local failed=0
  local success=0
  local skipped=0
  local tool_id
  local _tools_total
  _tools_total="$(echo ${tool_ids} | wc -w)"
  sf_emit_dashboard_event "{\"event\":\"install_start\",\"tools_total\":${_tools_total}}"

  for tool_id in ${tool_ids}; do
    local status
    status="$(check_tool_status "${tool_id}")"
    if [[ "${status}" == "installed" ]]; then
      skipped=$((skipped + 1))
      # Emit install_done so dashboard count reaches tools_total
      sf_emit_dashboard_event "{\"event\":\"install_done\",\"tool\":\"${tool_id}\",\"status\":\"skipped\",\"duration\":0}"
      continue
    fi
    if install_single_tool "${tool_id}"; then
      success=$((success + 1))
    else
      failed=$((failed + 1))
    fi
  done

  sf_log "Install all complete: ${success} installed, ${skipped} already present, ${failed} failed."
}

# ── --from-selection: Install from file ──────────────────────────────

do_install_from_selection() {
  sf_need_root
  _sf_init_install_dashboard

  local selection_file="$1"

  if [[ ! -r "${selection_file}" ]]; then
    sf_die "Cannot read selection file: ${selection_file}"
  fi

  local _sel_count
  _sel_count="$(grep -cve '^\s*$' "${selection_file}" 2>/dev/null || echo 0)"
  sf_emit_dashboard_event "{\"event\":\"install_start\",\"tools_total\":${_sel_count}}"

  local failed=0
  local success=0
  local line canonical

  while IFS= read -r line || [[ -n "${line}" ]]; do
    # Skip empty lines and comments
    line="$(printf '%s' "${line}" | sed 's/#.*//' | xargs)"
    [[ -z "${line}" ]] && continue

    canonical="$(normalize_alias "${line}")"
    if install_single_tool "${canonical}"; then
      success=$((success + 1))
    else
      failed=$((failed + 1))
    fi
  done < "${selection_file}"

  sf_log "Selection install complete: ${success} installed, ${failed} failed."
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
  if [[ "${#}" -eq 0 ]]; then
    usage
    exit 2
  fi

  case "$1" in
    --list|-l)
      do_list
      ;;

    --all|-a)
      do_install_all
      ;;

    --from-selection|-f)
      if [[ "${#}" -lt 2 ]]; then
        sf_die "--from-selection requires a file argument."
      fi
      do_install_from_selection "$2"
      ;;

    -h|--help)
      usage
      exit 0
      ;;

    -*)
      sf_warn "Unknown option: $1"
      usage
      exit 2
      ;;

    *)
      # Individual tool(s) install
      sf_need_root
      _sf_init_install_dashboard
      sf_emit_dashboard_event "{\"event\":\"install_start\",\"tools_total\":${#}}"

      local failed=0
      local success=0

      while [[ "${#}" -gt 0 ]]; do
        local canonical
        canonical="$(normalize_alias "$1")"
        if install_single_tool "${canonical}"; then
          success=$((success + 1))
        else
          failed=$((failed + 1))
        fi
        shift
      done

      if [[ "${failed}" -gt 0 ]]; then
        sf_log "Install complete: ${success} succeeded, ${failed} failed."
        exit 1
      fi
      sf_log "Install complete: ${success} tool(s) installed successfully."
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
