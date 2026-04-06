#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

SECFORGE_ROOT="${SECFORGE_ROOT:-$DEFAULT_ROOT}"
SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE:-${SECFORGE_ROOT}/config/secforge.conf}"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

sf_usage() {
  cat >&2 <<EOF
Usage:
  ${0##*/} --target <domain|url> [OPTIONS]

Options:
  --target <url>         Target domain or URL (required)
  --profile <name>       Legacy profile name
  --stack <name>         Stack profile (e.g. node-nginx, php-nginx)
  --skip <csv>           Comma-separated tool IDs to skip
  --tier <n>             Override TIER_MAX (1=passive, 2=active)
  --scan-mode <mode>     Scan mode: quick (default) or full
  --code-path <path>     Local code path for file-based stack detection
  --require-tools <csv>  Require these tools to be installed
  --session-id <id>      Override session ID

Outputs shell exports on stdout (safe to source), logs on stderr.
EOF
}

sf_parse_target() {
  local input="$1"
  python3 - "$input" <<'PY'
import json
import sys
from urllib.parse import urlparse

raw = sys.argv[1].strip()
if raw.lower() in ("this server", "this_server", "local", "localhost"):
    print(json.dumps({"raw": raw, "kind": "local", "url": "", "base_url": "", "host": "this_server", "port": ""}))
    raise SystemExit(0)

if not raw.startswith(("http://", "https://")):
    raw = "https://" + raw

u = urlparse(raw)
host = u.hostname or ""
port = str(u.port or "")

base_url = f"{u.scheme}://{u.netloc}" if host else raw

print(json.dumps({
  "raw": sys.argv[1],
  "kind": "url",
  "url": raw,
  "base_url": base_url,
  "host": host,
  "port": port,
}))
PY
}

sf_disclaimer_banner() {
  cat >&2 <<'EOF'
============================================================
 SecForge — Authorized Security Testing Only
 Only scan systems you own or have written permission to test.
============================================================
EOF
}

sf_require_authorization() {
  local target_key="$1"
  local auth_file="$2"

  sf_disclaimer_banner

  if [[ ! -e "${auth_file}" ]]; then
    sf_warn "Authorization cache missing: ${auth_file}"
    sf_warn "Run the installer again or create it (root) and ensure it's group-writable."
    return 1
  fi

  if grep -Fqx "${target_key}" "${auth_file}" 2>/dev/null; then
    return 0
  fi

  sf_warn "First time scanning: ${target_key}"
  sf_warn "To continue, you must confirm you own/are authorized to test this target."
  if ! sf_ask_tty_yes "Type YES to confirm authorization:" "YES"; then
    sf_die "Authorization not confirmed. Aborting."
  fi

  printf '%s\n' "${target_key}" >>"${auth_file}"
}

sf_dns_resolves() {
  local host="$1"
  if [[ "${host}" == "this_server" ]]; then
    return 0
  fi
  if sf_has_cmd getent; then
    getent ahosts "${host}" >/dev/null 2>&1 && return 0
  fi
  if sf_has_cmd dig; then
    dig +short "${host}" 2>/dev/null | head -n1 | grep -q . && return 0
  fi
  return 1
}

sf_http_baseline() {
  local url="$1"
  local timeout_s="${2:-10}"

  if [[ -z "${url}" ]]; then
    echo ""
    return 0
  fi

  # Return: "<http_code> <time_total>"
  curl -fsS -o /dev/null \
    --connect-timeout 5 \
    --max-time "${timeout_s}" \
    -w "%{http_code} %{time_total}\n" \
    "${url}" 2>/dev/null || true
}

sf_check_tools() {
  local csv="$1"
  local missing=()
  local tool

  if [[ -z "${csv}" ]]; then
    printf '%s' ""
    return 0
  fi

  IFS=',' read -r -a tools <<<"${csv}"
  for tool in "${tools[@]}"; do
    tool="${tool## }"
    tool="${tool%% }"
    [[ -z "${tool}" ]] && continue

    if [[ -x "${SECFORGE_ROOT}/bin/${tool}" ]]; then
      continue
    fi
    if command -v "${tool}" >/dev/null 2>&1; then
      continue
    fi
    missing+=("${tool}")
  done

  if [[ "${#missing[@]}" -gt 0 ]]; then
    printf '%s' "${missing[*]}"
  else
    printf '%s' ""
  fi
}

main() {
  local target="" profile="" require_tools="" session_id=""
  local stack="" skip_tools="" tier_override="" scan_mode="quick" code_path=""

  while [[ "${#}" -gt 0 ]]; do
    case "$1" in
      --target) target="${2:-}"; shift 2 ;;
      --profile) profile="${2:-}"; shift 2 ;;
      --require-tools) require_tools="${2:-}"; shift 2 ;;
      --session-id) session_id="${2:-}"; shift 2 ;;
      --stack) stack="${2:-}"; shift 2 ;;
      --skip) skip_tools="${2:-}"; shift 2 ;;
      --tier) tier_override="${2:-}"; shift 2 ;;
      --scan-mode) scan_mode="${2:-}"; shift 2 ;;
      --code-path) code_path="${2:-}"; shift 2 ;;
      -h|--help) sf_usage; exit 0 ;;
      *) sf_warn "Unknown argument: $1"; sf_usage; exit 2 ;;
    esac
  done

  if [[ -z "${target}" ]]; then
    sf_usage
    exit 2
  fi

  local auth_file scan_delay_ms max_concurrent threshold cooldown
  auth_file="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "AUTHORIZED_TARGETS_FILE" || true)"
  auth_file="${auth_file:-${SECFORGE_ROOT}/config/.authorized_targets}"
  scan_delay_ms="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "SCAN_DELAY_MS" || true)"
  max_concurrent="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "MAX_CONCURRENT_TOOLS" || true)"
  threshold="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "CIRCUIT_BREAKER_THRESHOLD_SECONDS" || true)"
  cooldown="$(sf_cfg_get_value "${SECFORGE_CONFIG_FILE}" "CIRCUIT_BREAKER_COOLDOWN_SECONDS" || true)"
  scan_delay_ms="${scan_delay_ms:-200}"
  max_concurrent="${max_concurrent:-3}"
  threshold="${threshold:-10}"
  cooldown="${cooldown:-30}"

  local parsed kind url base_url host port
  parsed="$(sf_parse_target "${target}")"
  kind="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["kind"])' <<<"${parsed}")"
  url="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["url"])' <<<"${parsed}")"
  base_url="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["base_url"])' <<<"${parsed}")"
  host="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["host"])' <<<"${parsed}")"
  port="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["port"])' <<<"${parsed}")"

  if [[ -z "${host}" ]]; then
    sf_die "Could not parse target host from: ${target}"
  fi

  sf_require_authorization "${host}" "${auth_file}"

  if ! sf_dns_resolves "${host}"; then
    sf_die "DNS resolution failed for ${host}."
  fi

  local baseline http_code latency_s
  baseline="$(sf_http_baseline "${base_url}")"
  http_code="$(awk '{print $1}' <<<"${baseline}" || true)"
  latency_s="$(awk '{print $2}' <<<"${baseline}" || true)"
  http_code="${http_code:-}"
  latency_s="${latency_s:-}"

  if [[ -n "${base_url}" && ( -z "${http_code}" || "${http_code}" == "000" ) ]]; then
    sf_warn "HTTP connectivity check failed for ${base_url}. Continuing, but web scanners may fail."
  fi

  if [[ -z "${session_id}" ]]; then
    local ts safe_host
    ts="$(date -u +'%Y-%m-%d_%H%M%S')"
    safe_host="$(printf '%s' "${host}" | tr -cd 'A-Za-z0-9._-' | sed 's/^\\.\\+//')"
    session_id="${ts}_${safe_host}"
  fi

  local reports_root session_dir
  reports_root="${SECFORGE_ROOT}/reports"
  session_dir="${reports_root}/${session_id}"

  mkdir -p "${session_dir}"
  mkdir -p \
    "${session_dir}/webapp" \
    "${session_dir}/api" \
    "${session_dir}/network" \
    "${session_dir}/ssl" \
    "${session_dir}/passwords" \
    "${session_dir}/secrets" \
    "${session_dir}/mobile" \
    "${session_dir}/compliance" \
    "${session_dir}/hardening" \
	    "${session_dir}/dependencies" \
	    "${session_dir}/emaildns" \
	    "${session_dir}/database" \
	    "${session_dir}/containers" \
	    "${session_dir}/iac" \
	    "${session_dir}/cloud"

  if [[ -d "${reports_root}" ]]; then
    # Global latest (may fail for non-root due to sticky bit — that's safe).
    (cd "${reports_root}" && ln -sfn "${session_id}" latest) >/dev/null 2>&1 || true
    # Per-user latest (always succeeds for the scan user).
    local _sf_user
    _sf_user="$(whoami 2>/dev/null || id -un 2>/dev/null || echo "uid$(id -u)")"
    _sf_user="$(printf '%s' "${_sf_user}" | tr -cd 'A-Za-z0-9._-')"
    if [[ -n "${_sf_user}" ]]; then
      (cd "${reports_root}" && ln -sfn "${session_id}" "latest-${_sf_user}") >/dev/null 2>&1 || true
    fi
  fi

  local missing_tools
  missing_tools="$(sf_check_tools "${require_tools}")"
  if [[ -n "${missing_tools}" ]]; then
    sf_warn "Missing required tools: ${missing_tools}"
  fi

  # preflight.json is written by the PYPLAN heredoc below (after planner runs)
  # so it includes stack detection, planned tools, estimates, etc.

  # Safe exports for callers (stdout only).
  # Use declare -p with an explicit allowlist to avoid shell injection.
  # Every variable MUST be set before declare -p is called.
  export SECFORGE_ROOT="${SECFORGE_ROOT}"
  export SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE}"
  export SECFORGE_SESSION_ID="${session_id}"
  export SECFORGE_SESSION_DIR="${session_dir}"
  export SECFORGE_TARGET_INPUT="${target}"
  export SECFORGE_TARGET_URL="${base_url}"
  export SECFORGE_TARGET_FULL_URL="${url}"
  export SECFORGE_TARGET_HOST="${host}"
  export SECFORGE_TARGET_PORT="${port}"
  export SECFORGE_SCAN_DELAY_MS="${scan_delay_ms}"
  export SECFORGE_MAX_CONCURRENT_TOOLS="${max_concurrent}"
  export SECFORGE_CIRCUIT_BREAKER_THRESHOLD_SECONDS="${threshold}"
  export SECFORGE_CIRCUIT_BREAKER_COOLDOWN_SECONDS="${cooldown}"
  export SECFORGE_MISSING_TOOLS="${missing_tools}"

  local _sf_var
  for _sf_var in \
    SECFORGE_ROOT SECFORGE_CONFIG_FILE SECFORGE_SESSION_ID SECFORGE_SESSION_DIR \
    SECFORGE_TARGET_INPUT SECFORGE_TARGET_URL SECFORGE_TARGET_FULL_URL \
    SECFORGE_TARGET_HOST SECFORGE_TARGET_PORT \
    SECFORGE_SCAN_DELAY_MS SECFORGE_MAX_CONCURRENT_TOOLS \
    SECFORGE_CIRCUIT_BREAKER_THRESHOLD_SECONDS SECFORGE_CIRCUIT_BREAKER_COOLDOWN_SECONDS \
    SECFORGE_MISSING_TOOLS; do
    declare -p "${_sf_var}" 2>/dev/null || true
  done

  # ── Stack detection, profile expansion, tool planning, estimates ──
  # This Python heredoc reads catalogs, resolves profiles, checks tool
  # installedness, computes time estimates, and outputs additional
  # declare -x lines to stdout (same mechanism as the loop above).
  SECFORGE_ROOT="${SECFORGE_ROOT}" \
  SECFORGE_STACK="${stack}" \
  SECFORGE_SKIP="${skip_tools}" \
  SECFORGE_TIER_OVERRIDE="${tier_override}" \
  SECFORGE_SCAN_MODE="${scan_mode}" \
  SECFORGE_TARGET_URL="${base_url}" \
  SECFORGE_TARGET_HOST="${host}" \
  SECFORGE_CODE_PATH="${code_path}" \
  SECFORGE_CONFIG_FILE="${SECFORGE_CONFIG_FILE}" \
  SF_PREFLIGHT_PATH="${session_dir}/preflight.json" \
  SF_TARGET_INPUT="${target}" \
  SF_TARGET_KIND="${kind}" \
  SF_TARGET_FULL_URL="${url}" \
  SF_TARGET_PORT="${port}" \
  SF_HTTP_CODE="${http_code}" \
  SF_LATENCY_SECONDS="${latency_s}" \
  SF_SCAN_DELAY_MS="${scan_delay_ms}" \
  SF_MAX_CONCURRENT="${max_concurrent}" \
  SF_CB_THRESHOLD="${threshold}" \
  SF_CB_COOLDOWN="${cooldown}" \
  SF_MISSING_TOOLS="${missing_tools}" \
  python3 - <<'PYPLAN'
import glob
import json
import os
import re
import shutil
import statistics
import subprocess
import sys


# ── Helpers ──────────────────────────────────────────────────────────

def safe_shell_value(val):
    """Escape a value for safe inclusion inside declare -x VAR="val"."""
    # Replace backslash first, then double-quote, then dollar sign, backtick.
    val = val.replace("\\", "\\\\")
    val = val.replace('"', '\\"')
    val = val.replace("$", "\\$")
    val = val.replace("`", "\\`")
    return val


def emit(name, value):
    """Print a declare -x statement safe for sourcing."""
    print(f'declare -x {name}="{safe_shell_value(str(value))}"')


def warn(msg):
    print(f"[secforge] WARN: {msg}", file=sys.stderr)


def cmd_exists(cmd, secforge_root):
    """Check if a command is available via PATH or under $SECFORGE_ROOT/bin/."""
    bin_path = os.path.join(secforge_root, "bin", cmd)
    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        return True
    return shutil.which(cmd) is not None


def path_exists(rel_path, secforge_root):
    """Check if a relative path exists under $SECFORGE_ROOT."""
    full = os.path.join(secforge_root, rel_path)
    return os.path.exists(full)


# ── Read environment ─────────────────────────────────────────────────

SECFORGE_ROOT = os.environ.get("SECFORGE_ROOT", "")
STACK = os.environ.get("SECFORGE_STACK", "").strip()
SKIP_CSV = os.environ.get("SECFORGE_SKIP", "").strip()
TIER_OVERRIDE = os.environ.get("SECFORGE_TIER_OVERRIDE", "").strip()
SCAN_MODE = os.environ.get("SECFORGE_SCAN_MODE", "quick").strip()
TARGET_URL = os.environ.get("SECFORGE_TARGET_URL", "").strip()
TARGET_HOST = os.environ.get("SECFORGE_TARGET_HOST", "").strip()
CODE_PATH = os.environ.get("SECFORGE_CODE_PATH", "").strip()
CONFIG_FILE = os.environ.get("SECFORGE_CONFIG_FILE", "").strip()

if not SECFORGE_ROOT:
    warn("SECFORGE_ROOT not set; skipping planner.")
    sys.exit(0)

skip_set = set()
if SKIP_CSV:
    skip_set = {s.strip() for s in SKIP_CSV.split(",") if s.strip()}


# ── Load catalogs ────────────────────────────────────────────────────

catalog_dir = os.path.join(SECFORGE_ROOT, "catalog")
tools_path = os.path.join(catalog_dir, "tools.json")
profiles_path = os.path.join(catalog_dir, "profiles.json")

try:
    with open(tools_path, "r", encoding="utf-8") as f:
        tools_catalog = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as exc:
    warn(f"Cannot load {tools_path}: {exc}")
    tools_catalog = {}

try:
    with open(profiles_path, "r", encoding="utf-8") as f:
        profiles_catalog = json.load(f)
except (FileNotFoundError, json.JSONDecodeError) as exc:
    warn(f"Cannot load {profiles_path}: {exc}")
    profiles_catalog = {}

# Strip _meta keys
tools_catalog.pop("_meta", None)
profiles_catalog.pop("_meta", None)


# ── Scan-mode tool sets (what each scan script actually runs) ────────

QUICK_SCAN_TOOLS = {
    "wafw00f", "whatweb", "nuclei", "nmap", "testssl",
    "check-email-dns", "secforge-builtin", "lynis", "ssh-audit",
}

FULL_SCAN_TOOLS = QUICK_SCAN_TOOLS | {
    "corscanner", "nikto", "ffuf", "observatory", "sslscan",
    "subfinder", "httpx", "interactsh", "masscan",
    "trivy", "trufflehog", "gitleaks", "osv-scanner", "pip-audit",
    "check-mysql", "systemd-analyze", "clamscan", "rkhunter",
    "aide", "aureport", "debsums",
    # Tier 2:
    "zap", "sqlmap", "dalfox", "xsstrike", "commix", "wapiti",
    "hydra", "netexec",
}


# ── TIER_MAX from config ─────────────────────────────────────────────

def read_config_value(cfg_path, key):
    """Read a KEY=VALUE from config file (simple parser)."""
    if not cfg_path or not os.path.isfile(cfg_path):
        return ""
    try:
        with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k == key:
                    return v
    except OSError:
        pass
    return ""


tier_max_str = ""
if TIER_OVERRIDE:
    tier_max_str = TIER_OVERRIDE
else:
    tier_max_str = read_config_value(CONFIG_FILE, "TIER_MAX")
    if not tier_max_str:
        tier_max_str = read_config_value(CONFIG_FILE, "DEFAULT_TIER")

try:
    TIER_MAX = int(tier_max_str)
except (ValueError, TypeError):
    TIER_MAX = 1  # safe default


# ── Stack detection ──────────────────────────────────────────────────

detected_profile_name = ""
detect_confidence = "none"
_detection_score = 0
_detection_threshold = 2
_detection_signals = []

if STACK:
    # Explicit --stack flag: use directly
    if STACK in profiles_catalog:
        detected_profile_name = STACK
        detect_confidence = "high"
    else:
        warn(f"Unknown stack profile '{STACK}'; falling back to auto-detect.")

if not detected_profile_name:
    # Auto-detect from HTTP headers + code path files + cookies
    # Fetch response headers once (best-effort)
    resp_headers = {}
    resp_cookies = []
    if TARGET_URL:
        try:
            result = subprocess.run(
                ["curl", "-fsS", "-I", "--max-time", "10", TARGET_URL],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    hname, _, hval = line.partition(":")
                    hname_lower = hname.strip().lower()
                    hval_stripped = hval.strip()
                    resp_headers[hname_lower] = hval_stripped
                    # Collect cookie names from Set-Cookie headers
                    if hname_lower == "set-cookie":
                        cookie_name = hval_stripped.split("=")[0].strip()
                        if cookie_name:
                            resp_cookies.append(cookie_name.lower())
        except Exception:
            pass  # header detection is best-effort

    # Score each profile (collect signals for rich stack_detection)
    profile_scores = {}   # profile_name -> signal_count
    profile_signals = {}  # profile_name -> list of signal description strings

    for pname, pdata in profiles_catalog.items():
        signals = 0
        signal_list = []

        # Check detect_headers (case-insensitive contains)
        detect_hdrs = pdata.get("detect_headers", {})
        for hdr_name, hdr_pattern in detect_hdrs.items():
            hdr_name_lower = hdr_name.lower()
            if hdr_name_lower in resp_headers:
                if not hdr_pattern:
                    signals += 1
                    signal_list.append(f"header:{hdr_name_lower}")
                elif hdr_pattern.lower() in resp_headers[hdr_name_lower].lower():
                    signals += 1
                    signal_list.append(f"header:{hdr_name_lower}={hdr_pattern}")

        # Check detect_cookies
        detect_cookies = pdata.get("detect_cookies", [])
        for cookie_pattern in detect_cookies:
            cookie_lower = cookie_pattern.lower()
            for rc in resp_cookies:
                if cookie_lower in rc:
                    signals += 1
                    signal_list.append(f"cookie:{rc}")
                    break

        # Check detect_files (if code path is available)
        detect_files = pdata.get("detect_files", [])
        if CODE_PATH and os.path.isdir(CODE_PATH):
            for df in detect_files:
                check = os.path.join(CODE_PATH, df)
                if os.path.exists(check):
                    signals += 1
                    signal_list.append(f"file:{df}")

        if signals > 0:
            profile_scores[pname] = signals
            profile_signals[pname] = signal_list

    # Confidence gating (with rich detection metadata)
    if profile_scores:
        max_score = max(profile_scores.values())
        winners = [p for p, s in profile_scores.items() if s == max_score]
        _detection_threshold = profiles_catalog.get(winners[0], {}).get("min_detect_signals", 2) if len(winners) == 1 else 2

        if len(winners) == 1 and max_score >= _detection_threshold:
            detected_profile_name = winners[0]
            detect_confidence = "high"
            _detection_score = max_score
            _detection_signals = profile_signals.get(winners[0], [])
        elif len(winners) == 1 and max_score >= 1:
            detect_confidence = "low"
            _detection_score = max_score
            _detection_signals = profile_signals.get(winners[0], [])
        else:
            detect_confidence = "low" if max_score >= 1 else "none"
            if winners:
                _detection_score = max_score
                _detection_signals = profile_signals.get(winners[0], [])


# ── Profile expansion → tools_planned ────────────────────────────────

profile_data = profiles_catalog.get(detected_profile_name, {}) if detected_profile_name else {}
tools_planned = []
tools_skipped = []
tools_missing = []

if detected_profile_name and detect_confidence == "high":
    # Start with profile's tools_include (strict allowlist)
    candidate_ids = list(profile_data.get("tools_include", []))

    # Intersect with what the scan script actually runs
    scan_mode_tools = QUICK_SCAN_TOOLS if SCAN_MODE == "quick" else FULL_SCAN_TOOLS
    candidate_ids = [t for t in candidate_ids if t in scan_mode_tools]

    # Remove tools_exclude
    exclude_set = set(profile_data.get("tools_exclude", []))
    candidate_ids = [t for t in candidate_ids if t not in exclude_set]

    # Remove tools above TIER_MAX
    candidate_ids = [t for t in candidate_ids if tools_catalog.get(t, {}).get("tier", 99) <= TIER_MAX]

    # Remove --skip tools (warn on unknown IDs)
    for skip_id in skip_set:
        if skip_id not in tools_catalog:
            warn(f"--skip: unknown tool ID '{skip_id}'")

    skipped_by_flag = set()
    remaining = []
    for t in candidate_ids:
        if t in skip_set:
            skipped_by_flag.add(t)
        else:
            remaining.append(t)
    candidate_ids = remaining

    # Determine tools removed by tier or exclude
    all_include = set(profile_data.get("tools_include", []))
    tier_or_exclude_removed = all_include - set(candidate_ids) - exclude_set - skipped_by_flag
    # Tools skipped = tier-gated + exclude + skip-flag
    tools_skipped_set = exclude_set | skipped_by_flag
    # Add tier-gated tools to skipped
    for t in list(all_include):
        if t not in candidate_ids and t not in exclude_set and t not in skipped_by_flag:
            tools_skipped_set.add(t)

    # Installedness check
    for tool_id in candidate_ids:
        tdata = tools_catalog.get(tool_id, {})
        installed = True

        # check.command
        check = tdata.get("check", {})
        check_cmd = check.get("command", "")
        check_path = check.get("path", "")

        if check_cmd:
            if not cmd_exists(check_cmd, SECFORGE_ROOT):
                installed = False
        elif check_path:
            if not path_exists(check_path, SECFORGE_ROOT):
                installed = False

        # depends_on: each dependency must pass its own check
        if installed:
            for dep_id in tdata.get("depends_on", []):
                dep_data = tools_catalog.get(dep_id, {})
                dep_check = dep_data.get("check", {})
                dep_cmd = dep_check.get("command", "")
                dep_path = dep_check.get("path", "")
                if dep_cmd and not cmd_exists(dep_cmd, SECFORGE_ROOT):
                    installed = False
                    break
                if dep_path and not path_exists(dep_path, SECFORGE_ROOT):
                    installed = False
                    break

        # requires_commands: all must be available
        if installed:
            for req_cmd in tdata.get("requires_commands", []):
                if not cmd_exists(req_cmd, SECFORGE_ROOT):
                    installed = False
                    break

        if installed:
            tools_planned.append(tool_id)
        else:
            tools_missing.append(tool_id)

    # Build final skipped list (only tool IDs that are in the catalog)
    tools_skipped = sorted(t for t in tools_skipped_set if t in tools_catalog)

else:
    # No profile active — legacy mode (tools_planned stays empty = run everything).
    # Still enforce --skip and TIER_MAX so they work without profiles.
    for skip_id in skip_set:
        if skip_id not in tools_catalog:
            warn(f"--skip: unknown tool ID '{skip_id}'")
        else:
            tools_skipped.append(skip_id)


# ── Build tools_effective (what will actually run) ───────────────────
# In profile mode: same as tools_planned.
# In no-profile mode: all installed tools minus skipped, minus tier-gated.
# Used for: estimates, dashboard tools_total, preflight.json.

def is_tool_installed(tool_id, catalog, root):
    """Check if a tool passes all installedness criteria."""
    tdata = catalog.get(tool_id, {})
    check = tdata.get("check", {})
    check_cmd = check.get("command", "")
    check_p = check.get("path", "")
    if check_cmd and not cmd_exists(check_cmd, root):
        return False
    if check_p and not path_exists(check_p, root):
        return False
    for dep_id in tdata.get("depends_on", []):
        dep_data = catalog.get(dep_id, {})
        dep_check = dep_data.get("check", {})
        if dep_check.get("command") and not cmd_exists(dep_check["command"], root):
            return False
        if dep_check.get("path") and not path_exists(dep_check["path"], root):
            return False
    for req_cmd in tdata.get("requires_commands", []):
        if not cmd_exists(req_cmd, root):
            return False
    return True

scan_mode_tools = QUICK_SCAN_TOOLS if SCAN_MODE == "quick" else FULL_SCAN_TOOLS

if tools_planned:
    tools_effective = [t for t in tools_planned if t in scan_mode_tools]
else:
    # Legacy mode: enumerate all installed tools, apply skip + tier + scan-mode gate
    tools_effective = []
    skip_set_final = set(tools_skipped)
    for tid, tdata in tools_catalog.items():
        if tid not in scan_mode_tools:
            continue
        if tid in skip_set_final:
            continue
        if tdata.get("tier", 99) > TIER_MAX:
            continue
        if tdata.get("install_method") == "builtin":
            tools_effective.append(tid)
            continue
        if is_tool_installed(tid, tools_catalog, SECFORGE_ROOT):
            tools_effective.append(tid)


# ── Time estimates ───────────────────────────────────────────────────

# Glob previous manifests for historical durations (two-tier: exact → target → static)
history_exact = {}   # tool -> [durations] from matching (target, profile, scan_mode)
history_target = {}  # tool -> [durations] from same target, any profile/mode
if TARGET_HOST:
    manifest_pattern = os.path.join(
        SECFORGE_ROOT, "reports", f"20*_{TARGET_HOST}*", "scan_manifest.json"
    )
    # Scan more than 5 manifests so exact-match isn't often empty
    manifest_files = sorted(glob.glob(manifest_pattern))[-20:]
    for mf in manifest_files:
        try:
            with open(mf, "r", encoding="utf-8") as fh:
                mdata = json.load(fh)
            m_profile = mdata.get("profile", "")
            m_mode = mdata.get("scan_mode", "")
            durations = mdata.get("tool_durations", {})
            for tid, dur in durations.items():
                if isinstance(dur, (int, float)) and dur > 0:
                    history_target.setdefault(tid, []).append(dur)
                    if m_profile == detected_profile_name and m_mode == SCAN_MODE:
                        history_exact.setdefault(tid, []).append(dur)
        except Exception:
            pass

# Estimate: exact (target+profile+mode) → target-only → static default
total_est = 0
for tool_id in tools_effective:
    exact = history_exact.get(tool_id, [])
    target_hist = history_target.get(tool_id, [])
    if exact:
        est = int(statistics.median(exact[-5:]))
    elif target_hist:
        est = int(statistics.median(target_hist[-5:]))
    else:
        est = tools_catalog.get(tool_id, {}).get("est_seconds", 0)
    total_est += est


# ── Nuclei tags ──────────────────────────────────────────────────────

nuclei_tags = ",".join(profile_data.get("nuclei_tags_boost", []))
nuclei_exclude_tags = ",".join(profile_data.get("nuclei_tags_skip", []))

# ── Common endpoints ─────────────────────────────────────────────────

common_endpoints = ",".join(profile_data.get("common_endpoints", []))


# ── Output declare -x lines ─────────────────────────────────────────

emit("SECFORGE_STACK_PROFILE", detected_profile_name)
emit("SECFORGE_DETECTED_STACK", detected_profile_name)
emit("SECFORGE_DETECT_CONFIDENCE", detect_confidence)
emit("SECFORGE_TOOLS_PLANNED", ",".join(tools_planned))
emit("SECFORGE_TOOLS_EFFECTIVE", ",".join(tools_effective))
emit("SECFORGE_TOOLS_SKIPPED", ",".join(tools_skipped))
emit("SECFORGE_TOOLS_MISSING", ",".join(tools_missing))
emit("SECFORGE_NUCLEI_TAGS", nuclei_tags)
emit("SECFORGE_NUCLEI_EXCLUDE_TAGS", nuclei_exclude_tags)
emit("SECFORGE_COMMON_ENDPOINTS", common_endpoints)
emit("SECFORGE_TIER_MAX", str(TIER_MAX))
emit("SECFORGE_SCAN_MODE", SCAN_MODE)
emit("SECFORGE_EST_SECONDS", str(total_est))
emit("SECFORGE_EST_TOOLS_TOTAL", str(len(tools_effective)))


# ── Write preflight.json (after planner, includes all results) ───────

def _int_or_none(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return None

preflight_path = os.environ.get("SF_PREFLIGHT_PATH", "")
if preflight_path:
    preflight_data = {
        "timestamp_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_input": os.environ.get("SF_TARGET_INPUT", ""),
        "target_kind": os.environ.get("SF_TARGET_KIND", "url"),
        "target_url": TARGET_URL,
        "target_full_url": os.environ.get("SF_TARGET_FULL_URL", ""),
        "target_host": TARGET_HOST,
        "target_port": os.environ.get("SF_TARGET_PORT", ""),
        "baseline": {
            "http_code": os.environ.get("SF_HTTP_CODE", ""),
            "latency_seconds": os.environ.get("SF_LATENCY_SECONDS", ""),
        },
        "config": {
            "scan_delay_ms": _int_or_none(os.environ.get("SF_SCAN_DELAY_MS", "")),
            "max_concurrent_tools": _int_or_none(os.environ.get("SF_MAX_CONCURRENT", "")),
            "circuit_breaker_threshold_seconds": _int_or_none(os.environ.get("SF_CB_THRESHOLD", "")),
            "circuit_breaker_cooldown_seconds": _int_or_none(os.environ.get("SF_CB_COOLDOWN", "")),
        },
        "missing_required_tools": [t for t in os.environ.get("SF_MISSING_TOOLS", "").split() if t],
        "stack_detection": {
            "detected_stack": detected_profile_name,
            "confidence": detect_confidence,
            "score": _detection_score,
            "threshold": _detection_threshold,
            "signals": _detection_signals,
            "stack_override": STACK,
        },
        "scan_mode": SCAN_MODE,
        "tier_max": TIER_MAX,
        "tools_planned": tools_planned,
        "tools_effective": tools_effective,
        "tools_skipped": tools_skipped,
        "tools_missing": tools_missing,
        "nuclei_tags": nuclei_tags,
        "nuclei_exclude_tags": nuclei_exclude_tags,
        "est_seconds": total_est,
        "est_tools_total": len(tools_effective),
    }
    try:
        with open(preflight_path, "w", encoding="utf-8") as pfh:
            json.dump(preflight_data, pfh, indent=2, sort_keys=True)
    except OSError as exc:
        warn(f"Could not write {preflight_path}: {exc}")
PYPLAN
}

main "$@"
