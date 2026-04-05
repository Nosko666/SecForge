# SecForge Vibecoder UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform SecForge from raw bash scripts into an AI-guided, visually polished security workflow with stack profiles, time estimates, guided onboarding, and a live tmux dashboard.

**Architecture:** 4 data/config files (`catalog/tools.json`, `catalog/profiles.json`, `config/secforge.conf`), 3 new bash scripts (`bootstrap.sh`, `install-tools.sh`, `dashboard.sh`), modifications to existing scan scripts + CLI + preflight for profile gating, and CLAUDE.md updates for AI orchestration. No Python module changes — `scripts/secforge/*.py` stays untouched.

**Tech Stack:** Bash, Python 3 (stdlib only for JSON parsing in preflight), `gum` (Charmbracelet TUI binary), `tmux`, `jq`

**Design spec:** `docs/superpowers/specs/2026-04-05-vibecoder-ux-design.md` (40+ locked decisions)

**Test server:** Hetzner `116.203.191.42` (Ubuntu 24.04, SSH key auth, testuser in secforge group)

---

## File Structure

### New files to create

| File | Responsibility |
|------|---------------|
| `catalog/tools.json` | Single source of truth for per-tool metadata: tier, description, estimates, install method, check field, depends_on |
| `catalog/profiles.json` | 9 stack profiles with tools_include/exclude, nuclei tags, endpoints, boosts, hints, detection signals |
| `scripts/bootstrap.sh` | Minimal installer: dir structure, secforge group, base deps (python3, curl, jq, git, tmux), gum binary, PATH setup. No security tools. |
| `scripts/install-tools.sh` | Per-tool install registry: reads `catalog/tools.json`, installs individual tools by method (apt, github_release, git_clone, pip_venv, custom) |
| `scripts/dashboard.sh` | TUI dashboard renderer: reads status file, draws with gum, 1s redraw loop, SIGWINCH resize, graceful fallback |

### Existing files to modify

| File | What changes |
|------|-------------|
| `scripts/preflight.sh` | Stack detection (--stack flag + auto-detect), profile expansion into env vars (SECFORGE_TOOLS_PLANNED, NUCLEI_TAGS, etc.), installedness checks via tools.json, TIER_MAX enforcement |
| `scripts/scan-quick.sh` | Add `sf_should_run_tool` gate before each tool, add `secforge-builtin` web checks, write dashboard status events, record `tool_durations` in manifest, fix canonical tool IDs |
| `scripts/scan-all.sh` | Same as scan-quick.sh plus tier2_prompt/approved/skipped status events |
| `scripts/_lib.sh` | Add `sf_should_run_tool` helper, `sf_emit_dashboard_event` helper |
| `bin/secforge` | Add `init`, `install`, `dashboard` subcommands. Add `--stack`, `--skip`, `--code-path`, `--dashboard`, `--tier` flags to scan. Rename `--stack` on export to `--stack-hints` (keep backward alias). |
| `install.sh` | Rework entry point to call `scripts/bootstrap.sh` instead of full menu |
| `CLAUDE.md` | Append "Vibecoder UX Protocol" section + update Session Start + Scanning sections |
| `config/secforge.conf.example` | Add TIER_MAX, DOMAIN, ENVIRONMENT, PAYMENTS, ADMIN_IP keys |

### Files NOT modified

| File | Why |
|------|-----|
| `scripts/secforge/*.py` | v2 pipeline modules stay as-is |
| `scripts/install-*.sh` (12 files) | Category installers preserved, called by `install-tools.sh --all` |
| `catalog/issue_keys.json` | No changes |
| `catalog/clusters.json` | No changes |
| `catalog/priority_weights.json` | No changes |

---

## Task 1: Create `catalog/tools.json` — Tool Metadata Registry

**Files:**
- Create: `catalog/tools.json`

This is the single source of truth for ALL per-tool metadata. Every other feature reads from it.

- [ ] **Step 1: Create tools.json with all 51 tools**

Create `catalog/tools.json`. Every tool SecForge can install/run gets an entry. Each entry has:
- `title`: Human-readable name
- `description`: One-sentence explanation for vibecoders
- `tier`: 0 (resource), 1 (passive/safe), or 2 (active/aggressive)
- `est_seconds`: Default scan duration estimate (integer seconds)
- `est_disk_mb`: Approximate disk usage
- `install_method`: One of: `builtin`, `apt`, `github_release`, `git_clone`, `pip_venv`, `npm_local`, `custom`
- Method-specific fields: `apt_packages`, `repo`, `expected_binary`, `dest_path`, `pip_package`, `custom_function`
- `check`: How to verify installed — `{"command": "nuclei"}` or `{"path": "tools/nuclei-templates"}`
- `depends_on`: Array of resource IDs this tool needs (e.g., nuclei depends on nuclei-templates)
- `requires_commands`: Optional array of system commands needed (e.g., check-email-dns needs `dig`)

The file must include entries for ALL tools currently in `/opt/secforge/bin/` plus built-in scripts. Use canonical tool IDs (matching `finding.tool` values from parsers):

Tools to include (grouped by current install category):
- **webapp**: wafw00f, corscanner, nuclei, ffuf, nikto, whatweb, wapiti, dalfox, xsstrike, commix, sqlmap
- **api**: vulnapi, kiterunner (kr), jwt-tool, interactsh-client
- **network**: nmap, masscan, netcat (nc)
- **ssl**: testssl, sslscan, observatory
- **passwords**: hydra, john, hashcat, netexec (nxc)
- **secrets**: trufflehog, gitleaks, apkleaks
- **mobile**: apkdeeplens, apkhunt, jadx
- **hardening**: lynis, ssh-audit, systemd-analyze, debsums, trivy, clamscan, rkhunter, fail2ban, aide, aureport
- **compliance**: oscap (openscap), checkov, prowler
- **dependencies**: osv-scanner, pip-audit, npm-audit
- **emaildns**: check-email-dns, subfinder, httpx, dnsrecon
- **database**: check-mysql
- **payment**: stripe-check
- **builtin**: secforge-builtin
- **resources (tier 0)**: nuclei-templates, wordlists, zap (OWASP ZAP)

Example entries (use these exact formats):

```json
{
  "_meta": {
    "version": "1.0",
    "description": "Per-tool metadata. Single source of truth for: dashboard descriptions, preflight tier gating, cost estimator defaults, installer methods, installedness checks."
  },
  "nuclei": {
    "title": "Nuclei",
    "description": "Template-based vulnerability scanner for known issues and misconfigurations",
    "tier": 1,
    "est_seconds": 90,
    "est_disk_mb": 45,
    "install_method": "github_release",
    "repo": "projectdiscovery/nuclei",
    "expected_binary": "nuclei",
    "depends_on": ["nuclei-templates"],
    "check": {"command": "nuclei"}
  },
  "nuclei-templates": {
    "title": "Nuclei Templates",
    "description": "9000+ vulnerability detection templates for Nuclei",
    "tier": 0,
    "est_seconds": 0,
    "est_disk_mb": 500,
    "install_method": "git_clone",
    "repo": "projectdiscovery/nuclei-templates",
    "dest_path": "tools/nuclei-templates",
    "check": {"path": "tools/nuclei-templates"}
  },
  "nmap": {
    "title": "Nmap",
    "description": "Discovers what ports and services are exposed to the internet",
    "tier": 1,
    "est_seconds": 60,
    "est_disk_mb": 2,
    "install_method": "apt",
    "apt_packages": ["nmap"],
    "check": {"command": "nmap"}
  },
  "secforge-builtin": {
    "title": "SecForge Built-in Checks",
    "description": "Checks for exposed files (.env, .git), missing headers, cookie flags, dangerous HTTP methods",
    "tier": 1,
    "est_seconds": 10,
    "est_disk_mb": 0,
    "install_method": "builtin",
    "check": {"path": "scripts/scan-quick.sh"}
  },
  "check-email-dns": {
    "title": "Email/DNS Security Checks",
    "description": "Checks SPF, DMARC, DKIM, DNSSEC records for your domain",
    "tier": 1,
    "est_seconds": 10,
    "est_disk_mb": 0,
    "install_method": "builtin",
    "check": {"path": "scripts/check-email-dns.sh"},
    "requires_commands": ["dig"]
  },
  "check-mysql": {
    "title": "MySQL Security Checks",
    "description": "Checks MySQL for anonymous accounts, remote root, weak passwords",
    "tier": 1,
    "est_seconds": 5,
    "est_disk_mb": 0,
    "install_method": "builtin",
    "check": {"path": "scripts/check-mysql.sh"}
  },
  "zap": {
    "title": "OWASP ZAP",
    "description": "Active web scanner — sends many payloads to discover vulnerabilities",
    "tier": 2,
    "est_seconds": 600,
    "est_disk_mb": 500,
    "install_method": "custom",
    "custom_function": "install_zap",
    "check": {"command": "zap.sh"}
  },
  "wordlists": {
    "title": "SecLists Subset",
    "description": "Curated wordlists for directory and password fuzzing",
    "tier": 0,
    "est_seconds": 0,
    "est_disk_mb": 50,
    "install_method": "custom",
    "custom_function": "install_wordlists",
    "check": {"path": "wordlists/directories.txt"}
  }
}
```

Fill in ALL ~51 tools following these patterns. Check the existing `bin/` directory and install scripts for the complete list. Use `check.command` for binaries and `check.path` for scripts/directories.

- [ ] **Step 2: Validate tools.json**

```bash
cd /var/www/secforge
python3 -c "
import json
t = json.load(open('catalog/tools.json'))
tools = {k: v for k, v in t.items() if k != '_meta'}
print(f'Total tools: {len(tools)}')
# Validate required fields
required = {'title', 'description', 'tier', 'est_seconds', 'est_disk_mb', 'install_method', 'check'}
for tid, meta in tools.items():
    missing = required - set(meta.keys())
    if missing:
        print(f'  ERROR: {tid} missing: {missing}')
# Validate install_method enum
valid_methods = {'builtin', 'apt', 'github_release', 'git_clone', 'pip_venv', 'npm_local', 'custom'}
for tid, meta in tools.items():
    if meta['install_method'] not in valid_methods:
        print(f'  ERROR: {tid} invalid method: {meta[\"install_method\"]}')
# Validate depends_on references exist
for tid, meta in tools.items():
    for dep in meta.get('depends_on', []):
        if dep not in tools:
            print(f'  ERROR: {tid} depends on unknown tool: {dep}')
# Count by tier
for tier in (0, 1, 2):
    count = sum(1 for m in tools.values() if m['tier'] == tier)
    print(f'  Tier {tier}: {count} tools')
print('VALIDATION OK')
"
```

Expected: Total tools >= 45, no ERRORs, VALIDATION OK.

- [ ] **Step 3: Commit**

```bash
git add catalog/tools.json
git commit -m "feat: add catalog/tools.json — single source of truth for 51 tools

Per-tool metadata: tier, description, est_seconds, est_disk_mb,
install_method + method-specific fields, check (installedness),
depends_on (resource dependencies), requires_commands.

Used by: dashboard, preflight, estimator, installer, AI explanations."
```

---

## Task 2: Create `catalog/profiles.json` — 9 Stack Profiles

**Files:**
- Create: `catalog/profiles.json`

- [ ] **Step 1: Create profiles.json with all 9 stack profiles**

Each profile has:
- `title`, `description`: Human-readable
- `detect_files`: Array of file paths that indicate this stack (checked by preflight when `--code-path` provided)
- `detect_headers`: Object of `{header_name: substring}` — case-insensitive contains match
- `detect_cookies`: Array of cookie name substrings (e.g., `"connect.sid"` for Express)
- `min_detect_signals`: Minimum matching signals for auto-detect (default: 2)
- `tools_include`: Array of canonical tool IDs — strict allowlist
- `tools_exclude`: Array of canonical tool IDs — explicitly not needed (for AI explanation)
- `dep_checker`: The dependency checker tool for this stack (e.g., `"npm-audit"`)
- `nuclei_tags_boost`: Tags for `-tags` in quick scan mode
- `nuclei_tags_skip`: Tags for `-etags` in full scan mode
- `common_endpoints`: Paths to probe (recon-only, no findings)
- `priority_boosts`: Category-keyed multipliers (AI-consumed, not code-enforced)
- `fix_hints`: Category-keyed advice strings (AI-consumed)
- `suggested_extras`: Array of `{tool, reason}` for tools worth considering

Create all 9 profiles:

```json
{
  "_meta": {
    "version": "1.0",
    "description": "Stack profiles. AI picks one based on detected tech. Override with --stack. Manual users get auto-detect from HTTP headers."
  },
  "node-nginx": {
    "title": "Node.js + nginx",
    "description": "Express/Next.js/Nuxt behind nginx reverse proxy",
    "detect_files": ["package.json", "node_modules/", "next.config.js", "next.config.mjs", "nuxt.config.ts", "nuxt.config.js"],
    "detect_headers": {"X-Powered-By": "Express", "Server": "nginx"},
    "detect_cookies": ["connect.sid"],
    "min_detect_signals": 2,
    "tools_include": [
      "wafw00f", "whatweb", "nuclei", "nmap", "testssl", "ffuf",
      "ssh-audit", "lynis", "gitleaks", "npm-audit", "check-email-dns",
      "secforge-builtin", "subfinder", "httpx"
    ],
    "tools_exclude": [
      "pip-audit", "osv-scanner", "apkdeeplens", "apkhunt", "apkleaks",
      "checkov", "prowler", "commix", "wapiti", "sqlmap", "xsstrike",
      "oscap", "john", "hashcat"
    ],
    "dep_checker": "npm-audit",
    "nuclei_tags_boost": ["nodejs", "express", "nextjs", "nuxtjs", "javascript", "npm"],
    "nuclei_tags_skip": ["wordpress", "joomla", "drupal", "php", "java", "spring", "ruby", "rails", "python", "django", "flask"],
    "common_endpoints": ["/api/", "/graphql", "/.env", "/.git/HEAD", "/node_modules/", "/package.json"],
    "priority_boosts": {
      "deps": 1.2,
      "secrets": 1.3,
      "headers": 1.1
    },
    "fix_hints": {
      "headers": "Add security headers via Express middleware (helmet) or nginx server block (add_header directives)",
      "tls": "Configure TLS in nginx: ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers HIGH:!aNULL:!MD5;",
      "secrets": "Use dotenv with .gitignore. Never commit .env files. Rotate any leaked keys immediately.",
      "deps": "Run 'npm audit fix' to patch known vulnerabilities. Pin versions in package-lock.json."
    },
    "suggested_extras": [
      {"tool": "trivy", "reason": "Scans your server OS for vulnerable system packages (OpenSSL, glibc, etc). Not Node-specific but catches issues other tools miss. Adds ~2 min."},
      {"tool": "nikto", "reason": "Additional web server misconfiguration checks. Good for catching things nuclei templates might miss. Adds ~3 min."},
      {"tool": "interactsh-client", "reason": "Captures out-of-band callbacks for blind SSRF/XSS/injection. Used automatically by nuclei OOB templates. Adds ~0 min (runs in background)."}
    ]
  }
}
```

Create the remaining 8 profiles following this exact format: `node-bare`, `python-nginx`, `php-nginx`, `wordpress`, `java-spring`, `ruby-rails`, `static-nginx`, `go-bare`.

For each profile, research the correct:
- `detect_files` (e.g., wordpress: `wp-config.php`, `wp-content/`, `wp-admin/`)
- `detect_headers` (e.g., ruby-rails: `X-Powered-By: Phusion Passenger` or `Puma`)
- `detect_cookies` (e.g., php: `PHPSESSID`)
- `tools_include` (stack-relevant Tier 1 tools)
- `tools_exclude` (clearly irrelevant tools with reasons the AI can explain)
- `nuclei_tags_boost` / `nuclei_tags_skip` (match nuclei template tag taxonomy)
- `common_endpoints` (stack-specific paths to probe)
- `fix_hints` (stack-specific remediation advice)

- [ ] **Step 2: Validate profiles.json**

```bash
cd /var/www/secforge
python3 -c "
import json
p = json.load(open('catalog/profiles.json'))
t = json.load(open('catalog/tools.json'))
tool_ids = set(k for k in t if k != '_meta')
profiles = {k: v for k, v in p.items() if k != '_meta'}
print(f'Profiles: {len(profiles)}')
for pid, prof in profiles.items():
    # Check tools_include reference valid tool IDs
    for tid in prof.get('tools_include', []):
        if tid not in tool_ids:
            print(f'  ERROR: {pid} includes unknown tool: {tid}')
    for tid in prof.get('tools_exclude', []):
        if tid not in tool_ids:
            print(f'  ERROR: {pid} excludes unknown tool: {tid}')
    # Check required fields
    for field in ('title', 'description', 'detect_files', 'detect_headers', 'tools_include', 'nuclei_tags_boost', 'nuclei_tags_skip'):
        if field not in prof:
            print(f'  ERROR: {pid} missing field: {field}')
print('VALIDATION OK')
"
```

Expected: 9 profiles, no ERRORs.

- [ ] **Step 3: Commit**

```bash
git add catalog/profiles.json
git commit -m "feat: add catalog/profiles.json — 9 stack profiles

node-nginx, node-bare, python-nginx, php-nginx, wordpress,
java-spring, ruby-rails, static-nginx, go-bare.

Each profile: tools_include/exclude, nuclei_tags, common_endpoints,
priority_boosts, fix_hints, detection signals, suggested_extras."
```

---

## Task 3: Add `sf_should_run_tool` + `sf_emit_dashboard_event` to `_lib.sh`

**Files:**
- Modify: `scripts/_lib.sh`

These are shared helpers used by scan-quick.sh, scan-all.sh, and install-tools.sh.

- [ ] **Step 1: Add sf_should_run_tool function**

Append to `scripts/_lib.sh`:

```bash
# --- Profile-based tool gating ---

sf_should_run_tool() {
  # Usage: sf_should_run_tool <canonical_tool_id>
  # Returns 0 (true) if the tool should run, 1 (false) if skipped.
  # Reads SECFORGE_TOOLS_PLANNED (CSV, set by preflight).
  # If SECFORGE_TOOLS_PLANNED is empty/unset, all tools run (legacy behavior).
  local tool_id="$1"
  local planned="${SECFORGE_TOOLS_PLANNED:-}"

  # No profile active → run everything (legacy behavior)
  if [[ -z "${planned}" ]]; then
    return 0
  fi

  # Check if tool_id is in the CSV
  local IFS=','
  for t in ${planned}; do
    if [[ "${t}" == "${tool_id}" ]]; then
      return 0
    fi
  done

  return 1
}

# --- Dashboard status events ---

sf_emit_dashboard_event() {
  # Usage: sf_emit_dashboard_event '{"event":"tool_start","tool":"nuclei","index":1}'
  # Writes a JSON line to the dashboard status file (if set).
  # Silent no-op if SECFORGE_DASHBOARD_STATUS is unset.
  local json_line="$1"
  local status_file="${SECFORGE_DASHBOARD_STATUS:-}"

  if [[ -n "${status_file}" ]]; then
    echo "${json_line}" >> "${status_file}" 2>/dev/null || true
  fi
}
```

- [ ] **Step 2: Validate bash syntax**

```bash
bash -n scripts/_lib.sh && echo "OK"
```

Expected: OK

- [ ] **Step 3: Commit**

```bash
git add scripts/_lib.sh
git commit -m "feat: add sf_should_run_tool + sf_emit_dashboard_event to _lib.sh

sf_should_run_tool: profile-based tool gating. Reads SECFORGE_TOOLS_PLANNED
CSV from preflight. If empty, all tools run (legacy behavior).

sf_emit_dashboard_event: writes JSON status lines to dashboard file.
Silent no-op when dashboard is not active."
```

---

## Task 4: Fix Canonical Tool IDs in Scan Scripts

**Files:**
- Modify: `scripts/scan-quick.sh`
- Modify: `scripts/scan-all.sh`

Three mismatches to fix: `emaildns` → `check-email-dns`, `mysql` → `check-mysql`, `builtin` → `secforge-builtin`.

- [ ] **Step 1: Fix scan-quick.sh tool IDs**

In `scripts/scan-quick.sh`, find and replace these `sf_track_run` first arguments:

```bash
# Find:   sf_track_run emaildns
# Replace: sf_track_run check-email-dns

# Find:   sf_track_run builtin  (if present — builtin checks are being added in Task 6)
# Note: scan-quick.sh may not have builtin yet — will be added in Task 6
```

Search for all `sf_track_run` calls and verify each first argument matches the canonical ID in `catalog/tools.json`.

- [ ] **Step 2: Fix scan-all.sh tool IDs**

In `scripts/scan-all.sh`, find and replace:

```bash
# Find:   sf_track_run emaildns
# Replace: sf_track_run check-email-dns

# Find:   sf_track_run mysql
# Replace: sf_track_run check-mysql

# Find:   _SF_TOOLS_RUN+=("builtin")
# Replace: _SF_TOOLS_RUN+=("secforge-builtin")

# Also fix the sf_track_run calls for builtin if present
```

Search for ALL occurrences of the old IDs (`emaildns`, `mysql`, `builtin`) and replace with canonical IDs.

- [ ] **Step 3: Validate syntax + verify IDs**

```bash
bash -n scripts/scan-quick.sh scripts/scan-all.sh && echo "bash OK"
# Verify no old IDs remain:
grep -n 'sf_track_run emaildns\|sf_track_run mysql\|sf_track_run builtin' scripts/scan-quick.sh scripts/scan-all.sh && echo "OLD IDS FOUND" || echo "ALL CANONICAL"
```

Expected: bash OK, ALL CANONICAL

- [ ] **Step 4: Commit**

```bash
git add scripts/scan-quick.sh scripts/scan-all.sh
git commit -m "fix: use canonical tool IDs in scan scripts

emaildns → check-email-dns, mysql → check-mysql, builtin → secforge-builtin.
Aligns manifest tools_run with finding.tool values from parsers.
Prevents state DB fixed-gating mismatches."
```

---

## Task 5: Add `--stack`, `--skip`, `--code-path`, `--dashboard`, `--tier` Flags to CLI

**Files:**
- Modify: `bin/secforge`

- [ ] **Step 1: Update scan command arg parsing**

In `bin/secforge`, find the `scan)` case block. Currently it parses `--full` and passes remaining args. Add new flag parsing:

```bash
scan)
    shift  # remove "scan"
    _sf_scan_full=0
    _sf_stack=""
    _sf_skip=""
    _sf_code_path=""
    _sf_dashboard=0
    _sf_tier=""

    # Collect our flags, pass everything else to scan script
    _sf_scan_args=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --full)       _sf_scan_full=1; shift ;;
        --stack)      _sf_stack="$2"; shift 2 ;;
        --skip)       _sf_skip="$2"; shift 2 ;;
        --code-path)  _sf_code_path="$2"; shift 2 ;;
        --dashboard)  _sf_dashboard=1; shift ;;
        --tier)       _sf_tier="$2"; shift 2 ;;
        *)            _sf_scan_args+=("$1"); shift ;;
      esac
    done

    # Build env vars for preflight/scan scripts
    [[ -n "${_sf_stack}" ]] && export SECFORGE_STACK="${_sf_stack}"
    [[ -n "${_sf_skip}" ]] && export SECFORGE_SKIP="${_sf_skip}"
    [[ -n "${_sf_code_path}" ]] && export SECFORGE_CODE_PATH="${_sf_code_path}"
    [[ -n "${_sf_tier}" ]] && export SECFORGE_TIER_OVERRIDE="${_sf_tier}"

    # Dashboard handling
    if [[ "${_sf_dashboard}" == "1" ]] && [[ -z "${TMUX:-}" ]] && command -v tmux >/dev/null 2>&1; then
      # Not in tmux but --dashboard requested: start tmux session
      exec tmux new-session -s secforge \
        "${SECFORGE_ROOT}/bin/secforge scan $(printf '%q ' "${_sf_scan_args[@]}") --stack '${_sf_stack}' --code-path '${_sf_code_path}' --skip '${_sf_skip}' --dashboard"
    fi

    # Select scan script
    if [[ "${_sf_scan_full}" == "1" ]]; then
      exec bash "${SCRIPT_DIR}/scan-all.sh" "${_sf_scan_args[@]}"
    else
      exec bash "${SCRIPT_DIR}/scan-quick.sh" "${_sf_scan_args[@]}"
    fi
    ;;
```

- [ ] **Step 2: Rename --stack to --stack-hints in export command**

In the `export)` case block, find the `--stack` arg parser and add `--stack-hints` as the primary name:

```python
    elif a == '--stack-hints' and i+1 < len(args):
        stack_hints = args[i+1]; i += 2
    elif a == '--stack' and i+1 < len(args):
        stack_hints = args[i+1]; i += 2  # backward-compat alias
```

- [ ] **Step 3: Update help text**

In `show_help()`, add the new flags:

```
Scanning:
  scan <target>                Tier-1 quick scan
  scan --full <target>         Full scan (Tier 1 + Tier 2 opt-in)
    --stack <profile>          Use stack profile (e.g. node-nginx, wordpress)
    --skip <tool1,tool2>       Skip specific tools this run
    --code-path <path>         Path to source code (enables gitleaks, npm-audit, etc)
    --dashboard                Open live dashboard in tmux pane
    --tier 1|2                 Override tier ceiling for this run
```

- [ ] **Step 4: Validate**

```bash
bash -n bin/secforge && echo "OK"
```

- [ ] **Step 5: Commit**

```bash
git add bin/secforge
git commit -m "feat: add --stack, --skip, --code-path, --dashboard, --tier flags to CLI

scan command now parses profile and dashboard flags, exports as env vars
for preflight/scan scripts. --stack-hints replaces --stack on export
(backward alias kept). Help text updated."
```

---

## Task 6: Add secforge-builtin Web Checks to scan-quick.sh

**Files:**
- Modify: `scripts/scan-quick.sh`

Currently `sf_builtin_web_checks` only runs in `scan-all.sh`. It's zero-dependency, ~5 seconds, and catches critical exposures (.env, .git, missing headers, cookie flags).

- [ ] **Step 1: Add builtin web checks to scan-quick.sh**

The `sf_builtin_web_checks` function is defined in `scan-all.sh`. Either:
a) Extract it to `_lib.sh` so both scripts can use it, OR
b) Copy the function to `scan-quick.sh`

Option (a) is cleaner. Move `sf_builtin_web_checks` from `scan-all.sh` to `scripts/_lib.sh`, then call it from both scan scripts:

In `scan-quick.sh`, add after the existing tool blocks (before the merge step):

```bash
    # Built-in curl checks (zero-dependency, high value).
    if sf_should_run_tool "secforge-builtin"; then
      _SF_TOOLS_RUN+=("secforge-builtin")
      sf_builtin_web_checks "${SECFORGE_TARGET_URL%/}" "${SECFORGE_SESSION_DIR}/webapp/builtin.json" "${delay_ms:-200}"
      if [[ ! -s "${SECFORGE_SESSION_DIR}/webapp/builtin.json" ]]; then
        _SF_TOOLS_FAILED+=("secforge-builtin")
      fi
    fi
```

- [ ] **Step 2: Validate**

```bash
bash -n scripts/scan-quick.sh scripts/scan-all.sh scripts/_lib.sh && echo "OK"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/_lib.sh scripts/scan-quick.sh scripts/scan-all.sh
git commit -m "feat: add secforge-builtin web checks to scan-quick.sh

Moved sf_builtin_web_checks to _lib.sh (shared). Now runs in both
quick and full scans. Zero-dep, ~5s, catches .env/.git exposure,
missing headers, cookie flags. Gated by sf_should_run_tool."
```

---

## Task 7: Extend `preflight.sh` — Stack Detection + Profile Expansion

**Files:**
- Modify: `scripts/preflight.sh`

This is the biggest task. Preflight becomes the single source of truth for stack resolution and tool planning.

- [ ] **Step 1: Add stack detection logic**

Add a Python section to preflight.sh that:
1. Reads `--stack` override from `SECFORGE_STACK` env var (highest priority)
2. If no override, auto-detects from HTTP headers + code path files
3. Writes `stack_detection` to `preflight.json`
4. Exports `SECFORGE_STACK_PROFILE`, `SECFORGE_DETECTED_STACK`, `SECFORGE_DETECT_CONFIDENCE`

The detection logic:
- Read `catalog/profiles.json` and `catalog/tools.json`
- For each profile, count matching signals:
  - `detect_headers`: case-insensitive contains match against HTTP response headers
  - `detect_cookies`: substring match against Set-Cookie header values
  - `detect_files`: file/directory existence check under `SECFORGE_CODE_PATH`
- If `--stack` was passed: use that profile directly (score = "explicit")
- If auto-detect: pick the profile with highest score, but only if:
  - Score >= `min_detect_signals` (default: 2)
  - No other profile has the same score (no ties)
  - Otherwise: no profile (empty string, legacy behavior)

Add this as a Python heredoc in preflight.sh, after the existing preflight logic:

```bash
# --- Stack detection + profile expansion ---
_sf_stack_result="$(python3 - "${SECFORGE_ROOT}" "${SECFORGE_STACK:-}" "${SECFORGE_CODE_PATH:-}" "${SECFORGE_TARGET_URL:-}" "${SECFORGE_SKIP:-}" "${SECFORGE_TIER_OVERRIDE:-}" <<'PYEOF'
import json, os, sys, subprocess
from pathlib import Path

secforge_root = Path(sys.argv[1])
stack_override = sys.argv[2]  # from --stack flag
code_path = sys.argv[3]       # from --code-path flag
target_url = sys.argv[4]      # target URL
skip_csv = sys.argv[5]        # from --skip flag
tier_override = sys.argv[6]   # from --tier flag

# Load catalogs
tools_path = secforge_root / "catalog" / "tools.json"
profiles_path = secforge_root / "catalog" / "profiles.json"

tools = {}
profiles = {}
if tools_path.exists():
    tools = {k: v for k, v in json.loads(tools_path.read_text()).items() if k != "_meta"}
if profiles_path.exists():
    profiles = {k: v for k, v in json.loads(profiles_path.read_text()).items() if k != "_meta"}

# --- Stack detection ---
detected_stack = ""
confidence = "none"
score = 0
threshold = 2
signals = []

if stack_override and stack_override in profiles:
    # Explicit --stack override
    detected_stack = stack_override
    confidence = "explicit"
    score = 999
    signals = ["flag:--stack"]
elif profiles:
    # Auto-detect from headers + files
    headers_raw = ""
    cookies_raw = ""
    if target_url:
        try:
            result = subprocess.run(
                ["curl", "-sI", "--max-time", "10", target_url],
                capture_output=True, text=True, timeout=15
            )
            headers_raw = result.stdout.lower()
            # Extract cookies
            for line in result.stdout.splitlines():
                if line.lower().startswith("set-cookie:"):
                    cookies_raw += line.lower() + "\n"
        except Exception:
            pass

    scores = {}
    signals_map = {}
    for pid, prof in profiles.items():
        s = 0
        sigs = []
        # Check headers (case-insensitive contains)
        for hdr_name, hdr_val in prof.get("detect_headers", {}).items():
            if hdr_val.lower() in headers_raw:
                s += 1
                sigs.append(f"header:{hdr_name.lower()}={hdr_val.lower()}")
        # Check cookies
        for cookie_name in prof.get("detect_cookies", []):
            if cookie_name.lower() in cookies_raw:
                s += 1
                sigs.append(f"cookie:{cookie_name.lower()}")
        # Check files (if code_path provided)
        if code_path:
            cp = Path(code_path)
            for detect_file in prof.get("detect_files", []):
                if (cp / detect_file).exists():
                    s += 1
                    sigs.append(f"file:{detect_file}")
        scores[pid] = s
        signals_map[pid] = sigs

    # Find winner
    if scores:
        max_score = max(scores.values())
        winners = [pid for pid, s in scores.items() if s == max_score and s > 0]
        min_signals = profiles.get(winners[0], {}).get("min_detect_signals", 2) if len(winners) == 1 else 2

        if len(winners) == 1 and max_score >= min_signals:
            detected_stack = winners[0]
            confidence = "high"
            score = max_score
            threshold = min_signals
            signals = signals_map[detected_stack]
        elif max_score > 0:
            confidence = "low"
            score = max_score
            # Collect all candidates for hint
            signals = [f"candidate:{pid}({scores[pid]})" for pid in winners]

# --- Profile expansion ---
resolved_profile = detected_stack if confidence in ("high", "explicit") else ""
prof = profiles.get(resolved_profile, {})

# Read config for TIER_MAX
tier_max = 1
config_path = secforge_root / "config" / "secforge.conf"
if config_path.exists():
    for line in config_path.read_text().splitlines():
        line = line.strip()
        if line.startswith("TIER_MAX="):
            try:
                tier_max = int(line.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass
        elif line.startswith("DEFAULT_TIER=") and tier_max == 1:
            try:
                tier_max = int(line.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass

# CLI --tier override
if tier_override:
    try:
        tier_max = int(tier_override)
    except ValueError:
        pass

# Build tools_planned
tools_planned = []
tools_skipped = []
tools_missing = []
skip_set = set(s.strip() for s in skip_csv.split(",") if s.strip()) if skip_csv else set()

if prof and prof.get("tools_include"):
    for tid in prof["tools_include"]:
        if tid not in tools:
            print(f"[secforge] WARN: profile '{resolved_profile}' references unknown tool '{tid}', skipping.", file=sys.stderr)
            continue
        tool_meta = tools[tid]
        # Tier gating
        if tool_meta.get("tier", 1) > tier_max:
            tools_skipped.append(tid)
            continue
        # --skip gating
        if tid in skip_set:
            tools_skipped.append(tid)
            continue
        # Installedness check
        check = tool_meta.get("check", {})
        installed = False
        if "command" in check:
            cmd_name = check["command"]
            bin_path = secforge_root / "bin" / cmd_name
            if bin_path.exists() or os.popen(f"command -v {cmd_name} 2>/dev/null").read().strip():
                installed = True
        elif "path" in check:
            check_path = secforge_root / check["path"]
            installed = check_path.exists()
        else:
            installed = True  # No check = assume available

        # Check depends_on
        if installed:
            for dep in tool_meta.get("depends_on", []):
                dep_meta = tools.get(dep, {})
                dep_check = dep_meta.get("check", {})
                if "path" in dep_check:
                    if not (secforge_root / dep_check["path"]).exists():
                        installed = False
                        break

        if installed:
            tools_planned.append(tid)
        else:
            tools_missing.append(tid)

    # Validate --skip unknown tools
    known_ids = set(tools.keys())
    for s in skip_set:
        if s not in known_ids:
            print(f"[secforge] WARN: unknown tool '{s}' in --skip, ignoring.", file=sys.stderr)

# Nuclei tags
nuclei_tags = ",".join(prof.get("nuclei_tags_boost", []))
nuclei_etags = ",".join(prof.get("nuclei_tags_skip", []))
common_endpoints = ",".join(prof.get("common_endpoints", []))

# DB auto-detect for local targets
target_input = os.environ.get("SECFORGE_TARGET_INPUT", "")
if target_input in ("this_server", "localhost", "127.0.0.1"):
    for db_tool, service in [("check-mysql", "mysql"), ("check-mysql", "mariadb")]:
        if db_tool not in tools_planned:
            try:
                result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    tools_planned.append(db_tool)
            except Exception:
                pass

# Output as declare statements for bash sourcing
print(f'SECFORGE_STACK_PROFILE="{resolved_profile}"')
print(f'SECFORGE_DETECTED_STACK="{detected_stack}"')
print(f'SECFORGE_DETECT_CONFIDENCE="{confidence}"')
print(f'SECFORGE_TOOLS_PLANNED="{",".join(tools_planned)}"')
print(f'SECFORGE_TOOLS_SKIPPED="{",".join(tools_skipped)}"')
print(f'SECFORGE_TOOLS_MISSING="{",".join(tools_missing)}"')
print(f'SECFORGE_NUCLEI_TAGS="{nuclei_tags}"')
print(f'SECFORGE_NUCLEI_EXCLUDE_TAGS="{nuclei_etags}"')
print(f'SECFORGE_COMMON_ENDPOINTS="{common_endpoints}"')
print(f'SECFORGE_TIER_MAX="{tier_max}"')
print(f'SECFORGE_SCAN_MODE="{os.environ.get("SECFORGE_SCAN_MODE", "quick")}"')
PYEOF
)" || true

# Source the stack detection results
if [[ -n "${_sf_stack_result}" ]]; then
  eval "${_sf_stack_result}"
fi

# Write stack_detection to preflight.json (append to existing)
# ... (add JSON merge logic or write a separate field)
```

This is complex. The implementation should:
1. Place this Python block AFTER the existing preflight logic (which already sets SECFORGE_TARGET_URL, etc.)
2. Export all the env vars via the `declare -p` + tempfile pattern already used by preflight

- [ ] **Step 2: Validate**

```bash
bash -n scripts/preflight.sh && echo "OK"
# Test with --stack flag:
SECFORGE_STACK="node-nginx" SECFORGE_ROOT=/var/www/secforge python3 -c "
# Quick test of the detection logic
import json
from pathlib import Path
root = Path('/var/www/secforge')
tools = json.loads((root / 'catalog/tools.json').read_text())
profiles = json.loads((root / 'catalog/profiles.json').read_text())
prof = profiles.get('node-nginx', {})
print('tools_include:', len(prof.get('tools_include', [])))
print('Profile loaded OK')
"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/preflight.sh
git commit -m "feat: add stack detection + profile expansion to preflight.sh

Reads --stack flag or auto-detects from HTTP headers + code path files.
Exports: SECFORGE_TOOLS_PLANNED, SECFORGE_NUCLEI_TAGS, SECFORGE_TIER_MAX,
SECFORGE_TOOLS_MISSING, etc. Scan scripts just read env vars.

Confidence-gated auto-detect: high (2+ signals) → auto-apply,
low/tie/none → legacy full scan + hint."
```

---

## Task 8: Gate Every Tool Block in Scan Scripts

**Files:**
- Modify: `scripts/scan-quick.sh`
- Modify: `scripts/scan-all.sh`

Add `sf_should_run_tool` gate before EVERY tool invocation.

- [ ] **Step 1: Gate tools in scan-quick.sh**

For each `sf_track_run` or `_SF_TOOLS_RUN+=` call in scan-quick.sh, wrap with the gate:

```bash
# Before (example):
if sf_tool wafw00f >/dev/null 2>&1; then
  sf_track_run wafw00f ...
fi

# After:
if sf_should_run_tool "wafw00f" && sf_tool wafw00f >/dev/null 2>&1; then
  sf_track_run wafw00f ...
else
  [[ -n "${SECFORGE_TOOLS_PLANNED:-}" ]] && sf_log "Skipping wafw00f (not in profile or not installed)"
fi
```

Apply this pattern to EVERY tool block in scan-quick.sh. The existing `sf_tool` check stays as a safety net.

Also add nuclei tag handling:
```bash
# For nuclei, apply profile tags:
if sf_should_run_tool "nuclei" && sf_tool nuclei >/dev/null 2>&1; then
  local _nuclei_tpl="${SECFORGE_ROOT}/tools/nuclei-templates"
  if [[ -d "${_nuclei_tpl}" ]]; then
    local _nuclei_extra_args=""
    # Quick scan: use -tags for filtered scanning
    if [[ -n "${SECFORGE_NUCLEI_TAGS:-}" ]]; then
      _nuclei_extra_args="-tags ${SECFORGE_NUCLEI_TAGS}"
    fi
    sf_track_run nuclei "${SECFORGE_SESSION_DIR}/webapp/nuclei.json" "${timeout_web}" "${SECFORGE_SESSION_DIR}/webapp/nuclei.log" "$(sf_tool nuclei)" -duc -u "${SECFORGE_TARGET_URL}" -t "${_nuclei_tpl}" ${_nuclei_extra_args} -json-export "${SECFORGE_SESSION_DIR}/webapp/nuclei.json"
  fi
fi
```

- [ ] **Step 2: Gate tools in scan-all.sh**

Same pattern for ALL tool blocks in scan-all.sh. Additionally for full scans:
- Nuclei uses `-etags` (exclude tags) instead of `-tags`:
```bash
if [[ -n "${SECFORGE_NUCLEI_EXCLUDE_TAGS:-}" ]]; then
  _nuclei_extra_args="-etags ${SECFORGE_NUCLEI_EXCLUDE_TAGS}"
fi
```

- [ ] **Step 3: Validate**

```bash
bash -n scripts/scan-quick.sh scripts/scan-all.sh && echo "bash OK"
# Count gates:
grep -c 'sf_should_run_tool' scripts/scan-quick.sh scripts/scan-all.sh
```

Expected: bash OK, each file should have 10+ gates.

- [ ] **Step 4: Commit**

```bash
git add scripts/scan-quick.sh scripts/scan-all.sh
git commit -m "feat: gate every tool block with sf_should_run_tool

All tool invocations in scan-quick.sh and scan-all.sh now check
SECFORGE_TOOLS_PLANNED before running. Nuclei uses -tags (quick)
or -etags (full) from profile. Legacy behavior preserved when
no profile is active (SECFORGE_TOOLS_PLANNED empty)."
```

---

## Task 9: Record `tool_durations` in Scan Manifest

**Files:**
- Modify: `scripts/scan-quick.sh`
- Modify: `scripts/scan-all.sh`

- [ ] **Step 1: Track per-tool duration in sf_track_run**

Modify `sf_track_run` in both scripts to capture start/end time and record duration:

```bash
sf_track_run() {
  local tool_name="$1"
  local check_file="$2"
  shift 2
  local _stdout_path="$2"
  _SF_TOOLS_RUN+=("${tool_name}")

  # Track duration
  local _start_time
  _start_time="$(date +%s)"

  sf_run "$@"

  local _end_time
  _end_time="$(date +%s)"
  local _duration=$(( _end_time - _start_time ))

  # Store duration for manifest
  _SF_TOOL_DURATIONS+=("${tool_name}:${_duration}")

  # ... existing exit code / failure checks ...
}
```

Add at the top of each scan script (near the manifest array declarations):
```bash
_SF_TOOL_DURATIONS=()
```

- [ ] **Step 2: Write tool_durations to manifest**

In `sf_write_manifest`, add tool_durations to the JSON output:

```bash
sf_write_manifest() {
  local session_dir="$1"
  local profile="${2:-quick}"
  local scan_date
  scan_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "${session_dir}" "${profile}" "${scan_date}" <<'PYEOF'
import json, sys, os
session_dir = sys.argv[1]
profile = sys.argv[2]
scan_date = sys.argv[3]
tools_run = os.environ.get("SF_MANIFEST_TOOLS_RUN", "").split(",")
tools_failed = os.environ.get("SF_MANIFEST_TOOLS_FAILED", "").split(",")
tool_durations_raw = os.environ.get("SF_MANIFEST_TOOL_DURATIONS", "").split(",")
tools_run = [t for t in tools_run if t]
tools_failed = [t for t in tools_failed if t]
# Parse durations: "nuclei:87,nmap:45" → {"nuclei": 87, "nmap": 45}
tool_durations = {}
for entry in tool_durations_raw:
    if ":" in entry:
        tid, dur = entry.rsplit(":", 1)
        try:
            tool_durations[tid] = int(dur)
        except ValueError:
            pass
manifest = {
    "tools_run": sorted(set(tools_run)),
    "tools_failed": sorted(set(tools_failed)),
    "tool_durations": tool_durations,
    "profile": os.environ.get("SECFORGE_STACK_PROFILE", ""),
    "scan_mode": profile,
    "tier_max": int(os.environ.get("SECFORGE_TIER_MAX", "1")),
    "scan_date": scan_date,
}
out = os.path.join(session_dir, "scan_manifest.json")
with open(out, "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=False)
PYEOF
}
```

Update the manifest writing call to pass durations:
```bash
SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]}")" \
SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]}")" \
SF_MANIFEST_TOOL_DURATIONS="$(IFS=,; echo "${_SF_TOOL_DURATIONS[*]}")" \
sf_write_manifest "${SECFORGE_SESSION_DIR}" "${SECFORGE_SCAN_MODE:-quick}"
```

- [ ] **Step 3: Validate**

```bash
bash -n scripts/scan-quick.sh scripts/scan-all.sh && echo "OK"
```

- [ ] **Step 4: Commit**

```bash
git add scripts/scan-quick.sh scripts/scan-all.sh
git commit -m "feat: record tool_durations in scan_manifest.json

Each sf_track_run now captures start/end time. Durations (integer
seconds) written to manifest as tool_durations object. Also writes
profile, scan_mode, tier_max to manifest for estimator matching."
```

---

## Task 10: Create `scripts/bootstrap.sh` — Minimal Installer

**Files:**
- Create: `scripts/bootstrap.sh`

- [ ] **Step 1: Write bootstrap.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

# SecForge Bootstrap — minimal install (no security tools)
# Creates dir structure, installs base deps + gum + tmux, sets up PATH.
# Security tools are installed later via: secforge install <tool1> <tool2> ...

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"
GUM_VERSION_PREFIX="0.14"  # Pin major.minor, allow patch updates

sf_log() { echo "[secforge] $*"; }
sf_warn() { echo "[secforge] WARN: $*" >&2; }
sf_die() { echo "[secforge] ERROR: $*" >&2; exit 1; }

# Must be root
[[ "${EUID}" -eq 0 ]] || sf_die "Bootstrap requires root. Run: sudo $0"

# Must be Ubuntu/Debian
command -v apt-get >/dev/null 2>&1 || sf_die "SecForge requires Ubuntu/Debian (apt-get not found)."

sf_log "SecForge Bootstrap — setting up base environment"

# --- Create directory structure ---
sf_log "Creating directory structure..."
mkdir -p "${SECFORGE_ROOT}"/{bin,tools,wordlists,venv,config,reports,backups,logs,state}

# --- Create secforge group ---
if ! getent group secforge >/dev/null 2>&1; then
  groupadd secforge
  sf_log "Created 'secforge' group"
fi

# Set permissions
chown root:secforge "${SECFORGE_ROOT}/state"
chmod 3770 "${SECFORGE_ROOT}/state"
touch "${SECFORGE_ROOT}/state/secforge.db"
chown root:secforge "${SECFORGE_ROOT}/state/secforge.db"
chmod 0660 "${SECFORGE_ROOT}/state/secforge.db"

chown root:secforge "${SECFORGE_ROOT}/reports"
chmod 2775 "${SECFORGE_ROOT}/reports"

chown root:secforge "${SECFORGE_ROOT}/backups"
chmod 2770 "${SECFORGE_ROOT}/backups"

# --- Install base dependencies ---
sf_log "Installing base dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv curl jq git tmux >/dev/null 2>&1

# --- Create Python venv ---
if [[ ! -d "${SECFORGE_ROOT}/venv" ]] || [[ ! -f "${SECFORGE_ROOT}/venv/bin/python3" ]]; then
  python3 -m venv "${SECFORGE_ROOT}/venv"
  sf_log "Created Python venv"
fi

# --- Install gum ---
sf_log "Installing gum (TUI toolkit)..."
_gum_arch="$(dpkg --print-architecture)"
case "${_gum_arch}" in
  amd64) _gum_arch="x86_64" ;;
  arm64) _gum_arch="aarch64" ;;
  *) sf_warn "Unsupported architecture for gum: ${_gum_arch}. Skipping gum install." ;;
esac

if [[ -n "${_gum_arch}" ]]; then
  # Find latest v0.14.x release
  _gum_url="$(curl -sL "https://api.github.com/repos/charmbracelet/gum/releases" | \
    python3 -c "
import json, sys
releases = json.load(sys.stdin)
for r in releases:
    tag = r.get('tag_name', '')
    if tag.startswith('v${GUM_VERSION_PREFIX}'):
        for a in r.get('assets', []):
            name = a.get('name', '')
            if 'Linux' in name and '${_gum_arch}' in name and name.endswith('.tar.gz'):
                print(a['browser_download_url'])
                sys.exit(0)
" 2>/dev/null || true)"

  if [[ -n "${_gum_url}" ]]; then
    _gum_tmp="$(mktemp -d)"
    curl -sL "${_gum_url}" -o "${_gum_tmp}/gum.tar.gz"
    tar xzf "${_gum_tmp}/gum.tar.gz" -C "${_gum_tmp}"
    find "${_gum_tmp}" -name "gum" -type f -exec cp {} "${SECFORGE_ROOT}/bin/gum" \;
    chmod +x "${SECFORGE_ROOT}/bin/gum"
    rm -rf "${_gum_tmp}"
    sf_log "Installed gum $(${SECFORGE_ROOT}/bin/gum --version 2>/dev/null || echo 'unknown version')"
  else
    sf_warn "Could not find gum v${GUM_VERSION_PREFIX}.x release. Dashboard will use plain text."
  fi
fi

# --- Create config from example if missing ---
if [[ ! -f "${SECFORGE_ROOT}/config/secforge.conf" ]] && [[ -f "${SECFORGE_ROOT}/config/secforge.conf.example" ]]; then
  cp "${SECFORGE_ROOT}/config/secforge.conf.example" "${SECFORGE_ROOT}/config/secforge.conf"
  sf_log "Created config from example"
fi

# --- Add to PATH ---
_path_file="/etc/profile.d/secforge.sh"
if [[ ! -f "${_path_file}" ]]; then
  cat > "${_path_file}" <<'PATHEOF'
# SecForge PATH
export PATH="/opt/secforge/bin:${PATH}"
export PYTHONPATH="/opt/secforge/scripts:${PYTHONPATH:-}"
PATHEOF
  sf_log "Added /opt/secforge/bin to system PATH"
fi

# --- Print next steps ---
echo ""
echo "============================================"
echo "  SecForge installed to ${SECFORGE_ROOT}/"
echo ""
command -v gum >/dev/null 2>&1 || [[ -x "${SECFORGE_ROOT}/bin/gum" ]] && echo "  gum ✓" || echo "  gum ✗ (plain text mode)"
command -v tmux >/dev/null 2>&1 && echo "  tmux ✓" || echo "  tmux ✗"
command -v python3 >/dev/null 2>&1 && echo "  python3 ✓" || echo "  python3 ✗"
echo ""
echo "  Next: open Claude Code or Codex in ${SECFORGE_ROOT}/"
echo "        and say \"scan my site\""
echo ""
echo "  Or:   secforge init (to configure manually)"
echo "============================================"
```

- [ ] **Step 2: Make executable and validate**

```bash
chmod +x scripts/bootstrap.sh
bash -n scripts/bootstrap.sh && echo "OK"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/bootstrap.sh
git commit -m "feat: add scripts/bootstrap.sh — minimal installer

Installs: dir structure, secforge group, python3, curl, jq, git, tmux,
gum v0.14.x binary, PATH setup. No security tools (~50MB, ~30s).
Tools installed later via: secforge install <tool1> <tool2>"
```

---

## Task 11: Create `scripts/install-tools.sh` — Per-Tool Installer

**Files:**
- Create: `scripts/install-tools.sh`

- [ ] **Step 1: Write install-tools.sh**

This script reads `catalog/tools.json` and installs tools by their `install_method`. It handles:
- `apt`: `apt-get install -y`
- `github_release`: download binary from GitHub releases
- `git_clone`: clone repo into tools/
- `pip_venv`: install in SecForge venv
- `custom`: call a named function
- `builtin`: no-op (always available)
- Alias normalization (emaildns → check-email-dns)
- `depends_on` resolution (install dependencies first)
- `--list`: show installed vs available
- `--all`: install everything

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SECFORGE_ROOT="${SECFORGE_ROOT:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

# Must be root for installs (not for --list)
_SF_NEED_ROOT=1

# --- Alias map (friendly names → canonical IDs) ---
declare -A _ALIASES=(
  [emaildns]="check-email-dns"
  [mysql]="check-mysql"
  [builtin]="secforge-builtin"
  [email-dns]="check-email-dns"
  [email]="check-email-dns"
  [dns]="check-email-dns"
)

sf_normalize_tool_id() {
  local id="$1"
  echo "${_ALIASES[$id]:-$id}"
}

# --- Read tools.json ---
sf_load_tools_json() {
  python3 -c "
import json, sys
t = json.load(open('${SECFORGE_ROOT}/catalog/tools.json'))
for k, v in t.items():
    if k == '_meta':
        continue
    print(k)
" 2>/dev/null
}

sf_get_tool_field() {
  local tool_id="$1"
  local field="$2"
  python3 -c "
import json, sys
t = json.load(open('${SECFORGE_ROOT}/catalog/tools.json'))
meta = t.get('${tool_id}', {})
val = meta.get('${field}', '')
if isinstance(val, list):
    print(','.join(val))
elif isinstance(val, dict):
    import json as j
    print(j.dumps(val))
else:
    print(val)
" 2>/dev/null
}

sf_is_tool_installed() {
  local tool_id="$1"
  local check_json
  check_json="$(sf_get_tool_field "${tool_id}" "check")"
  if [[ -z "${check_json}" ]] || [[ "${check_json}" == "{}" ]]; then
    return 0  # No check = assume available
  fi

  local check_cmd check_path
  check_cmd="$(python3 -c "import json; d=json.loads('${check_json}'); print(d.get('command',''))" 2>/dev/null)"
  check_path="$(python3 -c "import json; d=json.loads('${check_json}'); print(d.get('path',''))" 2>/dev/null)"

  if [[ -n "${check_cmd}" ]]; then
    [[ -x "${SECFORGE_ROOT}/bin/${check_cmd}" ]] && return 0
    command -v "${check_cmd}" >/dev/null 2>&1 && return 0
    return 1
  elif [[ -n "${check_path}" ]]; then
    [[ -e "${SECFORGE_ROOT}/${check_path}" ]] && return 0
    return 1
  fi
  return 0
}

# --- Install methods ---
sf_install_apt() {
  local tool_id="$1"
  local pkgs
  pkgs="$(sf_get_tool_field "${tool_id}" "apt_packages")"
  if [[ -n "${pkgs}" ]]; then
    local IFS=','
    # shellcheck disable=SC2086
    apt-get install -y -qq ${pkgs//,/ } >/dev/null 2>&1
  fi
}

sf_install_github_release() {
  local tool_id="$1"
  local repo expected_binary
  repo="$(sf_get_tool_field "${tool_id}" "repo")"
  expected_binary="$(sf_get_tool_field "${tool_id}" "expected_binary")"
  [[ -z "${repo}" ]] && { sf_warn "No repo for ${tool_id}"; return 1; }
  [[ -z "${expected_binary}" ]] && expected_binary="${tool_id}"

  # Use existing _lib.sh helper if available, otherwise basic download
  if type sf_install_github_release_binary >/dev/null 2>&1; then
    sf_install_github_release_binary "${repo}" "${expected_binary}"
  else
    # Basic GitHub release download
    local arch="$(dpkg --print-architecture)"
    [[ "${arch}" == "amd64" ]] && arch="x86_64"
    local url
    url="$(curl -sL "https://api.github.com/repos/${repo}/releases/latest" | \
      python3 -c "
import json, sys
r = json.load(sys.stdin)
for a in r.get('assets', []):
    n = a['name'].lower()
    if 'linux' in n and '${arch}' in n and (n.endswith('.tar.gz') or n.endswith('.zip')):
        if not any(x in n for x in ['.deb', '.rpm', '.apk', '.sig', '.sha']):
            print(a['browser_download_url'])
            break
" 2>/dev/null || true)"
    if [[ -n "${url}" ]]; then
      local tmp
      tmp="$(mktemp -d)"
      curl -sL "${url}" -o "${tmp}/archive"
      if file "${tmp}/archive" | grep -qi "gzip"; then
        tar xzf "${tmp}/archive" -C "${tmp}"
      elif file "${tmp}/archive" | grep -qi "zip"; then
        unzip -q "${tmp}/archive" -d "${tmp}"
      fi
      find "${tmp}" -name "${expected_binary}" -type f | head -1 | while read -r f; do
        cp "${f}" "${SECFORGE_ROOT}/bin/${expected_binary}"
        chmod +x "${SECFORGE_ROOT}/bin/${expected_binary}"
      done
      rm -rf "${tmp}"
    else
      sf_warn "Could not find release binary for ${repo}"
      return 1
    fi
  fi
}

sf_install_git_clone() {
  local tool_id="$1"
  local repo dest_path
  repo="$(sf_get_tool_field "${tool_id}" "repo")"
  dest_path="$(sf_get_tool_field "${tool_id}" "dest_path")"
  [[ -z "${repo}" ]] && { sf_warn "No repo for ${tool_id}"; return 1; }
  [[ -z "${dest_path}" ]] && dest_path="tools/${tool_id}"

  local full_path="${SECFORGE_ROOT}/${dest_path}"
  if [[ -d "${full_path}/.git" ]]; then
    cd "${full_path}" && git pull --ff-only 2>/dev/null || true
  else
    git clone --depth 1 "https://github.com/${repo}.git" "${full_path}"
  fi

  # Symlink binary if expected_binary is set
  local expected_binary
  expected_binary="$(sf_get_tool_field "${tool_id}" "expected_binary")"
  if [[ -n "${expected_binary}" ]] && [[ -f "${full_path}/${expected_binary}" ]]; then
    ln -sf "${full_path}/${expected_binary}" "${SECFORGE_ROOT}/bin/${expected_binary}"
    chmod +x "${SECFORGE_ROOT}/bin/${expected_binary}"
  fi
}

sf_install_pip_venv() {
  local tool_id="$1"
  local pip_package
  pip_package="$(sf_get_tool_field "${tool_id}" "pip_package")"
  [[ -z "${pip_package}" ]] && pip_package="${tool_id}"

  "${SECFORGE_ROOT}/venv/bin/pip" install -q "${pip_package}"

  # Symlink the binary to bin/
  local bin_name="${tool_id}"
  if [[ -f "${SECFORGE_ROOT}/venv/bin/${bin_name}" ]]; then
    ln -sf "${SECFORGE_ROOT}/venv/bin/${bin_name}" "${SECFORGE_ROOT}/bin/${bin_name}"
  fi
}

# --- Custom install functions (for oddballs) ---
install_zap() {
  sf_log "ZAP install requires the existing install-webapp.sh script"
  bash "${SCRIPT_DIR}/install-webapp.sh" 2>/dev/null || sf_warn "ZAP install failed"
}

install_wordlists() {
  if [[ -d "${SECFORGE_ROOT}/wordlists" ]] && [[ -f "${SECFORGE_ROOT}/wordlists/directories.txt" ]]; then
    sf_log "Wordlists already present"
    return 0
  fi
  # Download curated SecLists subset
  mkdir -p "${SECFORGE_ROOT}/wordlists"
  local seclists_base="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
  curl -sL "${seclists_base}/Discovery/Web-Content/raft-small-directories.txt" -o "${SECFORGE_ROOT}/wordlists/directories.txt" || true
  curl -sL "${seclists_base}/Passwords/Common-Credentials/10k-most-common.txt" -o "${SECFORGE_ROOT}/wordlists/passwords-top1000.txt" || true
}

# --- Main install logic ---
sf_install_tool() {
  local tool_id="$1"
  local method
  method="$(sf_get_tool_field "${tool_id}" "install_method")"

  case "${method}" in
    builtin)
      sf_log "${tool_id}: built-in (always available)"
      return 0
      ;;
    apt)            sf_install_apt "${tool_id}" ;;
    github_release) sf_install_github_release "${tool_id}" ;;
    git_clone)      sf_install_git_clone "${tool_id}" ;;
    pip_venv)       sf_install_pip_venv "${tool_id}" ;;
    custom)
      local func
      func="$(sf_get_tool_field "${tool_id}" "custom_function")"
      if type "${func}" >/dev/null 2>&1; then
        "${func}"
      else
        sf_warn "Custom function '${func}' not found for ${tool_id}"
        return 1
      fi
      ;;
    *)
      sf_warn "Unknown install method '${method}' for ${tool_id}"
      return 1
      ;;
  esac
}

# --- Entry point ---
main() {
  local action="${1:-}"

  case "${action}" in
    --list)
      # Show installed vs available (no root needed)
      _SF_NEED_ROOT=0
      python3 -c "
import json
from pathlib import Path
import subprocess, os

root = Path('${SECFORGE_ROOT}')
t = json.load(open(root / 'catalog' / 'tools.json'))
installed = 0
total = 0
for tid, meta in sorted(t.items()):
    if tid == '_meta' or meta.get('tier', 1) == 0:
        continue
    total += 1
    check = meta.get('check', {})
    is_installed = False
    if 'command' in check:
        cmd = check['command']
        is_installed = (root / 'bin' / cmd).exists() or bool(subprocess.run(['which', cmd], capture_output=True).returncode == 0)
    elif 'path' in check:
        is_installed = (root / check['path']).exists()
    else:
        is_installed = True
    mark = '✓' if is_installed else '✗'
    tier_label = f'Tier {meta[\"tier\"]}' if meta.get('tier', 1) > 0 else 'Resource'
    if is_installed:
        installed += 1
    print(f'  {mark} {tid:<20} {tier_label:<8} {meta.get(\"description\", \"\")[:60]}')
print(f'\n  {installed}/{total} tools installed')
"
      return 0
      ;;
    --all)
      [[ "${EUID}" -eq 0 ]] || sf_die "secforge install requires root. Run: sudo secforge install --all"
      sf_log "Installing ALL tools..."
      for tool_id in $(sf_load_tools_json); do
        local method
        method="$(sf_get_tool_field "${tool_id}" "install_method")"
        [[ "${method}" == "builtin" ]] && continue
        sf_log "Installing ${tool_id}..."
        sf_install_tool "${tool_id}" || sf_warn "Failed: ${tool_id}"
      done
      sf_log "Done."
      return 0
      ;;
    --from-selection)
      [[ "${EUID}" -eq 0 ]] || sf_die "secforge install requires root."
      local selection_file="${2:-}"
      [[ -r "${selection_file}" ]] || sf_die "Selection file not found: ${selection_file}"
      while IFS= read -r tool_id; do
        tool_id="$(sf_normalize_tool_id "${tool_id}")"
        [[ -z "${tool_id}" ]] && continue
        sf_log "Installing ${tool_id}..."
        # Install dependencies first
        local deps
        deps="$(sf_get_tool_field "${tool_id}" "depends_on")"
        if [[ -n "${deps}" ]]; then
          local IFS=','
          for dep in ${deps}; do
            if ! sf_is_tool_installed "${dep}"; then
              sf_log "  Installing dependency: ${dep}"
              sf_install_tool "${dep}" || sf_warn "Failed dependency: ${dep}"
            fi
          done
        fi
        sf_install_tool "${tool_id}" || sf_warn "Failed: ${tool_id}"
      done < "${selection_file}"
      return 0
      ;;
    "")
      sf_die "Usage: secforge install <tool1> [tool2] ... | --list | --all | --from-selection <file>"
      ;;
    *)
      # Install specific tools
      [[ "${EUID}" -eq 0 ]] || sf_die "secforge install requires root. Run: sudo secforge install $*"
      for raw_id in "$@"; do
        local tool_id
        tool_id="$(sf_normalize_tool_id "${raw_id}")"
        # Install dependencies first
        local deps
        deps="$(sf_get_tool_field "${tool_id}" "depends_on")"
        if [[ -n "${deps}" ]]; then
          local IFS=','
          for dep in ${deps}; do
            if ! sf_is_tool_installed "${dep}"; then
              sf_log "Installing dependency: ${dep}"
              sf_install_tool "${dep}" || sf_warn "Failed dependency: ${dep}"
            fi
          done
        fi
        sf_log "Installing ${tool_id}..."
        sf_install_tool "${tool_id}" || sf_warn "Failed: ${tool_id}"
      done
      return 0
      ;;
  esac
}

main "$@"
```

- [ ] **Step 2: Make executable and validate**

```bash
chmod +x scripts/install-tools.sh
bash -n scripts/install-tools.sh && echo "OK"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/install-tools.sh
git commit -m "feat: add scripts/install-tools.sh — per-tool installer

Reads catalog/tools.json for install methods. Supports: apt,
github_release, git_clone, pip_venv, custom. Handles depends_on
(one-level), alias normalization, --list, --all, --from-selection.
Requires root for installs (not for --list)."
```

---

## Task 12: Add `init`, `install`, `dashboard` Subcommands to CLI

**Files:**
- Modify: `bin/secforge`

- [ ] **Step 1: Add install subcommand**

In `bin/secforge`, add after the existing case blocks:

```bash
  install)
    shift
    exec bash "${SCRIPT_DIR}/install-tools.sh" "$@"
    ;;
```

- [ ] **Step 2: Add init subcommand**

```bash
  init)
    shift
    # Parse flags
    _domain="" _environment="" _payments="" _tier="" _admin_ip="" _reset=0
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --domain)      _domain="$2"; shift 2 ;;
        --environment) _environment="$2"; shift 2 ;;
        --payments)    _payments="$2"; shift 2 ;;
        --tier)        _tier="$2"; shift 2 ;;
        --admin-ip)    _admin_ip="$2"; shift 2 ;;
        --reset)       _reset=1; shift ;;
        *) shift ;;
      esac
    done

    _conf="${SECFORGE_ROOT}/config/secforge.conf"
    _conf_example="${SECFORGE_ROOT}/config/secforge.conf.example"
    _targets="${SECFORGE_ROOT}/config/.authorized_targets"

    # Backup existing config
    if [[ -f "${_conf}" ]]; then
      cp "${_conf}" "${_conf}.bak.$(date +%Y-%m-%dT%H%M%S)"
    fi

    # --reset: regenerate from template
    if [[ "${_reset}" == "1" ]] && [[ -f "${_conf_example}" ]]; then
      cp "${_conf_example}" "${_conf}"
      echo "Config reset from template."
    fi

    # If flags provided → merge mode (update only provided keys)
    if [[ -n "${_domain}${_environment}${_payments}${_tier}${_admin_ip}" ]]; then
      [[ ! -f "${_conf}" ]] && [[ -f "${_conf_example}" ]] && cp "${_conf_example}" "${_conf}"
      [[ ! -f "${_conf}" ]] && touch "${_conf}"

      [[ -n "${_domain}" ]] && sf_cfg_set_value "${_conf}" "DOMAIN" "${_domain}"
      [[ -n "${_environment}" ]] && sf_cfg_set_value "${_conf}" "ENVIRONMENT" "${_environment}"
      [[ -n "${_payments}" ]] && sf_cfg_set_value "${_conf}" "PAYMENTS" "${_payments}"
      [[ -n "${_tier}" ]] && sf_cfg_set_value "${_conf}" "TIER_MAX" "${_tier}"
      [[ -n "${_admin_ip}" ]] && sf_cfg_set_value "${_conf}" "ADMIN_IP" "${_admin_ip}"

      # Add domain to authorized targets
      if [[ -n "${_domain}" ]]; then
        touch "${_targets}"
        if ! grep -qxF "${_domain}" "${_targets}" 2>/dev/null; then
          echo "${_domain}" >> "${_targets}"
        fi
      fi

      echo "Config updated: ${_conf}"

    elif [[ -t 0 ]]; then
      # Interactive wizard (TTY detected, no flags)
      _gum="${SECFORGE_ROOT}/bin/gum"
      [[ -x "${_gum}" ]] || _gum="$(command -v gum 2>/dev/null || true)"

      # Read existing values as defaults
      _cur_domain="$(sf_cfg_get_value "${_conf}" "DOMAIN" 2>/dev/null || true)"
      _cur_env="$(sf_cfg_get_value "${_conf}" "ENVIRONMENT" 2>/dev/null || true)"
      _cur_payments="$(sf_cfg_get_value "${_conf}" "PAYMENTS" 2>/dev/null || true)"
      _cur_tier="$(sf_cfg_get_value "${_conf}" "TIER_MAX" 2>/dev/null || true)"
      _cur_ip="$(sf_cfg_get_value "${_conf}" "ADMIN_IP" 2>/dev/null || true)"

      # Auto-detect admin IP from SSH
      _ssh_ip=""
      if [[ -n "${SSH_CONNECTION:-}" ]]; then
        _ssh_ip="$(echo "${SSH_CONNECTION}" | awk '{print $1}')"
      fi
      [[ -z "${_cur_ip}" ]] && _cur_ip="${_ssh_ip}"

      echo ""
      echo "SecForge Setup Wizard"
      echo "====================="
      echo ""

      if [[ -x "${_gum}" ]]; then
        _domain="$("${_gum}" input --placeholder "example.com" --value "${_cur_domain}" --header "1. What's your domain?" --header.foreground "212")" || true
        _environment="$("${_gum}" choose "production" "staging" --header "2. Production or staging?" --selected "${_cur_env:-production}")" || true
        _payments="$("${_gum}" choose "no" "yes" --header "3. Accept payments on this site?" --selected "${_cur_payments:-no}")" || true
        _tier="$("${_gum}" choose "1" "2" --header "4. Max scanning tier? (1=safe, 2=active testing)" --selected "${_cur_tier:-1}")" || true
        _admin_ip="$("${_gum}" input --placeholder "auto-detect" --value "${_cur_ip}" --header "5. Your IP for safe hardening?$([ -n "${_ssh_ip}" ] && echo " (detected: ${_ssh_ip})")")" || true
      else
        # Plain text fallback
        read -rp "1. Your domain [${_cur_domain}]: " _domain
        [[ -z "${_domain}" ]] && _domain="${_cur_domain}"
        read -rp "2. Environment (production/staging) [${_cur_env:-production}]: " _environment
        [[ -z "${_environment}" ]] && _environment="${_cur_env:-production}"
        read -rp "3. Accept payments? (yes/no) [${_cur_payments:-no}]: " _payments
        [[ -z "${_payments}" ]] && _payments="${_cur_payments:-no}"
        read -rp "4. Max tier (1=safe, 2=active) [${_cur_tier:-1}]: " _tier
        [[ -z "${_tier}" ]] && _tier="${_cur_tier:-1}"
        _ip_hint=""
        [[ -n "${_ssh_ip}" ]] && _ip_hint=" (detected: ${_ssh_ip})"
        read -rp "5. Admin IP${_ip_hint} [${_cur_ip}]: " _admin_ip
        [[ -z "${_admin_ip}" ]] && _admin_ip="${_cur_ip}"
      fi

      # Write config
      [[ ! -f "${_conf}" ]] && [[ -f "${_conf_example}" ]] && cp "${_conf_example}" "${_conf}"
      [[ ! -f "${_conf}" ]] && touch "${_conf}"

      [[ -n "${_domain}" ]] && sf_cfg_set_value "${_conf}" "DOMAIN" "${_domain}"
      [[ -n "${_environment}" ]] && sf_cfg_set_value "${_conf}" "ENVIRONMENT" "${_environment}"
      [[ -n "${_payments}" ]] && sf_cfg_set_value "${_conf}" "PAYMENTS" "${_payments}"
      [[ -n "${_tier}" ]] && sf_cfg_set_value "${_conf}" "TIER_MAX" "${_tier}"
      [[ -n "${_admin_ip}" ]] && sf_cfg_set_value "${_conf}" "ADMIN_IP" "${_admin_ip}"

      # Add domain to authorized targets
      if [[ -n "${_domain}" ]]; then
        touch "${_targets}"
        if ! grep -qxF "${_domain}" "${_targets}" 2>/dev/null; then
          echo "${_domain}" >> "${_targets}"
        fi
      fi

      echo ""
      echo "Config saved to ${_conf}"
      echo "Domain added to authorized targets."

    else
      # No flags, no TTY → error
      echo "Usage: secforge init --domain <domain> --tier <1|2> [--environment production|staging] [--payments yes|no] [--admin-ip <ip>]" >&2
      echo "Or run interactively: secforge init (in a terminal)" >&2
      exit 2
    fi
    ;;
```

- [ ] **Step 3: Add dashboard subcommand (placeholder — full implementation in Task 14)**

```bash
  dashboard)
    shift
    case "${1:-}" in
      --start)   exec bash "${SCRIPT_DIR}/dashboard.sh" --start "${2:-}" ;;
      --restart) exec bash "${SCRIPT_DIR}/dashboard.sh" --restart "${2:-}" ;;
      --last)    exec bash "${SCRIPT_DIR}/dashboard.sh" --last ;;
      --close)
        tmux kill-pane -t secforge-dashboard 2>/dev/null && echo "Dashboard closed." || echo "No dashboard pane found."
        ;;
      *) echo "Usage: secforge dashboard --start|--restart|--last|--close" >&2; exit 2 ;;
    esac
    ;;
```

- [ ] **Step 4: Update help text with all new commands**

- [ ] **Step 5: Validate**

```bash
bash -n bin/secforge && echo "OK"
```

- [ ] **Step 6: Commit**

```bash
git add bin/secforge
git commit -m "feat: add init, install, dashboard subcommands to CLI

init: dual-mode (flags for AI, gum wizard for humans on TTY).
Merge-only by default, --reset for fresh start, admin IP auto-detect
from SSH_CONNECTION.

install: dispatches to scripts/install-tools.sh.
dashboard: dispatches to scripts/dashboard.sh (placeholder)."
```

---

## Task 13: Rework `install.sh` Entry Point

**Files:**
- Modify: `install.sh` (repo root)

- [ ] **Step 1: Update install.sh to call bootstrap.sh**

The curl one-liner `install.sh` currently clones the repo and runs the full menu. Update it to clone + run bootstrap only:

```bash
#!/usr/bin/env bash
set -euo pipefail

# SecForge Installer — bootstraps minimal environment
# Security tools are installed later via: secforge install <tool1> <tool2>
# Or use the interactive menu: sudo /opt/secforge/scripts/install.sh

SECFORGE_ROOT="${SECFORGE_ROOT:-/opt/secforge}"

echo "SecForge — AI-native security toolkit"
echo ""

# Install git if missing
if ! command -v git >/dev/null 2>&1; then
  apt-get update -qq && apt-get install -y -qq git >/dev/null 2>&1
fi

# Clone or update repo
if [[ -d "${SECFORGE_ROOT}/.git" ]]; then
  echo "Updating existing SecForge installation..."
  cd "${SECFORGE_ROOT}" && git pull --ff-only
else
  echo "Cloning SecForge..."
  git clone https://github.com/Nosko666/SecForge.git "${SECFORGE_ROOT}"
fi

# Run bootstrap
echo "Running bootstrap..."
bash "${SECFORGE_ROOT}/scripts/bootstrap.sh"
```

- [ ] **Step 2: Validate**

```bash
bash -n install.sh && echo "OK"
```

- [ ] **Step 3: Commit**

```bash
git add install.sh
git commit -m "feat: rework install.sh to use bootstrap (minimal install)

curl one-liner now: clone repo → run bootstrap.sh (base deps + gum + tmux).
No security tools installed. Users add tools via: secforge install <tool>
or the existing interactive menu: sudo /opt/secforge/scripts/install.sh"
```

---

## Task 14: Create `scripts/dashboard.sh` — Live TUI Dashboard

**Files:**
- Create: `scripts/dashboard.sh`

This is the biggest visual feature. The dashboard renderer runs in a tmux pane, reads JSON status events from a file, and draws the UI with gum (or plain text fallback).

- [ ] **Step 1: Write dashboard.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SECFORGE_ROOT="${SECFORGE_ROOT:-$(cd -- "${SCRIPT_DIR}/.." && pwd)}"

# --- Helpers ---
_GUM="${SECFORGE_ROOT}/bin/gum"
[[ -x "${_GUM}" ]] || _GUM="$(command -v gum 2>/dev/null || true)"
_HAS_GUM=0
[[ -x "${_GUM}" ]] && _HAS_GUM=1

_STATUS_FILE=""
_LAST_LINE=0
_SCAN_TARGET=""
_SCAN_PROFILE=""
_TOOLS_TOTAL=0
_EST_SECONDS=0
_SCAN_START_TS=0
_TIER2_WAITING=0

# Tool states: tool_id → "waiting|running|done|failed"
declare -A _TOOL_STATE
declare -A _TOOL_DURATION
declare -A _TOOL_FINDINGS
declare -A _TOOL_INDEX

_TOTAL_FINDINGS=0
_SEV_COUNTS="" # "2H 5M 1L 3I"
_SCAN_DONE=0
_SCAN_DURATION=0

# --- Drawing ---
_draw() {
  local cols lines
  cols="$(tput cols 2>/dev/null || echo 80)"
  lines="$(tput lines 2>/dev/null || echo 24)"

  # Clear screen
  printf '\033[2J\033[H'

  if [[ "${_SCAN_DONE}" == "1" ]]; then
    _draw_summary "${cols}" "${lines}"
  elif [[ "${_TIER2_WAITING}" == "1" ]]; then
    _draw_scan "${cols}" "${lines}"
    _draw_tier2_banner "${cols}"
  else
    _draw_scan "${cols}" "${lines}"
  fi
}

_draw_scan() {
  local cols="$1" lines="$2"
  local elapsed=0
  if [[ "${_SCAN_START_TS}" -gt 0 ]]; then
    elapsed=$(( $(date +%s) - _SCAN_START_TS ))
  fi
  local elapsed_fmt
  elapsed_fmt="$(printf '%dm %02ds' $((elapsed/60)) $((elapsed%60)))"

  echo "┌─ SecForge — Scanning ${_SCAN_TARGET} ─────────────────┐"
  [[ -n "${_SCAN_PROFILE}" ]] && echo "│  Profile: ${_SCAN_PROFILE}  │  Tier: ${SECFORGE_TIER_MAX:-1}"
  echo "│"

  # Tool list
  local idx=0
  for tool_id in "${!_TOOL_INDEX[@]}"; do
    local state="${_TOOL_STATE[$tool_id]:-waiting}"
    local dur="${_TOOL_DURATION[$tool_id]:-}"
    local finds="${_TOOL_FINDINGS[$tool_id]:-}"
    local mark="○"
    case "${state}" in
      done)    mark="✓" ;;
      running) mark="●" ;;
      failed)  mark="✗" ;;
      waiting) mark="○" ;;
    esac
    local line="│  ${mark} ${tool_id}"
    if [[ "${state}" == "running" ]]; then
      local running_elapsed=$(( $(date +%s) - ${_TOOL_DURATION[$tool_id]:-$(date +%s)} ))
      line+="  running... ${running_elapsed}s"
    elif [[ -n "${dur}" ]] && [[ "${state}" != "running" ]]; then
      line+="  ${dur}s"
    fi
    [[ -n "${finds}" ]] && line+="  ${finds} findings"
    echo "${line}"
  done

  echo "│"
  echo "│  Findings: ${_TOTAL_FINDINGS}  ${_SEV_COUNTS}"
  echo "│  Elapsed: ${elapsed_fmt}  /  ~$(((_EST_SECONDS + 30) / 60)) min estimated"

  # Progress bar
  local pct=0
  if [[ "${_TOOLS_TOTAL}" -gt 0 ]]; then
    local done_count=0
    for s in "${_TOOL_STATE[@]}"; do
      [[ "${s}" == "done" || "${s}" == "failed" ]] && ((done_count++)) || true
    done
    pct=$(( done_count * 100 / _TOOLS_TOTAL ))
  fi
  local bar_len=$(( (cols - 10) * pct / 100 ))
  local bar_empty=$(( cols - 10 - bar_len ))
  printf '│  '
  printf '█%.0s' $(seq 1 ${bar_len:-1} 2>/dev/null) || true
  printf '░%.0s' $(seq 1 ${bar_empty:-1} 2>/dev/null) || true
  printf '  %d%%\n' "${pct}"

  echo "└────────────────────────────────────────────────────┘"
}

_draw_tier2_banner() {
  local cols="$1"
  echo ""
  echo "  ┌──────────────────────────────────────────────────┐"
  echo "  │  ⚠️  TIER 2 CONFIRMATION NEEDED                 │"
  echo "  │  Type YES in the left pane to run                │"
  echo "  │  active tests, or anything else to skip          │"
  echo "  └──────────────────────────────────────────────────┘"
}

_draw_summary() {
  local cols="$1" lines="$2"
  local dur_fmt
  dur_fmt="$(printf '%dm %02ds' $((_SCAN_DURATION/60)) $((_SCAN_DURATION%60)))"
  local done_count=0
  for s in "${_TOOL_STATE[@]}"; do
    [[ "${s}" == "done" ]] && ((done_count++)) || true
  done

  echo "┌─ SecForge — Scan Complete ─────────────────────────┐"
  echo "│  Target: ${_SCAN_TARGET}"
  echo "│  Duration: ${dur_fmt}  │  Tools: ${done_count}/${_TOOLS_TOTAL}"
  echo "│"
  echo "│  Findings: ${_TOTAL_FINDINGS}  ${_SEV_COUNTS}"
  echo "│"
  echo "│  Next: tell Claude \"fix the top issues\" or run:"
  echo "│  secforge export --mode full-plan"
  echo "│"
  echo "│  Press q or Ctrl+D to close this panel"
  echo "└────────────────────────────────────────────────────┘"
}

# --- Event processing ---
_read_events() {
  [[ -z "${_STATUS_FILE}" ]] && return
  [[ -f "${_STATUS_FILE}" ]] || return

  local line_num=0
  while IFS= read -r line; do
    ((line_num++)) || true
    [[ "${line_num}" -le "${_LAST_LINE}" ]] && continue
    _LAST_LINE="${line_num}"

    # Parse JSON event (use python for reliability)
    local event tool index duration findings status error sev_json
    eval "$(python3 -c "
import json, sys
try:
    d = json.loads('${line//\'/\\\'}')
    for k in ('event','tool','index','duration','findings','status','error','target','profile','tools_total','est_seconds','severity','message'):
        v = d.get(k, '')
        if isinstance(v, dict):
            import json as j
            print(f'{k}=\"{j.dumps(v)}\"')
        else:
            print(f'{k}=\"{v}\"')
except:
    pass
" 2>/dev/null)" || continue

    case "${event}" in
      scan_start)
        _SCAN_TARGET="${target}"
        _SCAN_PROFILE="${profile}"
        _TOOLS_TOTAL="${tools_total}"
        _EST_SECONDS="${est_seconds}"
        _SCAN_START_TS="$(date +%s)"
        ;;
      tool_start)
        _TOOL_STATE["${tool}"]="running"
        _TOOL_INDEX["${tool}"]="${index}"
        _TOOL_DURATION["${tool}"]="$(date +%s)"
        ;;
      tool_done)
        _TOOL_STATE["${tool}"]="done"
        _TOOL_DURATION["${tool}"]="${duration}"
        _TOOL_FINDINGS["${tool}"]="${findings}"
        _TOTAL_FINDINGS=$(( _TOTAL_FINDINGS + ${findings:-0} ))
        ;;
      tool_fail)
        _TOOL_STATE["${tool}"]="failed"
        ;;
      tier2_prompt)
        _TIER2_WAITING=1
        ;;
      tier2_approved|tier2_skipped)
        _TIER2_WAITING=0
        ;;
      scan_done)
        _SCAN_DONE=1
        _SCAN_DURATION="${duration}"
        _SEV_COUNTS="${severity}"
        ;;
    esac
  done < "${_STATUS_FILE}"
}

# --- Main ---
main() {
  local action="${1:-}"

  case "${action}" in
    --start|--restart)
      local session_dir="${2:-}"
      if [[ -n "${session_dir}" ]]; then
        _STATUS_FILE="/tmp/secforge-dashboard-$(basename "${session_dir}").status"
      else
        _STATUS_FILE="/tmp/secforge-dashboard-latest.status"
        [[ -L "${_STATUS_FILE}" ]] && _STATUS_FILE="$(readlink -f "${_STATUS_FILE}")"
      fi
      ;;
    --last)
      _STATUS_FILE="/tmp/secforge-dashboard-latest.status"
      [[ -L "${_STATUS_FILE}" ]] && _STATUS_FILE="$(readlink -f "${_STATUS_FILE}")"
      ;;
    *)
      echo "Usage: dashboard.sh --start <session_dir> | --restart <session_dir> | --last" >&2
      exit 2
      ;;
  esac

  # Handle resize
  trap '_draw' WINCH

  # Handle quit
  trap 'exit 0' INT TERM

  # Main loop: read events + redraw every 1s
  while true; do
    _read_events
    _draw
    # Check for 'q' keypress (non-blocking)
    if read -rsn1 -t1 key 2>/dev/null; then
      [[ "${key}" == "q" ]] && exit 0
    else
      sleep 1
    fi
  done
}

main "$@"
```

- [ ] **Step 2: Make executable and validate**

```bash
chmod +x scripts/dashboard.sh
bash -n scripts/dashboard.sh && echo "OK"
```

- [ ] **Step 3: Commit**

```bash
git add scripts/dashboard.sh
git commit -m "feat: add scripts/dashboard.sh — live TUI dashboard

Runs in tmux pane, reads JSON status events from per-session file.
1s redraw loop + SIGWINCH resize handler. Views: scanning progress,
post-scan summary, tier2 confirmation banner. Press q to close.
Graceful fallback to plain text without gum."
```

---

## Task 15: Add Dashboard Status Events to Scan Scripts

**Files:**
- Modify: `scripts/scan-quick.sh`
- Modify: `scripts/scan-all.sh`

- [ ] **Step 1: Add status event emission to scan-quick.sh**

At scan start (after preflight):
```bash
# Dashboard status file
SECFORGE_DASHBOARD_STATUS="/tmp/secforge-dashboard-${SECFORGE_SESSION_ID}.status"
export SECFORGE_DASHBOARD_STATUS
ln -sf "${SECFORGE_DASHBOARD_STATUS}" "/tmp/secforge-dashboard-latest.status" 2>/dev/null || true

# If in tmux + dashboard requested, open pane
if [[ -n "${TMUX:-}" ]]; then
  tmux split-window -h -d -t "$(tmux display-message -p '#S')" \
    "${SECFORGE_ROOT}/scripts/dashboard.sh --start ${SECFORGE_SESSION_DIR}" 2>/dev/null || true
  tmux select-pane -t 0 2>/dev/null || true
fi

# Emit scan_start
_tool_count="${#_SF_TOOLS_RUN[@]}"  # Will be updated as tools run
sf_emit_dashboard_event "{\"event\":\"scan_start\",\"target\":\"${SECFORGE_TARGET_HOST}\",\"profile\":\"${SECFORGE_STACK_PROFILE:-}\",\"tools_total\":0,\"est_seconds\":0}"
```

Before each `sf_track_run`:
```bash
_sf_tool_index=$((_sf_tool_index + 1))
sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"wafw00f\",\"index\":${_sf_tool_index}}"
```

After each `sf_track_run`:
```bash
# Determine findings count from output file (best-effort)
_sf_findings_count=0
[[ -s "${SECFORGE_SESSION_DIR}/webapp/wafw00f.json" ]] && _sf_findings_count="$(python3 -c "import json; d=json.load(open('${SECFORGE_SESSION_DIR}/webapp/wafw00f.json')); print(len(d) if isinstance(d,list) else 1)" 2>/dev/null || echo 0)"
sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"wafw00f\",\"index\":${_sf_tool_index},\"duration\":${_SF_TOOL_DURATIONS[-1]##*:},\"findings\":${_sf_findings_count},\"status\":\"ok\"}"
```

At scan end:
```bash
sf_emit_dashboard_event "{\"event\":\"scan_done\",\"duration\":${SECONDS},\"total_findings\":0}"
```

- [ ] **Step 2: Add tier2_prompt events to scan-all.sh**

Before the Tier 2 opt-in prompt:
```bash
sf_emit_dashboard_event "{\"event\":\"tier2_prompt\",\"message\":\"Type YES in the main pane\"}"
```

After user responds:
```bash
# If user typed YES:
sf_emit_dashboard_event "{\"event\":\"tier2_approved\"}"
# If skipped:
sf_emit_dashboard_event "{\"event\":\"tier2_skipped\"}"
```

- [ ] **Step 3: Validate**

```bash
bash -n scripts/scan-quick.sh scripts/scan-all.sh && echo "OK"
```

- [ ] **Step 4: Commit**

```bash
git add scripts/scan-quick.sh scripts/scan-all.sh
git commit -m "feat: emit dashboard status events from scan scripts

scan_start, tool_start, tool_done, tool_fail, tier2_prompt,
tier2_approved, tier2_skipped, scan_done events written to
per-session status file. Auto-opens tmux dashboard pane when in tmux."
```

---

## Task 16: Update CLAUDE.md with Vibecoder UX Protocol

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update Session Start section**

Add to the beginning of "Session Start (always)":

```markdown
0. Check prerequisites:
   - Is gum installed? (`/opt/secforge/bin/gum --version`)
   - Is tmux available? (`command -v tmux`)
   - If either missing: "For the best experience, I recommend installing gum (pretty UI, 5MB) and tmux (live dashboard). Want me to install them?"
   - If user declines, save preference and don't ask again.
   - Is `config/secforge.conf` configured? If not, run `secforge init` (onboarding wizard).
```

- [ ] **Step 2: Update scanning section**

Update v2 CLI examples to include new flags:
```markdown
secforge scan example.com --stack node-nginx --code-path /var/www/myapp --dashboard
secforge scan example.com --stack node-nginx --skip nmap,lynis --dashboard
```

- [ ] **Step 3: Append Vibecoder UX Protocol section**

Append the full section from the spec (lines 1092-1197 of the design spec). This includes:
- First-Time Setup flow
- Scanning Flow
- Tool Recommendations
- Dashboard Management
- Returning Users

- [ ] **Step 4: Validate AGENTS.md is still a symlink**

```bash
readlink AGENTS.md  # Should output: CLAUDE.md
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add Vibecoder UX Protocol to CLAUDE.md

Append new section + update Session Start and Scanning examples
with --stack, --code-path, --dashboard flags. Tool tables, safety
protocols, lockout prevention unchanged."
```

---

## Task 17: Update `config/secforge.conf.example`

**Files:**
- Modify: `config/secforge.conf.example`

- [ ] **Step 1: Add new config keys**

Append to the example config:

```bash
# --- Vibecoder UX (set by secforge init) ---
# DOMAIN=example.com
# ENVIRONMENT=production
# PAYMENTS=no
# TIER_MAX=1
# ADMIN_IP=
# GUM_TMUX_DECLINED=0

# --- Stack profile (set by AI or auto-detect) ---
# DEFAULT_STACK=
```

- [ ] **Step 2: Commit**

```bash
git add config/secforge.conf.example
git commit -m "docs: add TIER_MAX, DOMAIN, ENVIRONMENT, PAYMENTS, ADMIN_IP to config example"
```

---

## Task 18: Integration Test on Hetzner

This is a manual test task executed on the Hetzner server.

- [ ] **Step 1: Deploy to Hetzner**

```bash
rsync -avz --delete \
  --exclude='.git' --exclude='reports/' --exclude='backups/' \
  --exclude='tools/' --exclude='venv/' --exclude='wordlists/' \
  --exclude='config/secforge.conf' --exclude='config/.authorized_targets' \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='state/' \
  /var/www/secforge/ root@116.203.191.42:/opt/secforge/
```

- [ ] **Step 2: Test catalog validation**

```bash
ssh root@116.203.191.42 'PYTHONDONTWRITEBYTECODE=1 python3 -c "
import json
t = json.load(open(\"/opt/secforge/catalog/tools.json\"))
p = json.load(open(\"/opt/secforge/catalog/profiles.json\"))
tools = {k for k in t if k != \"_meta\"}
profiles = {k: v for k, v in p.items() if k != \"_meta\"}
print(f\"tools: {len(tools)}, profiles: {len(profiles)}\")
# Cross-validate
for pid, prof in profiles.items():
    for tid in prof.get(\"tools_include\", []):
        assert tid in tools, f\"{pid} includes unknown tool: {tid}\"
print(\"CROSS-VALIDATION OK\")
"'
```

- [ ] **Step 3: Test secforge init (flags mode)**

```bash
ssh root@116.203.191.42 "su -s /bin/bash -c '/opt/secforge/bin/secforge init --domain localhost --environment staging --tier 1 --payments no' testuser"
```

- [ ] **Step 4: Test secforge install --list**

```bash
ssh root@116.203.191.42 "su -s /bin/bash -c '/opt/secforge/bin/secforge install --list' testuser"
```

- [ ] **Step 5: Test scan with --stack**

```bash
ssh root@116.203.191.42 "su -s /bin/bash -c '/opt/secforge/bin/secforge scan http://localhost:8888 --stack node-nginx' testuser"
```

Expected: Only node-nginx profile tools run. Others skipped.

- [ ] **Step 6: Verify manifest has profile + tool_durations**

```bash
ssh root@116.203.191.42 'SESS=$(ls -1dt /opt/secforge/reports/20* | head -1) && python3 -c "
import json
m = json.load(open(\"$SESS/scan_manifest.json\"))
print(\"profile:\", m.get(\"profile\"))
print(\"scan_mode:\", m.get(\"scan_mode\"))
print(\"tier_max:\", m.get(\"tier_max\"))
print(\"tool_durations:\", m.get(\"tool_durations\", {}))
print(\"MANIFEST OK\")
"'
```

- [ ] **Step 7: Test dashboard (if tmux available)**

```bash
ssh root@116.203.191.42 "su -s /bin/bash -c 'tmux new-session -d -s test-dash && tmux send-keys -t test-dash \"/opt/secforge/bin/secforge scan http://localhost:8888 --stack node-nginx --dashboard\" Enter && sleep 5 && tmux capture-pane -t test-dash -p | head -20 && tmux kill-session -t test-dash' testuser"
```

- [ ] **Step 8: Commit test results to memory**

Update `/root/.claude/projects/-var-www/memory/secforge_v2_status.md` with Vibecoder UX implementation status.

---

## Build Order Summary

| Task | What | Depends on |
|------|------|-----------|
| 1 | catalog/tools.json | — |
| 2 | catalog/profiles.json | Task 1 (references tool IDs) |
| 3 | _lib.sh helpers | — |
| 4 | Fix canonical tool IDs | — |
| 5 | CLI flags (--stack, --skip, etc) | — |
| 6 | secforge-builtin in scan-quick.sh | Task 3 |
| 7 | Preflight stack detection + expansion | Tasks 1, 2, 3 |
| 8 | Gate every tool block | Tasks 3, 7 |
| 9 | Record tool_durations | — |
| 10 | bootstrap.sh | — |
| 11 | install-tools.sh | Task 1 |
| 12 | CLI init/install/dashboard | Tasks 10, 11 |
| 13 | Rework install.sh | Task 10 |
| 14 | dashboard.sh | Task 3 |
| 15 | Dashboard events in scan scripts | Tasks 3, 14 |
| 16 | CLAUDE.md updates | Tasks 5, 7, 12, 14 |
| 17 | Config example | — |
| 18 | Integration test | All |

---

## Success Criteria

1. `secforge scan example.com --stack node-nginx` runs only node-nginx profile tools
2. `secforge scan example.com` without --stack auto-detects (or runs legacy if low confidence)
3. `secforge install --list` shows installed vs available with descriptions
4. `secforge install nuclei nmap` installs just those two tools + dependencies
5. `secforge init` shows gum wizard on TTY, accepts flags silently
6. `scan_manifest.json` has `profile`, `scan_mode`, `tier_max`, `tool_durations`
7. Dashboard shows live progress in tmux pane with tool status, findings, elapsed time
8. `--skip nmap` skips nmap with a log message
9. `--dashboard` opens tmux pane automatically
10. Everything degrades gracefully without gum/tmux
11. `bash -n` passes on all modified scripts
12. AGENTS.md is still a symlink to CLAUDE.md
