# SecForge Vibecoder UX Implementation Plan (v2 — corrected)

> **Status: IMPLEMENTED** — 22 commits on main (2026-04-06), 4 fix rounds, 17/17 Hetzner tests pass, 19/20 success criteria pass.

**Goal:** Transform SecForge from raw bash scripts into an AI-guided, visually polished security workflow with stack profiles, time estimates, guided onboarding, and a live tmux dashboard.

**Architecture:** Preflight.sh is the single planner — it reads catalogs, resolves profiles, checks installedness, computes estimates, and exports simple CSV env vars. Scan scripts stay dumb (gate tools, emit events, record durations). Dashboard.sh renders status events with gum. No Python module changes.

**Tech Stack:** Bash, Python 3 (stdlib only, used inside preflight heredocs), `gum` v0.14.x (Charmbracelet TUI binary), `tmux`, `jq`

**Design spec:** `docs/superpowers/specs/2026-04-05-vibecoder-ux-design.md`

**Test server:** Hetzner `116.203.191.42` (Ubuntu 24.04, SSH key auth, testuser in secforge group)

## Implementation Status (2026-04-06)

| Task | Status | Commits |
|------|--------|---------|
| 1. Validate catalog/tools.json | DONE | `424a951` |
| 2. Validate catalog/profiles.json | DONE | `424a951` |
| 3. Shared helpers in _lib.sh | DONE | `6dfa0ce` |
| 4. Preflight.sh single planner | DONE | `6319a17` + fixes |
| 5. Fix scan scripts | DONE | `6ec1880` + `b5ab706` + fixes |
| 6. Create install-tools.sh | DONE | `9887fcd` + `4dffbeb` |
| 7. Create bootstrap.sh | DONE | `88e7a34` |
| 8. Update bin/secforge | DONE | `9b3efbb` + fixes |
| 9. Rework install.sh | DONE | `0691abd` |
| 10. Update config example | DONE | `d5a027a` |
| 11. Create dashboard.sh | DONE | `ccbe11d` + fixes |
| 12. Update CLAUDE.md | DONE | `bf31dab` + `7957776` |
| 13. Integration test plan | DEFERRED | Hetzner tests ran manually |

### Fix Rounds Applied
- **Round 1** (`1556fee`): 9 spec compliance issues (catalogs, events, scan_done timing, scan_mode, skip enforcement, dashboard blocking, selection format, manifest fields, --stack-hints)
- **Round 2** (`f6f6441`): 9 critical gaps (flag wiring, TOOLS_EFFECTIVE, preflight.json, "all"→"full", close fallback, builtin events, check-mysql, install events, selection naming)
- **Round 3** (`b5ab706`, `4dffbeb`, `0edac45`): TIER_MAX guard, 6 bypass tool events+durations, EXIT trap fields, 11 custom installers, install/verify dashboard events, estimator chain, interactsh cleanup
- **Final** (`f3bce8d`, `2a4cf0a`, `0054505`, `1b69d74`, `7957776`): Missing import, masscan dedup, deprecated API, log messages, profile in findings.json, install dashboard completion, stale doc example

### Deferred Items (Round 4)
1. **Rich stack_detection** in preflight.json — spec wants score/threshold/signals for explainability
2. **Scan-mode toolset intersection** — tools_planned vs what scan-quick.sh actually runs
3. **secforge init --tier** — write TIER_MAX from init wizard
4. **Combined estimate display** — "N tools, ~M min" string + "first scan — rough estimates" qualifier

---

## Explicit Non-Goals (not in this phase)

- No changes to `scripts/secforge/*.py` (v2 pipeline modules stay as-is)
- No rewriting scan orchestration in Python
- No automatic score engine changes from `priority_boosts` (AI-consumed only)
- No parser changes for `common_endpoints` recon data
- No auto-sudo anywhere
- No parallel-scan support
- `npm-audit` deferred — no parser exists in the v2 pipeline; use `osv-scanner` for Node deps

---

## Canonical Tool ID Table

**Every layer uses these exact IDs.** Aliases accepted only at `secforge install` CLI input time.

| Canonical ID | Binary/Script | Aliases (install only) | Notes |
|---|---|---|---|
| `check-email-dns` | `scripts/check-email-dns.sh` | `emaildns`, `email-dns`, `email`, `dns` | builtin |
| `check-mysql` | `scripts/check-mysql.sh` | `mysql` | builtin |
| `secforge-builtin` | (inline in scan scripts) | `builtin` | builtin |
| `testssl` | `testssl.sh` | — | binary name differs from ID |
| `interactsh` | `interactsh-client` | `interactsh-client` | binary name differs from ID |
| `jwt_tool` | `jwt_tool` | `jwt-tool`, `jwttool` | underscore in ID |
| `netexec` | `nxc` | `nxc` | binary name differs from ID |
| `stripe-check` | `stripe-check` | `stripe` | |
| `systemd-analyze` | `systemd-analyze` | — | builtin (always available) |

All other IDs match their binary name exactly (e.g., `nuclei` → `nuclei`, `nmap` → `nmap`).

**Rule:** Manifests, dashboard events, INSTALLED_TOOLS in config, profiles.json, findings.json `tool` field, and state DB all use canonical IDs only. Never write aliases to persistent storage.

---

## Field Naming (no overloading)

| Field | Meaning | Values |
|---|---|---|
| `profile` | Stack profile name | `node-nginx`, `wordpress`, `""` (none) |
| `scan_mode` | Quick vs full | `quick`, `full` |
| `tier_max` | Aggressiveness ceiling | `1`, `2` |

These three are orthogonal. They appear in `scan_manifest.json`, `preflight.json`, dashboard events, and CLI flags. The old `profile: "quick"` in manifests is renamed to `scan_mode`.

---

## Installedness Rules

A tool is "installed" only if ALL of these pass:
1. `check.command` → found via `command -v` or exists at `$SECFORGE_ROOT/bin/<cmd>`
2. `check.path` → path exists under `$SECFORGE_ROOT`
3. All `depends_on` resources pass their own checks (e.g., `nuclei` requires `nuclei-templates/` to exist)
4. All `requires_commands` are available (e.g., `check-email-dns` requires `dig`)

If any check fails, the tool goes in `SECFORGE_TOOLS_MISSING`, not `SECFORGE_TOOLS_PLANNED`.

---

## Dashboard Event Schema (locked contract)

Scan scripts and dashboard.sh MUST agree on this exact schema:

```json
{"event":"scan_start","target":"example.com","profile":"node-nginx","scan_mode":"quick","tools_total":12,"est_seconds":480}
{"event":"tool_start","tool":"nuclei","index":1}
{"event":"tool_done","tool":"nuclei","index":1,"duration":87,"findings":8,"status":"ok"}
{"event":"tool_fail","tool":"masscan","index":5,"error":"requires root"}
{"event":"tier2_prompt","message":"Type YES in the main pane to run Tier 2 active tests"}
{"event":"tier2_approved"}
{"event":"tier2_skipped"}
{"event":"scan_done","duration":443,"total_findings":19,"severity":{"high":2,"medium":13,"low":1,"info":3}}
{"event":"install_start","tools_total":5}
{"event":"install_done","tool":"nuclei","status":"ok","duration":12}
{"event":"verify_start","pack":"FP-http-header-hardening","checks_total":3}
{"event":"verify_done","pack":"FP-http-header-hardening","passed":2,"failed":1}
```

**Status file:** One per session at `/tmp/secforge-dashboard-${SECFORGE_SESSION_ID}.status`. Symlink at `/tmp/secforge-dashboard-latest.status`.

**tmux pane:** Named `secforge-dashboard` via `tmux select-pane -T secforge-dashboard`. All dashboard commands target this name. Pane persists between scans — `--restart` clears and reattaches to new status file.

---

## Build Order

| Step | Task | Creates/Modifies | Depends on |
|---|---|---|---|
| 1 | Validate catalog/tools.json (Codex already created) | catalog/tools.json | — |
| 2 | Validate catalog/profiles.json (Codex already created) | catalog/profiles.json | Step 1 |
| 3 | Shared helpers in _lib.sh | scripts/_lib.sh | — |
| 4 | Extend preflight.sh (single planner) | scripts/preflight.sh | Steps 1, 2, 3 |
| 5 | Fix scan scripts (canonical IDs, builtin in quick, tool gates, durations, events) | scripts/scan-quick.sh, scripts/scan-all.sh | Steps 3, 4 |
| 6 | Create install-tools.sh | scripts/install-tools.sh | Step 1 |
| 7 | Create bootstrap.sh | scripts/bootstrap.sh | — |
| 8 | Update bin/secforge (init, install, dashboard, scan flags) | bin/secforge | Steps 4, 6, 7 |
| 9 | Rework install.sh entry point | install.sh | Step 7 |
| 10 | Update config example | config/secforge.conf.example | — |
| 11 | Create dashboard.sh | scripts/dashboard.sh | Step 3 |
| 12 | Update CLAUDE.md | CLAUDE.md | Steps 4, 8, 11 |
| 13 | Integration test plan | docs/superpowers/tests/ | All |

---

## Task 1: Validate `catalog/tools.json`

Codex already created this file. Validate it matches the spec.

**Files:**
- Validate: `catalog/tools.json`

- [ ] **Step 1: Run structural validation**

```bash
cd /var/www/secforge
python3 -c "
import json
t = json.load(open('catalog/tools.json'))
tools = {k: v for k, v in t.items() if k != '_meta'}
print(f'Total entries: {len(tools)}')

required = {'title', 'description', 'tier', 'est_seconds', 'est_disk_mb', 'install_method', 'check'}
valid_methods = {'builtin', 'apt', 'github_release', 'git_clone', 'pip_venv', 'npm_local', 'custom'}
errors = []

for tid, meta in tools.items():
    missing = required - set(meta.keys())
    if missing:
        errors.append(f'{tid}: missing fields {missing}')
    if meta.get('install_method') not in valid_methods:
        errors.append(f'{tid}: invalid method {meta.get(\"install_method\")}')
    for dep in meta.get('depends_on', []):
        if dep not in tools:
            errors.append(f'{tid}: depends_on unknown {dep}')
    check = meta.get('check', {})
    if not check.get('command') and not check.get('path'):
        if meta.get('install_method') != 'builtin' or tid not in ('systemd-analyze',):
            errors.append(f'{tid}: check has neither command nor path')

for tier in (0, 1, 2):
    count = sum(1 for m in tools.values() if m['tier'] == tier)
    print(f'  Tier {tier}: {count}')

if errors:
    for e in errors:
        print(f'  ERROR: {e}')
else:
    print('VALIDATION OK')
"
```

Expected: no ERRORs.

- [ ] **Step 2: Verify canonical IDs match known parsers**

```bash
cd /var/www/secforge
python3 -c "
import json
t = json.load(open('catalog/tools.json'))
# These are the tool names v2 parsers actually emit in finding.tool
parser_tools = {
    'wafw00f', 'whatweb', 'nuclei', 'nmap', 'testssl', 'secforge-builtin',
    'check-email-dns', 'check-mysql', 'ssh-audit', 'wapiti', 'dalfox',
    'nikto', 'zap', 'ffuf', 'gitleaks', 'trufflehog', 'trivy',
    'osv-scanner', 'pip-audit', 'interactsh', 'corscanner', 'stripe-check',
    'hydra', 'netexec', 'commix', 'sqlmap', 'xsstrike'
}
tool_ids = set(k for k in t if k != '_meta')
missing = parser_tools - tool_ids
extra = tool_ids - parser_tools  # OK — includes resources, hardening tools, etc.
if missing:
    print(f'MISSING from tools.json: {missing}')
else:
    print(f'All parser tool IDs found in tools.json')
    print(f'Extra entries (resources/hardening/etc): {len(extra)}')
"
```

- [ ] **Step 3: Commit validation (if fixes needed)**

Only commit if changes were required. If tools.json is already valid, skip.

---

## Task 2: Validate `catalog/profiles.json`

Codex already created this file. Validate cross-references against tools.json.

**Files:**
- Validate: `catalog/profiles.json`

- [ ] **Step 1: Cross-validate profiles against tools.json**

```bash
cd /var/www/secforge
python3 -c "
import json
t = json.load(open('catalog/tools.json'))
p = json.load(open('catalog/profiles.json'))
tool_ids = set(k for k in t if k != '_meta')
profiles = {k: v for k, v in p.items() if k != '_meta'}
print(f'Profiles: {len(profiles)}')
errors = []

for pid, prof in profiles.items():
    for field in ('title', 'description', 'detect_files', 'detect_headers', 'tools_include', 'nuclei_tags_boost', 'nuclei_tags_skip'):
        if field not in prof:
            errors.append(f'{pid}: missing field {field}')
    for tid in prof.get('tools_include', []):
        if tid not in tool_ids:
            errors.append(f'{pid}: tools_include references unknown {tid}')
    for tid in prof.get('tools_exclude', []):
        if tid not in tool_ids:
            errors.append(f'{pid}: tools_exclude references unknown {tid}')
    # npm-audit should NOT be in any profile (deferred)
    if 'npm-audit' in prof.get('tools_include', []):
        errors.append(f'{pid}: includes npm-audit (deferred — use osv-scanner)')

if errors:
    for e in errors:
        print(f'  ERROR: {e}')
else:
    print('CROSS-VALIDATION OK')
"
```

- [ ] **Step 2: Fix any npm-audit references**

If any profile includes `npm-audit`, replace with `osv-scanner` (which already has a v2 parser).

- [ ] **Step 3: Commit fixes (if needed)**

---

## Task 3: Add Shared Helpers to `_lib.sh`

**Files:**
- Modify: `scripts/_lib.sh`

- [ ] **Step 1: Add sf_should_run_tool**

Append to `scripts/_lib.sh`:

```bash
# --- Profile-based tool gating ---
# Reads SECFORGE_TOOLS_PLANNED (CSV, set by preflight).
# If empty/unset, all tools run (legacy behavior).
sf_should_run_tool() {
  local tool_id="$1"
  local planned="${SECFORGE_TOOLS_PLANNED:-}"
  [[ -z "${planned}" ]] && return 0  # No profile → run everything
  local IFS=','
  for t in ${planned}; do
    [[ "${t}" == "${tool_id}" ]] && return 0
  done
  return 1
}
```

- [ ] **Step 2: Add sf_emit_dashboard_event**

```bash
# --- Dashboard status events ---
# Writes JSON line to dashboard status file. Silent no-op if unset.
sf_emit_dashboard_event() {
  local json_line="$1"
  local status_file="${SECFORGE_DASHBOARD_STATUS:-}"
  [[ -n "${status_file}" ]] && echo "${json_line}" >> "${status_file}" 2>/dev/null || true
}
```

- [ ] **Step 3: Move sf_builtin_web_checks from scan-all.sh to _lib.sh**

Extract the `sf_builtin_web_checks` function from `scripts/scan-all.sh` and place it in `scripts/_lib.sh` so both scan scripts can call it. Remove the original from scan-all.sh (it will source it from _lib.sh).

- [ ] **Step 4: Validate**

```bash
bash -n scripts/_lib.sh && echo "OK"
```

- [ ] **Step 5: Commit**

```bash
git add scripts/_lib.sh scripts/scan-all.sh
git commit -m "feat: add sf_should_run_tool, sf_emit_dashboard_event, move sf_builtin_web_checks to _lib.sh"
```

---

## Task 4: Extend `preflight.sh` — The Single Planner

**Files:**
- Modify: `scripts/preflight.sh`

Preflight becomes the ONLY component that:
- Reads `catalog/tools.json` and `catalog/profiles.json`
- Resolves `--stack` or auto-detects from headers/files
- Computes the runnable tool plan (installedness + tier gating + --skip)
- Computes time estimates (median of last 5 manifests or static defaults)
- Exports ALL results as simple env vars for scan scripts

**Scan scripts MUST NOT parse JSON.** They only read env vars.

- [ ] **Step 1: Add Python heredoc for stack detection + profile expansion + estimation**

After the existing preflight logic in `scripts/preflight.sh`, add a Python heredoc that:

1. **Reads catalogs:** `catalog/tools.json` + `catalog/profiles.json`
2. **Resolves stack:**
   - `SECFORGE_STACK` env var (from `--stack` flag) → use directly
   - Or auto-detect from HTTP headers (case-insensitive contains) + code path files
   - Confidence gating: high (2+ signals, single winner) → auto-apply; low/tie/none → empty
3. **Builds tools_planned:**
   - Start with profile `tools_include` (strict allowlist)
   - Remove `tools_exclude`
   - Remove tier-gated tools (tier > TIER_MAX)
   - Remove `--skip` tools (warn on unknown)
   - Remove tools that fail installedness check (check.command/check.path + depends_on + requires_commands)
   - If no profile: tools_planned stays empty (legacy behavior — run everything)
4. **Computes estimates:**
   - Glob previous manifests: `$SECFORGE_ROOT/reports/20*_${target}*/scan_manifest.json`
   - For each planned tool, find median of last 5 durations (exact match: target+profile+scan_mode first, then target-only, then static default from tools.json)
   - Sum all tool estimates → total est_seconds
5. **DB auto-detect:** If target is this_server/localhost, check if mysql/postgresql/redis are running via systemctl
6. **Writes stack_detection to preflight.json**
7. **Exports env vars:**

```bash
SECFORGE_STACK_PROFILE="node-nginx"
SECFORGE_DETECTED_STACK="node-nginx"
SECFORGE_DETECT_CONFIDENCE="high"
SECFORGE_TOOLS_PLANNED="wafw00f,whatweb,nuclei,nmap,testssl,secforge-builtin,check-email-dns"
SECFORGE_TOOLS_SKIPPED="pip-audit,sqlmap,wapiti"
SECFORGE_TOOLS_MISSING="gitleaks,ssh-audit"
SECFORGE_NUCLEI_TAGS="nodejs,express"           # for quick scan -tags
SECFORGE_NUCLEI_EXCLUDE_TAGS="wordpress,php"    # for full scan -etags
SECFORGE_COMMON_ENDPOINTS="/api/,/.env,/.git/HEAD"
SECFORGE_TIER_MAX="1"
SECFORGE_SCAN_MODE="quick"
SECFORGE_EST_SECONDS="480"
SECFORGE_EST_TOOLS_TOTAL="12"
```

**IMPORTANT:** The Python heredoc must use `SECFORGE_ROOT` (not hardcoded `/opt/secforge`) for all path resolution. Read it from the env var.

**IMPORTANT:** Use the tempfile + source pattern already established in preflight.sh (write to temp file, source it) rather than eval.

- [ ] **Step 2: Read TIER_MAX from config with DEFAULT_TIER fallback**

```python
# Inside the Python heredoc:
tier_max = 1
config_path = secforge_root / "config" / "secforge.conf"
if config_path.exists():
    for line in config_path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("TIER_MAX="):
            try: tier_max = int(stripped.split("=", 1)[1].strip().strip('"'))
            except ValueError: pass
        elif stripped.startswith("DEFAULT_TIER=") and tier_max == 1:
            # Backward compat fallback
            try: tier_max = int(stripped.split("=", 1)[1].strip().strip('"'))
            except ValueError: pass
# CLI --tier override
tier_override = os.environ.get("SECFORGE_TIER_OVERRIDE", "")
if tier_override:
    try: tier_max = int(tier_override)
    except ValueError: pass
```

- [ ] **Step 3: Validate**

```bash
bash -n scripts/preflight.sh && echo "bash OK"
# Smoke test with --stack:
SECFORGE_ROOT=/var/www/secforge SECFORGE_STACK=node-nginx SECFORGE_TARGET_URL=http://localhost:8888 \
  bash -c 'source scripts/preflight.sh --target localhost --profile quick --require-tools curl,jq > /tmp/pf_test.sh 2>/dev/null; source /tmp/pf_test.sh; echo "STACK=$SECFORGE_STACK_PROFILE PLANNED=$SECFORGE_TOOLS_PLANNED EST=$SECFORGE_EST_SECONDS"'
```

- [ ] **Step 4: Commit**

```bash
git add scripts/preflight.sh
git commit -m "feat: preflight.sh as single planner — stack detection, profile expansion, estimates

Reads catalogs, resolves --stack or auto-detects (confidence-gated),
computes SECFORGE_TOOLS_PLANNED (installedness + tier + --skip),
SECFORGE_EST_SECONDS (median of last 5 manifests), nuclei tags.
Exports all as env vars. Scan scripts never parse JSON."
```

---

## Task 5: Fix Scan Scripts (IDs, builtin, gates, durations, events)

**Files:**
- Modify: `scripts/scan-quick.sh`
- Modify: `scripts/scan-all.sh`

This task makes 6 changes to both scan scripts:

- [ ] **Step 1: Fix canonical tool IDs**

In both scripts, change `sf_track_run` first arguments:
- `emaildns` → `check-email-dns`
- `mysql` → `check-mysql`
- `builtin` / `_SF_TOOLS_RUN+=("builtin")` → `secforge-builtin`

Verify with: `grep -n 'sf_track_run emaildns\|sf_track_run mysql\|sf_track_run builtin\|TOOLS_RUN.*builtin' scripts/scan-quick.sh scripts/scan-all.sh`

- [ ] **Step 2: Add secforge-builtin web checks to scan-quick.sh**

Add after the existing tool blocks, before the merge step:

```bash
# Built-in web checks (zero-dep, ~5s, catches .env/.git/headers/cookies)
if sf_should_run_tool "secforge-builtin" && [[ "${SECFORGE_TARGET_HOST}" != "this_server" ]]; then
  _SF_TOOLS_RUN+=("secforge-builtin")
  local _builtin_start="$(date +%s)"
  sf_builtin_web_checks "${SECFORGE_TARGET_URL%/}" "${SECFORGE_SESSION_DIR}/webapp/builtin.json" "${delay_ms:-200}"
  local _builtin_dur=$(( $(date +%s) - _builtin_start ))
  _SF_TOOL_DURATIONS+=("secforge-builtin:${_builtin_dur}")
  if [[ ! -s "${SECFORGE_SESSION_DIR}/webapp/builtin.json" ]]; then
    _SF_TOOLS_FAILED+=("secforge-builtin")
  fi
fi
```

- [ ] **Step 3: Gate every tool block with sf_should_run_tool**

For EVERY `sf_track_run` or `_SF_TOOLS_RUN+=` in both scripts, add the gate:

```bash
# Pattern: wrap existing tool check with profile gate
if sf_should_run_tool "wafw00f" && sf_tool wafw00f >/dev/null 2>&1; then
  # ... existing sf_track_run wafw00f ...
fi
```

For nuclei, add tag handling:
```bash
if sf_should_run_tool "nuclei" && sf_tool nuclei >/dev/null 2>&1; then
  local _nuclei_tpl="${SECFORGE_ROOT}/tools/nuclei-templates"
  if [[ -d "${_nuclei_tpl}" ]]; then
    local _nuclei_extra=""
    # Quick scan: filter with -tags; Full scan: exclude with -etags
    if [[ -n "${SECFORGE_NUCLEI_TAGS:-}" ]] && [[ "${SECFORGE_SCAN_MODE:-quick}" == "quick" ]]; then
      _nuclei_extra="-tags ${SECFORGE_NUCLEI_TAGS}"
    elif [[ -n "${SECFORGE_NUCLEI_EXCLUDE_TAGS:-}" ]]; then
      _nuclei_extra="-etags ${SECFORGE_NUCLEI_EXCLUDE_TAGS}"
    fi
    sf_track_run nuclei ... ${_nuclei_extra} ...
  fi
fi
```

- [ ] **Step 4: Record tool_durations in sf_track_run**

Add `_SF_TOOL_DURATIONS=()` array declaration near the top (next to `_SF_TOOLS_RUN`).

Modify `sf_track_run` to capture duration:

```bash
sf_track_run() {
  local tool_name="$1"
  local check_file="$2"
  shift 2
  local _stdout_path="$2"
  _SF_TOOLS_RUN+=("${tool_name}")
  local _tool_start_ts="$(date +%s)"

  sf_run "$@"

  local _tool_end_ts="$(date +%s)"
  local _tool_dur=$(( _tool_end_ts - _tool_start_ts ))
  _SF_TOOL_DURATIONS+=("${tool_name}:${_tool_dur}")

  # ... existing exit code / failure detection ...
}
```

Update `sf_write_manifest` to include `tool_durations`, `profile`, `scan_mode`, `tier_max`:

```bash
SF_MANIFEST_TOOLS_RUN="$(IFS=,; echo "${_SF_TOOLS_RUN[*]}")" \
SF_MANIFEST_TOOLS_FAILED="$(IFS=,; echo "${_SF_TOOLS_FAILED[*]}")" \
SF_MANIFEST_TOOL_DURATIONS="$(IFS=,; echo "${_SF_TOOL_DURATIONS[*]}")" \
sf_write_manifest "${SECFORGE_SESSION_DIR}" "${SECFORGE_SCAN_MODE:-quick}"
```

- [ ] **Step 5: Emit dashboard status events**

At scan start (after preflight):
```bash
SECFORGE_DASHBOARD_STATUS="/tmp/secforge-dashboard-${SECFORGE_SESSION_ID}.status"
export SECFORGE_DASHBOARD_STATUS
ln -sf "${SECFORGE_DASHBOARD_STATUS}" /tmp/secforge-dashboard-latest.status 2>/dev/null || true

sf_emit_dashboard_event "{\"event\":\"scan_start\",\"target\":\"${SECFORGE_TARGET_HOST}\",\"profile\":\"${SECFORGE_STACK_PROFILE:-}\",\"scan_mode\":\"${SECFORGE_SCAN_MODE:-quick}\",\"tools_total\":${SECFORGE_EST_TOOLS_TOTAL:-0},\"est_seconds\":${SECFORGE_EST_SECONDS:-0}}"
```

Before/after each tool (wrap sf_track_run with event emission — create a helper `sf_track_run_with_events`):
```bash
_sf_tool_index=0

sf_track_run_with_events() {
  local tool_name="$1"
  ((_sf_tool_index++)) || true
  sf_emit_dashboard_event "{\"event\":\"tool_start\",\"tool\":\"${tool_name}\",\"index\":${_sf_tool_index}}"
  sf_track_run "$@"
  local dur="${_SF_TOOL_DURATIONS[-1]##*:}"
  sf_emit_dashboard_event "{\"event\":\"tool_done\",\"tool\":\"${tool_name}\",\"index\":${_sf_tool_index},\"duration\":${dur:-0},\"findings\":0,\"status\":\"ok\"}"
}
```

At scan end:
```bash
sf_emit_dashboard_event "{\"event\":\"scan_done\",\"duration\":${SECONDS},\"total_findings\":0}"
```

In scan-all.sh, before/after Tier 2 prompt:
```bash
sf_emit_dashboard_event "{\"event\":\"tier2_prompt\",\"message\":\"Type YES in the main pane\"}"
# ... existing sf_tier2_opt_in ...
# If approved:
sf_emit_dashboard_event "{\"event\":\"tier2_approved\"}"
# If skipped:
sf_emit_dashboard_event "{\"event\":\"tier2_skipped\"}"
```

- [ ] **Step 6: Add no-parallel-scan guard**

At the start of both scan scripts, after preflight:
```bash
_SF_LOCK="/tmp/secforge-scan.lock"
if ! (set -C; echo $$ > "${_SF_LOCK}") 2>/dev/null; then
  sf_die "A scan is already running (lock: ${_SF_LOCK}). Wait for it to finish or remove the lock."
fi
trap 'rm -f "${_SF_LOCK}"; ...' EXIT  # Add to existing EXIT trap
```

- [ ] **Step 7: Validate**

```bash
bash -n scripts/scan-quick.sh scripts/scan-all.sh && echo "OK"
grep -c 'sf_should_run_tool' scripts/scan-quick.sh scripts/scan-all.sh
```

- [ ] **Step 8: Commit**

```bash
git add scripts/scan-quick.sh scripts/scan-all.sh
git commit -m "feat: profile-gated scan scripts with durations, events, scan lock

Canonical tool IDs fixed. secforge-builtin in both quick+full.
Every tool gated by sf_should_run_tool. Nuclei uses -tags (quick)
or -etags (full) from profile. tool_durations recorded. Dashboard
events emitted. Parallel scan guard via lock file."
```

---

## Task 6: Create `scripts/install-tools.sh`

**Files:**
- Create: `scripts/install-tools.sh`

Reads `catalog/tools.json` for install methods. Supports: `apt`, `github_release`, `git_clone`, `pip_venv`, `custom`, `builtin` (no-op). Handles `depends_on` (one level), alias normalization, `--list`, `--all`, `--from-selection`. Requires root for installs (not for `--list`).

Key behaviors:
- `secforge install nuclei` → installs nuclei + nuclei-templates (via depends_on)
- `secforge install emaildns` → normalizes to `check-email-dns`, installs nothing (builtin)
- `secforge install --list` → reads tools.json, runs check on each, shows installed vs available
- All paths use `$SECFORGE_ROOT` (not hardcoded `/opt/secforge`)
- After successful install, update `INSTALLED_TOOLS` in config with canonical IDs

See design spec section "Installer Rework" for full requirements. The implementation from the previous plan version is mostly correct — apply corrections:
- Use `$SECFORGE_ROOT` everywhere
- Normalize aliases at input time
- Check `depends_on` + `requires_commands` in installedness check
- `--list` runs without root

- [ ] **Step 1: Write install-tools.sh** (full implementation)
- [ ] **Step 2: chmod +x, bash -n validate**
- [ ] **Step 3: Commit**

---

## Task 7: Create `scripts/bootstrap.sh`

**Files:**
- Create: `scripts/bootstrap.sh`

Minimal installer: dir structure, secforge group, base deps (python3, curl, jq, git, tmux), gum v0.14.x binary, PATH setup. Does NOT install security tools. Does NOT start tmux.

Key behaviors:
- `SECFORGE_ROOT` configurable (default `/opt/secforge`)
- gum pinned to v0.14.x (major.minor pin, patch updates OK)
- State dir: root:secforge 3770, DB file 0660
- Creates config from example if missing
- Prints next steps on completion

See design spec "Installer Rework → Phase 1: Bootstrap" for full requirements.

- [ ] **Step 1: Write bootstrap.sh** (full implementation)
- [ ] **Step 2: chmod +x, bash -n validate**
- [ ] **Step 3: Commit**

---

## Task 8: Update `bin/secforge` — init, install, dashboard, scan flags

**Files:**
- Modify: `bin/secforge`

Add subcommands and flags:

### scan flags
- `--stack <profile>` → exports `SECFORGE_STACK`
- `--skip <csv>` → exports `SECFORGE_SKIP`
- `--code-path <path>` → exports `SECFORGE_CODE_PATH`
- `--dashboard` → handles tmux pane creation
- `--tier 1|2` → exports `SECFORGE_TIER_OVERRIDE`

### init subcommand
- Dual-mode: flags (AI) vs interactive wizard (TTY)
- Merge-only by default, `--reset` for fresh start
- Admin IP auto-detect from `SSH_CONNECTION` in interactive mode
- Multiple `--domain` flags supported (or comma-separated)
- Timestamped backup before changes
- Stale config detection (compare with .example)

### install subcommand
- Dispatches to `scripts/install-tools.sh`

### dashboard subcommand
- `--start <session>` → opens named tmux pane running dashboard.sh
- `--restart <session>` → kills and re-opens
- `--last` → opens with latest status file
- `--close` → kills pane by name

### --stack-hints rename
- Export `--stack` on export as `--stack-hints` (backward alias kept)

### tmux pane management
When `--dashboard` is passed and in tmux:
```bash
tmux split-window -h -d -p 40 "${SECFORGE_ROOT}/scripts/dashboard.sh --start ${session_dir}"
tmux select-pane -T secforge-dashboard  # Name the pane
```
When `--dashboard` and NOT in tmux:
```bash
tmux new-session -d -s secforge "..."
tmux split-window -h -p 40 -t secforge "${SECFORGE_ROOT}/scripts/dashboard.sh --start ..."
tmux select-pane -t secforge:0.1 -T secforge-dashboard
tmux attach -t secforge
```

### help text
Update to document ALL new flags and subcommands.

- [ ] **Step 1: Implement all changes**
- [ ] **Step 2: bash -n validate**
- [ ] **Step 3: Commit**

---

## Task 9: Rework `install.sh` Entry Point

**Files:**
- Modify: `install.sh`

Change the curl one-liner to: clone repo → run bootstrap.sh (no full menu). The existing `scripts/install.sh` interactive menu stays available for non-AI users.

- [ ] **Step 1: Rewrite install.sh**
- [ ] **Step 2: Validate**
- [ ] **Step 3: Commit**

---

## Task 10: Update `config/secforge.conf.example`

**Files:**
- Modify: `config/secforge.conf.example`

Add: `TIER_MAX`, `DOMAIN`, `ENVIRONMENT`, `PAYMENTS`, `ADMIN_IP`, `GUM_TMUX_DECLINED`, `INSTALLED_TOOLS`.

- [ ] **Step 1: Append new keys**
- [ ] **Step 2: Commit**

---

## Task 11: Create `scripts/dashboard.sh`

**Files:**
- Create: `scripts/dashboard.sh`

TUI renderer with 5 views: tool selection (gum choose), install progress, scan progress, tier2 banner, post-scan summary, verification.

Key behaviors:
- 1-second redraw loop + SIGWINCH trap for resize
- Reads JSON events from per-session status file
- Compact mode when terminal too narrow
- Press q or Ctrl+D to close
- Graceful fallback: no gum → plain text (clear + printf)
- Post-scan summary includes "tell Claude: fix the headers" hint + exact FP-ID

### Tool selection view (for manual users)
When invoked with `--select`:
```bash
# gum choose with descriptions from tools.json
gum choose --no-limit --header "Select tools to install" \
  "nuclei — Template-based vulnerability scanner" \
  "nmap — Discovers open ports and services" \
  ...
# Write selections to /tmp/secforge-dashboard-<session>.selection
```
Claude captures via `tmux capture-pane` or reads the selection file.

### Install progress view
Shows: tool name, downloading/installed/failed, progress bar.

### Verification view
Shows: [PASS]/[FAIL] for each check, results summary.

- [ ] **Step 1: Write dashboard.sh** (full implementation with all views)
- [ ] **Step 2: chmod +x, bash -n validate**
- [ ] **Step 3: Commit**

---

## Task 12: Update CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

**Scope: append + 3 targeted edits. No rewrite.**

### Edits to existing sections:
1. **Session Start:** Add: check gum/tmux, offer install; check config exists → secforge init; detect stack
2. **v2 CLI Workflow / Scanning:** Update examples with `--stack`, `--code-path`, `--dashboard`, `--skip`
3. **Scan Profiles:** Replace static list with "read catalog/profiles.json"

### New section to append:
"Vibecoder UX Protocol" — full onboarding flow, scanning flow, tool recommendations, dashboard management, returning users. See design spec lines 1092-1197.

- [ ] **Step 1: Make edits + append**
- [ ] **Step 2: Verify `readlink AGENTS.md` → `CLAUDE.md`**
- [ ] **Step 3: Commit**

---

## Task 13: Write Integration Test Plan

**Files:**
- Create: `docs/superpowers/tests/vibecoder-ux.md`

Written checkbox test plan for Hetzner execution. Exact commands + expected output for:
- `--stack` + auto-detect behavior
- `SECFORGE_TOOLS_PLANNED` vs `SECFORGE_TOOLS_MISSING`
- `tool_durations` + estimate median
- `secforge install` per-tool + `depends_on`
- `secforge init` (TTY wizard, flags, merge + `--reset`)
- Dashboard (tmux pane create/restart/last/close, events, resize)
- Bootstrap (no tmux auto-start)
- `--skip` with known and unknown tools
- Tier gating (`TIER_MAX=1` blocks Tier 2)
- Scan lock (no parallel scans)
- Graceful degradation (no gum, no tmux)

- [ ] **Step 1: Write test plan**
- [ ] **Step 2: Commit**

---

## Success Criteria (concrete checks)

1. `secforge scan example.com --stack node-nginx` only runs tools in `SECFORGE_TOOLS_PLANNED`
2. Quick scan runs `secforge-builtin` web checks
3. `scan_manifest.json` contains `profile`, `scan_mode`, `tier_max`, `tool_durations` (integer seconds)
4. `secforge install --list` shows installed/available using `tools.json` check fields
5. `secforge install nuclei` also installs `nuclei-templates` (via `depends_on`)
6. `secforge init` merges config; `--reset` regenerates from template with backup
7. `secforge init --domain a.com --domain b.com` adds both to `.authorized_targets`
8. Export uses `--stack-hints`; `--stack` is backward-compatible alias on export only
9. `AGENTS.md` remains a symlink to `CLAUDE.md`
10. Dashboard shows live tool progress in named `secforge-dashboard` tmux pane
11. Dashboard persists between scans; `--restart` clears for new scan
12. Second scan attempt errors "scan already running" (lock file)
13. No `--stack` + high-confidence auto-detect → auto-applies profile
14. No `--stack` + low/tie/no confidence → runs legacy full scan + hint
15. `TIER_MAX=1` blocks ALL Tier 2 tools even with `--full`
16. `--skip nmap` skips nmap; `--skip nmapp` warns and continues
17. Time estimates shown: "12 tools, ~8 min" (or "first scan — rough estimates")
18. `bash -n` passes on all modified scripts
19. All paths use `$SECFORGE_ROOT` (not hardcoded `/opt/secforge`)
20. Tool counts derived from `tools.json`, not hardcoded "51"
