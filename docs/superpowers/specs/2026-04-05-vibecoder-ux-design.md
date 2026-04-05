# SecForge Vibecoder UX — Design Spec

## Goal

Transform SecForge from a "run bash scripts and read JSON" experience into an AI-guided, visually polished security workflow where vibecoders interact with Claude/Codex and see live progress in a persistent dashboard — from first install through scanning, fixing, and verification.

## Architecture Overview

The AI (Claude Code or Codex) is the brain. SecForge provides: structured data (profiles, catalogs), a CLI with flags the AI passes, and a gum-powered TUI dashboard in a tmux pane. The AI handles detection, recommendation, explanation, and orchestration. SecForge never needs to be "smart" — it just needs to accept what the AI tells it.

**4 features, build order:**
1. Scan Profiles by Stack (`--stack`, `catalog/profiles.json`)
2. Scan Cost Estimator (tool duration tracking in manifest)
3. AI-Guided Onboarding (CLAUDE.md instructions, `secforge init` for config)
4. Live TUI Dashboard (gum + tmux persistent pane)

**Dropped:** GitHub Issues export (AI can do `gh issue create` natively)

---

## Feature 1: Scan Profiles by Stack

### What it does

A profile tells SecForge which tools to run, which nuclei template tags to use, what endpoints to probe, how to boost priority scores, and what stack-specific fix advice to give. The AI detects the stack from project files, picks a profile, and passes `--stack <name>` to the scan command.

### Profile data format

Single file: `catalog/profiles.json`. One entry per stack profile.

```json
{
  "_meta": {
    "version": "1.0",
    "description": "Stack profiles. AI picks one based on detected tech. Override with --stack."
  },
  "node-nginx": {
    "title": "Node.js + nginx",
    "description": "Express/Next.js/Nuxt behind nginx reverse proxy",
    "detect_files": ["package.json", "node_modules/", "next.config.js", "nuxt.config.ts"],
    "detect_headers": {"X-Powered-By": "Express", "Server": "nginx"},  // case-insensitive contains match
    "tools_include": [
      "wafw00f", "whatweb", "nuclei", "nmap", "testssl", "ffuf",
      "ssh-audit", "lynis", "gitleaks", "check-email-dns", "secforge-builtin"
    ],
    "tools_exclude": [
      "pip-audit", "osv-scanner", "apkdeeplens", "apkhunt", "apkleaks",
      "checkov", "prowler", "wapiti", "sqlmap", "commix", "xsstrike"
    ],
    "dep_checker": "npm-audit",
    "nuclei_tags_boost": ["nodejs", "express", "nextjs", "javascript"],
    "nuclei_tags_skip": ["wordpress", "joomla", "drupal", "php", "java", "spring"],
    "common_endpoints": ["/api/", "/graphql", "/.env", "/.git/HEAD", "/node_modules/"],
    "priority_boosts": {
      "deps": 1.2,
      "secrets": 1.3
    },
    "fix_hints": {
      "headers": "Add security headers in Express middleware (helmet) or nginx server block",
      "tls": "Configure TLS in nginx ssl_protocols/ssl_ciphers directives",
      "secrets": "Use dotenv with .gitignore, never commit .env files"
    },
    "suggested_extras": [
      {"tool": "trivy", "reason": "Scans your server OS for vulnerable system packages (OpenSSL, etc). Adds ~2 min."},
      {"tool": "nikto", "reason": "Additional web server misconfiguration checks. Adds ~3 min."}
    ]
  }
}
```

### Profiles to ship (day one)

| Profile | Stack | Detection signals |
|---------|-------|-------------------|
| `node-nginx` | Express/Next.js/Nuxt + nginx | package.json + Server: nginx |
| `node-bare` | Express/Next.js direct | package.json + X-Powered-By: Express, no nginx |
| `python-nginx` | Django/Flask/FastAPI + nginx | requirements.txt/Pipfile + Server: nginx |
| `php-nginx` | Laravel/generic PHP + nginx | composer.json + Server: nginx |
| `wordpress` | WordPress | wp-config.php, wp-content/, wp-admin/ |
| `java-spring` | Spring Boot + nginx/Tomcat | pom.xml/build.gradle + Spring headers |
| `ruby-rails` | Rails + Puma + nginx | Gemfile + X-Powered-By: Phusion/Puma |
| `static-nginx` | Static HTML/JS + nginx | Only HTML/CSS/JS files, Server: nginx |
| `go-bare` | Go HTTP server | go.mod, no reverse proxy detected |

Database detection is separate — not part of the stack profile. Preflight auto-detects locally running databases and adds their check tools to `SECFORGE_TOOLS_PLANNED` only when the service is actually running:

```bash
# In preflight.sh (only for this_server target):
if [[ "$target" == "this_server" || "$target" == "localhost" ]]; then
  systemctl is-active mysql >/dev/null 2>&1 && add_to_planned "check-mysql"
  systemctl is-active postgresql >/dev/null 2>&1 && add_to_planned "check-postgres"  # future
  systemctl is-active redis >/dev/null 2>&1 && add_to_planned "check-redis"  # future
fi
```

DB checks run in both quick and full modes for local targets (they take <10s and finding "MySQL has no root password" is critical). For remote targets: DB checks are never added (they can't connect). This keeps estimates and dashboard accurate — no "check-mysql: can't connect" noise on remote scans.

### Canonical tool IDs

One canonical ID per tool, used everywhere: `profiles.json` (tools_include/exclude), `scan_manifest.json` (tools_run/tools_failed/tool_durations), dashboard events, state DB fixed-gating, and `finding.tool` in findings.json.

**Canonical = the parser's `finding.tool` value.** Scan scripts must write these exact IDs in `sf_track_run` calls and the manifest. Current mismatches to fix:

| Scan script ID (current) | Parser/findings.json ID (canonical) | Action |
|--------------------------|-------------------------------------|--------|
| `emaildns` | `check-email-dns` | Change sf_track_run to `check-email-dns` |
| `mysql` | `check-mysql` | Change sf_track_run to `check-mysql` |
| `builtin` | `secforge-builtin` | Change sf_track_run to `secforge-builtin` |

All other tool IDs already match (nuclei, nmap, wafw00f, testssl, gitleaks, etc.). This prevents subtle state gating bugs where a tool "succeeds" in the manifest but the DB can't match it to findings.

**Friendly aliases for `secforge install`:** Users and Claude can type short names. An alias map in `bin/secforge` normalizes to canonical IDs internally:

| User types | Normalizes to |
|-----------|---------------|
| `secforge install nmap` | `nmap` (already canonical) |
| `secforge install emaildns` | `check-email-dns` |
| `secforge install mysql` | `check-mysql` |
| `secforge install builtin` | `secforge-builtin` |

The alias map is only in the `install` command. Everywhere else (profiles, manifest, dashboard, state DB) uses canonical IDs only.

### What profiles control (all 5 knobs, day one)

All 5 knobs are active from day one — no phased rollout. Three are **enforced by code** (scan scripts/preflight), two are **consumed by the AI** (read from profiles.json, used in conversation):

**Code-enforced (scan scripts change behavior):**
1. **Tool selection** (`tools_include`/`tools_exclude`) — preflight builds `SECFORGE_TOOLS_PLANNED`, scan scripts gate each tool
2. **Nuclei tag selection** (`nuclei_tags_boost`/`nuclei_tags_skip`) — behavior varies by scan mode:
   - **Quick scan:** nuclei runs with `-tags <boost>` (filtered, fast — only stack-relevant templates). E.g., `-tags nodejs,express` runs ~200 templates instead of 9000.
   - **Full scan:** nuclei runs unfiltered (all templates) but with `-etags <skip>` to exclude obviously irrelevant stacks. E.g., `-etags wordpress,php,java` saves time without losing relevant coverage.
   - **No stack / low confidence:** nuclei runs fully unfiltered (today's behavior).
3. **Endpoint probes** (`common_endpoints`) — **recon-only**, no new findings. Scan scripts probe these paths and record `{path, http_code, time_ms}` into `webapp/builtin.json` for AI context. The AI reads this to understand the target surface ("your /api/ is publicly accessible, /graphql returned 404"). Does NOT create findings — the existing nuclei + ffuf + builtin parser already handle discovery findings. Keeps us out of `scripts/secforge/*.py`.

**AI-consumed (data in profiles.json, no Python module changes):**
4. **Priority boosts** (`priority_boosts`) — the AI reads these and explains scoring context: "I'm prioritizing secrets findings for your Node.js stack because package.json often contains sensitive config." The scoring engine itself stays unchanged — the existing 7-factor scoring already produces good results. Boosts are AI guidance, not code multipliers.
5. **Fix hints** (`fix_hints`) — the AI reads these and includes stack-specific advice in fix explanations: tells a Node user "add helmet middleware" not "edit wp-config.php." The export module stays unchanged — the AI wraps export output with stack context from the profile.

This avoids modifying `scripts/secforge/*.py` while still giving vibecoders the full stack-aware experience. The AI is the consumer of knobs 4 and 5.

### Field naming: profile vs scan_mode vs tier

Three orthogonal dimensions, kept separate everywhere:

| Field | Meaning | Values | Example |
|-------|---------|--------|---------|
| `profile` | Stack profile | `node-nginx`, `python-nginx`, `wordpress`, etc. | What stack are we scanning? |
| `scan_mode` | Scan depth | `quick`, `full` | How many tools? |
| `tier_max` | Aggressiveness | `1`, `2` | Passive only or active testing? |

These appear in `scan_manifest.json`, `preflight.json`, dashboard events, and CLI flags. The existing `profile` field in manifests (which currently holds "quick"/"all") is renamed to `scan_mode`. The `profile` field now holds the stack profile name.

A user can combine all three: `secforge scan example.com --stack node-nginx --full` runs the node-nginx profile in full mode. Add `SECFORGE_ASSUME_YES=1` for Tier 2.

**Per-run tool exclusion with `--skip`:**

```bash
# Run node-nginx profile but skip nmap and lynis this time
secforge scan example.com --stack node-nginx --skip nmap,lynis

# "Quick check headers + TLS" = AI skips everything except what matters
secforge scan example.com --stack node-nginx --skip nuclei,nmap,lynis,ssh-audit,gitleaks
```

No `--tools` include flag needed. The profile already includes the right tools. `--skip` is a CSV of canonical tool IDs to exclude from this run only. The AI uses this for "quick check" — no new mode, just skip flags.

### Flag naming: `--stack` vs `--stack-hints`

`--stack` means ONE thing: the profile name from `catalog/profiles.json`.

| Command | Flag | Meaning |
|---------|------|---------|
| `secforge scan` | `--stack node-nginx` | Profile name (lookup in profiles.json, controls tools/tags/boosts) |
| `secforge export` | `--stack-hints "nginx, node, mysql"` | Freeform text for AI front-matter (what tech the user runs) |

The existing `--stack` on export is kept as a backward-compatible alias for `--stack-hints` (don't break existing usage). New code uses `--stack-hints` explicitly.

### Preflight expands profiles into env vars

`preflight.sh` is the only place that reads `catalog/profiles.json`. It resolves the stack profile and exports ready-to-use env vars so scan scripts never parse JSON:

```bash
# Exported by preflight.sh:
SECFORGE_STACK_PROFILE="node-nginx"
SECFORGE_TOOLS_PLANNED="wafw00f,whatweb,nuclei,nmap,testssl,ffuf,ssh-audit,lynis,gitleaks,check-email-dns,secforge-builtin"
SECFORGE_TOOLS_SKIPPED="pip-audit,osv-scanner,apkdeeplens,wapiti,sqlmap"
SECFORGE_NUCLEI_TAGS="nodejs,express,nextjs,javascript"
SECFORGE_NUCLEI_EXCLUDE_TAGS="wordpress,joomla,drupal,php,java,spring"
SECFORGE_COMMON_ENDPOINTS="/api/,/graphql,/.env,/.git/HEAD,/node_modules/"
```

Scan scripts use a simple gate before each tool:

```bash
# In scan-quick.sh / scan-all.sh, before each tool block:
if ! sf_should_run_tool "nuclei"; then
    sf_log "Skipping nuclei (not in profile)"
else
    sf_track_run nuclei ...
fi
```

`sf_should_run_tool` checks if the canonical tool ID is in `SECFORGE_TOOLS_PLANNED`. **`tools_include` is a strict allowlist** — only tools in the allowlist can run. The full formula:

```
tools that run = (tools in scan script) ∩ (tools_include) − (tools_exclude) − (--skip) − (not installed) − (tier gated)
```

Scan scripts keep their existing tool blocks unchanged. Each block gets a one-line gate. If the tool isn't in `SECFORGE_TOOLS_PLANNED`, it's skipped with a log message. No JSON parsing in bash.

**`--skip` validation:** Unknown tool names in `--skip` produce a warning and are ignored (best-effort). The scan continues. Example: `--skip nmapp` → `"[secforge] WARN: unknown tool 'nmapp' in --skip, ignoring."` The typo'd tool runs normally (safer than crashing — worst case an extra tool runs).

**`TIER_MAX` config key:** The canonical config key is `TIER_MAX` (default: `1`). Replaces the old `DEFAULT_TIER` with clearer semantics — it's a ceiling, not a suggestion.

- **Migration:** Preflight reads `TIER_MAX` first. If missing, falls back to `DEFAULT_TIER` for backward compat. Old configs keep working.
- **`secforge init --tier 1|2`** writes `TIER_MAX=1` or `TIER_MAX=2` to config.
- **`secforge scan --tier 2`** overrides for that run only (still requires YES prompt).

**Enforcement by preflight.sh:**
- `TIER_MAX=1` → ALL Tier 2 tool blocks are skipped silently in `scan-all.sh`, even with `--full`. The scan runs all Tier 1 tools for the profile but never touches Tier 2. `--full` means "all Tier 1 tools" not "bypass safety."
- `TIER_MAX=2` → Tier 2 is allowed but still requires the existing per-scan "Type YES" confirmation prompt (current behavior preserved). Production users don't get surprised by active payloads.
- `--tier 2` on command line overrides `TIER_MAX=1` for that run (explicit, deliberate).

Two layers of protection: config ceiling + per-scan confirmation.

### Tool selection scope: install vs scan

**Gum multi-select (dashboard checkboxes) controls what gets INSTALLED** (downloaded to disk). It does NOT override which tools run during a scan.

**Profile (`--stack`) controls what gets RUN** during a scan — but only from tools that are installed.

The flow:
1. User picks tools in dashboard (or Claude picks them) → installed to disk
2. Profile says "run nuclei, nmap, testssl for node-nginx" → only runs these if installed
3. If user installs extras (e.g., wapiti), Claude can suggest including them in future scans

Scans stay deterministic via profile. Install is where user choice happens. For explicit scan-time overrides, `--tools-include`/`--tools-exclude` flags can be added later.

### CLI integration

```bash
# AI passes the profile + code path
secforge scan example.com --stack node-nginx --code-path /var/www/myapp

# Full scan with all flags
secforge scan example.com --full --stack node-nginx --code-path /var/www/myapp --dashboard

# Env var still works as fallback (backwards compatible)
SECFORGE_CODE_PATH=/var/www/myapp secforge scan example.com --stack node-nginx
```

`--code-path` serves two purposes:
1. Enables code-scanning tools (gitleaks, trufflehog, npm-audit, osv-scanner, pip-audit)
2. Enables file-based stack detection (`detect_files` in profiles — preflight checks for package.json, requirements.txt, etc.)

The `bin/secforge` wrapper passes `--code-path` to preflight.sh which exports `SECFORGE_CODE_PATH` for scan scripts. Scan scripts read the profile via `SECFORGE_STACK_PROFILE` (set by preflight):
1. Load `catalog/profiles.json`
2. Read `tools_include` / `tools_exclude` for the resolved stack
3. Skip excluded tools, only run included ones
4. Pass `nuclei_tags_boost` as `--tags` if applicable

### How the AI uses it

CLAUDE.md instructions tell the AI:
1. Read `catalog/profiles.json` to see available profiles
2. Detect the stack by reading project files + running `curl -sI` against the target
3. Pick the best-matching profile
4. Show the user what will run, what's skipped, and why
5. Suggest extras from `suggested_extras` with explanations
6. Pass `--stack <name>` to secforge scan

### When `--stack` is NOT passed (auto-detect with confidence gating)

If the user runs `secforge scan example.com` without `--stack`:
- Preflight detects the stack from HTTP headers (see below)
- **High confidence** (2+ matching signals, e.g., `X-Powered-By: Express` + `connect.sid` cookie):
  - Auto-selects the matching profile
  - Shows: "Detected: node-nginx (high confidence). Running 12/51 tools. Override with --stack."
- **Low confidence** (only 1 weak signal, e.g., just `Server: nginx`):
  - Runs the full default tool set (today's behavior)
  - Hints: "Detected: possibly nginx. Consider --stack node-nginx for a faster, targeted scan."
- **Tie between profiles** (e.g., node-nginx scores 2 AND python-nginx scores 2):
  - Does NOT auto-apply either profile
  - Runs the full default tool set (today's behavior)
  - Hints: "Possible stacks: node-nginx (2 signals), python-nginx (2 signals). Pass --stack to choose."
  - The AI reads this hint and asks the user which stack they're running
- **No detection** (CDN/WAF stripping headers, or no matching signals):
  - Runs the full default tool set (today's behavior)

Auto-apply only fires when there is a **single clear winner** — one profile whose signal count meets `min_detect_signals` AND is strictly greater than all other profiles. Any ambiguity falls back to the safe default.

This protects manual users from missing vulnerabilities due to a wrong guess. AI users always pass `--stack` explicitly — auto-detect is the fallback for humans.

Each profile in `profiles.json` has a `min_detect_signals` field (default: 2). Auto-apply only triggers when the number of matching signals (`detect_headers` + `detect_files`) meets or exceeds this threshold AND no other profile ties.

### HTTP header fallback detection

When no code path is available (remote-only scan), preflight.sh does basic detection:
- WhatWeb fingerprinting (already runs)
- HTTP response headers: `Server`, `X-Powered-By`, `X-Generator`
- Cookie names (e.g., `PHPSESSID` → PHP, `connect.sid` → Express)

**Header matching is case-insensitive contains.** `"Server": "nginx"` matches `Server: nginx/1.24.0 (Ubuntu)`. This handles real-world header formats where versions, OS info, and extra text are appended.

This populates `preflight.json` with a rich detection object:

```json
{
  "stack_detection": {
    "detected_stack": "node-nginx",
    "confidence": "high",
    "score": 2,
    "threshold": 2,
    "signals": ["header:server=nginx", "cookie:connect.sid"]
  }
}
```

This makes detection explainable — the AI can tell the user "I detected Node.js because your server returned `X-Powered-By: Express` and a `connect.sid` cookie." When detection is wrong, the signals show exactly why. The scan script reads `stack_detection.detected_stack` when no `--stack` flag is passed, and only auto-applies if `score >= threshold`.

### Preflight is the single source of truth for stack resolution

`preflight.sh` is the ONLY component that resolves the final stack profile. Nobody else does detection.

**Flow:**
1. `bin/secforge scan` forwards `--stack` (if provided) and `--scan-mode` to preflight.sh
2. `preflight.sh` either:
   - Uses the explicit `--stack` value (AI/user override — highest priority)
   - Or auto-detects from HTTP headers + files (when no `--stack` passed)
3. Preflight writes `stack_detection` to `preflight.json`
4. Preflight exports env vars for scan scripts to consume:
   - `SECFORGE_STACK_PROFILE=node-nginx` (resolved profile name, or empty)
   - `SECFORGE_DETECTED_STACK=node-nginx` (what auto-detect found, for logging)
   - `SECFORGE_DETECT_CONFIDENCE=high` (high/low/none)
5. Scan scripts read `SECFORGE_STACK_PROFILE` — no detection logic, no profile loading, just "which tools do I skip?"

**Why:** One place to debug, one place to fix. Scan scripts stay dumb tool runners. The AI reads `preflight.json` for explainability.

**Preflight computes a runnable plan (not just a wish list):**

```
SECFORGE_TOOLS_PLANNED = (profile tools_include ∩ scan script tools)
                        − tools_exclude − tier_gated − unknown_IDs − not_installed − --skip
SECFORGE_TOOLS_MISSING = tools in profile include that aren't installed on disk
```

Preflight checks if each tool is actually installed (`sf_tool <id>` check). Missing tools are removed from PLANNED and added to MISSING. This means:
- Time estimates are accurate (only count tools that will actually run)
- Dashboard shows exactly what runs (no "skipped: not installed" clutter)
- The AI sees MISSING and can offer: "2 recommended tools aren't installed. Want me to install them first?"
- `sf_tool` checks in scan scripts stay as a safety net but should never fire

**Profile validation against `tools.json`:** When preflight expands a profile's `tools_include` list, it cross-checks each tool ID against `catalog/tools.json`. Unknown IDs produce a warning and are skipped — the rest of the profile stays intact:

```
[secforge] WARN: profile 'node-nginx' references unknown tool 'nmappp', skipping it.
```

The scan runs with 11/12 valid tools. A typo in one tool ID does NOT cause a fallback to the full default toolset (that would be the opposite of what profiles do). Consistent with `--skip` validation: typos produce warnings, not crashes or mode switches.

### Tool selection plumbing (tmux pane → main process)

Two paths for tool selection:

**AI path (common):** Claude picks tools and runs `secforge install nuclei nmap testssl` directly. No selection file needed.

**Manual/dashboard path:** When the user manually selects tools in the dashboard pane via `gum choose --no-limit`:
1. Dashboard pane writes newline-separated tool IDs to `/tmp/secforge-dashboard-<session>.selection`
2. Main process polls for this file (with timeout + "cancelled" path if user closes pane)
3. Main process reads selection and runs `secforge install --from-selection /tmp/secforge-...selection`
4. Dashboard pane switches from tool selection view to install progress view

---

## Feature 2: Scan Cost Estimator

### What it does

Before every scan, show how many tools will run and how long it will take. The AI presents this to the user as part of the "here's what I'll do" conversation.

### Implementation

**Static defaults** from `catalog/tools.json` — the single source of truth for all per-tool metadata:

```json
{
  "_meta": {
    "version": "1.0",
    "description": "Per-tool metadata. Used by: dashboard (descriptions), preflight (tier gating), estimator (defaults), installer (method)."
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
  "testssl": {
    "title": "testssl.sh",
    "description": "Checks your SSL certificate and TLS encryption settings",
    "tier": 1,
    "est_seconds": 30,
    "est_disk_mb": 5,
    "install_method": "git_clone",
    "repo": "testssl/testssl.sh",
    "dest_path": "tools/testssl",
    "expected_binary": "testssl.sh",
    "check": {"command": "testssl.sh"}
  },
  "sqlmap": {
    "title": "SQLMap",
    "description": "SQL injection testing — sends real payloads to find database vulnerabilities",
    "tier": 2,
    "est_seconds": 180,
    "est_disk_mb": 15,
    "install_method": "apt",
    "apt_packages": ["sqlmap"],
    "check": {"command": "sqlmap"}
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
  "wafw00f": {
    "title": "wafw00f",
    "description": "Detects if a Web Application Firewall is protecting your site",
    "tier": 1,
    "est_seconds": 5,
    "est_disk_mb": 3,
    "install_method": "pip_venv",
    "pip_package": "wafw00f",
    "check": {"command": "wafw00f"}
  },
  "ffuf": {
    "title": "ffuf",
    "description": "Directory and endpoint discovery by fuzzing common paths",
    "tier": 1,
    "est_seconds": 45,
    "est_disk_mb": 10,
    "install_method": "github_release",
    "repo": "ffuf/ffuf",
    "expected_binary": "ffuf",
    "depends_on": ["wordlists"],
    "check": {"command": "ffuf"}
  },
  "wordlists": {
    "title": "SecLists Subset",
    "description": "Curated wordlists for directory/password fuzzing",
    "tier": 0,
    "est_seconds": 0,
    "est_disk_mb": 50,
    "install_method": "custom",
    "custom_function": "install_wordlists",
    "check": {"path": "wordlists/directories.txt"}
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
  }
}
```

**Shared resources as pseudo-tools (`tier: 0`):**

Some tools depend on shared resources (wordlists, template directories). These are modeled as `tier: 0` entries in `tools.json`:
- `tier: 0` means "resource, not a scanner" — dashboard doesn't show it as a tool, estimator doesn't time it
- Tools declare `depends_on: ["resource-id"]` — one level deep, no recursive resolution
- `secforge install nuclei` sees `depends_on: ["nuclei-templates"]` and installs both automatically
- Preflight considers a tool "installed" only if the binary exists AND all `depends_on` resources are present (e.g., nuclei binary + `tools/nuclei-templates/` directory)

**Installedness check (`check` field):**

Every tool in `tools.json` has a `check` object that tells preflight how to verify the tool is installed:

| Check type | How it works | Example |
|-----------|-------------|---------|
| `{"command": "nuclei"}` | `command -v nuclei` or check `/opt/secforge/bin/nuclei` | Binary tools |
| `{"path": "tools/nuclei-templates"}` | Check if path exists under `SECFORGE_ROOT` | Resources, directories, scripts |

Optional `requires_commands` field lists system commands the tool needs (e.g., `check-email-dns` requires `dig`). Preflight warns if these are missing.

This keeps installedness logic data-driven. Preflight reads `tools.json`, runs checks, outputs:
- `SECFORGE_TOOLS_PLANNED` = tools that passed all checks
- `SECFORGE_TOOLS_MISSING` = tools in profile but failed check

**`INSTALLED_TOOLS` in config** stores canonical IDs from `tools.json` (not freeform strings). Updated by `secforge install` after successful installs.

**`secforge install --list`** reads `tools.json`, runs each tool's `check`, shows installed vs available:
```
secforge install --list
  ✓ nuclei         Tier 1  Template-based vulnerability scanner
  ✓ nmap           Tier 1  Discovers what ports and services are exposed
  ✗ gitleaks       Tier 1  Finds leaked secrets in your code
  ✗ sqlmap         Tier 2  SQL injection testing (active payloads)
  12/51 tools installed
```

**`install_method` enum:**

| Method | What it does | JSON fields |
|--------|-------------|-------------|
| `builtin` | Always available (secforge-builtin, check-email-dns) | none |
| `apt` | `apt-get install` | `apt_packages: ["pkg"]` |
| `github_release` | Download binary from GitHub release | `repo`, `expected_binary` |
| `git_clone` | Clone repo into tools/ | `repo`, `dest_path`, `expected_binary` |
| `pip_venv` | Install in SecForge's Python venv | `pip_package` |
| `npm_local` | npm install in a local dir | `npm_package`, `dest_path` |
| `custom` | Dedicated function in `install-tools.sh` | `custom_function` |

~70% of tools are `apt` or `github_release` (one-liner installs). ~20% are `git_clone` or `pip_venv`. ~10% are `custom` (ZAP, Commix, Observatory — oddballs needing multi-step scripts). The `custom` method keeps `tools.json` clean while giving `install-tools.sh` a named function to implement the weird cases.

**Why a separate `catalog/tools.json` (not in profiles.json):** Profiles are about stacks ("for node-nginx, include nuclei"). Tool metadata is about tools ("nuclei is Tier 1, ~90s, scans for vulns"). Different concerns, different update patterns. `tools.json` is the single source of truth for:
- Dashboard `gum choose` descriptions and tier badges
- Tier gating in preflight.sh (reads `tier` field)
- Cost estimator static defaults (reads `est_seconds`)
- Install registry (reads `install_method` + `install_source`)
- AI tool explanations (reads `description`)

**Duration units:** Integer seconds (rounded). Bash `$SECONDS` and `date +%s` give integers naturally — no floating point math in scan scripts. Plenty accurate for "~8 minutes" estimates.

**History source:** Estimator reads past `tool_durations` from `scan_manifest.json` files on disk (no DB changes). Globs for matching sessions: `ls -1dt /opt/secforge/reports/20*_${target}*/scan_manifest.json | head -5`

**Historical refinement** — after each scan, record actual tool durations in `scan_manifest.json`:

```json
{
  "tools_run": ["nuclei", "nmap", "testssl"],
  "tools_failed": [],
  "tool_durations": {
    "nuclei": 87,
    "nmap": 45,
    "testssl": 28
  },
  "profile": "node-nginx",
  "scan_mode": "quick",
  "tier_max": 1,
  "scan_date": "2026-04-05T01:00:00Z"
}
```

The estimator uses a 3-level lookup chain per tool, keyed to avoid cross-pollination between different scan configurations:

1. **Exact match:** `(target_host, stack_profile, scan_mode, tool_id)` — same target, same profile, same mode. Uses **median of last 5 scans** (robust to outliers — one slow network day doesn't ruin the estimate).
2. **Partial match:** `(target_host, tool_id)` — same target, any profile/mode. Median of last 5. Less accurate but better than guessing.
3. **Static default:** `tool_estimates.<tool_id>.est_seconds` from `catalog/profiles.json`. Generic fallback for first scan or new targets.

**Why median, not average or last-only:** If nuclei took [45, 48, 50, 120, 200] across 5 scans, median=50s (realistic), average=92s (skewed by one slow run), last=200s (noisy). Median gives the user an honest estimate.

This matters because nuclei with filtered templates (`node-nginx` profile) takes ~45s, but nuclei unfiltered takes ~120s. Using the wrong estimate would mislead the user.

The lookup reads `tool_durations` from `scan_manifest.json` files in previous session directories on disk. Match by globbing `/opt/secforge/reports/20*_<target>*/scan_manifest.json`, reading `profile` and `scan_mode` from each manifest to find exact matches. No state DB involved — purely filesystem-based.

### How the AI presents it

```
Claude: "Running node-nginx profile: 12 tools, estimated ~8 minutes.
         Based on your last scan (actual: 7m 23s)."
```

The `secforge scan` command also shows this before starting (with `gum` formatting) when run directly without AI.

---

## Feature 3: AI-Guided Onboarding

### What it does

CLAUDE.md and AGENTS.md instructions tell the AI how to handle first-time and returning users. No new Python code — this is orchestration instructions + a small `secforge init` command.

### First-time flow

When no `config/secforge.conf` exists (or user asks to redo setup), the AI walks through:

```
Claude: "Welcome to SecForge! Let me set things up. This only
         happens once (you can redo it anytime with 'redo setup').

  1. What's your domain?
     → This is the site I'll scan. I'll only scan domains you
       authorize. Example: example.com

  2. Production or staging?
     → Production means I'll be extra careful — Tier 1 only by
       default, no aggressive testing. Staging means I can be
       more thorough.

  3. Do you accept payments on this site?
     → If yes, I'll enable payment-specific security checks
       (Stripe integration, PCI compliance, card field detection).

  4. Max scanning tier?
     → Tier 1 (recommended): passive/safe checks only. Won't affect
       your site's performance.
     → Tier 2: includes active testing (SQL injection, XSS payloads).
       Can slow your app and fill logs. Best for staging.

  5. Your IP address for safe hardening?
     → If I harden your server (SSH, firewall), I'll make sure
       your IP is always whitelisted so you don't get locked out.
     → Auto-detected: 203.0.113.5 (your current SSH connection)

  Config saved to /opt/secforge/config/secforge.conf.
  Domain added to authorized targets.

  You won't see this again unless you ask me to redo it.

  I'm opening the SecForge dashboard — you'll see a panel on the
  right side of your screen showing live scan progress. You can
  keep chatting with me here while it runs."
```

### Tool installation (new flow)

After config, before first scan, Claude handles tool selection:

```
Claude: "I detected your stack: Node.js (Express) + nginx + MySQL.

  Before we scan, let me install the right tools. Check the
  dashboard panel to select tools, or just tell me what you want.

  RECOMMENDED for your stack:
  ✓ nuclei       — scans for known vulnerabilities using 9000+ templates
  ✓ nmap         — discovers what ports and services are exposed to the internet
  ✓ testssl.sh   — checks your SSL certificate and TLS encryption settings
  ✓ npm-audit    — checks your package.json for packages with known vulnerabilities
  ✓ gitleaks     — scans your code for leaked API keys, passwords, and secrets
  ✓ ssh-audit    — checks if your SSH server has weak algorithms or settings
  ✓ lynis        — comprehensive system hardening audit (read-only, safe)
  ✓ wafw00f      — detects if a Web Application Firewall is protecting your site
  ✓ whatweb      — fingerprints what technologies your site uses
  ✓ check-email  — checks your DNS for SPF, DMARC, DKIM email security records
  ✓ builtin      — SecForge's own checks for exposed files, headers, cookies

  NOT NEEDED for your stack:
  ✗ pip-audit    — Python dependency checker. You're running Node.js, not Python.
  ✗ osv-scanner  — Go/Rust/Java dependency scanner. Not relevant for your stack.
  ✗ apkdeeplens  — Android APK analysis. You don't have a mobile app.
  ✗ checkov      — Infrastructure-as-Code scanner. No Terraform/CloudFormation found.

  WORTH CONSIDERING:
  ? trivy        — scans your entire server OS for vulnerable system packages
                   (like outdated OpenSSL that affects everything). Not Node-specific
                   but catches issues other tools miss. Adds ~2 min to scan.
  ? nikto        — additional web server misconfiguration checks, good for catching
                   things nuclei might miss. Adds ~3 min.

  Select in the dashboard, or tell me: 'install recommended' /
  'install recommended + trivy' / 'install everything'"
```

The dashboard pane shows a `gum choose --no-limit` multi-select with descriptions. Claude captures the selection and runs the appropriate install scripts.

### Returning user flow

When config exists and tools are installed:

```
User: "scan my site"

Claude: opens dashboard pane (or refreshes if already open)

Claude: "What are you looking for today?
  a) Full rescan — 12 tools, ~8 min (based on last scan: 7m 23s)
  b) Quick check — headers + TLS only, ~2 min
  c) Verify my fixes — run verification checks only
  d) Something specific — tell me what you want to check"

User: "full rescan"
Claude: "Starting scan of example.com (node-nginx profile)...
         Check the dashboard for live progress."
```

### `secforge init` command

Dual-mode: flags for AI, interactive wizard for humans.

**With flags (AI path — no prompts):**

```bash
secforge init \
  --domain example.com \
  --environment production \
  --payments no \
  --tier 1 \
  --admin-ip 203.0.113.5
```

**Without flags on a TTY (human path — interactive wizard):**

```bash
secforge init
# → launches gum wizard (or plain read prompts if gum missing)
# → asks the 5 questions with explanations
# → saves config
```

**Detection logic:**
- Has flags? → Use them, no prompts. Missing optional flags use safe defaults.
- No flags + TTY detected (`[ -t 0 ]`)? → Interactive wizard via gum (or plain `read` fallback).
- No flags + no TTY? → Error: `"Usage: secforge init --domain <domain> --tier <1|2> ..."` (exit 2).

**Admin IP auto-detection:** In interactive mode (TTY), the wizard reads `SSH_CONNECTION` env var to prefill the admin IP:
```
Your IP for safe hardening? 203.0.113.5 (auto-detected from SSH) [Enter to confirm]:
```
User presses Enter to accept, or types a different IP (VPN, multiple IPs). If no SSH session detected, prompts without a default. In non-interactive (AI/flag) mode: only set if `--admin-ip` is explicitly passed — no auto-detect surprises.

This is how every good CLI works. The AI always passes flags. Humans type `secforge init` and get the beautiful wizard. Nobody needs to remember `--interactive`.

**Re-running `secforge init`:** Three behaviors depending on how it's called:

- **Interactive (no flags, TTY):** Wizard shows current config values as defaults. User presses Enter to keep each one, types to change. Only touched keys are updated. Untouched keys (INSTALLED_TOOLS, timeouts, custom knobs) are preserved. If onboarding keys are missing (domain, tier, etc.), wizard prompts for them.
- **AI with flags:** Merge — only provided flags are updated. `secforge init --tier 2` changes tier, leaves everything else alone.
- **`--reset` flag:** Full regenerate from template. Starts fresh. For corrupted config or clean slate.

**Always:** Timestamped backup written before any changes: `config/secforge.conf.bak.2026-04-05T012345`. Rollback is always possible.

**Stale config detection:** If `config/secforge.conf.example` has keys not present in the user's config, print a short summary after init:
```
New config options available (not yet in your config):
  SCAN_DELAY_MS — delay between requests (default: 200)
  CIRCUIT_BREAKER_THRESHOLD — pause if target responds slowly (default: 10s)
Run 'secforge init' to configure them, or they'll use safe defaults.
```
Does NOT auto-inject new keys — the user decides when to adopt them.

Writes to `config/secforge.conf` and `config/.authorized_targets`. The AI can also write these files directly — `secforge init` is a convenience wrapper.

---

## Feature 4: Live TUI Dashboard

### What it does

A persistent tmux pane showing real-time SecForge activity: tool installation progress, scan progress with per-tool status, findings counter, and post-scan summary. Powered by `gum`.

### Architecture

```
scan-quick.sh / scan-all.sh
    │
    │  writes status updates to
    ▼
/tmp/secforge-dashboard-<session>.status  (JSON lines)
    │
    │  read by
    ▼
scripts/dashboard.sh  (runs in tmux pane, reads status file, renders with gum)
```

Two processes:
1. **Scanner** (existing bash scripts) — runs tools, writes status lines to a file
2. **Renderer** (new `dashboard.sh`) — watches the status file, redraws with gum

**Renderer loop:** `dashboard.sh` runs a 1-second redraw loop with SIGWINCH handling:

```bash
trap 'redraw' WINCH  # terminal resize → immediate redraw

while true; do
  read_new_events    # check status file for new JSON lines since last read
  redraw             # update display: tool list, elapsed timer, progress bar, findings count
  sleep 1            # 1s tick keeps elapsed/progress live between events
done
```

This handles three things:
- **New events:** tool starts/finishes → update tool status
- **Timer tick:** "elapsed: 2m 31s" updates every second, progress bar moves smoothly
- **Terminal resize:** SIGWINCH trap redraws immediately with new dimensions (`tput cols`/`tput lines`)

Without the timer, the elapsed counter and progress bar freeze between tool events. Without SIGWINCH, resizing garbles the display until the next event.

**Status file rotation:** One file per scan session, not a global append file:
- Path: `/tmp/secforge-dashboard-${SECFORGE_SESSION_ID}.status`
- Symlink: `/tmp/secforge-dashboard-latest.status` → current session file
- `secforge dashboard --restart` points the renderer at the new file (old file stays as debug breadcrumb)
- `secforge dashboard --last` reads the symlink to find the most recent session
- No seek/offset logic needed — each file is one scan, read from top to bottom
- Old status files auto-cleaned on next scan (or by OS /tmp cleanup)

This keeps the scan scripts almost unchanged — just add a few `echo` calls to write status.

### Status file format

Each line is a JSON object appended to the status file:

```json
{"event": "scan_start", "target": "example.com", "profile": "node-nginx", "tools_total": 12, "est_seconds": 480}
{"event": "tool_start", "tool": "nuclei", "index": 1}
{"event": "tool_done", "tool": "nuclei", "index": 1, "duration": 87, "findings": 8, "status": "ok"}
{"event": "tool_start", "tool": "nmap", "index": 2}
{"event": "tool_done", "tool": "nmap", "index": 2, "duration": 45, "findings": 1, "status": "ok"}
{"event": "tool_fail", "tool": "masscan", "index": 5, "error": "requires root"}
{"event": "tier2_prompt", "message": "Type YES in the main pane to run Tier 2 active tests"}
{"event": "tier2_approved"}
{"event": "scan_done", "duration": 443, "total_findings": 19, "severity": {"high": 2, "medium": 13, "low": 1, "info": 3}}
```

### Dashboard views

**During tool installation:**
```
┌─ SecForge — Installing Tools ──────────────────────┐
│                                                     │
│  ✓ nuclei          downloaded     (45 MB)          │
│  ✓ nmap            already installed               │
│  ✓ testssl.sh      downloaded     (2 MB)           │
│  ● gitleaks        downloading... 67%              │
│  ○ ssh-audit       waiting                         │
│  ○ lynis           waiting                         │
│                                                     │
│  4/10 complete, ~1 min remaining                   │
└─────────────────────────────────────────────────────┘
```

**During scan:**
```
┌─ SecForge — Scanning example.com ──────────────────┐
│  Profile: node-nginx  │  Tier: 1                   │
│                                                     │
│  ✓ wafw00f       3s     0 findings                 │
│  ✓ whatweb       5s     1 finding   (info)         │
│  ✓ nuclei       87s     8 findings  (2H 4M 2I)    │
│  ● nmap         running... 45s                     │
│  ○ testssl      waiting                            │
│  ○ ssh-audit    waiting                            │
│  ○ lynis        waiting                            │
│  ○ npm-audit    waiting                            │
│  ○ gitleaks     waiting                            │
│  ○ emaildns     waiting                            │
│  ○ builtin      waiting                            │
│  ○ check-mysql  waiting                            │
│                                                     │
│  Findings: 9  (2 high, 4 medium, 1 low, 2 info)   │
│  Elapsed: 2m 20s  /  ~8 min estimated              │
│  ████████░░░░░░░░░░░░  29%                         │
└─────────────────────────────────────────────────────┘
```

**Post-scan summary (stays visible):**
```
┌─ SecForge — Scan Complete ─────────────────────────┐
│  Target: example.com  │  Profile: node-nginx       │
│  Duration: 7m 23s     │  Tools: 12/12 succeeded    │
│                                                     │
│  ┌─ Findings: 19 ──────────────────────────────┐   │
│  │  HIGH     2  ████                           │   │
│  │  MEDIUM  13  ██████████████████████████      │   │
│  │  LOW      1  ██                             │   │
│  │  INFO     3  ██████                         │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  Top Fix Packs:                                    │
│  1. HTTP Headers    (6 findings, easy)             │
│  2. Secrets Cleanup (2 findings, easy)             │
│  3. DNS/Email       (4 findings, easy)             │
│  4. TLS Hardening   (3 findings, medium)           │
│  5. Network         (1 finding,  medium)           │
│                                                     │
│  Next: tell Claude "fix the headers" or run:        │
│  secforge export --mode fix-pack --pack             │
│    http-header-hardening                            │
│                                                     │
│  Press q or Ctrl+D to close this panel              │
└─────────────────────────────────────────────────────┘
```

**During Tier 2 confirmation (waiting for user):**
```
┌─ SecForge — Scanning example.com ──────────────────┐
│                                                     │
│  ✓ wafw00f       3s     0 findings                 │
│  ✓ nuclei       87s     8 findings  (1H 5M 2I)    │
│  ✓ nmap         45s     1 finding                  │
│  ...                                                │
│                                                     │
│  ┌────────────────────────────────────────────────┐ │
│  │  ⚠️  TIER 2 CONFIRMATION NEEDED               │ │
│  │  Type YES in the left pane to run              │ │
│  │  active tests, or anything else to skip        │ │
│  └────────────────────────────────────────────────┘ │
│                                                     │
│  Findings: 9  (1 high, 5 medium, 3 info)           │
│  Elapsed: 3m 12s  /  ~8 min estimated              │
└─────────────────────────────────────────────────────┘
```

The scan script emits `tier2_prompt` before the TTY prompt and `tier2_approved` or `tier2_skipped` after the user responds. Two extra JSON lines, dashboard renders a banner.

**During verification:**
```
┌─ SecForge — Verifying FP-http-header-hardening ────┐
│                                                     │
│  [PASS] CSP header present                         │
│  [PASS] HSTS header present                        │
│  [FAIL] X-Frame-Options header                     │
│                                                     │
│  Results: 2/3 passed                               │
│                                                     │
│  Tell Claude: "fix the X-Frame-Options" to continue│
└─────────────────────────────────────────────────────┘
```

### tmux pane management

```bash
# Open dashboard pane (called by scan scripts or AI)
secforge dashboard --start <session_dir>
  → creates named pane: secforge-dashboard
  → runs dashboard.sh watching the status file

# Refresh for new scan (clears and restarts)
secforge dashboard --restart <session_dir>
  → kills old renderer, starts new one with new status file

# Show last scan summary
secforge dashboard --last
  → opens pane showing the most recent scan summary

# Close
secforge dashboard --close
  → kills the secforge-dashboard pane

# AI control (from CLAUDE.md instructions):
tmux kill-pane -t secforge-dashboard          # close
tmux capture-pane -t secforge-dashboard -p    # read content
```

### Dashboard auto-open semantics

Three scenarios based on tmux state:

**Already in tmux (most common — AI always sets this up):**
- Auto-split pane, no `--dashboard` flag needed
- Dashboard appears in right pane automatically
- This is the default experience for AI-guided usage

**Not in tmux + `--dashboard` flag passed:**
- Start a new tmux session, split pane, attach
- The user explicitly asked for the dashboard — give it to them
```bash
tmux new-session -d -s secforge "secforge scan example.com --stack node-nginx --dashboard"
tmux split-window -h -t secforge
tmux select-pane -t secforge:0.0
tmux attach -t secforge
```

**Not in tmux + no `--dashboard` flag (manual CLI user):**
- Run inline with gum spinners (pretty but not split-pane)
- Print hint after scan starts: `"Tip: run inside tmux or pass --dashboard for a live split-pane view."`
- No surprise tmux session creation

The AI (CLAUDE.md instructions) always uses `--dashboard` when orchestrating. Manual users get the hint and can opt in.

### Graceful degradation

| Condition | Behavior |
|-----------|----------|
| In tmux + gum installed | Full dashboard experience (auto-split pane) |
| In tmux + no gum | Plain text dashboard in split pane + message: "Install gum for a better experience" |
| Not in tmux + `--dashboard` | Start tmux session + split pane + attach |
| Not in tmux + no flag | Inline gum spinners + hint: "Run inside tmux or pass --dashboard" |
| gum not installed | Plain text fallback for all features (dashboard, tool selection, spinners) |
| tmux not installed | No split pane possible, inline output only |
| Not a terminal (`[ ! -t 1 ]`) | JSON progress to stdout (`--quiet` mode) |
| `--quiet` flag | JSON lines to stdout for AI consumption |

**AI must check and recommend gum + tmux:** CLAUDE.md instructs the AI to check for gum and tmux on first interaction. If either is missing:
```
Claude: "For the best SecForge experience, I recommend installing gum (pretty UI)
         and tmux (live dashboard). Want me to install them?
         - gum: 5MB binary, makes menus and progress bars beautiful
         - tmux: terminal multiplexer, lets you see scan progress while we chat
         Without them, SecForge still works but with plain text output."
```
The AI offers to install both. If the user declines, SecForge degrades gracefully — no crashes, just less pretty.

**Per-feature fallback without gum:**
- Dashboard: plain text redraws (clear screen + printf, no fancy boxes)
- Tool selection: numbered list + `read` prompt from `/dev/tty`
- Spinners/progress: plain `sf_log` lines (today's behavior)
- No minimum gum version — if a specific gum flag fails, catch error and fall back to plain text for that call

### `--dashboard` flag on scan commands

```bash
secforge scan example.com --stack node-nginx --dashboard
```

Behavior:
1. Check if inside tmux (`$TMUX` set?)
2. If yes: create/restart `secforge-dashboard` pane, run dashboard.sh in it
3. If no: start tmux session, split, attach (user explicitly requested dashboard)
4. Scan writes status events to the status file
5. Dashboard renderer picks them up and redraws

---

## Installer Rework

### Current state

`install.sh` (curl one-liner) → clones repo → runs `scripts/install.sh` (interactive menu) → installs ALL selected categories (7GB+).

### New state

**Phase 1: Bootstrap** (the curl one-liner or `git clone`)

```bash
curl -sSL https://raw.githubusercontent.com/Nosko666/SecForge/main/install.sh | sudo bash
```

OR the AI can do:
```bash
git clone https://github.com/Nosko666/SecForge.git /opt/secforge
cd /opt/secforge && sudo scripts/bootstrap.sh
```

`bootstrap.sh` installs ONLY:
- Creates `/opt/secforge/` directory structure
- Creates `secforge` group + runtime dirs (state/, reports/, backups/, config/)
- Installs base deps: `python3`, `curl`, `jq`, `git`, `tmux`
- Downloads `gum` binary to `/opt/secforge/bin/` (pinned to major.minor, e.g., `v0.14.x` — accepts patch updates for bug fixes, avoids breaking changes. Version pinned in bootstrap.sh, updated intentionally with SecForge releases)
- Adds `/opt/secforge/bin` to PATH
- Does NOT install any security tools
- Does NOT start tmux (runs as root/sudo — user or AI starts tmux later as their own user)

Prints next steps on completion:
```
SecForge installed to /opt/secforge/
  gum ✓  tmux ✓  python3 ✓

Next: open Claude Code or Codex in /opt/secforge/ and say "scan my site"
Or:   secforge init (to configure manually)
```

Result: SecForge is ready for AI-guided tool selection. ~50MB, ~30 seconds.

**Phase 2: Tool installation** (AI-guided, after stack detection)

The AI calls existing install scripts selectively:

```bash
# Install specific tools based on user selection
secforge install nuclei nmap testssl gitleaks ssh-audit lynis
```

`secforge install` installs **individual tools**, not category bundles. When the user picks `nuclei` in the dashboard, they get nuclei — not nuclei + ffuf + wafw00f + ZAP + nikto. This is the core difference from the old menu installer.

A **tool install registry** in `bin/secforge` (or a JSON data file) maps each canonical tool ID to its specific install method:

```bash
# Per-tool install methods (in bin/secforge install handler):
case "$tool" in
  nuclei)            install_github_binary "projectdiscovery/nuclei" ;;
  nmap)              apt_install "nmap" ;;
  testssl)           git_clone_tool "testssl/testssl.sh" "tools/testssl" ;;
  gitleaks)          install_github_binary "gitleaks/gitleaks" ;;
  lynis)             apt_install "lynis" ;;
  ssh-audit)         apt_install "ssh-audit" ;;
  wafw00f)           pip_venv_install "wafw00f" ;;
  ffuf)              install_github_binary "ffuf/ffuf" ;;
  sqlmap)            apt_install "sqlmap" ;;
  trivy)             install_github_binary "aquasecurity/trivy" ;;
  check-email-dns)   : ;; # built-in script, always available
  secforge-builtin)  : ;; # built-in, always available
  *)                 sf_warn "Unknown tool: $tool" ;;
esac
```

The existing `scripts/install-*.sh` category scripts are preserved for `secforge install --all` and the manual menu installer. Per-tool install extracts the individual install logic (most are one-liners: apt, GitHub binary, git clone, or pip in venv).

**Phase 3: Full install option** (still available)

```bash
secforge install --all
```

Runs all category installers — equivalent to today's "Install Everything" option. For users who want maximum coverage regardless of stack.

### Existing install scripts preserved

All `scripts/install-*.sh` files remain unchanged. They become the building blocks that `secforge install` calls selectively. No rewrite of individual installers needed.

### Non-AI install path (still works)

Users without Claude/Codex can still use the interactive menu installer:

```bash
sudo /opt/secforge/scripts/install.sh
```

This shows the existing bash menu with category checkboxes (Install Everything / Essential Only / Custom). It installs all selected tools in one go. No AI needed.

**The core experience is AI-driven, but the manual path is always available.** The install scripts are the same either way — the only difference is who decides what to install (AI vs user menu).

---

## CLAUDE.md / AGENTS.md Updates

**Scope: B (append + small surgical edits).** Don't rewrite — the existing tool tables, safety protocols, lockout prevention, and fix workflows are correct and tested. Only change what's needed for the new features.

### Existing sections to edit (small, targeted)

**1. "Session Start" section** — add these steps at the beginning:
- Check if gum + tmux are installed. If not, offer to install: "For the best experience, I recommend gum (pretty UI) and tmux (live dashboard). Want me to install them?"
- Check if `config/secforge.conf` exists. If not, run onboarding wizard via `secforge init`.
- Detect stack from project files. Show detected profile.
- All existing Session Start steps (authorization, tier preference, system discovery) still apply after setup.

**2. "v2 CLI Workflow / Scanning" section** — update examples:
- `secforge scan example.com` → `secforge scan example.com --stack node-nginx --dashboard`
- Add `--code-path /var/www/myapp` to examples where code scanning is shown
- Add `--skip tool1,tool2` example
- Note that `--stack` is picked by the AI from `catalog/profiles.json`
- Add time estimate note: "Always show the user how many tools and how long before starting"

**3. "Scan Profiles" section** — update to reference `--stack` profiles:
- Replace the current static list with "Read `catalog/profiles.json` for available profiles"
- Add: "Quick Scan = scan-quick.sh with profile. Full Scan = scan-all.sh with profile + Tier 2 opt-in"

### New section to append: Vibecoder UX Protocol

```markdown
## Vibecoder UX Protocol

### First-Time Setup
When no config/secforge.conf exists:
1. Check if gum + tmux are installed. If not: offer to install with explanation of what each does.
2. Run the onboarding wizard (ask the 5 questions, explain each one).
3. Save config with `secforge init`.
4. Detect the stack from project files + HTTP headers.
5. Read `catalog/profiles.json` and `catalog/tools.json` to get profile + tool descriptions.
6. Show recommended tools with explanations of what each does and why.
7. Show tools NOT needed with explanations of why they're skipped.
8. Suggest extras from `suggested_extras` with clear explanations.
9. Let user choose (or accept recommendations). Install selected tools.
10. Show install progress in dashboard pane.

### Scanning Flow
1. Always use `--dashboard` flag (opens tmux split pane for live progress).
2. Show what will run, how long it will take (from estimator), and ask for confirmation.
3. Always include time estimates: "12 tools, ~8 min (based on last scan: 7m 23s)."
4. Run scan with `secforge scan <target> --stack <profile> --code-path <path> --dashboard`.
5. Stay interactive while scan runs — answer questions, explain findings.
6. When scan completes, present results from findings.json as fix packs (not raw findings).
7. Always explain Tier 2 risks before running active scanners. Never run Tier 2 on production without explicit warning.

### Tool Recommendations
- Read `catalog/profiles.json` to get the profile for the detected stack.
- Read `catalog/tools.json` for tool descriptions, tiers, and install info.
- Explain WHY each tool is recommended and WHY others are skipped.
- Suggest extras from `suggested_extras` with clear explanations.
- Always warn about Tier 2 risks. Show the risk explanation from CLAUDE.md.

### Dashboard Management
- Open: `secforge scan ... --dashboard` (auto-splits tmux pane)
- Read content: `tmux capture-pane -t secforge-dashboard -p`
- Close: `secforge dashboard --close` (or user says "close the dashboard")
- Reopen summary: `secforge dashboard --last`
- The pane stays open between scans. Clears and restarts on new scan.
- User can ask "what's in the dashboard?" — capture pane content and summarize.

### Returning Users
When config exists and tools are installed, ask:
- "What are you looking for today?"
- Offer: full rescan, quick check, verify fixes, something specific
- Always show time estimates
- Use `--skip` for targeted quick checks: "I just fixed headers, check only those"
```

### What does NOT change in CLAUDE.md
- Tool command tables (all 14 categories) — still correct
- Safety protocols / lockout prevention — critical, tested, don't touch
- Fix application workflow (backup → apply → verify → mark fixed)
- Report merging / findings.json schema
- "Never do these" rules
- Update procedures
- Tiered scanning explanations (just add `TIER_MAX` reference)

---

## Files Created/Modified

### New files
| File | What |
|------|------|
| `catalog/profiles.json` | 9 stack profiles with all 5 knobs |
| `catalog/tools.json` | Per-tool metadata: tier, description, estimates, install method (single source of truth) |
| `scripts/bootstrap.sh` | Minimal installer (base deps + gum + tmux) |
| `scripts/install-tools.sh` | Per-tool install registry (sources _lib.sh, enforces root, individual tool installs + alias normalization) |
| `scripts/dashboard.sh` | Dashboard renderer (reads status file, draws with gum) + tool selection UI (gum choose, pure Bash) |

### Modified files
| File | Change |
|------|--------|
| `bin/secforge` | Add `init`, `install`, `dashboard` subcommands + `--stack`/`--dashboard` flags |
| `scripts/scan-quick.sh` | Read profile, skip excluded tools, write status events to dashboard file, **add secforge-builtin web checks** (currently only in scan-all.sh — zero-dep, 5s, catches .env/.git/headers/cookies) |
| `scripts/scan-all.sh` | Same (already has builtin checks) |
| `scripts/preflight.sh` | Add `detected_stack` to preflight.json from HTTP headers |
| `install.sh` | Rework to call bootstrap.sh (minimal) instead of full menu |
| `CLAUDE.md` | Add Vibecoder UX Protocol section |
| `AGENTS.md` | Symlink to CLAUDE.md (unchanged, auto-updated) |
| `catalog/profiles.json` | New file (tool_estimates section for cost estimator) |
| `scripts/scan-quick.sh` / `scan-all.sh` | Record tool_durations in scan_manifest.json |

### Preserved (no changes)
| File | Why |
|------|-----|
| `scripts/install-*.sh` | All 12 category installers stay as-is. Called selectively by `secforge install`. |
| `scripts/secforge/*.py` | All v2 pipeline modules stay as-is. |
| `catalog/issue_keys.json` | No changes. |
| `catalog/clusters.json` | No changes. |
| `catalog/priority_weights.json` | No changes. |

---

## Build Order

1. **Scan Profiles** — `catalog/profiles.json` + `--stack` flag in scan scripts + profile loading in preflight
2. **Scan Cost Estimator** — tool_durations in manifest + estimation logic + gum display
3. **Installer Rework** — `bootstrap.sh` + `secforge install` command + tool selection logic
4. **AI Onboarding** — CLAUDE.md instructions + `secforge init` command
5. **Dashboard** — `dashboard.sh` + status file writing in scan scripts + tmux pane management + gum rendering

Steps 1-2 are data + small code changes. Step 3 is the installer rework. Step 4 is mostly documentation. Step 5 is the big visual feature.

---

## Success Criteria

1. First-time user installs SecForge in <1 minute (bootstrap only)
2. AI walks them through setup, explains every question
3. Only relevant tools are installed (~800MB vs 7GB)
4. User sees live scan progress in a persistent dashboard pane
5. Time estimates are shown before every scan and are within 20% of actual
6. User can chat with Claude while scan runs (dashboard in separate pane)
7. Post-scan summary shows severity chart + fix packs in dashboard
8. Verification results shown in same dashboard pane
9. Everything degrades gracefully without gum/tmux (plain text fallback)
10. Returning users get "what do you want?" flow, not onboarding again

---

## Additional Locked Decisions

### Test plan
Written checklist doc (`docs/superpowers/tests/vibecoder-ux.md`) with exact commands + expected output, same style as v2 punchlist test plan. Written AFTER implementation, executed on Hetzner. Not automated tests — repeatable manual checklist.

### Install privileges
`secforge install` requires root. If not root, error with hint:
```
Error: secforge install requires root.
Run: sudo secforge install nuclei nmap testssl
```
Never auto-sudo (no surprise password prompts, works in scripts/CI). Consistent with existing `sf_need_root` pattern.

### Final design decisions (locked)

**Profiles:**
- Self-contained — no inheritance/extends. Each profile explicitly lists all its tools, tags, boosts. Adding new profiles later doesn't affect existing configs. ~20 lines per profile is fine.
- Malformed/missing `profiles.json` → warn, fall back to no-profile behavior (run all tools).
- `common_endpoints` is recon-only — probe results are raw data for AI, not findings. No Python changes.
- `priority_boosts` and `fix_hints` are AI-consumed data, not code-enforced multipliers. No Python changes.

**Quick vs full tool surface:**
- `secforge-builtin` (web checks: .env, .git, headers, cookies) runs in BOTH quick and full scans. It's zero-dep, ~5 seconds, Tier 1, and catches critical exposures. Added to `scan-quick.sh` (gated by `sf_should_run_tool`). Currently only in `scan-all.sh`.
- Adding new profiles in updates is safe — they're just new JSON entries, existing configs unaffected.

**Estimator display:**
- First scan (no history): `~8 min (rough estimate — first scan for this target)`
- With history (median of 5): `~7m 23s (based on previous scans)`
- Always show tool count: `12 tools, ~8 min`

**Onboarding:**
- User declines gum/tmux install → save preference to config, never ask again.
- Multiple domains: `secforge init --domain example.com --domain staging.example.com` or comma-separated. All added to `.authorized_targets`.

**Dashboard:**
- Color scheme: gum defaults + SecForge yellow header. No custom theme system.
- Narrow terminal: compact mode (shorter lines, abbreviate tool names). No crash.
- Parallel scans: not supported. Second scan errors: `"Error: scan already running. Wait for current scan or cancel with Ctrl+C."`
- Per-session status files (already locked).

**INSTALLED_TOOLS:**
- Always stores canonical IDs from `tools.json` (not freeform/aliases).
- `secforge install` writes canonical IDs after successful installs.
- Legacy/unknown entries from old configs kept in file but shown as "unknown" in `secforge install --list`.
- Aliases (emaildns → check-email-dns) only accepted at input time, normalized before storage.
