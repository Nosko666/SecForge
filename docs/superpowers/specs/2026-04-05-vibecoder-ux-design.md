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
    "detect_headers": {"X-Powered-By": "Express", "Server": "nginx"},
    "tools_include": [
      "wafw00f", "whatweb", "nuclei", "nmap", "testssl", "ffuf",
      "ssh-audit", "lynis", "gitleaks", "emaildns", "builtin"
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

Database detection is separate — always auto-detect: is MySQL running? Check it. Postgres? Check it. Redis? Check it. Not part of the profile.

### CLI integration

```bash
# AI passes the profile
secforge scan example.com --stack node-nginx

# Scan scripts read the profile
# In scan-quick.sh / scan-all.sh:
#   1. Load catalog/profiles.json
#   2. Read tools_include / tools_exclude for the given stack
#   3. Skip excluded tools, only run included ones
#   4. Pass nuclei_tags_boost as --tags if applicable
```

### How the AI uses it

CLAUDE.md instructions tell the AI:
1. Read `catalog/profiles.json` to see available profiles
2. Detect the stack by reading project files + running `curl -sI` against the target
3. Pick the best-matching profile
4. Show the user what will run, what's skipped, and why
5. Suggest extras from `suggested_extras` with explanations
6. Pass `--stack <name>` to secforge scan

### HTTP header fallback detection

When no code path is available (remote-only scan), preflight.sh can do basic detection:
- WhatWeb fingerprinting (already runs)
- HTTP response headers: `Server`, `X-Powered-By`, `X-Generator`
- Cookie names (e.g., `PHPSESSID` → PHP, `connect.sid` → Express)

This populates `preflight.json` with a `detected_stack` field the AI or scan script can read.

---

## Feature 2: Scan Cost Estimator

### What it does

Before every scan, show how many tools will run and how long it will take. The AI presents this to the user as part of the "here's what I'll do" conversation.

### Implementation

**Static defaults** in `catalog/profiles.json` — each tool has an `est_seconds` field:

```json
{
  "tool_estimates": {
    "nuclei": {"est_seconds": 90, "est_disk_mb": 5},
    "nmap": {"est_seconds": 60, "est_disk_mb": 2},
    "testssl": {"est_seconds": 30, "est_disk_mb": 1},
    "lynis": {"est_seconds": 120, "est_disk_mb": 3}
  }
}
```

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
  "scan_date": "2026-04-05T01:00:00Z"
}
```

The estimator reads the latest manifest for the same target+profile. If historical data exists, use it. Otherwise use static defaults.

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

A simple command that writes config programmatically (for when the AI calls it):

```bash
secforge init \
  --domain example.com \
  --environment production \
  --payments no \
  --tier 1 \
  --admin-ip 203.0.113.5
```

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
│  Type in Claude: "fix the headers" to start        │
│  Press q or Ctrl+D to close this panel             │
└─────────────────────────────────────────────────────┘
```

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

### Graceful degradation

| Condition | Behavior |
|-----------|----------|
| tmux not available | Scan runs inline with gum spinners (pretty but not split-pane) |
| gum not installed | Plain text output (sf_log as today) |
| Not a terminal (`[ ! -t 1 ]`) | JSON progress to stdout (`--quiet` mode) |
| `--quiet` flag | JSON lines to stdout for AI consumption |
| tmux available, gum available | Full dashboard experience |

### `--dashboard` flag on scan commands

```bash
secforge scan example.com --stack node-nginx --dashboard
```

Behavior:
1. Check if tmux is running
2. If yes: create/restart `secforge-dashboard` pane, run dashboard.sh in it
3. Start scan in the current pane (or background if AI is orchestrating)
4. Scan writes status events to the status file
5. Dashboard renderer picks them up and redraws

If tmux is NOT running but `--dashboard` is passed, start a tmux session first:
```bash
tmux new-session -d -s secforge "secforge scan example.com --stack node-nginx --dashboard"
tmux split-window -h -t secforge
tmux select-pane -t secforge:0.0
tmux attach -t secforge
```

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
- Downloads `gum` binary to `/opt/secforge/bin/`
- Adds `/opt/secforge/bin` to PATH
- Does NOT install any security tools

Result: SecForge is ready for AI-guided tool selection. ~50MB, ~30 seconds.

**Phase 2: Tool installation** (AI-guided, after stack detection)

The AI calls existing install scripts selectively:

```bash
# Install specific tools based on user selection
secforge install nuclei nmap testssl gitleaks ssh-audit lynis
```

This dispatches to the existing category installers:
- `nuclei` → `scripts/install-dependencies.sh` (subset)
- `nmap` → `apt-get install nmap`
- `testssl` → `scripts/install-dependencies.sh` (subset)
- etc.

The `secforge install` command maps tool names to install methods.

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

### New section: Vibecoder UX Protocol

```markdown
## Vibecoder UX Protocol

### First-Time Setup
When no config/secforge.conf exists:
1. Check if tmux is running. If not: "I'll set up tmux for a better experience"
   and install/start it.
2. Run the onboarding wizard (ask the 5 questions, explain each one).
3. Save config with `secforge init`.
4. Detect the stack from project files + HTTP headers.
5. Show recommended tools with explanations. Let user choose.
6. Install selected tools (show progress in dashboard pane).

### Scanning Flow
1. Always open the dashboard pane (tmux split) before scanning.
2. Show what will run, how long it will take, and ask for confirmation.
3. Always include time estimates based on historical data or defaults.
4. Run scan with `secforge scan <target> --stack <profile> --dashboard`.
5. Stay interactive while scan runs — answer questions, explain findings.
6. When scan completes, present results from findings.json as fix packs.

### Tool Recommendations
- Read catalog/profiles.json to get the profile for the detected stack.
- Explain WHY each tool is recommended and WHY others are skipped.
- Suggest extras from suggested_extras with clear explanations.
- Always warn about Tier 2 risks before running active scanners.

### Dashboard Management
- Open: secforge dashboard --start (or pass --dashboard to scan)
- Read content: tmux capture-pane -t secforge-dashboard -p
- Close: secforge dashboard --close (or user says "close the dashboard")
- Reopen summary: secforge dashboard --last
- The pane stays open between scans. Clear and restart on new scan.

### Returning Users
When config exists and tools are installed, ask:
- "What are you looking for today?"
- Offer: full rescan, quick check, verify fixes, something specific
- Always show time estimates
```

---

## Files Created/Modified

### New files
| File | What |
|------|------|
| `catalog/profiles.json` | 9 stack profiles with all 5 knobs |
| `scripts/bootstrap.sh` | Minimal installer (base deps + gum + tmux) |
| `scripts/dashboard.sh` | Dashboard renderer (reads status file, draws with gum) |
| `scripts/secforge/dashboard.py` | Tool selection UI helper (gum choose wrapper) |

### Modified files
| File | Change |
|------|--------|
| `bin/secforge` | Add `init`, `install`, `dashboard` subcommands + `--stack`/`--dashboard` flags |
| `scripts/scan-quick.sh` | Read profile, skip excluded tools, write status events to dashboard file |
| `scripts/scan-all.sh` | Same |
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
