# SecForge — AI-Guided Security Toolkit for Vibecoders

## What You Are Building

SecForge is a free, open-source security toolkit that installs on any Ubuntu system (VPS, local machine, cloud instance). It gives vibecoders — developers who build with AI but aren't security experts — the ability to fully secure their web apps and servers by simply talking to an AI coding assistant (Claude Code or Codex) in the terminal.

The AI assistant is the orchestrator. The user never needs to know how any tool works. They just say "scan my site" or "harden my server" and the assistant runs the right tools, reads the reports, builds a plan, and fixes things with user approval.

## Core Principles

1. ONE FOLDER: Everything lives under `/opt/secforge/`
2. ONE COMMAND TO INSTALL: `curl -sSL https://raw.githubusercontent.com/USER/secforge/main/install.sh | sudo bash`
3. AI ORCHESTRATOR IS THE BRAIN: Users interact with their AI assistant (Claude Code or Codex), not with tools directly
4. ASK BEFORE ACTING: Always get user confirmation before changing anything
5. BACK UP EVERYTHING: Save original configs before modifying
6. VERIFY FIXES: Re-run the relevant scan after every patch
7. ONLY SCAN WHAT YOU OWN: Require user to confirm domain/server ownership

## Decisions Locked (v1)

These decisions are locked to keep SecForge reliable for vibecoders (easy installs/updates) while staying safe (least privilege + explicit authorization + backups).

1. Install/update strategy: `git clone` into `/opt/secforge/` by default
   - The curl one-liner fetches a **repo-root** `install.sh` bootstrapper that:
     1) installs `git` if missing, 2) clones the repo into `/opt/secforge/`, 3) execs `/opt/secforge/scripts/install.sh` (the real menu installer).
   - Updates: `cd /opt/secforge && git pull` (fast-forward only).

2. Config policy: ship only `.example`, never overwrite real config
   - Git tracks `config/secforge.conf.example` only.
   - `config/secforge.conf` is created at install-time if missing, **gitignored**, and never overwritten by updates.
   - New config options go into `.example`; the AI instructions (`CLAUDE.md`/`AGENTS.md`) instruct the assistant to warn users and propose safe defaults.

3. Privilege model: installer=root, scans=user, fixes=sudo (with confirmation)
   - Installer runs as root for package installs and `/opt/secforge/` setup.
   - Scans run as the invoking user by default.
   - Fixes that require root use targeted `sudo` only after explicit user approval.

4. Runtime permissions: use a `secforge` group + setgid directories
   - Create a `secforge` group.
   - Make **only the directories that must be writable by non-root scans** group-writable. Do **not** make git-cloned tool repos group-writable (otherwise a non-root user could drop git hooks and get root code execution when `update-all.sh` runs `git pull`).
     - `reports/`: `root:secforge` + `2775` (scan outputs must be writable)
     - `backups/`: `root:secforge` + `2750` (root writes; group can read)
     - `config/`: `root:secforge` + `2755` (directory not writable); but the runtime files are group-writable:
       - `config/secforge.conf`: `root:secforge` + `0664`
       - `config/.authorized_targets`: `root:secforge` + `0664`
     - `tools/` and `wordlists/`: `root:root` + `0755` (read-only for scans; avoids privilege escalation)
   - Add `$SUDO_USER` to `secforge` and prompt to re-login so scans work without sudo.

5. OWASP ZAP packaging: tarball under `/opt/secforge/tools/`, no snap/.deb
   - Download the official ZAP Linux tarball and extract to `/opt/secforge/tools/zap/` to keep installs contained under `/opt/secforge/`.
   - Drive ZAP via its bundled CLI/API (localhost:8080). Avoid `zap-cli`.

6. MobSF: Docker-only and optional
   - MobSF is optional and installed only if `docker` exists; otherwise skip with a clear message.

7. Python tools: primary venv at `/opt/secforge/venv/`
   - Install most pip tools into the primary venv (`/opt/secforge/venv/`).
   - Exception: NetExec uses a dedicated venv at `/opt/secforge/venvs/netexec/` to avoid dependency conflicts (it requires native C extensions and has conflicting transitive deps).
   - `/opt/secforge/bin/` exposes all tools via wrappers/symlinks so users never deal with Python packaging.

8. Versioning: “always latest” for v1
   - Use GitHub release downloads for `/opt/secforge/bin/` tools, `pip install -U` (venv), `git pull` for cloned tools, plus signature/template updates (Nuclei templates, ClamAV, rkhunter).
   - `update-all.sh` logs everything and prints before/after versions to help debug breakage.

9. Session/output contract: deterministic layout + timeouts
   - Session ID format: `YYYY-MM-DD_HHMMSS_TARGET` (example: `2026-03-30_143022_example.com`).
   - Predictable per-tool output filenames under category folders.
   - Every tool gets a timeout; on hang/timeouts, log and continue.

10. Redaction: two-layer, never store raw secrets
   - Prefer tool-native redaction where available.
   - `merge-reports.py` runs a second pass to strip anything that looks like raw secrets/keys/tokens.
   - Reports store metadata (type + location + fingerprint), not secret values.

11. Authorization enforcement: scripts + `CLAUDE.md` + disclaimer banner
   - Defense in depth: scan scripts also require explicit target authorization (works even without an AI assistant).
   - First-time scan requires typing `YES` and records authorization in `/opt/secforge/config/.authorized_targets`.
   - Every scan prints an “authorized testing only” disclaimer banner before starting.

12. Pre-flight checklist + rate limiting/circuit breaker (mandatory)
   - Every scan runs a pre-flight: authorization, DNS resolution, connectivity, required tools installed, output dir created.
   - Ethical scanning defaults: request delay, conservative concurrency, and a health-check circuit breaker to avoid accidental DoS.

13. Lockout prevention protocol for server hardening (mandatory)
   - Any change that could lock the user out (SSH/UFW/fail2ban) must be phased, reversible, and verified between phases.
   - Use automatic revert mechanisms (`at`-scheduled rollback) and “verification gates” before proceeding.

14. `bin/` policy: track SecForge wrappers, gitignore generated tool links
   - Track wrapper scripts you write (e.g., `bin/secforge-*`).
   - Gitignore installer-generated symlinks/wrappers to third-party tools (e.g., `bin/nuclei -> /opt/secforge/bin/nuclei`).
   - This keeps git clean and prevents tool/runtime data from accidentally being committed.

15. Scan safety defaults: Tier 1 first, Tier 2 is opt-in
   - Default scans run Tier 1 (passive/low-risk) tools only.
   - Tier 2 (active/aggressive) tools require an explicit opt-in (typed `YES`).

16. AI orchestration instructions: `CLAUDE.md` and `AGENTS.md` must be identical
   - SecForge supports both Claude Code and Codex by shipping the same orchestration instructions under two filenames:
     - `/opt/secforge/CLAUDE.md` (Claude Code)
     - `/opt/secforge/AGENTS.md` (Codex)
   - Requirement: these files must be byte-for-byte identical so updating one updates the other.
   - Implementation: in git, prefer making `AGENTS.md` a symlink to `CLAUDE.md` (Ubuntu install via `git clone` preserves symlinks). If symlinks are undesirable, generate/copy `AGENTS.md` from `CLAUDE.md` as part of the build/release process.

## Optional v1.1 Add-ons (nice-to-have; keep v1 lean)

- Ubuntu Security Guide (`usg`) — CIS/DISA auditing on Ubuntu (typically requires Ubuntu Pro). Useful for compliance-focused users.
- `kernel-hardening-checker` — checks kernel config/sysctls against hardening expectations (advanced, read-only).
- `spectre-meltdown-checker` — reports CPU speculative-execution vulnerability mitigation status (read-only).
- CrowdSec — modern, community-driven “ban decisions” engine (optional alternative/companion to fail2ban).
- Not recommended for v1: `osquery` (powerful, but heavier and can conflict with `auditd` in some setups; more “EDR/telemetry” than “one-off audit”).

## Directory Structure To Create

```
/opt/secforge/
├── install.sh                  # Bootstrap installer (repo root; curl entrypoint)
├── bin/                        # Symlinks and wrapper scripts for all tools
├── venv/                       # Python virtualenv for all pip-installed tools
├── tools/                      # Git-cloned tools that aren't in apt/pip/go
│   ├── testssl/
│   ├── whatweb/
│   ├── jwt_tool/
│   ├── lynis/
│   ├── apkdeeplens/
│   ├── apkhunt/
│   └── ...
├── wordlists/                  # SecLists subset — common directories, passwords
│   ├── common.txt
│   ├── directories.txt
│   └── passwords-top1000.txt
├── reports/                    # All scan output goes here
│   ├── latest/                 # Symlink to most recent scan
│   └── YYYY-MM-DD_HHMMSS_TARGET/  # Timestamped scan folders
│       ├── webapp/
│       ├── api/
│       ├── network/
│       ├── ssl/
│       ├── emaildns/
│       ├── database/
│       ├── containers/
│       ├── iac/
│       ├── cloud/
│       ├── passwords/
│       ├── secrets/
│       ├── mobile/
│       ├── compliance/
│       ├── hardening/
│       ├── dependencies/
│       └── findings.json       # MERGED unified report
├── backups/                    # Config backups before any changes
│   └── YYYY-MM-DD_HHMMSS/
├── scripts/
│   ├── install.sh              # Master installer
│   ├── install-webapp.sh       # Category installers
│   ├── install-api.sh
│   ├── install-network.sh
│   ├── install-ssl.sh
│   ├── install-passwords.sh
│   ├── install-secrets.sh
│   ├── install-mobile.sh
│   ├── install-compliance.sh
│   ├── install-hardening.sh
│   ├── install-dependencies.sh
│   ├── install-emaildns.sh     # Category 12 installer
│   ├── install-database.sh     # Category 13 installer
│   ├── install-containers.sh   # Category 14 installer (optional tooling)
│   ├── scan-all.sh             # Run every scanner
│   ├── scan-quick.sh           # Run essentials only
│   ├── system-check.sh         # Outputs JSON system profile for the AI assistant
│   ├── preflight.sh            # Pre-flight checks + authorization gating
│   ├── check-email-dns.sh       # SPF/DMARC/DNSSEC/MTA-STS checks (JSON)
│   ├── check-mysql.sh           # MySQL security checks (JSON)
│   ├── hardening-watchdog.sh    # Optional: heartbeat-based auto-revert
│   ├── merge-reports.py        # Combine all reports into findings.json
│   ├── export-sarif.py          # Optional: findings.json → findings.sarif
│   ├── update-all.sh           # Update every tool
│   └── stripe-check.py         # Custom payment security checker
├── config/
│   ├── secforge.conf.example   # Default config template (tracked)
│   ├── secforge.conf           # Runtime config (created at install; gitignored)
│   ├── .authorized_targets      # Targets authorized for scanning (created at runtime)
│   ├── fail2ban/               # Pre-configured jail templates
│   └── ufw/                    # Firewall rule templates
├── CLAUDE.md                   # AI orchestration instructions (Claude Code; identical to AGENTS.md)
├── AGENTS.md                   # AI orchestration instructions (Codex; identical to CLAUDE.md)
├── CREDITS.md                  # Tool attributions and licenses
├── LICENSE                     # MIT
└── README.md                   # User-facing docs
```

## The AI Instructions Files (CLAUDE.md + AGENTS.md)

Create these files at:
- `/opt/secforge/CLAUDE.md` (Claude Code)
- `/opt/secforge/AGENTS.md` (Codex)

They must contain the same content so either AI can orchestrate SecForge the same way.

```markdown
# SecForge — AI Orchestration Instructions

You are the security orchestrator for this toolkit. The user is likely a vibecoder who builds apps with AI assistance but is not a security expert. Your job is to guide them through securing their web application and server.

## Session Start (always)

1. Ask what they want to do today:
   - Scan a website / web app
   - Harden this server (local)
   - Check an APK
   - Payment security audit
   - Full audit

2. Ask for the target (domain/URL, repo path, APK path, or "this server").

3. Confirm authorization/ownership (mandatory):
   - "I need to confirm — do you own this domain/server/app (or have written permission) and authorize this security scan?"
   - If they cannot confirm, STOP.

4. Ask whether this is **production** or **staging**, and whether they want:
   - **Tier 1** (passive/low-risk) only, or
   - **Tier 2** (active/aggressive) tests too (requires explicit opt-in).

5. Run system discovery and summarize in plain English (don’t ask questions the system can answer):
   - `/opt/secforge/scripts/system-check.sh | jq .`

6. If required tools are missing:
   - Propose the smallest install that matches their goal.
   - Explain risks in plain language.
   - Ask permission before installing/updating anything.

## System Discovery & Setup Assistant (first run and anytime)

Vibecoders usually don’t know what’s installed (Docker, Node, Python version, Ubuntu version). Don’t ask — detect.

Run `/opt/secforge/scripts/system-check.sh` and build a short “system profile” for the user:
- Ubuntu version + architecture (amd64/arm64)
- Python version (used for venv tools)
- Docker present? (only needed for MobSF and some container scans)
- Available disk + RAM (warn before heavy scans/installs)
- Which SecForge categories/tools are installed (from `config/secforge.conf`)

Then recommend an install option based on their goal and system constraints.

Before installing anything, do quick conflict checks:
- Is ZAP already installed via snap/docker? (avoid duplicate installs)
- Is `/etc` already a git repo? (etckeeper needs special handling)
- Is UFW already enabled and restrictive? (hardening must be extra careful)

If `config/secforge.conf.example` changed since install:
- Do **not** overwrite `config/secforge.conf`.
- Warn the user that new options exist and propose safe defaults.

## Installation/Update Risk Levels (how to explain changes)

| Risk | Meaning | Examples | Assistant must do |
|------|---------|----------|----------------|
| Safe | Adds tools, no service impact | `nmap`, `jq`, `curl` | Explain briefly + ask permission |
| Low | Adds/updates a service | `fail2ban`, `clamav` | Explain what it runs + ask permission |
| Medium | Touches /etc or security baselines | `etckeeper`, `aide --init`, `openscap` | Explain impact + check for existing setup first |
| High | Could break apps/services | Large `apt upgrade`, changing Java versions | Warn clearly + offer alternatives + require explicit YES |
| Dangerous | Could lock the user out | UFW enable, SSH config/port changes | Follow full lockout prevention protocol + verification gates |

## Never Do These (non-negotiable)

- Never scan targets without explicit authorization/ownership confirmation.
- Never upgrade/replace system Python/Go/Node to satisfy a tool requirement (use venv + prebuilt binaries).
- Never `pip install --break-system-packages` on the system Python.
- Never enable/tighten UFW before whitelisting the admin IP first.
- Never restart/reload `sshd` without `sshd -t` passing.
- Never run Tier 2 tools on production without warning + explicit opt-in.

## Available Tools

All tools are installed under /opt/secforge/. Reports go to /opt/secforge/reports/

### Category 1: Web Application Scanning
| Tool | Command | Output |
|------|---------|--------|
| wafw00f | `wafw00f TARGET -f json -o /opt/secforge/reports/SESSION/webapp/wafw00f.json` | JSON |
| CORScanner (optional) | `python3 /opt/secforge/tools/corscanner/cors_scan.py -u TARGET -o /opt/secforge/reports/SESSION/webapp/corscanner.json` | JSON |
| OWASP ZAP | Run ZAP headless from `/opt/secforge/tools/zap/` and scan TARGET via ZAP’s built-in API (localhost:8080); output JSON to `/opt/secforge/reports/SESSION/webapp/zap.json` | JSON |
| Nuclei | `nuclei -u TARGET -json-export /opt/secforge/reports/SESSION/webapp/nuclei.json` | JSON |
| SQLMap | `sqlmap -u "TARGET" --batch --forms --crawl=3 --output-dir=/opt/secforge/reports/SESSION/webapp/sqlmap/` | text |
| ffuf | `ffuf -u TARGET/FUZZ -w /opt/secforge/wordlists/directories.txt -o /opt/secforge/reports/SESSION/webapp/ffuf.json -of json` | JSON |
| Nikto | `nikto -h TARGET -Format json -output /opt/secforge/reports/SESSION/webapp/nikto.json` | JSON |
| XSStrike | `python3 /opt/secforge/tools/xsstrike/xsstrike.py -u TARGET --crawl` | text (capture stdout) |
| Dalfox | `dalfox url TARGET -o /opt/secforge/reports/SESSION/webapp/dalfox.json --format json` | JSON |
| Commix | `commix --url="TARGET" --batch --output-dir=/opt/secforge/reports/SESSION/webapp/` | text |
| WhatWeb | `whatweb TARGET --log-json=/opt/secforge/reports/SESSION/webapp/whatweb.json` | JSON |
| Wapiti | `wapiti -u TARGET -f json -o /opt/secforge/reports/SESSION/webapp/wapiti.json` | JSON |

Built-in web checks (no extra tools; implemented in scan scripts):
- `.git` / `.env` exposure (probe `/.git/HEAD`, `/.env`)
- Cookie flags: `Secure`, `HttpOnly`, `SameSite` on session/auth cookies
- Dangerous HTTP methods: `PUT`, `DELETE`, `TRACE`
- Clickjacking protection: `X-Frame-Options` or `CSP frame-ancestors`
- Basic SSRF probe endpoints (lightweight, non-destructive)

### Category 2: API Security
| Tool | Command | Output |
|------|---------|--------|
| VulnAPI | `vulnapi scan curl TARGET_API_URL` | text/JSON |
| Kiterunner | `kr scan TARGET -w /opt/secforge/wordlists/api-routes.txt -o /opt/secforge/reports/SESSION/api/kiterunner.json` | JSON |
| jwt_tool | `python3 /opt/secforge/tools/jwt_tool/jwt_tool.py TOKEN -A` | text |
| Interactsh | `interactsh-client -json -o /opt/secforge/reports/SESSION/api/interactsh.json` | JSON |

Note: Interactsh provides an out-of-band (OOB) callback server for detecting blind SSRF, blind XSS, blind SQLi, and blind command injection. Nuclei has built-in interactsh integration — when running OOB templates it uses interactsh callbacks automatically. The standalone client can also be used with ZAP, Commix, and SQLMap for blind injection testing. Start the client before running other tools so it captures callbacks during scans.

### Category 3: Network Scanning
| Tool | Command | Output |
|------|---------|--------|
| Nmap | `nmap -sT -sV -sC -T3 TARGET -oX /opt/secforge/reports/SESSION/network/nmap.xml` | XML |
| Masscan (sudo-only) | `sudo masscan TARGET -p0-65535 --rate=1000 -oJ /opt/secforge/reports/SESSION/network/masscan.json` | JSON |
| Netcat | `nc -zv TARGET PORT_RANGE` | text (capture stdout) |

Notes:
- Nmap OS detection (`-O`) and SYN scans (`-sS`) require root. If the user approves sudo, prefer: `sudo nmap -sS -sV -sC -O -T3 TARGET -oX ...`.
- Masscan requires sudo; if the user doesn’t approve sudo, skip Masscan and rely on Nmap.

### Category 4: SSL/TLS & Headers
| Tool | Command | Output |
|------|---------|--------|
| testssl.sh | `/opt/secforge/tools/testssl/testssl.sh --jsonfile /opt/secforge/reports/SESSION/ssl/testssl.json TARGET` | JSON |
| sslscan | `sslscan --xml=/opt/secforge/reports/SESSION/ssl/sslscan.xml TARGET` | XML |
| Observatory | `observatory TARGET --format json > /opt/secforge/reports/SESSION/ssl/observatory.json` | JSON |

### Category 5: Password & Auth Testing
| Tool | Command | Output |
|------|---------|--------|
| Hydra | `hydra -L users.txt -P /opt/secforge/wordlists/passwords-top1000.txt TARGET ssh` | text |
| John the Ripper | `john --wordlist=/opt/secforge/wordlists/passwords-top1000.txt HASHFILE` | text |
| Hashcat | `hashcat -m HASHTYPE -a 0 HASHFILE /opt/secforge/wordlists/passwords-top1000.txt` | text |
| NetExec | `nxc ssh TARGET -u USER -p /opt/secforge/wordlists/passwords-top1000.txt` | text |

### Category 6: Secret & Key Detection
| Tool | Command | Output |
|------|---------|--------|
| TruffleHog | `trufflehog filesystem /path/to/code --json > /opt/secforge/reports/SESSION/secrets/trufflehog.json` | JSON |
| Gitleaks | `gitleaks detect --source /path/to/repo --report-path /opt/secforge/reports/SESSION/secrets/gitleaks.json --report-format json` | JSON |
| APKLeaks | `apkleaks -f app.apk -o /opt/secforge/reports/SESSION/secrets/apkleaks.json --json` | JSON |

### Category 7: Mobile / APK Security
| Tool | Command | Output |
|------|---------|--------|
| MobSF (optional) | Docker-only: run MobSF container if `docker` exists; use REST API at localhost:8000 | JSON/PDF |
| APKDeepLens | `python3 /opt/secforge/tools/apkdeeplens/APKDeepLens.py -apk FILE.apk -report` | HTML/PDF |
| APKHunt | `apkhunt -p FILE.apk -l` | text |

### Category 8: Payment / PCI Compliance
| Tool | Command | Output |
|------|---------|--------|
| Lynis (PCI mode) | `lynis audit system --test-from-group PCI` | text |
| OpenSCAP | `oscap xccdf eval --profile pci-dss --results /opt/secforge/reports/SESSION/compliance/openscap.xml --report /opt/secforge/reports/SESSION/compliance/openscap.html DATASTREAM` | XML/HTML |
| Stripe Check | `python3 /opt/secforge/scripts/stripe-check.py TARGET` | JSON |

The Stripe Check script should verify:
- All pages with payment forms load Stripe.js from https://js.stripe.com ONLY
- No raw card number fields exist in HTML (should use Stripe Elements or Checkout)
- Content-Security-Policy header blocks inline scripts on payment pages
- No card data appears in server logs, local storage, or cookies
- HTTPS is enforced on all payment pages (no mixed content)
- Subresource Integrity (SRI) tags are present on external scripts
- No third-party scripts loaded on checkout pages that could skim card data

### Category 9: Server Hardening
| Tool | Command | Output |
|------|---------|--------|
| Lynis | `lynis audit system --no-colors --logfile /opt/secforge/reports/SESSION/hardening/lynis.log --report-file /opt/secforge/reports/SESSION/hardening/lynis.dat` | text/dat |
| ssh-audit | `ssh-audit -j TARGET:22 > /opt/secforge/reports/SESSION/hardening/ssh-audit.json` | JSON |
| systemd-analyze security | `systemd-analyze security > /opt/secforge/reports/SESSION/hardening/systemd-security.txt` | text |
| debsums | `debsums -s > /opt/secforge/reports/SESSION/hardening/debsums.txt` | text |
| Trivy (rootfs) | `trivy rootfs --format json --output /opt/secforge/reports/SESSION/hardening/trivy-rootfs.json /` | JSON |
| ClamAV | `clamscan -r /home /var/www /opt /tmp --log=/opt/secforge/reports/SESSION/hardening/clamav.log --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" --exclude-dir="^/run"` | text |
| rkhunter | `rkhunter --check --skip-keypress --logfile /opt/secforge/reports/SESSION/hardening/rkhunter.log` | text |
| fail2ban | Check status: `fail2ban-client status` | text |
| AIDE | `aide --check > /opt/secforge/reports/SESSION/hardening/aide.log` | text |
| auditd | `aureport --summary > /opt/secforge/reports/SESSION/hardening/audit-summary.log` | text |
| OpenSCAP | (shared with compliance) CIS benchmark check for Ubuntu | XML/HTML |

Notes:
- Default ClamAV scan scope is limited for practicality. Offer a full filesystem scan (`/`) as an explicit opt-in (it may take hours and should be run with sudo).

### Category 10: System Configuration (no install needed)
- ufw: `ufw status verbose`
- unattended-upgrades: `apt-config dump | grep Unattended`
- SSH: Review `/etc/ssh/sshd_config`
- AppArmor: `aa-status` (if available)

### Category 11: Dependency & Supply Chain
| Tool | Command | Output |
|------|---------|--------|
| OSV-Scanner | `osv-scanner --json /path/to/project > /opt/secforge/reports/SESSION/dependencies/osv.json` | JSON |
| npm audit | `cd /path/to/project && npm audit --json > /opt/secforge/reports/SESSION/dependencies/npm-audit.json` | JSON |
| pip-audit | `pip-audit --format json > /opt/secforge/reports/SESSION/dependencies/pip-audit.json` | JSON |

### Category 12: Email / DNS Security & Attack Surface
| Tool | Command | Output |
|------|---------|--------|
| Email/DNS checks | `/opt/secforge/scripts/check-email-dns.sh TARGET > /opt/secforge/reports/SESSION/emaildns/emaildns.json` | JSON |
| Subfinder | `subfinder -d TARGET -oJ -cs -o /opt/secforge/reports/SESSION/emaildns/subfinder.jsonl` | JSONL |
| httpx | `jq -r .host /opt/secforge/reports/SESSION/emaildns/subfinder.jsonl | httpx -silent -j -o /opt/secforge/reports/SESSION/emaildns/httpx.jsonl` | JSONL |
| dnsrecon (optional) | `dnsrecon -d TARGET -j /opt/secforge/reports/SESSION/emaildns/dnsrecon.json` | JSON |

Email/DNS checks should include: SPF, DKIM (if selector provided or common selectors), DMARC policy, DNSSEC, MTA-STS policy, SMTP TLS reporting (TLS-RPT), and basic zone-transfer attempts.

### Category 13: Database Security (local-first)
| Tool | Command | Output |
|------|---------|--------|
| MySQL security checks | `/opt/secforge/scripts/check-mysql.sh > /opt/secforge/reports/SESSION/database/mysql.json` | JSON |

Database checks should focus on common production mistakes: anonymous accounts, users with empty passwords, remote root access, test DB present, SSL not required, and excessive privileges.

### Category 14: Containers / IaC / Cloud (optional)
| Tool | Command | Output |
|------|---------|--------|
| Trivy (container images) | `trivy image --format json --output /opt/secforge/reports/SESSION/containers/trivy-image.json IMAGE` | JSON |
| Trivy (IaC/config) | `trivy config --format json --output /opt/secforge/reports/SESSION/iac/trivy-config.json /path/to/iac/` | JSON |
| Checkov (IaC) | `checkov -d /path/to/iac --output json > /opt/secforge/reports/SESSION/iac/checkov.json` | JSON |
| Prowler (cloud) | `prowler <provider> -M json -o /opt/secforge/reports/SESSION/cloud/` | JSON |

## Tiered Scanning (Tier 1 vs Tier 2)

SecForge has two scanning tiers so vibecoders can choose “safe and quiet” vs “active testing”.

### Tier 1 — Passive / low-risk (default)
These tools **observe and report**. They can still generate load (many requests/packets), but they do not intentionally send exploit payloads.
- `wafw00f`: detects WAF/CDN so you understand false negatives.
- `WhatWeb`: fingerprints the tech stack.
- `Nuclei` (safe templates): checks for known CVEs/misconfigs.
- `ffuf`: finds hidden paths/files by requesting common directories.
- `Nikto`: checks common web server misconfigs.
- `Nmap` / `Masscan`: finds open ports/services.
- `testssl.sh` / `sslscan`: audits TLS protocols/ciphers.
- `Observatory`: checks headers and TLS posture (HTTP-focused).
- `Lynis`, `ssh-audit`, `systemd-analyze security`, `debsums`: local system/security auditing.
- `Trivy rootfs`: scans OS packages for known vulnerabilities (read-only, may need sudo for full coverage).
- `TruffleHog`, `Gitleaks`: secret detection in code/repo/filesystem.
- `OSV-Scanner`, `npm audit`, `pip-audit`: dependency vulnerability checks.
- `Subfinder` + `httpx`, `check-email-dns.sh`, `check-mysql.sh`: attack-surface + DNS/email + DB posture checks.

### Tier 2 — Active / aggressive (explicit opt-in)
These tools send **real attack payloads** or **brute-force attempts** to confirm vulnerabilities.
- `SQLMap`: sends SQL injection payloads (can pollute data/logs; avoid destructive flags).
- `OWASP ZAP` active scan: crawls and sends many attack payloads (can slow production).
- `XSStrike` / `Dalfox`: injects XSS payloads into params/inputs (can create stored test data).
- `Commix`: sends command-injection payloads (if vulnerable, payloads may execute).
- `Wapiti`: active web vulnerability scanner (SSRF/XXE/LFI-style probes).
- `Hydra` / `NetExec`: brute-force auth checks (can trigger lockouts or fail2ban bans).

Before running Tier 2, warn the user in plain English about:
- Potential production slowdown and log volume
- Possible account lockouts / IP bans
- Possible test data appearing in the database

Recommend staging/off-peak first, then ask: “Type `YES` to run Tier 2 tools.”

## Scan Profiles

### Quick Scan (5-10 minutes)
Run (Tier 1 only): wafw00f, WhatWeb, Nuclei, Nmap (top 1000 ports), testssl.sh, Lynis, ssh-audit, Email/DNS checks
Use when: User wants a fast overview

### Full Web Scan (30-60 minutes)
Run: Tier 1 baseline first (Category 1/2/4 Tier 1 tools), then offer Tier 2 tools (SQLMap, ZAP active scan, XSStrike/Dalfox, Commix, Wapiti).
Start Interactsh client first so it captures blind callbacks during the scan.
Use when: User says "scan my website" or "check my web app"

### Safe System Audit (10-20 minutes, no changes)
Run: Read-only checks from Category 9 + Category 10 (no config changes)
Use when: User wants a server assessment without hardening risk

### Full Server Hardening (15-30 minutes)
Run: All Category 9 + Category 10 + Category 5 (SSH brute test)
Use when: User says "harden my server" or "secure my VPS"

### Email/DNS Audit (1-3 minutes)
Run: Category 12 only
Use when: User says "check my DNS/email security" or "SPF/DMARC check"

### Database Audit (2-5 minutes)
Run: Category 13 only
Use when: User says "check my database security"

### Payment Security Audit (10-20 minutes)
Run: Category 8 + Category 4 (SSL) + Category 6 (secrets) + Category 1 (focused on payment pages)
Use when: User mentions Stripe, payments, credit cards, PCI, or checkout

### Mobile App Audit (15-30 minutes)
Run: Category 7 + Category 6 (APKLeaks)
Use when: User provides an APK file

### Full Audit — Everything (60-120 minutes)
Run: Categories 1–13, plus Category 14 if relevant and user opts in (Docker/IaC/Cloud)
Use when: User says "full audit", "check everything", or "I want maximum security"

### Dependency Check (2-5 minutes)
Run: Category 11 tools on the project directory
Use when: User says "check my dependencies" or "are my packages safe"

## Scan Script Requirements (v1)

These rules apply to `scan-all.sh` and `scan-quick.sh` to keep scans reliable, ethical, and predictable.

Pre-flight checklist (before launching any tool):
1. Authorization present for the target (or prompt user to type `YES`).
2. Target resolves (DNS check).
3. Target responds (HTTP/HTTPS connectivity check).
4. Required tools for the chosen profile are installed (otherwise offer install or skip with warning).
5. Output session directory created and writable (non-root scans must be able to write).
6. Baseline response time recorded (used for circuit breaker).

Rate limiting / circuit breaker (defaults; configurable in `secforge.conf`):
- Default delay between HTTP requests: 200ms
- Max concurrent tools running: 3–5
- Conservative defaults (e.g., Nmap `-T3`, not `-T5`)
- If median response time exceeds a threshold (example: >10s), pause scanning for a cooldown window (example: 30s) and warn the user.

Failure handling:
- Every tool must run with a timeout; on timeout/hang, kill it, log the error, and continue.
- If wafw00f detects a WAF/CDN, warn the user about false negatives and automatically reduce scan intensity.
- Tier 2 tools must be gated behind an explicit opt-in (interactive prompt or a `--tier2` flag). Default is Tier 1 only.

Privilege-aware execution:
- Prefer non-root modes by default (example: Nmap `-sT` and no `-O` OS detection).
- If a tool requires sudo (Masscan; optional Nmap OS detection; full filesystem malware scans), ask permission and explain why. If not approved, skip and continue.
- Long-running tools (ClamAV, full port scans) must use practical default scopes and/or longer timeouts, and offer “full” modes only as explicit opt-ins.

Optional outputs:
- Generate `findings.sarif` alongside `findings.json` so results can be uploaded to GitHub’s Security tab / viewed in IDE SARIF viewers.

## Report Merging

After every scan, run the merge script:
```bash
python3 /opt/secforge/scripts/merge-reports.py /opt/secforge/reports/SESSION/
```

This reads all tool outputs and creates `/opt/secforge/reports/SESSION/findings.json` with this schema:

```json
{
  "scan_date": "2026-03-30T14:30:00Z",
  "target": "example.com",
  "scan_profile": "full_web",
  "tools_run": ["nuclei", "nmap", "zap", "testssl", "..."],
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "info": 23
  },
  "findings": [
    {
      "id": "SF-001",
      "severity": "CRITICAL",
      "tool": "nuclei",
      "also_found_by": ["zap"],
      "category": "sql-injection",
      "title": "SQL Injection in login form",
      "url": "https://example.com/api/login",
      "description": "The login endpoint is vulnerable to SQL injection via the username parameter",
      "evidence": "Parameter: username, Payload: ' OR 1=1--",
      "remediation": "Use parameterized queries/prepared statements",
      "cwe": "CWE-89",
      "owasp": "A03:2021-Injection",
      "status": "open"
    }
  ]
}
```

## How To Present Findings To The User

After generating findings.json, present results like this:

```
🔴 CRITICAL (2 findings)
  SF-001: SQL Injection in login form — /api/login
  SF-002: Exposed admin panel with default credentials — /admin

🟠 HIGH (5 findings)
  SF-003: Missing Content-Security-Policy header
  SF-004: SSH allows password authentication
  SF-005: TLS 1.0 still enabled
  ...

🟡 MEDIUM (12 findings) ...
🔵 LOW (8 findings) ...
ℹ️  INFO (23 findings) ...

Total: 50 findings across 10 tools
```

Then ask: "Would you like me to start fixing these? I'll go in order of severity — critical first. I'll explain each fix and ask for your approval before making any changes."

## How To Fix Things

For EVERY fix:
1. Explain what the vulnerability is in plain English
2. Explain what you're going to change
3. Show the exact command or file change
4. ASK FOR PERMISSION: "Should I apply this fix? [y/n]"
5. Back up the original file: `cp FILE /opt/secforge/backups/SESSION/`
6. Apply the fix
7. Re-run the specific scan that found the issue
8. Report whether the fix worked

NEVER apply fixes without user confirmation.
NEVER modify application code without showing the exact diff first.

### Lockout Prevention Protocol (non-negotiable for SSH/UFW/fail2ban)

For server config changes (SSH, firewall, fail2ban), follow this exact safety workflow:

1. Safety prerequisites (ask the user to confirm):
   - They have console/out-of-band access via their VPS provider (and know how to use it)
   - They can access/adjust any VPS provider firewall / security group rules (if applicable)
   - They have a second SSH session open (lifeline session)
   - They are running inside `tmux` (or keep the lifeline session open at all times)
   - Optional (recommended): enable the `hardening-watchdog.sh` auto-revert while hardening

2. Automatic rollback before risky edits:
   - Before editing `/etc/ssh/sshd_config`, schedule an `at` job to revert after 5 minutes (and record the job ID).
   - Validate before applying: `sshd -t` (never reload/restart with a broken config).
   - After the user confirms a NEW SSH connection works, cancel the `at` job.
   - Example:
     - Backup: `cp /etc/ssh/sshd_config /etc/ssh/sshd_config.secforge.bak`
     - Schedule revert: `echo "cp /etc/ssh/sshd_config.secforge.bak /etc/ssh/sshd_config && systemctl restart ssh" | at now + 5 minutes`
     - Cancel after verification: `atq` then `atrm <job_id>`

3. UFW rules: whitelist first, then harden
   - Insert an allow rule for the user’s current IP before enabling or tightening UFW rules.
   - Before enabling/tightening UFW, schedule an `at` job to `ufw disable` after 5 minutes as an auto-revert safety net.
   - Prefer `ufw limit ssh` during initial setup rather than a hard deny.
   - Example: `ufw insert 1 allow from <YOUR_IP> to any port <SSH_PORT>`

4. fail2ban: never ban the administrator
   - Auto-detect the current SSH client IP and recommend adding it to `ignoreip` before enabling aggressive jails.

5. Phased hardening with verification gates (no “apply everything”)
   - Phase 1: Prep (console access, tmux, lifeline session, backups, rollback job, optional temporary backup SSH port)
   - Phase 2: Firewall changes → VERIFY: new SSH connection works
   - Phase 3: SSH hardening → VERIFY: new SSH connection works
   - Phase 4: fail2ban enablement → VERIFY: admin IP is whitelisted + SSH still works
   - Phase 5: Other hardening
   - Phase 6: Cleanup (remove temporary rules/ports, stop watchdogs if used)

## Updating Tools

Run: `/opt/secforge/scripts/update-all.sh`

This script should:
- apt update (always)
- For apt-installed tools: prefer `apt-get install --only-upgrade <secforge package list>` (safer than upgrading the whole server); offer full `apt-get upgrade` only with explicit user confirmation
- pip install --upgrade for pip tools
- Re-download latest GitHub release binaries for tools installed into `/opt/secforge/bin/`
- git pull for git-cloned tools
- Nuclei templates are updated via the `tools/*` git-pull loop (`/opt/secforge/tools/nuclei-templates`); no separate template command needed
- freshclam for ClamAV signatures
- rkhunter --update for rootkit definitions
- Print a summary of what was updated

## Rules

1. Only scan domains/servers the user confirms they own
2. Never apply fixes without explicit user approval
3. Always back up configs before changing them
4. Re-verify after every fix
5. If a scan tool is not installed, offer to install it
6. If a scan fails, log the error and continue with other tools
7. Never store actual passwords or secrets in reports — redact them
8. For password testing, only test the user's OWN systems
9. Keep all reports under /opt/secforge/reports/ organized by timestamp
10. Update findings.json status to "fixed" after verified remediation
```

## The Install Scripts (install.sh + scripts/install.sh)

There are two installers:
- `install.sh` (repo root): the curl one-liner entrypoint. Installs `git` if missing, clones the repo into `/opt/secforge/`, then execs `/opt/secforge/scripts/install.sh`.
- `scripts/install.sh`: the real menu-driven installer described below.

Build the **menu installer** (`/opt/secforge/scripts/install.sh`) so it:

1. Checks running as root on Ubuntu 20.04+ (Ubuntu 22.04+ recommended; some optional tools require newer Python)
2. Shows a menu:
```
╔══════════════════════════════════════════════╗
║          SecForge Installer v1.0             ║
║    AI-Guided Security Toolkit for Vibecoders ║
╠══════════════════════════════════════════════╣
║                                              ║
║  1) Install Everything (≈60 tools, ~7GB+)    ║
║  2) Essential Only (≈15 tools, ~2GB)         ║
║     (Nuclei, Nmap, ZAP, testssl, ffuf,       ║
║      Lynis, ssh-audit, wafw00f, fail2ban,    ║
║      ClamAV, rkhunter, TruffleHog, Gitleaks, ║
║      OSV-Scanner, Observatory)               ║
║  3) Custom — Choose Categories               ║
║  4) Web App Scanning Only (≈12 tools)        ║
║  5) Server Hardening Only (≈10 tools)        ║
║  6) Mobile/APK Testing Only (3 tools)        ║
║  7) Payment/PCI Compliance Only (3 tools)    ║
║                                              ║
║  u) Update All Installed Tools               ║
║  s) Show Installed Tools & Versions          ║
║  0) Exit                                     ║
║                                              ║
╚══════════════════════════════════════════════╝
```
3. If user picks option 3 (Custom), show category checkboxes
4. Creates the full directory structure under `/opt/secforge/`
5. Installs tools by category using the appropriate method:

### Install Methods Per Tool

**apt install:**
nmap, masscan, netcat-openbsd, sslscan, hydra, john, hashcat, ufw, clamav, clamav-freshclam, rkhunter, fail2ban, aide, auditd, wapiti, openscap-scanner, openscap-utils, python3-pip, python3-venv, ruby, default-jre (for ZAP), nodejs, npm, dnsutils, jq, tmux, at, etckeeper, debsums, default-mysql-client, nikto

**apt install (mobile/APK category only):**
golang-go (only needed to build the APKHunt binary during install)

**direct download (tarball into /opt/secforge/tools/):**
OWASP ZAP (extract to `/opt/secforge/tools/zap/`)

**direct download (binaries into /opt/secforge/bin/):**
nuclei, ffuf, dalfox, subfinder, httpx, interactsh-client, osv-scanner, trufflehog, gitleaks, kiterunner (kr), trivy, vulnapi

Notes:
- The installer must detect CPU architecture (`uname -m`) and download the matching asset (amd64 vs arm64) when using prebuilt binaries.
- Prefer extracting release zips/tars into `/opt/secforge/bin/` to keep the “everything under /opt/secforge/” principle.
- `vulnapi` should default to `cerberauth/vulnapi` but allow overriding its source (e.g., via `SECFORGE_VULNAPI_REPO`) if forks use different distribution.

**pip install (inside /opt/secforge/venv/):**
sqlmap, commix, apkleaks, pip-audit, wafw00f, ssh-audit, dnsrecon (optional), checkov (optional), prowler (optional), requests, beautifulsoup4

Notes:
- Some optional pip tools have minimum Python version requirements; the installer should detect the system Python and skip with a clear message if unsupported.
  - wafw00f: Python >= 3.10
  - checkov: Python >= 3.9
  - prowler: Python 3.9–3.12
  - dnsrecon: upstream requires Python >= 3.12 (treat as optional / best-effort)
- `dnsrecon`, `checkov`, and `prowler` should be treated as optional (cloud/IaC/DNS-heavy use cases), not required for a basic web/server audit.

**git clone into /opt/secforge/tools/:**
testssl.sh (github.com/drwetter/testssl.sh)
whatweb (github.com/urbanadventurer/WhatWeb)
jwt_tool (github.com/ticarpi/jwt_tool)
corscanner (github.com/chenjj/CORScanner)
xsstrike (github.com/s0md3v/XSStrike)
lynis (github.com/CISOfy/lynis)
apkdeeplens (github.com/d78ui98/APKDeepLens)
apkhunt (github.com/Cyber-Buddy/APKHunt)
netexec (github.com/Pennyw0rth/NetExec)

Notes:
- `install-mobile.sh` should compile APKHunt during install (`go build`) and place the binary at `/opt/secforge/bin/apkhunt` so scans do not require Go at runtime.

**docker (optional):**
MobSF (pull/run only if `docker` exists)

**npm install (local under /opt/secforge/):**
observatory-cli (Mozilla Observatory) installed into `/opt/secforge/tools/observatory-cli/` and exposed via an `/opt/secforge/bin/observatory` wrapper

**Custom script (stripe-check.py):**
Write a Python script that uses requests + BeautifulSoup to check payment security

**Download wordlists:**
Download a small curated subset from SecLists (not the full 4.5GB):
- Discovery/Web-Content/common.txt
- Discovery/Web-Content/directory-list-2.3-small.txt
- Passwords/Common-Credentials/top-1000-most-common-passwords.txt
- Discovery/Web-Content/api/api-endpoints.txt

6. After installation:
   - Create wrappers/symlinks in `/opt/secforge/bin/` for each tool
   - Add /opt/secforge/bin to PATH in /etc/profile.d/secforge.sh
   - Create `secforge` group + safe permissions so non-root scans can write reports without letting non-root users modify tool repos:
     - `reports/`: `root:secforge` + `2775`
     - `backups/`: `root:secforge` + `2750`
     - `config/`: `root:secforge` + `2755` and create runtime files as `0664`:
       - `config/secforge.conf`
       - `config/.authorized_targets`
     - `tools/` and `wordlists/`: `root:root` + `0755`
   - Ensure `atd` is installed/enabled (needed for auto-revert safety during hardening)
   - Initialize `etckeeper` (track `/etc` changes) and commit a baseline snapshot
   - Initialize AIDE database (aide --init)
   - Initialize ClamAV database (freshclam)
   - Clone Nuclei templates repo into `/opt/secforge/tools/nuclei-templates` (scan scripts pass `-t` to this directory; updates via `tools/*` git-pull loop)
   - Create `/opt/secforge/config/secforge.conf` from `config/secforge.conf.example` if missing (never overwrite existing config)
   - Write installed tool list/categories to `/opt/secforge/config/secforge.conf`
   - Copy CLAUDE.md to /opt/secforge/CLAUDE.md

7. Print summary:
```
✅ SecForge installed successfully!
   Tools installed: depends on selected option
   Location: /opt/secforge/
   Reports: /opt/secforge/reports/

   To start: cd /opt/secforge and start your AI assistant (Claude Code or Codex)
   Then tell it: "Scan my site example.com"
```

## The Merge Script (merge-reports.py)

Build a Python script that:

1. Takes a session report directory as argument
2. Reads every file in every subdirectory
3. Parses based on file extension:
   - .json → json.load()
   - .jsonl → parse JSON Lines (one JSON object per line)
   - .xml → xml.etree.ElementTree
   - .txt/.log/.dat → regex parsing for known tool output formats
4. Maps each tool's native severity to a unified scale:
   - CRITICAL / HIGH / MEDIUM / LOW / INFO
5. Deduplicates: if ZAP and Nuclei both find "missing CSP header", merge into one finding with `also_found_by` field
6. Maps findings to CWE and OWASP categories where possible
7. Sorts by severity
8. Redacts any secrets/tokens from evidence fields (defense-in-depth; never store raw secrets)
9. Outputs findings.json with the schema defined in CLAUDE.md
10. (Optional) Also outputs findings.sarif for GitHub/IDE integration

## The Update Script (update-all.sh)

Build a bash script that:

1. Reads /opt/secforge/config/secforge.conf to know what's installed
2. For each installed tool, runs the appropriate update command
   - apt tools: `apt update` + `apt-get install --only-upgrade <secforge package list>` (offer full `apt-get upgrade` only with explicit confirmation)
   - venv tools: `pip install -U ...` inside `/opt/secforge/venv/`
   - git-cloned tools: `git pull` in each `/opt/secforge/tools/*`
   - binary tools in `/opt/secforge/bin/`: re-download latest GitHub releases
   - signatures/templates: `freshclam`, `rkhunter --update` (Nuclei templates updated via `tools/*` git-pull loop)
3. Shows a before/after version comparison
4. Logs everything to /opt/secforge/logs/updates.log (root-only; prevents symlink attacks in group-writable reports/)

## The Stripe/Payment Check Script (stripe-check.py)

Build a Python script that:

1. Takes a URL as argument
2. Fetches the page and all linked pages containing "checkout", "payment", "billing", "subscribe"
3. Checks:
   - HTTPS enforced (no HTTP, no mixed content)
   - Stripe.js loaded from js.stripe.com only (not self-hosted)
   - No `<input type="text" name="card">` or similar raw card fields in HTML
   - Content-Security-Policy header present and blocks unsafe-inline
   - No card patterns (16 digits) in page source, local storage references, or cookie names
   - SRI integrity attributes on external script tags
   - X-Frame-Options or CSP frame-ancestors prevents clickjacking on payment pages
   - No third-party analytics/tracking scripts on checkout pages that could skim
4. Outputs JSON report with pass/fail per check

## README.md Content

Write a README that includes:

- Project name and one-line description
- "Why SecForge?" section explaining the vibecoder security gap
- One-liner install command
- Screenshot placeholder for the install menu
- Quick start: install → cd /opt/secforge → start your AI assistant → "scan my site"
- Full tool list table with all tools, their purpose, and category
- Scan profiles explained
- How it works with AI assistants (CLAUDE.md/AGENTS.md approach)
- Estimated disk space per install option
- FAQ: Is this legal? (yes, MIT license, only scan what you own), Do I need a paid AI plan? (depends on the assistant you use), Can I use this without an AI assistant? (yes, run scan-all.sh manually)
- Contributing guidelines
- Credits and licenses for all included tools
- Credits and licenses for all included third-party tools (and their install sources)
- Disclaimer: "For authorized security testing only. Only scan systems you own or have written permission to test. The authors are not responsible for misuse."

## Files To Create

0. `/opt/secforge/install.sh` — Repo-root bootstrap installer (curl entrypoint; clones repo, then execs scripts/install.sh)
1. `/opt/secforge/scripts/install.sh` — Master installer with menu
2. `/opt/secforge/scripts/install-webapp.sh` — Category installer
3. `/opt/secforge/scripts/install-api.sh`
4. `/opt/secforge/scripts/install-network.sh`
5. `/opt/secforge/scripts/install-ssl.sh`
6. `/opt/secforge/scripts/install-passwords.sh`
7. `/opt/secforge/scripts/install-secrets.sh`
8. `/opt/secforge/scripts/install-mobile.sh`
9. `/opt/secforge/scripts/install-compliance.sh`
10. `/opt/secforge/scripts/install-hardening.sh`
11. `/opt/secforge/scripts/install-dependencies.sh`
12. `/opt/secforge/scripts/scan-all.sh` — Master scan script
13. `/opt/secforge/scripts/scan-quick.sh` — Essential scan only
14. `/opt/secforge/scripts/merge-reports.py` — Report merger
15. `/opt/secforge/scripts/update-all.sh` — Tool updater
16. `/opt/secforge/scripts/stripe-check.py` — Payment security checker
17. `/opt/secforge/CLAUDE.md` — AI orchestration instructions (identical to AGENTS.md)
18. `/opt/secforge/AGENTS.md` — Same as CLAUDE.md (Codex instructions; keep in sync)
19. `/opt/secforge/README.md` — User docs
20. `/opt/secforge/CREDITS.md` — Tool attributions
21. `/opt/secforge/LICENSE` — MIT license
22. `/opt/secforge/.gitignore` — Ignore runtime data: reports/, backups/, tools/, wordlists/, venv/, config/secforge.conf, config/.authorized_targets, and generated bin/ links (keep `bin/secforge-*` tracked)
23. `/opt/secforge/scripts/preflight.sh` — Pre-flight checks + authorization gating
24. `/opt/secforge/scripts/check-email-dns.sh` — Email/DNS checks (SPF/DMARC/DNSSEC/MTA-STS) → JSON
25. `/opt/secforge/scripts/check-mysql.sh` — Local MySQL security checks → JSON
26. `/opt/secforge/scripts/export-sarif.py` — Optional SARIF export (findings.json → findings.sarif)
27. `/opt/secforge/scripts/install-emaildns.sh` — Category 12 installer
28. `/opt/secforge/scripts/install-database.sh` — Category 13 installer
29. `/opt/secforge/scripts/install-containers.sh` — Category 14 installer (optional)
30. `/opt/secforge/scripts/system-check.sh` — Output a JSON system profile (Ubuntu/arch/Python/Docker/RAM/disk/installed categories)
31. `/opt/secforge/scripts/hardening-watchdog.sh` — Optional heartbeat-based auto-revert for multi-file hardening
32. `/opt/secforge/config/secforge.conf.example` — Default config template (tracked in git; installer copies to secforge.conf if missing)
33. `/opt/secforge/scripts/_lib.sh` — Shared bash helpers for installers/scripts (internal)

## Build Order

Phase 1: Create directory structure + CLAUDE.md + AGENTS.md + config/secforge.conf.example
Phase 2: Build installers (bootstrap + menu) and category installers (including emaildns/database/containers)
Phase 3: Build scan scripts (system-check.sh, preflight.sh, scan-all.sh, scan-quick.sh, check-email-dns.sh, check-mysql.sh, hardening-watchdog.sh)
Phase 4: Build reporting (merge-reports.py + export-sarif.py)
Phase 5: Build update-all.sh
Phase 6: Build stripe-check.py
Phase 7: Build README.md, CREDITS.md, LICENSE (and .gitignore)
Phase 8: Test by installing on a fresh Ubuntu system
Phase 9: Push to GitHub

Start with Phase 1 and work through sequentially. Test each phase before moving to the next.

## Phase Checklists (Definition of Done)

Use these as “go/no-go” checklists so each phase ships something complete, safe, and testable.

### Phase 1 — Repo Scaffold + AI Instructions
- [ ] Create repo folders: `bin/`, `config/`, `scripts/`
- [ ] Add `config/secforge.conf.example` with documented defaults (delay, concurrency, timeouts, tier defaults, installed categories list)
- [ ] Add `CLAUDE.md` + `AGENTS.md` (byte-for-byte identical; prefer symlink)
- [ ] Add `.gitignore` early to prevent committing runtime data (`reports/`, `backups/`, `tools/`, `wordlists/`, `venv/`, `config/secforge.conf`, `config/.authorized_targets`, generated `bin/` links)
- [ ] Validate: `diff -q CLAUDE.md AGENTS.md` (or `readlink AGENTS.md`) and confirm no runtime folders are tracked by git

### Phase 2 — Installers (Bootstrap + Menu + Categories)
- [ ] Repo-root `install.sh` (curl entrypoint) is a safe bootstrapper:
  - [ ] Requires root
  - [ ] Installs `git` if missing
  - [ ] `git clone` (or fast-forward pull) into `/opt/secforge`
  - [ ] Executes `/opt/secforge/scripts/install.sh`
- [ ] `scripts/install.sh` menu is idempotent and supports:
  - [ ] Essential install
  - [ ] Full install
  - [ ] Custom categories
  - [ ] Update/show versions
- [ ] Category installers exist and work: `install-webapp.sh`, `install-api.sh`, `install-network.sh`, `install-ssl.sh`, `install-passwords.sh`, `install-secrets.sh`, `install-mobile.sh`, `install-compliance.sh`, `install-hardening.sh`, `install-dependencies.sh`, `install-emaildns.sh`, `install-database.sh`, `install-containers.sh`
- [ ] Creates `/opt/secforge` directory tree + runtime permissions:
  - [ ] `secforge` group created; permissions set:
    - [ ] `reports/`: `root:secforge` + `2775`
    - [ ] `backups/`: `root:secforge` + `2750`
    - [ ] `config/`: `root:secforge` + `2755` and runtime files (`secforge.conf`, `.authorized_targets`) are group-writable
    - [ ] `tools/` and `wordlists/`: `root:root` + `0755`
  - [ ] Current user added to `secforge` group (with clear “re-login required” message)
- [ ] Packaging rules enforced:
  - [ ] pip tools go into `/opt/secforge/venv` only (never system pip)
  - [ ] binaries go into `/opt/secforge/bin` with arch detection
  - [ ] ZAP installed as tarball under `/opt/secforge/tools/zap`
  - [ ] MobSF docker-only + optional
  - [ ] Observatory installed locally under `/opt/secforge/tools/observatory-cli` with wrapper in `/opt/secforge/bin`
  - [ ] Mobile/APK: `golang-go` only if installing mobile category; APKHunt compiled at install to `/opt/secforge/bin/apkhunt`
- [ ] Config policy enforced:
  - [ ] `config/secforge.conf.example` tracked in git
  - [ ] `config/secforge.conf` created from `.example` only if missing; never overwritten

### Phase 3 — Scan Foundation (Discovery + Preflight + Scan Scripts)
- [ ] `scripts/system-check.sh` outputs JSON profile (Ubuntu/arch/Python/Docker/RAM/disk + installed categories/tools)
- [ ] `scripts/preflight.sh` implements:
  - [ ] authorization gating + disclaimer banner
  - [ ] DNS resolve + HTTP(S) connectivity checks
  - [ ] session folder creation + `reports/latest` update
  - [ ] “tools present?” checks per profile with clear skip/install prompts
  - [ ] baseline response time capture for circuit breaker
- [ ] `scripts/scan-quick.sh` runs Tier 1 only and finishes with `merge-reports.py`
- [ ] `scripts/scan-all.sh` runs Tier 1 first, then offers Tier 2 opt-in (`YES`) before active tools
- [ ] Safety mechanics implemented in scan scripts:
  - [ ] timeouts per tool, circuit breaker, conservative concurrency, WAF-aware intensity
  - [ ] privilege-aware execution (non-root defaults; sudo-only tools require permission and are skippable)
- [ ] “New categories” scripts exist and output JSON:
  - [ ] `scripts/check-email-dns.sh`
  - [ ] `scripts/check-mysql.sh` (local-first; safe queries; no data dumps)
- [ ] Optional: `scripts/hardening-watchdog.sh` present and can be enabled/disabled safely

### Phase 4 — Reporting (Merge + SARIF)
- [ ] `scripts/merge-reports.py`:
  - [ ] parses JSON/JSONL/XML/text outputs used by included tools
  - [ ] maps severities to CRITICAL/HIGH/MEDIUM/LOW/INFO
  - [ ] deduplicates and fills `also_found_by`
  - [ ] redacts secrets (defense-in-depth)
  - [ ] writes `findings.json` with the documented schema
- [ ] `scripts/export-sarif.py` (optional) converts `findings.json` → `findings.sarif`

### Phase 5 — Updates
- [ ] `scripts/update-all.sh`:
  - [ ] updates apt packages via `apt-get install --only-upgrade <secforge list>` (full upgrade only with explicit confirmation)
  - [ ] updates venv pip tools
  - [ ] updates git-cloned tools
  - [ ] re-downloads binary tools
  - [ ] updates templates/signatures (Nuclei, ClamAV, rkhunter)
  - [ ] logs everything with before/after versions

### Phase 6 — Payment Checks
- [ ] `scripts/stripe-check.py`:
  - [ ] crawls only payment-related pages
  - [ ] checks Stripe.js origin, raw card fields, HTTPS/mixed content, CSP, SRI, clickjacking protections, third-party scripts
  - [ ] outputs a JSON pass/fail report

### Phase 7 — Docs + Legal
- [ ] `README.md` matches the actual behavior (tiers, scan profiles, install options, safety rules)
- [ ] `CREDITS.md` includes every third-party tool attribution + license
- [ ] `LICENSE` is MIT for SecForge code
- [ ] `.gitignore` matches the locked decisions (no runtime/user data in git)

### Phase 8 — Fresh-System Testing
- [ ] Test Essential + Full installs on at least Ubuntu 22.04 amd64 (and ideally 24.04 + arm64)
- [ ] Verify non-root scans can write to `reports/` (group/setgid works)
- [ ] Verify Tier 2 gating (must require explicit opt-in)
- [ ] Verify lockout safety mechanisms (at-revert for sshd/UFW; phased verification gates; watchdog optional)

### Phase 9 — Release
- [ ] Push repo with repo-root `install.sh` working for the curl one-liner
- [ ] Tag a release and document supported Ubuntu versions and limitations (Docker optional; some tools optional by Python version)
