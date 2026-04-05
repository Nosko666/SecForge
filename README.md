# SecForge

Free, open-source security toolkit built for vibecoders. You talk to Claude or Codex, it scans your site, finds problems, and walks you through fixing them. No security expertise needed.

## What Does It Do?

You say **"scan my site"** to your AI assistant. SecForge:

1. **Detects your stack** (Node+Nginx? WordPress? Python+Django?) and picks the right tools
2. **Runs 51 security scanners** (network, web, SSL, secrets, dependencies, server hardening)
3. **Groups findings into fix packs** — "Fix your HTTP headers (12 issues, easy)" instead of 200 raw warnings
4. **Scores priorities** — critical stuff first, with plain English explanations
5. **Tracks progress** — rescan after fixing and it shows what's fixed, what's new, what came back
6. **Generates fixes** — actual commands, diffs, and config changes you can copy-paste

## Install (30 seconds, Ubuntu 20.04+)

```bash
curl -sSL https://raw.githubusercontent.com/Nosko666/SecForge/main/install.sh | sudo bash
```

This installs the base (~50MB): directory structure, gum (pretty dashboard), tmux, and base deps. **No security tools yet** — your AI picks the right ones for your stack.

Or manually:
```bash
git clone https://github.com/Nosko666/SecForge.git /opt/secforge
cd /opt/secforge && sudo scripts/bootstrap.sh
```

## Getting Started

### The AI Way (recommended)

Open Claude Code, Codex, or any AI terminal in `/opt/secforge/` and say:

- **"Scan my site example.com"** — full scan with live dashboard
- **"Harden this server"** — audit + fix suggestions
- **"Check my app for secrets"** — scans your code for leaked keys/tokens
- **"Payment security audit"** — checks Stripe/payment pages

The AI reads `CLAUDE.md` (the orchestration instructions) and handles everything: picks tools for your stack, shows progress, explains findings, generates fixes, verifies them.

### The CLI Way

```bash
# Setup
secforge init                            # Interactive wizard (domain, environment, payments)
secforge install --list                  # See all available tools
secforge install nuclei nmap testssl     # Install specific tools

# Scan
secforge scan example.com                                # Quick scan
secforge scan example.com --stack node-nginx --dashboard # With stack profile + live dashboard
secforge scan example.com --skip nmap,testssl            # Skip specific tools
secforge scan --full example.com                         # Full scan (Tier 1 + Tier 2)

# Review
secforge list                            # Findings grouped by fix pack
secforge diff                            # What changed since last scan
secforge export --mode full-plan         # AI-ready remediation plan
secforge export --mode explain --finding SF-001  # Plain English explanation

# Fix + Verify
secforge verify --pack FP-http-header-hardening --run    # Auto-check if fix worked
secforge history --finding SF-001                         # Track one finding over time
```

### No AI, No CLI? Raw scripts still work:

```bash
/opt/secforge/scripts/scan-quick.sh https://example.com
/opt/secforge/scripts/scan-all.sh https://example.com
```

## Stack Profiles

SecForge knows about your tech stack and only runs relevant tools:

| Profile | For | Tools included |
|---------|-----|----------------|
| `node-nginx` | Node.js behind Nginx | nuclei (nodejs tags), nmap, testssl, gitleaks, osv-scanner, ssh-audit |
| `python-nginx` | Django/Flask behind Nginx | nuclei (python tags), pip-audit, trivy, lynis |
| `wordpress` | WordPress sites | nuclei (wordpress tags), wapiti, wafw00f, xmlrpc checks |
| `php-nginx` | PHP behind Nginx | nuclei (php tags), ffuf, nikto |
| `java-spring` | Spring Boot apps | nuclei (java tags), trivy, osv-scanner |
| `ruby-rails` | Ruby on Rails | nuclei (ruby tags), gitleaks, osv-scanner |
| `static-nginx` | Static sites on Nginx | testssl, ssh-audit, lynis (minimal toolset) |
| `go-bare` | Go backends | nuclei, nmap, gitleaks, trivy |
| `node-bare` | Node.js standalone | Same as node-nginx minus nginx-specific checks |

Auto-detection: SecForge reads HTTP headers + your code files to guess the stack. If confident, it picks the profile automatically. If unsure, it tells you and runs the full scan.

Use `--stack <profile>` to override: `secforge scan example.com --stack wordpress`

## Live Dashboard

When you add `--dashboard`, SecForge opens a side-by-side tmux pane showing:

- Which tool is running right now
- Progress bar (3/12 tools done)
- Time estimates ("~8 min total, 5 min remaining")
- Results as they come in
- Post-scan summary with fix pack hints

No dashboard? Works fine without it — just logs to the terminal.

## How Scanning Works

```
You: "scan my site"
        |
        v
  Stack detection (auto or --stack)
        |
        v
  Tool selection (profile + installedness + tier gating)
        |
        v
  51 tools run (each gated by profile, skipped if missing)
        |
        v
  Parse → Fingerprint → Dedup → Cluster → Score → Fix Packs
        |
        v
  findings.json with findings[], clusters[], fix_packs[], summary
        |
        v
  State DB tracks everything across scans (new/fixed/reopened)
        |
        v
  AI presents fix packs, generates fixes, verifies them
```

## What's a Fix Pack?

Instead of showing you 200 raw vulnerabilities, SecForge groups related issues:

```
You have 47 findings in 8 fix packs:

#1 Injection Prevention (critical, 3 findings)
#2 HTTP Header Hardening (high, 12 findings, easy fix)
#3 Secrets Exposure (high, 4 findings)
#4 TLS/SSL Hardening (medium, 6 findings)
...
```

Each fix pack has:
- What's wrong (plain English)
- How to fix it (commands + config changes)
- How to verify it worked (automated checks)
- What might break (rollback plan)

## Tier 1 vs Tier 2

| | Tier 1 (default) | Tier 2 (opt-in) |
|---|---|---|
| **What it does** | Observes and reports | Sends attack payloads to test |
| **Safe for production?** | Yes | Be careful — can cause slowdowns |
| **Examples** | nmap, nuclei, testssl, lynis | sqlmap, ZAP active scan, hydra |
| **When to use** | Always | Staging, off-peak, with explicit approval |

Tier 2 never runs unless you explicitly say YES.

## Tool Installation

SecForge installs tools individually, not in big bundles:

```bash
secforge install --list                  # See what's available
secforge install nuclei gitleaks nmap    # Install specific tools
secforge install --all                   # Install everything (~7GB)
```

Each tool knows how to install itself (apt, GitHub binary, git clone, pip venv). Dependencies are handled automatically — `nuclei` installs `nuclei-templates` too.

Or let the AI pick: it reads your stack profile and suggests exactly what you need.

## 51 Security Tools

Organized by what they check:

**Web scanning:** Nuclei, ZAP, ffuf, Nikto, WhatWeb, wafw00f, Wapiti, CORScanner, SQLMap, XSStrike, Dalfox, Commix
**API security:** Kiterunner, jwt_tool, VulnAPI, Interactsh
**Network:** Nmap, Masscan, Netcat
**SSL/TLS:** testssl.sh, sslscan, Observatory
**Secrets:** TruffleHog, Gitleaks, APKLeaks
**Server hardening:** Lynis, ssh-audit, systemd-analyze, debsums, Trivy, ClamAV, rkhunter, fail2ban, AIDE, auditd
**Dependencies:** OSV-Scanner, npm audit, pip-audit
**Email/DNS:** check-email-dns, Subfinder, httpx, dnsrecon
**Password testing:** Hydra, John the Ripper, Hashcat, NetExec (Tier 2 only)
**Mobile:** MobSF, APKDeepLens, APKHunt
**Compliance:** OpenSCAP, stripe-check
**Cloud/IaC:** Trivy config, Checkov, Prowler

Plus built-in checks (no extra tools needed): .git/.env exposure, cookie flags, clickjacking protection, dangerous HTTP methods, SSRF probes.

## Safety

- **Authorization required** — SecForge asks you to confirm you own/are authorized to test the target
- **Lockout prevention** — SSH/firewall changes use auto-revert + phased verification gates
- **Conservative tracking** — findings only marked "fixed" when the detecting tool actually ran and confirmed
- **No system Python pollution** — tools install in venvs and the SecForge bin/ directory

## Directory Layout

```
/opt/secforge/
  bin/          SecForge CLI + tool wrappers
  catalog/      tools.json + profiles.json (tool metadata + stack profiles)
  config/       secforge.conf + authorized targets
  scripts/      Scan scripts, installers, dashboard, merge pipeline
  tools/        Git-cloned security tools
  wordlists/    Curated SecLists subset
  venv/         Python tool virtual environments
  reports/      Scan output (timestamped sessions + latest symlink)
  backups/      Config backups before fixes
  state/        SQLite DB for cross-scan tracking
  logs/         Update and install logs
```

## Updating

```bash
secforge update                # Update all installed tools
# or
sudo /opt/secforge/scripts/update-all.sh
```

Safe by default: only upgrades what SecForge installed.

## FAQ

**Is this legal?**
Yes — for authorized security testing. Only scan systems you own or have permission to test.

**Do I need a paid AI plan?**
SecForge works with any AI that can read files and run commands. Larger context windows help with big scan outputs.

**Can it lock me out of my server?**
Hardening can be risky. SecForge's lockout prevention protocol uses auto-revert, phased verification gates, and always asks before touching SSH/firewall configs. Keep console access available.

**What if I don't have Claude/Codex?**
Everything works from the CLI. The AI just makes it easier — it picks tools, explains findings, and generates fixes.

## Contributing

PRs welcome:
- New scanners and parsers
- Better stack profiles
- Safer hardening playbooks
- Improved defaults for vibecoders

Keep safety rules intact: authorization gating, explicit confirmations, backups, verification rescans.

## License

MIT (see `LICENSE`).

## Disclaimer

For authorized security testing only. Only scan systems you own or have written permission to test. The authors are not responsible for misuse or damages.
