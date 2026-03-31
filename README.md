# SecForge

AI-guided security toolkit for vibecoders: install on Ubuntu, then secure your web apps and servers by talking to your AI assistant in the terminal.

## Why SecForge?

Most developers who build with AI aren’t security experts. SecForge bundles (and safely orchestrates) common security scanners, hardening checks, and report merging so you can say:
- “Scan my site”
- “Harden this server”
- “Run a safe audit only”

…and get a clear, prioritized findings report with verification steps and guardrails (authorization prompts, Tier 1/Tier 2 scanning, and lockout-prevention protocols).

## Install (Ubuntu 20.04+)

```bash
curl -sSL https://raw.githubusercontent.com/Nosko666/SecForge/main/install.sh | sudo bash
```

What this does:
- Clones SecForge into `/opt/secforge/`
- Runs the menu installer at `/opt/secforge/scripts/install.sh`
- Installs selected tools, creates the runtime folders, and sets up `/opt/secforge/bin` in your PATH

![Installer menu screenshot (placeholder)](docs/installer-menu.png)

## Quick Start

```bash
cd /opt/secforge
```

Then start your AI assistant in that folder (e.g. Claude Code or Codex). Both read the same orchestration instructions:
- `/opt/secforge/CLAUDE.md`
- `/opt/secforge/AGENTS.md` (identical to `CLAUDE.md`)

Example prompts:
- “Scan my site https://example.com (Tier 1 only)”
- “Run a Safe System Audit on this server”
- “Payment security audit for https://example.com/checkout”

No AI? Run scripts directly:
- `/opt/secforge/scripts/scan-quick.sh https://example.com`
- `/opt/secforge/scripts/scan-all.sh https://example.com`

## Safety & Ethics (non-negotiable)

- Authorized testing only: scan systems you own or have written permission to test.
- Tiered scanning:
  - Tier 1 = passive/low-risk (default)
  - Tier 2 = active/aggressive (requires explicit opt-in)
- Hardening lockout prevention:
  - Phased changes with verification gates
  - Auto-revert for risky SSH/UFW changes
  - Optional watchdog for multi-file rollback

## Directory Layout

SecForge is installed under a single root:

```
/opt/secforge/
  bin/          # wrappers + tool entrypoints
  tools/        # git-cloned tools
  wordlists/    # curated SecLists subset
  venv/         # Python tools live here (no system Python pollution)
  config/       # secforge.conf + templates
  reports/      # scan output (timestamped sessions + latest symlink)
  backups/      # config backups before any fixes
  scripts/      # installers + scan + merge + update scripts
```

## Install Options (approx.)

The menu installer offers:

| Option | What it’s for | Disk (approx.) |
|---|---|---:|
| Install Everything | full coverage (web + server + secrets + deps + optional cloud) | ~7GB+ |
| Essential Only | fast baseline + high-value checks | ~2GB |
| Custom | select categories | varies |

Notes:
- Some tools are optional (example: MobSF is Docker-only).
- Some tooling is downloaded as prebuilt binaries (no Go toolchain required).

## Scan Profiles

Common workflows:
- Quick Scan (Tier 1): baseline web + TLS + basic host checks
- Full Web Scan: Tier 1 baseline, then Tier 2 opt-in
- Safe System Audit: read-only system checks only
- Full Server Hardening: audit first, then propose fixes with lockout prevention
- Payment Security Audit: Stripe/payment checks + TLS + focused web checks
- Dependency Check: OSV + npm/pip audits

## Tooling (high-level)

SecForge installs and orchestrates tools across categories like:
- Web scanning: Nuclei, ZAP, ffuf, Nikto, WhatWeb, Wapiti, and more
- API: Kiterunner, jwt_tool, Interactsh
- Network: Nmap, Masscan
- TLS/Headers: testssl.sh, sslscan, Observatory
- Secrets: TruffleHog, Gitleaks
- Server audits: Lynis, ssh-audit, systemd-analyze security, Trivy rootfs, debsums
- Email/DNS: SPF/DMARC/DKIM/DNSSEC/MTA-STS/TLS-RPT checks + Subfinder/httpx
- Payment: `stripe-check` (custom, outputs JSON checks)

For the full command contract and safety protocols, see:
- `CLAUDE.md` / `AGENTS.md`

## Tool List (security tools)

This is the core security tooling SecForge installs/orchestrates (support packages like `curl`, `jq`, `tmux`, `at`, etc. are omitted here).

| Tool | Category | Tier | Purpose (plain English) |
|---|---|---:|---|
| wafw00f | Web | 1 | Detects if a WAF is in front of the site (helps avoid false negatives) |
| CORScanner | Web | 1 | Checks for CORS misconfigurations that can leak data cross-site |
| OWASP ZAP | Web | 2 | Active web scanner (sends many payloads to discover vulns) |
| Nuclei | Web | 1 | Template-based vulnerability scanner for known issues/misconfigs |
| SQLMap | Web | 2 | SQL injection testing (active payloads) |
| ffuf | Web | 1 | Directory/endpoint discovery by fuzzing common paths |
| Nikto | Web | 1 | Web server misconfiguration/vulnerability checks |
| XSStrike | Web | 2 | XSS testing (active payloads) |
| Dalfox | Web | 2 | XSS testing (active payloads) |
| Commix | Web | 2 | Command injection testing (active payloads) |
| WhatWeb | Web | 1 | Fingerprints site technologies (frameworks, server, CMS, etc.) |
| Wapiti | Web | 2 | Web vulnerability scanner (active testing) |
| VulnAPI | API | 1 | API security scanning (fast checks for common issues) |
| Kiterunner (kr) | API | 1 | API route discovery and probing |
| jwt_tool | API | 1 | Analyzes JWTs for common weaknesses/misuse |
| Interactsh (client) | API | 1 | Captures out-of-band callbacks for blind vulnerabilities (SSRF/XSS/etc.) |
| Nmap | Network | 1 | Port + service discovery (safe mode without root) |
| Masscan | Network | 1 | High-speed port scan (sudo-only; optional) |
| Netcat (nc) | Network | 1 | Quick TCP connectivity checks |
| testssl.sh | SSL/TLS | 1 | TLS configuration and certificate audit |
| sslscan | SSL/TLS | 1 | TLS scan (cipher/protocol enumeration) |
| Mozilla Observatory CLI | SSL/TLS | 1 | Security header analysis and grading |
| Hydra | Passwords | 2 | Brute-force testing (active; can trigger bans/lockouts) |
| John the Ripper | Passwords | 2 | Password hash cracking (offline) |
| Hashcat | Passwords | 2 | Password hash cracking (offline; GPU-accelerated) |
| NetExec (nxc) | Passwords | 2 | Auth testing/enumeration against services (active) |
| TruffleHog | Secrets | 1 | Finds secrets in code/repos/filesystems |
| Gitleaks | Secrets | 1 | Finds secrets in repos with rulesets |
| APKLeaks | Secrets | 1 | Finds hardcoded secrets in APKs |
| MobSF (Docker) | Mobile | 1 | Mobile app security analysis (Docker-only, optional) |
| APKDeepLens | Mobile | 1 | Static APK analysis/reporting |
| APKHunt | Mobile | 1 | APK analysis for common issues |
| Lynis | Hardening/Compliance | 1 | System audit with hardening guidance (read-only) |
| OpenSCAP (oscap) | Compliance | 1 | Compliance/benchmark evaluation (read-only) |
| stripe-check | Payment | 1 | Stripe/payment security heuristics (CSP, mixed content, raw card fields, etc.) |
| ssh-audit | Hardening | 1 | SSH server configuration audit |
| systemd-analyze security | Hardening | 1 | Audits systemd unit sandboxing/hardening settings |
| debsums | Hardening | 1 | Detects modified files from installed packages |
| Trivy (rootfs/config/image) | Hardening/Containers/IaC | 1 | Finds vulnerabilities in OS/filesystems, images, and configs |
| ClamAV | Hardening | 1 | Malware scanning |
| rkhunter | Hardening | 1 | Rootkit scanning |
| fail2ban | Hardening | 1 | Brute-force protection (service; configured carefully to avoid lockout) |
| AIDE | Hardening | 1 | File integrity monitoring |
| auditd/aureport | Hardening | 1 | Security auditing/log reporting |
| OSV-Scanner | Dependencies | 1 | Dependency vulnerability scanning (multi-ecosystem) |
| npm audit | Dependencies | 1 | Node.js dependency vulnerability checks |
| pip-audit | Dependencies | 1 | Python dependency vulnerability checks |
| check-email-dns | Email/DNS | 1 | SPF/DMARC/DKIM/DNSSEC/MTA-STS/TLS-RPT checks |
| Subfinder | Email/DNS | 1 | Subdomain discovery (finds forgotten hosts) |
| httpx | Email/DNS | 1 | Probes discovered hosts for live HTTP services |
| dnsrecon | Email/DNS | 1 | DNS enumeration/audit (optional) |
| check-mysql | Database | 1 | Local MySQL misconfiguration checks (no secret dumping) |
| Checkov | IaC/Cloud | 1 | Infrastructure-as-Code scanning (optional) |
| Prowler | Cloud | 1 | Cloud account posture checks (optional) |

## Updating

```bash
sudo /opt/secforge/scripts/update-all.sh
```

Default behavior is safe-by-default:
- `apt-get install --only-upgrade` on SecForge-related packages that are already installed
- venv package upgrades for SecForge-installed Python tooling
- `git pull --ff-only` for git-cloned tools
- re-download latest GitHub release binaries where applicable

## FAQ

### Is this legal?
Yes—when used for authorized security testing. Only scan systems you own or have written permission to test.

### Do I need a paid AI plan?
Depends on which assistant you use. SecForge works with any terminal AI that can read project files and run shell commands, but large scan outputs may benefit from larger context windows.

### Can SecForge lock me out of my server?
Hardening can lock you out if done incorrectly. SecForge’s orchestration instructions include a lockout-prevention protocol (auto-revert + phased verification gates). Always keep console/out-of-band access available before making SSH/UFW changes.

## Contributing

PRs welcome:
- new scanners and parsers
- improved report merging + dedupe
- safer hardening playbooks
- better defaults for vibecoders

Please keep safety rules intact: authorization gating, explicit confirmations, backups, and verification rescans.

## License

MIT (see `LICENSE`).

## Disclaimer

For authorized security testing only. Only scan systems you own or have written permission to test. The authors are not responsible for misuse or damages.
