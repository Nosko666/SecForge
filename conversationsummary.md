# SecForge — Conversation Context & Decision Log

## What This Is

This document summarizes a planning conversation between a HRvoje  and Claude (chat) that resulted in the SecForge project. Read this before building anything — it contains all the research, decisions, tool evaluations, and rejected alternatives so you don't repeat the exploration.
This whole document is just for context what research was done before writing the real implementation plan in /var/www/ikeacustomerflow.com/secforge/implementationplan.md. do not make this source of truth, only the first step thatwas taken. So when we research what tools we need more, below is explained what we researched


## The Problem

The user builds web apps with AI assistance (vibecoder) and wants to secure their web application (ikeacustomerflow.com — a Three.js-based DXF viewer) and their Ubuntu VPS server. They wanted a comprehensive security toolkit that could be guided by Claude Code in the terminal. The vision expanded into an open-source project that any vibecoder could use.

## How We Got Here — Key Decisions Made

### 1. Burp Suite Was The Starting Point — We Moved Away From It
The user initially asked about Burp Suite for penetration testing. We determined Burp Suite is not ideal because:
- It's a GUI tool, awkward on a headless VPS (needs X11/VNC)
- Community Edition is severely limited (no active scanning, throttled)
- Pro costs $449/year
- OWASP ZAP does everything Burp does in headless/daemon mode for free
- **Decision: Use ZAP instead of Burp. Burp is not needed.**

### 2. We Researched All Existing Toolkits — None Do What SecForge Does
We did extensive research across GitHub, Reddit, and the security ecosystem. Closest projects found:

- **Nexus-VPS** (github.com/nexus-arm/Nexus-VPS) — 10 pentesting tools with interactive menu installer. No scanning automation, no AI integration, no server hardening, no reports.
- **PTF by TrustedSec** (github.com/trustedsec/ptf) — 224 tools with Metasploit-style shell. Just installs tools, doesn't run them or produce reports.
- **HuntKit** (github.com/mcnamee/huntkit) — Docker container with pentesting tools. No automation.
- **Sn1per** (github.com/1N3/Sn1per) — Closest match. Bundles Nmap, SQLMap, Nikto, etc. with one-command scanning. But Community Edition has limited reporting, Pro costs money, no server hardening, no AI integration.
- **RapidScan** (github.com/skavngr/rapidscan) — Multi-tool scanner with 80 tests. Old, unmaintained, no JSON output, no AI integration.
- **HexStrike AI** (github.com/0x4m4/hexstrike-ai) — 150+ tools as MCP server for Claude/GPT. Purely offensive/bug bounty. No server hardening, no auto-remediation.
- **AgentSecOps/SecOpsAgentKit** — 25+ Claude Code skills for security. Loose collection, no unified installer, no server hardening, no merged reporting.
- **Claude Bug Bounty** (github.com/shuvonsec/claude-bug-bounty) — Claude Code agent for bug bounty hunting. Offensive focused, not defensive.
- **Ubuntu Security Hardening Script** (gensecaihq) — Server hardening only, no web scanning.
- **Claude Code Security** (Anthropic's own) — Enterprise/Team only, code scanning only, no infrastructure.

**Deep research conclusion: No existing project combines all 6 capabilities — (1) easy installer, (2) AI-orchestrated, (3) web app scanning + server hardening, (4) unified reports, (5) scan→analyze→patch→verify loop, (6) vibecoder accessible. SecForge is genuinely novel.**

### 3. We Did Extensive Tool Overlap Analysis
We mapped every tool from every toolkit and identified duplicates:

- **Web fuzzing**: ffuf, Wfuzz, Gobuster, Dirb all do the same thing → **Keep ffuf only** (fastest, best JSON)
- **SQL injection**: SQLMap is the only real option → **Keep SQLMap**
- **XSS**: XSStrike for deep analysis + Dalfox for fast sweeps → **Keep both**
- **Full web scanning**: ZAP vs Burp Community → **Keep ZAP only** (better headless)
- **Port scanning**: Nmap for depth + Masscan for speed → **Keep both**
- **Rootkit detection**: rkhunter vs chkrootkit → **Keep rkhunter only** (chkrootkit dropped)
- **Password cracking**: Hydra, John, Hashcat → **Initially dropped, later added back** at user's request

Tools we explicitly DROPPED from other toolkits:
- Metasploit, SET, Empire, PowerSploit (exploitation frameworks — user wants defense not offense)
- BeEF-XSS (XSS exploitation, overkill)
- Recon-ng, theHarvester, Sherlock (OSINT recon — user knows their own site)
- ProxyChains (anonymity — scanning own server)
- Aircrack-ng (WiFi — irrelevant for VPS)
- WPScan (WordPress only — user's site isn't WordPress)
- Burp Suite Community (ZAP covers it)
- chkrootkit (rkhunter covers it)

### 4. We Decided MCP Servers Are NOT Needed For Phase 1
Key architectural decision: Claude Code can run bash commands directly. The CLAUDE.md file serves as the orchestration layer — it tells Claude Code what tools exist, how to run them, and what workflow to follow. No MCP servers, no middleware, no API layer needed.

MCP servers would only matter later if we want Claude Desktop (non-terminal) users to use SecForge. That's Phase 2+.

### 5. We Expanded Beyond The Original 18 Tools To 45
The user requested additional categories beyond the initial web scanning + server hardening:

- **Password & auth testing** (Hydra, John the Ripper, Hashcat, NetExec) — added because user wants to test if their own logins can be brute-forced
- **API security** (VulnAPI, Kiterunner, jwt_tool, Interactsh) — critical for any SaaS or app with APIs
- **Secret detection** (TruffleHog, Gitleaks, APKLeaks) — catches leaked API keys in code and git history
- **Mobile/APK security** (MobSF, APKDeepLens, APKHunt) — for users who build mobile apps
- **Payment/PCI compliance** (Lynis PCI mode, OpenSCAP, custom Stripe checker) — essential for anyone handling payments
- **Dependency scanning** (OSV-Scanner, npm audit, pip-audit) — catches vulnerable packages
- **Wapiti** added to web scanning (catches SSRF, XXE that ZAP sometimes misses)
- **Mozilla Observatory** added to SSL/headers (HTTP security headers check)
- **Interactsh** added as tool #45 for blind/out-of-band vulnerability detection

### 6. PCI/Stripe Decision
For vibecoders using Stripe: if they use Stripe Checkout or Stripe Elements, most PCI requirements are handled by Stripe itself. The toolkit verifies they're doing this correctly rather than implementing full PCI DSS compliance scanning. A custom stripe-check.py script checks: HTTPS enforcement, CSP headers, no raw card fields in HTML, Stripe.js loaded from official source only, SRI tags, no card data in logs.

### 7. Legal/Licensing Decision
- MIT license on SecForge's own scripts
- Tools are NOT bundled — installer downloads them from original sources (apt, pip, go, git clone)
- Disclaimer required: "For authorized testing only"
- CREDITS.md lists every tool, author, license, and repo URL
- This approach is identical to how Nexus-VPS, PTF, and Kali Linux operate

### 8. Auto-Update Strategy
Each tool updates differently:
- apt tools: `apt update && apt upgrade`
- pip tools: `pip install --upgrade`
- Go tools: `go install ...@latest`
- git clone tools: `cd tool && git pull`
- Nuclei templates: `nuclei -update-templates` (updates frequently, should run on every update cycle)
- ClamAV signatures: `freshclam`
- rkhunter definitions: `rkhunter --update`

The update script should show a before/after version table and optionally run via weekly cron job.

## The 45 Tools — Final List

### Category 1: Web Application Scanning (10 tools)
1. OWASP ZAP — full proxy/spider/active scanner
2. Nuclei — template-based CVE/misconfig scanner (8000+ templates)
3. SQLMap — SQL injection testing
4. ffuf — directory/file/parameter fuzzing
5. Nikto — legacy server misconfig scanner
6. XSStrike — deep XSS analysis with WAF bypass
7. Dalfox — fast parameter-based XSS
8. Commix — command injection testing
9. WhatWeb — technology fingerprinting
10. Wapiti — web vuln scanner (SSRF, XXE, file inclusion)

### Category 2: API Security (4 tools)
11. VulnAPI — DAST for APIs, OWASP API Top 10
12. Kiterunner — hidden API endpoint discovery
13. jwt_tool — JWT token testing and cracking
14. Interactsh — out-of-band/blind vulnerability callback server

### Category 3: Network Scanning (3 tools)
15. Nmap — port/service/OS detection + NSE scripts
16. Masscan — ultra-fast full port scan
17. Netcat — manual connection testing

### Category 4: SSL/TLS & Headers (3 tools)
18. testssl.sh — comprehensive TLS/SSL audit
19. sslscan — quick cipher/protocol check
20. Mozilla Observatory CLI — HTTP security headers

### Category 5: Password & Auth Testing (4 tools)
21. Hydra — network login brute-forcer
22. John the Ripper — password hash cracker
23. Hashcat — GPU-accelerated hash cracking
24. NetExec — multi-protocol credential testing

### Category 6: Secret & Key Detection (3 tools)
25. TruffleHog — scans repos/filesystems for leaked secrets
26. Gitleaks — detects hardcoded secrets in git history
27. APKLeaks — extracts secrets from APK files

### Category 7: Mobile / APK Security (3 tools)
28. MobSF — full mobile app security framework (static + dynamic)
29. APKDeepLens — OWASP Mobile Top 10 scanner
30. APKHunt — OWASP MASVS static analyzer

### Category 8: Payment / PCI Compliance (3 tools)
31. Lynis (PCI mode) — PCI DSS compliance checks
32. OpenSCAP — CIS/DISA-STIG/PCI compliance scanning
33. stripe-check.py — custom Stripe/payment security checker

### Category 9: Server Hardening (7 tools)
34. Lynis — full system security audit
35. ClamAV — malware/virus scanning
36. rkhunter — rootkit detection
37. fail2ban — brute-force protection
38. AIDE — file integrity monitoring
39. auditd — system call auditing
40. OpenSCAP — CIS benchmark hardening (shared with Category 8)

### Category 10: System Configuration (configure only, no install)
41. ufw — firewall rules
42. unattended-upgrades — automatic security patches
43. sshd hardening — key-only auth, disable root, change port

### Category 11: Dependency & Supply Chain (2 tools + built-ins)
44. OSV-Scanner — Google's package vulnerability scanner
45. npm audit / pip-audit — built-in dependency checking

## Estimated Sizes
- Full install (45 tools): ~7GB
- Essential only (12 tools): ~2GB
- Minimal (Nuclei + Nmap + testssl + Lynis): ~300MB

## Architecture — How It All Fits Together

```
User talks to Claude Code in terminal
         ↓
Claude Code reads /opt/secforge/CLAUDE.md
         ↓
Claude Code asks user what to scan/harden
         ↓
Claude Code runs tools via bash commands
         ↓
Reports saved to /opt/secforge/reports/SESSION/
         ↓
merge-reports.py combines into findings.json
         ↓
Claude Code presents prioritized findings
         ↓
Claude Code proposes fixes, asks permission
         ↓
Claude Code applies fixes, re-scans to verify
```

No MCP servers. No middleware. No API layer. Just CLAUDE.md + bash + tools.

## What To Build — The Deliverable

The complete project prompt is in the file `SECFORGE-PROJECT-PROMPT.md`. It contains:
- Full directory structure
- The CLAUDE.md content (Claude Code's instruction manual)
- Every tool with exact install commands and run commands
- 7 scan profiles (quick, full web, server hardening, payment, mobile, full audit, dependency)
- The findings.json merged report schema
- The install.sh menu system design
- All 21 files to create
- 9-phase build order

**Start building from that file. Do not re-research tools or alternatives — all of that has been done. Go straight to implementation.**