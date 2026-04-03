# Credits & Attributions

SecForge is an orchestrator. It installs and runs many excellent third-party tools, each maintained by its respective authors. SecForge does not claim ownership of those tools.

Licenses vary per tool; always refer to each upstream project for authoritative licensing terms. When SecForge installs a tool via git clone, the tool’s license is typically included in that tool’s directory under `/opt/secforge/tools/`.

## Wordlists

- SecLists (curated subset downloaded at install time) — upstream: `danielmiessler/SecLists`

## Scanners & Auditors (by category)

### Web Application Scanning

- OWASP ZAP — upstream: `zaproxy/zaproxy`
- Nuclei — upstream: `projectdiscovery/nuclei`
- ffuf — upstream: `ffuf/ffuf`
- Nikto — upstream: `sullo/nikto`
- WhatWeb — upstream: `urbanadventurer/WhatWeb`
- Wapiti — upstream: `wapiti-scanner/wapiti`
- SQLMap — upstream: `sqlmapproject/sqlmap`
- Dalfox — upstream: `hahwul/dalfox`
- XSStrike — upstream: `s0md3v/XSStrike`
- Commix — upstream: `commixproject/commix`
- wafw00f — upstream: `EnableSecurity/wafw00f`
- CORScanner — upstream: `chenjj/CORScanner`

### API Security

- Kiterunner — upstream: `assetnote/kiterunner`
- jwt_tool — upstream: `ticarpi/jwt_tool`
- Interactsh (client) — upstream: `projectdiscovery/interactsh`
- VulnAPI — upstream: see `scripts/install-api.sh` for configured source

### Network Scanning

- Nmap — upstream: `nmap/nmap`
- Masscan — upstream: `robertdavidgraham/masscan`
- Netcat (OpenBSD) — upstream: Ubuntu package `netcat-openbsd`

### SSL/TLS & Headers

- testssl.sh — upstream: `drwetter/testssl.sh`
- sslscan — upstream: `rbsec/sslscan` (packaged on Ubuntu)
- Mozilla Observatory CLI — upstream: `mozilla/observatory` (installed via npm as `observatory-cli`)

### Password & Auth Testing

- Hydra — upstream: `vanhauser-thc/thc-hydra`
- John the Ripper — upstream: `openwall/john`
- Hashcat — upstream: `hashcat/hashcat`
- NetExec — upstream: `Pennyw0rth/NetExec`

### Secret & Key Detection

- TruffleHog — upstream: `trufflesecurity/trufflehog`
- Gitleaks — upstream: `gitleaks/gitleaks`
- APKLeaks — upstream: `dwisiswant0/apkleaks`

### Mobile / APK Security

- MobSF — upstream: `MobSF/Mobile-Security-Framework-MobSF` (Docker-only in SecForge)
- APKDeepLens — upstream: `d78ui98/APKDeepLens`
- APKHunt — upstream: `Cyber-Buddy/APKHunt`
- jadx — upstream: `skylot/jadx` (Java decompiler, required by APKLeaks)

### Payment / Compliance

- Lynis — upstream: `CISOfy/lynis`
- OpenSCAP — upstream: OpenSCAP project (packaged for Ubuntu)
- stripe-check — implemented in this repo (`scripts/stripe-check.py`)

### Server Hardening / Integrity / Malware Checks

- ssh-audit — upstream: `jtesta/ssh-audit` (packaged for Ubuntu)
- systemd-analyze security — upstream: systemd project (ships with Ubuntu)
- debsums — upstream: Debian/Ubuntu package `debsums`
- Trivy — upstream: `aquasecurity/trivy`
- ClamAV — upstream: `Cisco-Talos/clamav` (packaged for Ubuntu)
- rkhunter — upstream: Rootkit Hunter (packaged for Ubuntu)
- fail2ban — upstream: `fail2ban/fail2ban` (packaged for Ubuntu)
- AIDE — upstream: AIDE project (packaged for Ubuntu)
- auditd — upstream: Linux Audit project (packaged for Ubuntu)

### Dependency & Supply Chain

- OSV-Scanner — upstream: `google/osv-scanner`
- npm audit — upstream: npm
- pip-audit — upstream: `pypa/pip-audit`

### Email / DNS Security & Attack Surface

- Subfinder — upstream: `projectdiscovery/subfinder`
- httpx — upstream: `projectdiscovery/httpx`
- dnsrecon — upstream: `darkoperator/dnsrecon`
- DNS utilities (dig) — upstream: Ubuntu package `dnsutils`
- check-email-dns — implemented in this repo (`scripts/check-email-dns.sh`)

### Database Security

- check-mysql — implemented in this repo (`scripts/check-mysql.sh`)
- MySQL client — upstream: Ubuntu package `default-mysql-client`

### Containers / IaC / Cloud (optional)

- Trivy config/IaC/image scanning — upstream: `aquasecurity/trivy`
- Checkov — upstream: `bridgecrewio/checkov`
- Prowler — upstream: `prowler-cloud/prowler`

