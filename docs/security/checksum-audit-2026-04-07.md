# SecForge Checksum Audit — 2026-04-07

For SecForge v2.0.0 release. Tracks which tools published via GitHub release have upstream SHA-256 checksum files.

## Methodology

For each tool with `install_method: "github_release"` in `catalog/tools.json`:
1. Default behavior: `sf_install_github_release_binary` looks for one of these five exact asset names in the GitHub release: `checksums.txt`, `<basename>_checksums.txt`, `<basename>.sha256`, `SHA256SUMS`, `checksums_sha256.txt`.
2. If found, verify the downloaded asset against the listed hash. Fail closed on mismatch.
3. If not found, install fails closed. Override per-tool by adding `verify: { mode: "none", reason, tracking_url }` to the catalog entry.

## Status

All github_release tools default to `sha256` mode. Per-tool exceptions are recorded below as they're discovered (e.g., during cleanroom install runs).

## Audit results

| Tool | Repo | Status | Notes |
|------|------|--------|-------|
| dalfox | hahwul/dalfox | PENDING | default sha256 |
| ffuf | ffuf/ffuf | PENDING | default sha256 |
| gitleaks | gitleaks/gitleaks | PENDING | default sha256 |
| httpx | projectdiscovery/httpx | PENDING | default sha256 |
| interactsh | projectdiscovery/interactsh | PENDING | default sha256 |
| kiterunner | assetnote/kiterunner | PENDING | default sha256 |
| nuclei | projectdiscovery/nuclei | PENDING | default sha256 |
| osv-scanner | google/osv-scanner | PENDING | default sha256 |
| subfinder | projectdiscovery/subfinder | PENDING | default sha256 |
| trivy | aquasecurity/trivy | PENDING | default sha256 |
| trufflehog | trufflesecurity/trufflehog | PENDING | default sha256 |
| vulnapi | cerberauth/vulnapi | PENDING | default sha256 |

## Per-tool exceptions

(empty — none discovered yet)

## How to add an exception

If a tool's upstream genuinely lacks checksums, edit `catalog/tools.json`:

```json
"some-tool": {
  "...": "...",
  "install_method": "github_release",
  "verify": {
    "mode": "none",
    "reason": "upstream does not publish checksums",
    "tracking_url": "https://github.com/<repo>/issues/N"
  }
}
```

Then add a row to the "Per-tool exceptions" table above with the same reason.
