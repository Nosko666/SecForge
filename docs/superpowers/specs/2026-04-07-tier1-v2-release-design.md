# SecForge v2.0.0 Hardened Release — Design Spec

> **Status:** Approved 2026-04-07. Ready for implementation plan.

## Context

SecForge has reached feature completeness for the Vibecoder UX phase (30 commits since the UX plan, 4 fix rounds, all spec items + Round 4 polish complete). It has never had a release tag, no CHANGELOG, no CI, and no clean-room install verification. A security review also identified 4 P0/P1 hardening items that should ship with the first release.

This spec covers Tier 1: ship `v2.0.0` as a security-hardened release with CI and a clean-room test process.

**Goal:** Tag `v2.0.0` after landing 8 changes — 4 security hardening items, plus release artifacts (CHANGELOG, install.sh `--reinstall`), CI, and clean-room test infrastructure.

**Out of scope:** Tier 2-5 items (dashboard remaining time, more profiles, fix --auto, MCP server, etc.). Lower-priority security items (signed releases, dedicated runtime user, tamper-evident audit log).

---

## Architecture overview

Three categories of work converging on a single `v2.0.0` release tag:

1. **Security hardening (4 items)** — applied first, makes the release worth tagging
2. **Release artifacts (3 items)** — CHANGELOG, `--reinstall` flag, version tag
3. **Validation infrastructure (2 items)** — public CI workflow, private clean-room test script

The clean-room test runs on Hetzner before tagging. CI runs on every push to catch regressions automatically. Security fixes ship with the release, not after it.

---

## Section 1: Security hardening

### 1.1 Remove `curl | sudo bash` from README

**Problem:** README instructs `curl -sSL https://.../install.sh | sudo bash`. This is the canonical "supply-chain risk" anti-pattern in security tools — users execute remote code as root with zero review opportunity.

**Solution:** Replace the recommended install with a clone-and-review pattern:

```bash
git clone https://github.com/Nosko666/SecForge.git /opt/secforge
cd /opt/secforge
git checkout v2.0.0   # pin to verified release
sudo ./install.sh
```

The README gets a brief "Why no curl-pipe?" callout explaining the security rationale (one paragraph, links to NIST/OWASP guidance).

`install.sh` continues to work the same way — we're not breaking the existing installer, just no longer recommending the curl-pipe path. The standalone curl-pipe one-liner stays as a footnote for users who explicitly opt into convenience over security review.

### 1.2 Pin install.sh to a release tag

**Problem:** `install.sh` clones whatever is on `main`. Users installing today vs. tomorrow can get different code with no version anchor. `update-all.sh` does `git pull --ff-only` with no tag enforcement.

**Solution:** Both `install.sh` and `update-all.sh` get version pinning:

- New env var `SECFORGE_VERSION` (default: latest tag matching `v[0-9]*` from `git tag -l | sort -V | tail -1`)
- New CLI flag `--version v2.0.0` as alias for the env var
- After clone, do `git fetch --tags origin` then `git checkout "${SECFORGE_VERSION}"`
- Fail closed with a clear error if the requested version doesn't exist as a tag
- `update-all.sh` no longer does bare `git pull` — requires explicit version selection

This means installs are reproducible and auditable. Users know exactly what version they ran.

### 1.3 SHA-256 verification for GitHub release binaries

**Problem:** `sf_install_github_release_binary` in `_lib.sh` downloads tool binaries (nuclei, ffuf, gum, etc.) from GitHub releases without verifying checksums. The current code explicitly filters out `.sha256` and `.sig` files when picking the asset URL — verification metadata is being discarded instead of used. This is the highest-leverage security fix in this release.

**Solution:** Modify `sf_install_github_release_binary` to:

1. After selecting the binary asset URL, look for a checksum asset in the same release. Try (in order):
   - `checksums.txt`
   - `<binary>_checksums.txt`
   - `<binary>.sha256`
   - `SHA256SUMS`
2. Download both the binary and its checksum file.
3. Compute `sha256sum` of the downloaded binary.
4. Parse the checksum file to find the matching line for the binary's filename.
5. Compare. **Fail closed** (delete download, exit with error) if:
   - No checksum file exists in the release
   - The matching line is missing from the checksum file
   - The hashes don't match
6. Provide an escape hatch: `SECFORGE_SKIP_CHECKSUMS=1` env var bypasses verification with a loud `WARN` message. This is for users who explicitly opt out, NOT for tools that lack upstream checksums.

7. For tools that genuinely lack upstream checksums, add a per-tool `verify: "none"` field in `catalog/tools.json` with a justification comment. The installer reads this field and skips verification for those specific tools (still logs a `WARN`). This is hardcoded per-tool, not a global override.

**Audit step (post-implementation):** Iterate every tool in `catalog/tools.json` with `install_method: github_release`. For each, verify upstream publishes checksums. Document the result in a comment. Tools with checksums get verified by default. Tools without get an explicit `verify: "none"` field with a TODO comment pointing to the upstream tracker.

### 1.4 Tighten `.authorized_targets` permissions

**Problem:** `_lib.sh` creates `config/.authorized_targets` with mode `0664` (group-writable). Any user in the `secforge` group can add unauthorized scan targets without going through the normal authorization prompt.

**Solution:** Change the create mode to `0640`:
- Owner: root, can read/write
- Group: secforge, can read only
- World: no access

Adding new authorized targets goes through `secforge init --domain` (which writes as root) or the `sf_require_authorization` helper (which prompts the user and appends as root). Group members still get visibility but cannot self-authorize.

---

## Section 2: Release artifacts

### 2.1 v2.0.0 git tag

Annotated tag at the tip of `main` after all 8 items land. Tag message references the `## [2.0.0]` entry in `CHANGELOG.md`. Created via `git tag -a v2.0.0 -m "..."`, not lightweight.

### 2.2 CHANGELOG.md (themed summary)

Use the [Keep a Changelog](https://keepachangelog.com/) format with [SemVer](https://semver.org/). Top-level themes for `## [2.0.0] - 2026-04-07`:

- **AI-Guided Workflow**
  - Stack profiles auto-detect tech stack and pick relevant tools (9 profiles: node-nginx, wordpress, python-nginx, etc.)
  - Live tmux dashboard with per-tool progress, ETA, and post-scan summary
  - `secforge init` interactive wizard for first-time setup
  - Per-target time estimates (`12 tools, ~8 min`) before scan starts

- **v2 Pipeline**
  - 29 parsers normalize 57 security tools into canonical findings
  - SHA-256 fingerprints with 3-level dedup (same-tool, cross-tool, cross-scan)
  - 18 root-cause clusters → fix packs with verification + rollback steps
  - 7-factor priority scoring (0-100) with conservative fixed-gating
  - SQLite state DB tracks findings across scans (new/existing/fixed/reopened)
  - 5 AI export modes: quick-fix, fix-pack, full-plan, patch, explain

- **Per-Tool Installer**
  - `secforge install <tool>` installs individual security tools from a 57-tool catalog
  - 11 custom install functions ported from category scripts
  - Alias normalization (e.g., `testssl.sh` → `testssl`)
  - Source guard for safe sourcing during validation

- **CLI**
  - `secforge scan` with `--stack`, `--skip`, `--tier`, `--code-path`, `--dashboard` flags
  - `secforge init`, `install`, `dashboard`, `verify`, `list`, `diff`, `history`, `purge`
  - `secforge ignore`, `accept`, `false-positive` for finding lifecycle management

- **Security Hardening**
  - Removed `curl | sudo bash` from documented install path (clone-and-review now required)
  - Install/update pinned to tagged releases via `SECFORGE_VERSION` env var
  - SHA-256 verification for all GitHub release binary downloads (fails closed)
  - Tightened `.authorized_targets` to mode 0640
  - Tier validation: `--tier 1|2` rejects out-of-range values; preflight clamps bad config

### 2.3 install.sh `--reinstall` flag

New flag that:
1. Backs up `/opt/secforge/config/secforge.conf` and `/opt/secforge/state/` to `/tmp/secforge-backup-${timestamp}/`
2. Deletes `/opt/secforge/`
3. Runs the normal clone + bootstrap path
4. Restores `secforge.conf` and `state/` from backup
5. Reports backup location and what was preserved

Modifier flag `--purge-all` skips the backup step entirely (full nuke). Used together: `install.sh --reinstall --purge-all`.

This is the same flag the cleanroom test uses. Users get the same tool we use for testing — no special install path for tests.

---

## Section 3: Validation infrastructure

### 3.1 GitHub Actions CI (`.github/workflows/ci.yml`)

**Trigger:** push to `main`, pull_request to `main`. Public workflow, no secrets, no protected branches.

**Jobs (run in parallel):**

**Job: `syntax`** — runs on `ubuntu-latest`, ~10 sec
- `find scripts/ bin/ install.sh -name '*.sh' -exec bash -n {} \;`
- `python3 -m py_compile scripts/secforge/*.py scripts/secforge/parsers/*.py`
- `python3 -c "compile(open('scripts/merge-reports.py').read(), 'merge-reports.py', 'exec')"`
- Fail on any syntax error

**Job: `catalogs`** — runs on `ubuntu-latest`, ~5 sec
- Validate `catalog/tools.json` is well-formed JSON
- Validate `catalog/profiles.json` is well-formed JSON
- Cross-reference: every tool ID in `profiles[*].tools_include` and `profiles[*].tools_exclude` exists in `tools.json`
- Verify no `npm-audit` references (deferred per spec)
- Verify all `_meta` keys present

**Job: `smoke`** — runs on `ubuntu-latest`, ~30 sec
- Install minimal deps via apt: `jq`, `python3`, `bash`, `curl`
- Set `SECFORGE_ROOT=$GITHUB_WORKSPACE`
- Run `scripts/install-tools.sh --list` — verify exit 0 and output contains "INSTALLED"/"AVAILABLE"/"BUILTIN" markers
- Run `scripts/preflight.sh --target localhost --scan-mode quick --stack node-nginx --session-id ci-test --require-tools curl,jq` — verify exit 0
- Verify `reports/ci-test/preflight.json` exists and contains required fields: `stack_detection.detected_stack`, `tools_planned`, `tools_effective`, `est_seconds`, `est_tools_total`
- Cleanup `reports/ci-test/`

**Status badge** in README pointing to the workflow.

**Total CI runtime budget:** ~30 seconds wall-clock (jobs run parallel).

### 3.2 Cleanroom Hetzner test script (`scripts/test/cleanroom-hetzner.sh`)

In-repo bash script. I run it before tagging a release. Not automated.

**Inputs:**
- `--version <tag>` — version to test (default: latest local tag)
- `--host <ip>` — Hetzner host (default: `116.203.191.42`)
- `--user <user>` — SSH user (default: `root`)

**Steps the script performs (via SSH):**

1. **Pre-flight checks**
   - Verify SSH connectivity
   - Check `git`, `bash`, `python3` available on remote
   - Confirm `/opt/secforge` exists (bail if not — wrong host?)

2. **Backup**
   - SSH to host
   - `cp -r /opt/secforge/config/secforge.conf /tmp/cleanroom-backup-${ts}/secforge.conf`
   - `cp -r /opt/secforge/state /tmp/cleanroom-backup-${ts}/state`
   - `cp -r /opt/secforge/config/.authorized_targets /tmp/cleanroom-backup-${ts}/`

3. **Wipe**
   - `rm -rf /opt/secforge`

4. **Fresh install**
   - `git clone https://github.com/Nosko666/SecForge.git /opt/secforge`
   - `cd /opt/secforge && git checkout ${VERSION}`
   - `sudo bash install.sh` (or `bootstrap.sh` if install.sh expects piping)

5. **Validate install**
   - `secforge --version` returns expected version
   - `secforge install --list` exits 0 and shows tools
   - `secforge init --tier 1 --domain test.local` writes `TIER_MAX="1"` to config
   - `bash -n scripts/*.sh bin/secforge install.sh` passes
   - Catalogs valid (re-run the CI catalog check)

6. **Validate scan**
   - `secforge scan localhost --stack node-nginx` exits 0
   - `reports/<latest>/scan_manifest.json` has fields: `profile=node-nginx`, `scan_mode=quick`, `tier_max=1`, `tool_durations` non-empty
   - `reports/<latest>/findings.json` exists and has `scan_profile=node-nginx`
   - `reports/<latest>/preflight.json` has rich `stack_detection` with `detected_stack`, `score`, `signals`
   - `/tmp/secforge-dashboard-*.status` contains `scan_start` and `scan_done` events with per-tool events between

7. **Restore**
   - Restore backed-up config, state, .authorized_targets
   - Remove backup directory

8. **Report**
   - Print PASS/FAIL summary table
   - Exit 0 on success, non-zero on any failure
   - Save full log to `/tmp/cleanroom-${ts}.log` on remote

The script uses `set -euo pipefail` and explicit error checks. Failures abort early and skip restore (so debugging is possible). Success path always restores.

---

## Build order

1. **Section 1.4** (`.authorized_targets` perms) — trivial, do first
2. **Section 1.2** (version pinning) — needed before testing
3. **Section 1.1** (README curl-pipe removal) — docs change
4. **Section 1.3** (SHA-256 verification) — biggest item, do after 1.2 so we can test pinned releases
5. **Section 2.3** (`--reinstall` flag) — needed by cleanroom test
6. **Section 3.1** (GitHub Actions CI) — protects everything else going forward
7. **Section 3.2** (cleanroom test script) — validates the full release path
8. **Run cleanroom test** on Hetzner — must pass
9. **Section 2.2** (CHANGELOG) — final, after everything is in place
10. **Section 2.1** (v2.0.0 tag) — ship it

---

## Success criteria

1. `git tag -l` shows `v2.0.0`
2. `CHANGELOG.md` exists with v2.0.0 themed entry
3. `install.sh --reinstall` works (preserves config/state by default, `--purge-all` skips backup)
4. `install.sh --version v2.0.0` checks out the tag explicitly
5. `update-all.sh` no longer does bare `git pull` (requires explicit version)
6. `sf_install_github_release_binary` verifies checksums and fails closed when missing
7. `_lib.sh` creates `.authorized_targets` with mode 0640
8. README shows clone-and-review as the recommended install (no `curl | sudo bash` in primary path)
9. `.github/workflows/ci.yml` runs syntax + catalogs + smoke jobs in parallel, all pass
10. `scripts/test/cleanroom-hetzner.sh` runs end-to-end on Hetzner and reports PASS
11. Status badge in README links to the CI workflow
12. CI passes on the v2.0.0 tag commit

---

## Files to be modified or created

### Created
- `CHANGELOG.md`
- `.github/workflows/ci.yml`
- `scripts/test/cleanroom-hetzner.sh`

### Modified
- `README.md` — replace curl-pipe install, add status badge, add "why no curl-pipe" callout
- `install.sh` — add `--reinstall`, `--purge-all`, `--version`, `SECFORGE_VERSION` support
- `scripts/update-all.sh` — replace `git pull` with version-pinned fetch+checkout
- `scripts/_lib.sh` — modify `sf_install_github_release_binary` for SHA-256 verification, change `.authorized_targets` mode to 0640

### Tagged
- `v2.0.0` annotated git tag at HEAD after all changes land
