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

**Solution:** All three entry points (`install.sh`, `update-all.sh`, and `bin/secforge update`) get version pinning:

- New env var `SECFORGE_VERSION` (default: latest tag matching `v[0-9]*` from `git tag -l | sort -V | tail -1`)
- New CLI flag `--version v2.0.0` as alias for the env var
- After clone/fetch, do `git fetch --tags origin` then `git checkout "${SECFORGE_VERSION}"`
- Fail closed with a clear error if the requested version doesn't exist as a tag
- **No silent fallback to main:** If `git tag -l` returns nothing AND `SECFORGE_VERSION` is unset, fail with clear message ("No tagged releases found. Set SECFORGE_VERSION explicitly or use --version main to opt in to bleeding edge.")
- `update-all.sh` no longer does bare `git pull` — requires explicit version selection
- `bin/secforge update` accepts `--version <tag>` and forwards it to `update-all.sh`

This means installs are reproducible and auditable. Users know exactly what version they ran.

### 1.3 SHA-256 verification for GitHub release downloads

**Problem:** `sf_install_github_release_binary` in `_lib.sh` downloads release archives (nuclei, ffuf, gum, etc.) from GitHub without verifying checksums. The current code explicitly filters out `.sha256` and `.sig` files when picking the asset URL — verification metadata is being discarded instead of used. This is the highest-leverage security fix in this release.

**Solution:** Modify `sf_install_github_release_binary` to verify the **downloaded asset** (the .tar.gz / .zip / single binary that GitHub serves), NOT the binary extracted from inside it. Upstream checksum files always hash the asset filename as published, not what's inside.

1. After selecting the asset URL (binary or archive), look for a checksum asset in the same release. Try (in order):
   - `checksums.txt`
   - `<asset_basename>_checksums.txt`
   - `<asset_basename>.sha256`
   - `SHA256SUMS`
2. Download the asset to a temp file (e.g., `/tmp/sf-download-XXXXXX/${asset_filename}`).
3. Download the matching checksum file.
4. Compute `sha256sum` of the downloaded asset (NOT the extracted binary).
5. Parse the checksum file. Find the line matching the asset filename. Compare hashes.
6. **Fail closed** (delete temp dir, exit with error) if:
   - No checksum file exists in the release
   - The matching line is missing from the checksum file
   - The hashes don't match
7. Only AFTER verification passes, extract the archive and proceed with normal install.

**Two escape hatches:**

a) **Global opt-out (user choice):** `SECFORGE_SKIP_CHECKSUMS=1` env var bypasses verification with a loud `WARN` message on every download. For users who explicitly accept the risk.

b) **Per-tool exception (catalog choice):** Tools that genuinely lack upstream checksums get a structured field in `catalog/tools.json`:
```json
"verify": {
  "mode": "none",
  "reason": "upstream does not publish checksums",
  "tracking_url": "https://github.com/<repo>/issues/N"
}
```
The installer reads this field, logs a `WARN`, and skips verification for that specific tool. Default mode is `"sha256"` (implicit if field missing).

**bootstrap.sh gum download:** Currently downloads gum directly via `sf_curl` outside `_lib.sh`'s github helper. This must ALSO verify checksums (charmbracelet publishes `gum_<version>_checksums.txt` for every release). Either refactor bootstrap.sh to use `sf_install_github_release_binary`, or add an inline checksum verification block. Same fail-closed semantics.

**Audit step (during implementation):** Iterate every tool in `catalog/tools.json` with `install_method: github_release`. For each, verify upstream publishes checksums. Tools with checksums use default `sha256` mode. Tools without get an explicit `verify: { "mode": "none", ... }` block with reason and tracking URL. Document the audit result in a separate file: `docs/security/checksum-audit-2026-04-07.md`.

### 1.4 Tighten `.authorized_targets` permissions (root-controlled authorization)

**Problem:** `_lib.sh` creates `config/.authorized_targets` with mode `0664` (group-writable). Any user in the `secforge` group can add unauthorized scan targets without going through any review. Worse, `sf_require_authorization` currently appends to the file as the scan user (whoever is running the scan), assuming group-write — so non-root scans self-authorize new targets interactively.

**Solution:** Switch to a root-controlled authorization model.

1. **File creation:** `_lib.sh` creates `${SECFORGE_ROOT}/config/.authorized_targets` as `root:secforge` with mode `0640` (root: rw, secforge group: r, world: none).

2. **Non-root scans cannot modify the file.** `sf_require_authorization` is updated:
   - If the target is already in the file → proceed (existing behavior, group can read)
   - If the target is NOT in the file → print a clear error and abort:
     ```
     [secforge] ERROR: Target 'example.com' not authorized.
     [secforge] To authorize, run as root:
     [secforge]   sudo secforge init --domain example.com
     [secforge] Or for one-off:
     [secforge]   echo 'example.com' | sudo tee -a /opt/secforge/config/.authorized_targets
     ```
   - No interactive prompt, no `read` from `/dev/tty`, no auto-sudo.

3. **Root scans bypass the prompt:** When `EUID=0`, the existing append-as-root path still works (root can write the file directly).

4. **`secforge init --domain` is the supported authorization helper.** It already writes as root (since init is meant to be run with sudo). Document this clearly in CLAUDE.md and the wizard prompt.

**Impact on existing flows:**
- Root scans: unchanged
- Non-root scans of already-authorized targets: unchanged
- Non-root scans of NEW targets: now fail with a clear "run sudo secforge init --domain" instruction instead of self-authorizing
- The CI smoke test (Section 3.1) must pre-create `config/.authorized_targets` containing `this_server` before running preflight, otherwise preflight will fail closed.
- The cleanroom test (Section 3.2) must do the same after fresh install.

**Spec text drift cleanup:** Anywhere in `_lib.sh` or docs that says "ensure it's group-writable" must be updated to "owned by root, group-readable only".

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

**Self-delete safety check:** Before deleting `${SECFORGE_DEST}`, check whether the running script lives inside that path. If it does, abort with a clear error:
```
[secforge] ERROR: Cannot --reinstall while running install.sh from inside ${SECFORGE_DEST}.
[secforge] You're running: ${BASH_SOURCE[0]}
[secforge] To reinstall, run from a separate location:
[secforge]   curl -sSL https://raw.githubusercontent.com/Nosko666/SecForge/v2.0.0/install.sh -o /tmp/secforge-install.sh
[secforge]   sudo bash /tmp/secforge-install.sh --reinstall
[secforge] Or clone fresh into /tmp first.
```
This prevents the script from `rm -rf`ing itself mid-execution. Use `realpath` or `readlink -f` to compare paths reliably.

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
- **Auth bootstrap:** `mkdir -p config && echo 'this_server' > config/.authorized_targets && chmod 0640 config/.authorized_targets` (preflight will fail closed without this after Section 1.4 lands)
- Run `scripts/install-tools.sh --list` — verify exit 0 and output contains "INSTALLED"/"AVAILABLE"/"BUILTIN" markers
- Run `SECFORGE_ASSUME_YES=1 scripts/preflight.sh --target this_server --scan-mode quick --stack node-nginx --session-id ci-test --require-tools curl,jq` — verify exit 0
- Verify `reports/ci-test/preflight.json` exists and contains required fields: `stack_detection.detected_stack`, `tools_planned`, `tools_effective`, `est_seconds`, `est_tools_total`
- Cleanup `reports/ci-test/`

**Status badge** in README pointing to the workflow.

**Total CI runtime budget:** ~30 seconds wall-clock (jobs run parallel).

### 3.2 Cleanroom Hetzner test script (`scripts/test/cleanroom-hetzner.sh`)

In-repo bash script. I run it before tagging a release. Not automated.

**Critical design point:** The script must test the **real install.sh flow** — meaning install.sh fetches the code itself, not the script pre-cloning into `/opt/secforge`. Pre-cloning hides bugs in `install.sh --version`, tag resolution, and fresh-install behavior. The test downloads `install.sh` to a temp location and runs it; install.sh handles the clone.

**Inputs:**
- `--version <tag>` — version to test (default: latest local tag from `git tag -l 'v*' | sort -V | tail -1`)
- `--host <ip>` — Hetzner host (default: `116.203.191.42`)
- `--user <user>` — SSH user (default: `root`)

**Steps the script performs (via SSH):**

1. **Pre-flight checks**
   - Verify SSH connectivity
   - Check `git`, `bash`, `python3`, `curl` available on remote
   - Print version under test

2. **Backup existing install**
   - On host: `mkdir -p /tmp/cleanroom-backup-${ts}`
   - `cp /opt/secforge/config/secforge.conf /tmp/cleanroom-backup-${ts}/` (if exists)
   - `cp -r /opt/secforge/state /tmp/cleanroom-backup-${ts}/` (if exists)
   - `cp /opt/secforge/config/.authorized_targets /tmp/cleanroom-backup-${ts}/` (if exists)

3. **Wipe**
   - `rm -rf /opt/secforge`

4. **Fresh install via real install.sh flow**
   - Download `install.sh` to a temp location: `curl -sSL "https://raw.githubusercontent.com/Nosko666/SecForge/${VERSION}/install.sh" -o /tmp/cleanroom-install.sh`
   - Set `SECFORGE_VERSION=${VERSION}` to pin the install
   - Run: `sudo SECFORGE_VERSION=${VERSION} bash /tmp/cleanroom-install.sh`
   - install.sh handles the clone, tag checkout, and bootstrap itself
   - This exercises the real user flow end-to-end

5. **Validate install**
   - `secforge version` returns version containing the tag (NOTE: command is `version` not `--version`)
   - `secforge install --list` exits 0 and shows tools
   - Verify `/opt/secforge/config/.authorized_targets` exists with mode 0640 (`stat -c '%a' ...` returns `640`)
   - `sudo secforge init --tier 1 --domain test.local` writes `TIER_MAX="1"` to config
   - Verify `test.local` was added to `.authorized_targets`
   - `bash -n scripts/*.sh bin/secforge install.sh` passes
   - Catalogs valid (re-run the CI catalog check)

6. **Validate scan**
   - `sudo secforge init --domain this_server` (authorize the local target as root)
   - `secforge scan this_server --stack node-nginx` exits 0
   - `reports/<latest>/scan_manifest.json` has fields: `profile=node-nginx`, `scan_mode=quick`, `tier_max=1`, `tool_durations` non-empty
   - `reports/<latest>/findings.json` exists and has `scan_profile=node-nginx`
   - `reports/<latest>/preflight.json` has rich `stack_detection` with `detected_stack`, `score`, `signals`
   - `/tmp/secforge-dashboard-*.status` contains `scan_start` and `scan_done` events with per-tool events between

7. **Validate non-root authorization rejection (Section 1.4 fix)**
   - As non-root user (e.g., `testuser`), run: `secforge scan unauthorized.example.com --stack node-nginx`
   - Verify it exits non-zero with the "run sudo secforge init --domain" instruction
   - Verify `unauthorized.example.com` is NOT added to `.authorized_targets`

8. **Restore**
   - Restore backed-up config, state, .authorized_targets
   - Remove backup directory and `/tmp/cleanroom-install.sh`

9. **Report**
   - Print PASS/FAIL summary table
   - Exit 0 on success, non-zero on any failure
   - Save full log to `/tmp/cleanroom-${ts}.log` on remote

The script uses `set -euo pipefail` and explicit error checks. Failures abort early and skip restore (so debugging is possible — the broken state stays on disk). Success path always restores.

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
3. `install.sh --reinstall` works (preserves config/state by default, `--purge-all` skips backup, refuses to self-delete when run from inside `${SECFORGE_DEST}`)
4. `install.sh --version v2.0.0` checks out the tag explicitly
5. `update-all.sh` no longer does bare `git pull` (requires explicit version)
6. `bin/secforge update --version v2.0.0` forwards correctly to `update-all.sh`
7. `sf_install_github_release_binary` verifies the downloaded asset (not extracted binary), fails closed when missing checksums or hash mismatch
8. `bootstrap.sh` verifies gum download checksum
9. `catalog/tools.json` has `verify` field for any tool that lacks upstream checksums (or all default to sha256)
10. `_lib.sh` creates `.authorized_targets` with mode 0640
11. Non-root scan of an unauthorized target prints the "sudo secforge init --domain" instruction and exits non-zero (does NOT self-authorize)
12. Root scan or already-authorized target proceeds normally (no regression)
13. README shows clone-and-review as the recommended install (no `curl | sudo bash` in primary path)
14. `.github/workflows/ci.yml` runs syntax + catalogs + smoke jobs in parallel, all pass
15. CI smoke job pre-creates `.authorized_targets` containing `this_server` so preflight works
16. `scripts/test/cleanroom-hetzner.sh` runs end-to-end on Hetzner via the real install.sh flow and reports PASS
17. Cleanroom test uses `secforge version` (not `--version`) to check installed version
18. Status badge in README links to the CI workflow
19. CI passes on the v2.0.0 tag commit
20. If no tagged release exists AND `SECFORGE_VERSION` is unset, install.sh fails with clear message (no silent fallback to main)

---

## Files to be modified or created

### Created
- `CHANGELOG.md`
- `.github/workflows/ci.yml`
- `scripts/test/cleanroom-hetzner.sh`
- `docs/security/checksum-audit-2026-04-07.md` — per-tool checksum audit results

### Modified
- `README.md` — replace curl-pipe install, add status badge, add "why no curl-pipe" callout
- `install.sh` — add `--reinstall`, `--purge-all`, `--version`, `SECFORGE_VERSION` support, self-delete safety check
- `scripts/update-all.sh` — replace `git pull` with version-pinned fetch+checkout
- `scripts/bootstrap.sh` — add SHA-256 verification for gum download (or refactor to use `sf_install_github_release_binary`)
- `scripts/_lib.sh` — modify `sf_install_github_release_binary` for SHA-256 verification of downloaded asset (not extracted binary), change `.authorized_targets` mode to 0640, rewrite `sf_require_authorization` to fail-closed for non-root scans
- `bin/secforge` — `update` subcommand accepts `--version` and forwards to `update-all.sh`
- `catalog/tools.json` — add `verify` field to tools that lack upstream checksums (per audit)

### Tagged
- `v2.0.0` annotated git tag at HEAD after all changes land
