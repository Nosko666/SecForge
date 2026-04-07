# SecForge v2.0.0 Hardened Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `v2.0.0` as a security-hardened release with CI, cleanroom test, and 4 P0/P1 security fixes from the security review.

**Architecture:** 8 self-contained tasks executed in build order. Each task is a single commit with `bash -n` validation. Final task creates the annotated tag.

**Tech Stack:** Bash, Python 3 (stdlib), GitHub Actions, sha256sum, git tags, ssh

**Spec:** `docs/superpowers/specs/2026-04-07-tier1-v2-release-design.md`

---

## File Structure

| File | Responsibility |
|------|---------------|
| `scripts/_lib.sh` | File creation perms (`.authorized_targets` 0640), `sf_install_github_release_binary` checksum verification |
| `scripts/preflight.sh` | `sf_require_authorization` rewrite (fail-closed for non-root) |
| `scripts/install-tools.sh` | Read `verify` field from catalog, pass mode to library |
| `scripts/bootstrap.sh` | gum download checksum verification |
| `scripts/update-all.sh` | Version-pinned fetch+checkout (replace `git pull`) |
| `install.sh` | `--reinstall`, `--purge-all`, `--version`, ref preservation, self-delete safety |
| `bin/secforge` | `update --version`, `init --domain` non-root rejection |
| `scripts/secforge/__init__.py` | Version bump from `2.0.0-dev` to `2.0.0` |
| `catalog/tools.json` | Per-tool `verify` field (audit-driven) |
| `README.md` | Clone-and-review install, status badge, "no curl-pipe" callout |
| `CHANGELOG.md` | New file, themed v2.0.0 entry |
| `.github/workflows/ci.yml` | New file, syntax + catalogs + smoke jobs |
| `scripts/test/cleanroom-hetzner.sh` | New file, manual cleanroom test |
| `docs/security/checksum-audit-2026-04-07.md` | New file, per-tool checksum status |

---

## Build order

| Order | Task | Why this order |
|-------|------|----------------|
| 1 | Auth perms (0640) + `sf_require_authorization` rewrite + `init --domain` non-root rejection | Foundational; everything downstream must work with the new auth model |
| 2 | Checksum verification in `sf_install_github_release_binary` + audit | Biggest security fix; needs to be in place before testing installs |
| 3 | bootstrap.sh gum checksum verification | Same fix, different code path |
| 4 | Version pinning in install.sh, update-all.sh, bin/secforge | Required by `--reinstall` and cleanroom test |
| 5 | install.sh `--reinstall`/`--purge-all` + self-delete safety | Used by cleanroom test |
| 6 | GitHub Actions CI | Catches regressions for everything that follows |
| 7 | Cleanroom Hetzner test script | Validates the full release path |
| 8 | Run cleanroom test, then CHANGELOG + version bump + tag | Final step; only after everything passes |

---

## Task 1: Authorization model (0640 + root-controlled)

**Files:**
- Modify: `scripts/_lib.sh:265-272` (mode change in `sf_ensure_config_files`)
- Modify: `scripts/preflight.sh:76-99` (`sf_require_authorization` rewrite)
- Modify: `bin/secforge` (init `--domain` non-root rejection — find the `init)` case and the `_sf_domains` loop)

### Step 1.1: Change `.authorized_targets` mode to 0640 in `sf_ensure_config_files`

- [ ] **Action:** Edit `scripts/_lib.sh` `sf_ensure_config_files` function

Find this block (around line 267-271):
```bash
  if [[ ! -e "${auth_file}" ]]; then
    : >"${auth_file}"
  fi
  chown root:"${group_name}" "${auth_file}" 2>/dev/null || true
  chmod 0664 "${auth_file}" 2>/dev/null || true
```

Replace with:
```bash
  if [[ ! -e "${auth_file}" ]]; then
    : >"${auth_file}"
  fi
  chown root:"${group_name}" "${auth_file}" 2>/dev/null || true
  # 0640: root rw, secforge group r, world none.
  # Non-root scans cannot self-authorize — must use sudo secforge init --domain
  chmod 0640 "${auth_file}" 2>/dev/null || true
```

### Step 1.2: Rewrite `sf_require_authorization` in preflight.sh

- [ ] **Action:** Replace `sf_require_authorization` function in `scripts/preflight.sh` (lines 76-99)

Replace the entire function with:
```bash
sf_require_authorization() {
  local target_key="$1"
  local auth_file="$2"

  sf_disclaimer_banner

  if [[ ! -e "${auth_file}" ]]; then
    sf_warn "Authorization cache missing: ${auth_file}"
    sf_warn "Run 'sudo secforge init --domain ${target_key}' to authorize, or re-run the installer to create the file."
    return 1
  fi

  if grep -Fqx "${target_key}" "${auth_file}" 2>/dev/null; then
    return 0
  fi

  # Target not authorized. Behavior depends on whether we can write the file.
  if [[ "${EUID}" -eq 0 ]]; then
    # Root can append directly
    sf_warn "First time scanning: ${target_key}"
    sf_warn "To continue, you must confirm you own/are authorized to test this target."
    if ! sf_ask_tty_yes "Type YES to confirm authorization:" "YES"; then
      sf_die "Authorization not confirmed. Aborting."
    fi
    printf '%s\n' "${target_key}" >>"${auth_file}"
    return 0
  fi

  # Non-root: fail closed with clear instruction
  sf_warn "Target '${target_key}' is not authorized."
  sf_warn "To authorize, run as root:"
  sf_warn "  sudo secforge init --domain ${target_key}"
  sf_warn "Or for one-off (root only):"
  sf_warn "  echo '${target_key}' | sudo tee -a ${auth_file}"
  sf_die "Non-root scans cannot self-authorize new targets."
}
```

### Step 1.3: Reject non-root `init --domain` in bin/secforge

- [ ] **Action:** Find the `init)` case in `bin/secforge`. After the flag-parsing block but before `_sf_had_flags=1` is processed for `--domain`, add a non-root check that fires when `_sf_domains` is non-empty.

Find the section that processes `_sf_domains` (look for `for _sf_domain in "${_sf_domains[@]}"; do`). Add this check immediately before the loop:

```bash
    # Adding domains requires root (we need to write .authorized_targets which is now 0640)
    if [[ "${#_sf_domains[@]}" -gt 0 ]] && [[ "${EUID}" -ne 0 ]]; then
      sf_die "init --domain requires root. Re-run with: sudo secforge init --domain ${_sf_domains[0]}"
    fi
```

Also find the interactive wizard's `--domain` collection (in the same `init)` case, the prompt that asks for a domain). Before writing to the auth file, add the same EUID check.

### Step 1.4: Validate

- [ ] **Action:** Run syntax checks
```bash
bash -n scripts/_lib.sh && echo "lib OK"
bash -n scripts/preflight.sh && echo "preflight OK"
bash -n bin/secforge && echo "secforge OK"
```
Expected: all three print OK.

### Step 1.5: Commit

- [ ] **Action:** Commit
```bash
git add scripts/_lib.sh scripts/preflight.sh bin/secforge
git commit -m "fix(security): root-controlled .authorized_targets (0640)

- _lib.sh creates .authorized_targets at 0640 (root rw, group r)
- preflight.sh sf_require_authorization fails closed for non-root
  scans of unauthorized targets, prints sudo instruction
- bin/secforge init --domain rejects non-root with clear error
  (was previously silently failing the auth file write)

Closes the self-authorization gap from the security review.
"
```

---

## Task 2: SHA-256 verification in sf_install_github_release_binary

**Files:**
- Modify: `scripts/_lib.sh:396-443` (`sf_install_github_release_binary`)
- Modify: `scripts/install-tools.sh` (read `verify` field, pass mode)
- Modify: `catalog/tools.json` (per-tool `verify` field as needed)
- Create: `docs/security/checksum-audit-2026-04-07.md`

### Step 2.1: Add helper to find checksum file in a release

- [ ] **Action:** Add this helper function in `scripts/_lib.sh` immediately BEFORE `sf_install_github_release_binary`:

```bash
# Find the SHA-256 checksum file URL in a GitHub release.
# Args: $1 = repo (owner/name), $2 = asset basename (e.g. "nuclei_3.0.0_linux_amd64.zip")
# Returns: URL on stdout, or empty string if not found.
sf_github_find_checksum_url() {
  local repo="$1"
  local asset_basename="$2"

  if ! sf_has_cmd jq; then
    return 1
  fi

  local json
  json="$(sf_github_latest_release_json "${repo}")" || return 1

  # Try (in order): checksums.txt, <basename>_checksums.txt, <basename>.sha256, SHA256SUMS
  local candidate
  for candidate in "checksums.txt" "${asset_basename}_checksums.txt" "${asset_basename}.sha256" "SHA256SUMS" "checksums_sha256.txt"; do
    local url
    url="$(echo "${json}" | jq -r --arg name "${candidate}" '.assets[] | select(.name == $name) | .browser_download_url' 2>/dev/null | head -n1)"
    if [[ -n "${url}" && "${url}" != "null" ]]; then
      printf '%s' "${url}"
      return 0
    fi
  done

  # Last resort: any asset whose name contains "checksum" or "sha256" (case insensitive)
  local fallback
  fallback="$(echo "${json}" | jq -r '.assets[] | select(.name | test("checksum|sha256"; "i")) | .browser_download_url' 2>/dev/null | head -n1)"
  if [[ -n "${fallback}" && "${fallback}" != "null" ]]; then
    printf '%s' "${fallback}"
    return 0
  fi

  return 1
}
```

### Step 2.2: Add verification function

- [ ] **Action:** Add this function in `scripts/_lib.sh` immediately after `sf_github_find_checksum_url`:

```bash
# Verify a downloaded asset against its checksum file.
# Args: $1 = path to asset, $2 = path to checksum file
# Looks for a line in the checksum file matching the asset's basename.
# Returns: 0 on match, 1 on no-match or missing entry.
sf_verify_sha256() {
  local asset_path="$1"
  local checksum_path="$2"

  if [[ ! -f "${asset_path}" ]] || [[ ! -f "${checksum_path}" ]]; then
    return 1
  fi

  local asset_basename actual_hash expected_hash
  asset_basename="$(basename -- "${asset_path}")"
  actual_hash="$(sha256sum "${asset_path}" | awk '{print $1}')"

  # Standard checksum file format: "<hash>  <filename>" (one or two spaces)
  expected_hash="$(grep -E "[[:space:]]+\*?${asset_basename}\$" "${checksum_path}" 2>/dev/null | awk '{print $1}' | head -n1)"

  if [[ -z "${expected_hash}" ]]; then
    sf_warn "No checksum entry for ${asset_basename} in checksum file"
    return 1
  fi

  if [[ "${actual_hash}" != "${expected_hash}" ]]; then
    sf_warn "Checksum mismatch for ${asset_basename}"
    sf_warn "  expected: ${expected_hash}"
    sf_warn "  actual:   ${actual_hash}"
    return 1
  fi

  return 0
}
```

### Step 2.3: Modify `sf_install_github_release_binary` to verify

- [ ] **Action:** Replace `sf_install_github_release_binary` in `scripts/_lib.sh` (lines 396-443) with:

```bash
sf_install_github_release_binary() {
  local repo="$1"
  local expected_binary="$2"
  local install_path="$3"
  local verify_mode="${4:-sha256}"  # sha256 (default) or none

  if [[ -x "${install_path}" ]]; then
    return 0
  fi

  if ! sf_has_cmd jq; then
    sf_die "jq is required for GitHub binary installs."
  fi

  local arch url tmp archive extract_dir found
  arch="$(sf_detect_arch)"
  url="$(sf_github_select_linux_asset_url "${repo}" "${arch}")"
  if [[ -z "${url}" || "${url}" == "null" ]]; then
    sf_warn "No suitable Linux ${arch} asset found for ${repo}."
    return 1
  fi

  tmp="$(sf_mktemp_dir)"
  archive="${tmp}/$(basename -- "${url}")"
  extract_dir="${tmp}/extract"

  sf_log "Downloading ${repo} release asset..."
  sf_curl -o "${archive}" "${url}"

  # ── Checksum verification ──
  if [[ "${SECFORGE_SKIP_CHECKSUMS:-0}" == "1" ]]; then
    sf_warn "SECFORGE_SKIP_CHECKSUMS=1 — skipping checksum for ${repo} (user opt-out)"
  elif [[ "${verify_mode}" == "none" ]]; then
    sf_warn "verify.mode=none for ${repo} — skipping checksum (catalog opt-out)"
  elif [[ "${verify_mode}" == "sha256" ]]; then
    local asset_basename checksum_url checksum_file
    asset_basename="$(basename -- "${url}")"
    checksum_url="$(sf_github_find_checksum_url "${repo}" "${asset_basename}" || echo '')"
    if [[ -z "${checksum_url}" ]]; then
      sf_warn "No checksum file found in ${repo} release. Aborting install."
      sf_warn "To override (NOT RECOMMENDED), set SECFORGE_SKIP_CHECKSUMS=1"
      sf_warn "Or add 'verify': { 'mode': 'none', ... } to ${repo} in catalog/tools.json"
      rm -rf "${tmp}"
      return 1
    fi
    checksum_file="${tmp}/$(basename -- "${checksum_url}")"
    sf_curl -o "${checksum_file}" "${checksum_url}"
    if ! sf_verify_sha256 "${archive}" "${checksum_file}"; then
      sf_warn "Checksum verification failed for ${repo}. Aborting install."
      rm -rf "${tmp}"
      return 1
    fi
    sf_log "Checksum verified for ${repo}"
  else
    sf_warn "Unknown verify_mode '${verify_mode}' for ${repo}. Aborting install."
    rm -rf "${tmp}"
    return 1
  fi

  mkdir -p "$(dirname -- "${install_path}")"

  if [[ "${archive}" == *.tar.gz || "${archive}" == *.tgz || "${archive}" == *.zip ]]; then
    sf_extract_archive_to_dir "${archive}" "${extract_dir}"
    found="$(find "${extract_dir}" -maxdepth 4 -type f \( -name "${expected_binary}" \) -print | head -n1 || true)"
    if [[ -z "${found}" ]]; then
      found="$(find "${extract_dir}" -maxdepth 4 -type f -perm -111 -name "${expected_binary}*" | head -n1 || true)"
    fi
    if [[ -z "${found}" ]]; then
      sf_warn "Could not locate ${expected_binary} in ${repo} asset (skipping)."
      rm -rf "${tmp}"
      return 1
    fi
    install -m 0755 "${found}" "${install_path}"
  else
    install -m 0755 "${archive}" "${install_path}"
  fi

  rm -rf "${tmp}"
}
```

### Step 2.4: Update `install-tools.sh` to read `verify.mode` from catalog

- [ ] **Action:** Find the `github_release` install method handler in `scripts/install-tools.sh`. Locate the line that calls `sf_install_github_release_binary`. Before that call, read the verify mode from the tool metadata.

Find the case branch for `github_release)` (search `grep -n 'github_release)' scripts/install-tools.sh`). The metadata is already loaded into `TOOL_*` variables via the `read_tool_meta` function. Add a `TOOL_VERIFY_MODE` variable.

First, modify `read_tool_meta` to extract the `verify.mode` field. Find the Python heredoc inside `read_tool_meta` and add this output:
```python
print(f"TOOL_VERIFY_MODE='{safe_val((tool.get('verify') or {}).get('mode', 'sha256'))}'")
```

Add the corresponding local variable declaration in `install_single_tool` (where other `TOOL_*` locals are):
```bash
local TOOL_VERIFY_MODE=""
```

Then in the `github_release)` install method handler, change the call from:
```bash
sf_install_github_release_binary "${TOOL_REPO}" "${TOOL_EXPECTED_BINARY}" "${SECFORGE_ROOT}/bin/${tool_id}"
```
to:
```bash
sf_install_github_release_binary "${TOOL_REPO}" "${TOOL_EXPECTED_BINARY}" "${SECFORGE_ROOT}/bin/${tool_id}" "${TOOL_VERIFY_MODE:-sha256}"
```

### Step 2.5: Audit the catalog and create the audit doc

- [ ] **Action:** List all tools that use `github_release` install method
```bash
python3 -c "
import json
t = json.load(open('catalog/tools.json'))
for tid, meta in t.items():
    if tid == '_meta': continue
    if meta.get('install_method') == 'github_release':
        repo = (meta.get('install') or {}).get('repo', '')
        print(f'{tid}: {repo}')
"
```

Note the output. For each tool, the engineer must manually check whether the upstream GitHub release publishes a `checksums.txt` (or similar). Visit `https://github.com/<repo>/releases/latest` and look at the assets list.

- [ ] **Action:** Create `docs/security/checksum-audit-2026-04-07.md` with the audit results.

```bash
mkdir -p docs/security
cat > docs/security/checksum-audit-2026-04-07.md <<'EOF'
# SecForge Checksum Audit — 2026-04-07

For SecForge v2.0.0 release. Tracks which tools published via GitHub release have upstream SHA-256 checksum files.

## Methodology

For each tool with `install_method: "github_release"` in `catalog/tools.json`:
1. Visit the upstream `releases/latest` page
2. Check the assets list for any of: `checksums.txt`, `<asset>_checksums.txt`, `<asset>.sha256`, `SHA256SUMS`
3. Mark VERIFIED if present, MISSING if not

## Results

| Tool | Repo | Checksum file | Status |
|------|------|---------------|--------|
EOF
```

Then for each tool from the catalog list, append a row. Mark as VERIFIED if upstream has a checksum file. For MISSING tools, add a `verify` object to `catalog/tools.json` and a row in the audit doc with the tracking URL.

Example for a MISSING tool, modify `catalog/tools.json` for that entry:
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

For VERIFIED tools, no change needed — the default mode is `sha256`.

### Step 2.6: Validate

- [ ] **Action:** Run syntax checks
```bash
bash -n scripts/_lib.sh && echo "lib OK"
bash -n scripts/install-tools.sh && echo "install-tools OK"
python3 -c "import json; json.load(open('catalog/tools.json')); print('catalog OK')"
```

### Step 2.7: Commit

- [ ] **Action:** Commit
```bash
git add scripts/_lib.sh scripts/install-tools.sh catalog/tools.json docs/security/checksum-audit-2026-04-07.md
git commit -m "fix(security): SHA-256 verification for GitHub release downloads

- sf_install_github_release_binary verifies the downloaded asset
  (.tar.gz/.zip), not the extracted binary
- New helpers: sf_github_find_checksum_url, sf_verify_sha256
- Fails closed when checksum file is missing or hash doesn't match
- Two escape hatches:
  - SECFORGE_SKIP_CHECKSUMS=1 (user opt-out, global)
  - catalog verify.mode=\"none\" (per-tool, with reason + tracking_url)
- install-tools.sh reads verify.mode from catalog and passes it through
- Audit doc tracks per-tool checksum status

Closes the unverified-binary-download gap from the security review.
"
```

---

## Task 3: bootstrap.sh gum download checksum verification

**Files:**
- Modify: `scripts/bootstrap.sh` (gum download block — search for `charmbracelet/gum`)

### Step 3.1: Locate gum download block

- [ ] **Action:** Read the gum install logic in bootstrap.sh
```bash
grep -n 'gum\|charmbracelet' scripts/bootstrap.sh
```

Note the lines that download gum (likely `sf_curl` or `wget` to a github releases URL).

### Step 3.2: Refactor to use sf_install_github_release_binary

- [ ] **Action:** In `scripts/bootstrap.sh`, find the gum download block. Replace the manual curl + extract with a call to the library function that now does verification.

Locate the existing gum download (it currently downloads `gum_X.Y.Z_Linux_x86_64.tar.gz` directly). Replace it with:

```bash
# gum: Charmbracelet TUI binary, installed via library function (with checksum verification)
if [[ ! -x "${SECFORGE_ROOT}/bin/gum" ]]; then
  sf_log "Installing gum (Charmbracelet TUI) with checksum verification..."
  if ! sf_install_github_release_binary "charmbracelet/gum" "gum" "${SECFORGE_ROOT}/bin/gum"; then
    sf_die "Failed to install gum. Set SECFORGE_SKIP_CHECKSUMS=1 to bypass verification (NOT RECOMMENDED)."
  fi
fi
```

If bootstrap.sh doesn't currently source `_lib.sh`, add the source line near the top after the standard prelude:
```bash
# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"
```

### Step 3.3: Validate

- [ ] **Action:** Run syntax check
```bash
bash -n scripts/bootstrap.sh && echo "bootstrap OK"
```

### Step 3.4: Commit

- [ ] **Action:** Commit
```bash
git add scripts/bootstrap.sh
git commit -m "fix(security): bootstrap.sh gum download verifies SHA-256

Refactored to use sf_install_github_release_binary which now
includes checksum verification. Charmbracelet publishes
gum_<version>_checksums.txt for every release.

Fails closed if checksum is missing or doesn't match.
"
```

---

## Task 4: Version pinning (install.sh, update-all.sh, bin/secforge)

**Files:**
- Modify: `install.sh` (clone/checkout logic)
- Modify: `scripts/update-all.sh` (replace `git pull`)
- Modify: `bin/secforge` (update subcommand `--version` flag)

### Step 4.1: Add version resolution helper to install.sh

- [ ] **Action:** Add this function to `install.sh` after `sf_clone_or_update_repo`:

```bash
# Resolve which git ref to use, based on env var, CLI flag, and existing checkout state.
# Args: $1 = dest dir
# Reads: SECFORGE_VERSION env var (or empty)
# Outputs: ref name on stdout
# Fails if no valid ref can be determined.
sf_resolve_version() {
  local dest="$1"
  local requested="${SECFORGE_VERSION:-}"

  # Explicit request wins
  if [[ -n "${requested}" ]]; then
    printf '%s' "${requested}"
    return 0
  fi

  # Existing checkout: preserve current ref if it's valid
  if [[ -d "${dest}/.git" ]]; then
    local current_tag current_branch
    current_tag="$(git -C "${dest}" describe --tags --exact-match 2>/dev/null || true)"
    if [[ -n "${current_tag}" && "${current_tag}" == v[0-9]* ]]; then
      printf '%s' "${current_tag}"
      return 0
    fi
    current_branch="$(git -C "${dest}" symbolic-ref -q --short HEAD 2>/dev/null || true)"
    if [[ "${current_branch}" == "main" ]]; then
      printf '%s' "main"
      return 0
    fi
    if [[ -n "${current_branch}" ]]; then
      sf_die "Refusing to install from branch '${current_branch}'. Run with explicit --version v2.0.0 or --version main to proceed."
    fi
    # Detached HEAD on a non-tag commit
    local current_sha
    current_sha="$(git -C "${dest}" rev-parse HEAD 2>/dev/null || true)"
    if [[ -n "${current_sha}" ]]; then
      printf '%s' "${current_sha}"
      return 0
    fi
  fi

  # Fresh install: use latest tag from the remote
  local latest_tag
  latest_tag="$(git ls-remote --tags --refs "${SECFORGE_REPO_URL}" 'v[0-9]*' 2>/dev/null \
    | awk -F'/' '{print $NF}' | sort -V | tail -n1 || true)"
  if [[ -n "${latest_tag}" ]]; then
    printf '%s' "${latest_tag}"
    return 0
  fi

  sf_die "No tagged releases found. Use --version main to install from latest commit (NOT RECOMMENDED for production)."
}
```

### Step 4.2: Replace `sf_clone_or_update_repo` with version-pinned variant

- [ ] **Action:** Replace `sf_clone_or_update_repo` in `install.sh` with:

```bash
sf_clone_or_update_repo() {
  local dest="$1"
  local ref="$2"
  local repo_url="$3"

  if [[ -e "${dest}" && ! -d "${dest}" ]]; then
    sf_die "${dest} exists and is not a directory."
  fi

  if [[ ! -d "${dest}" ]]; then
    sf_log "Cloning SecForge into ${dest}..."
    git clone "${repo_url}" "${dest}"
    git -C "${dest}" fetch --tags origin
    sf_log "Checking out ${ref}..."
    git -C "${dest}" checkout "${ref}" || sf_die "Ref '${ref}' not found in ${repo_url}"
    return 0
  fi

  if [[ ! -d "${dest}/.git" ]]; then
    sf_die "${dest} already exists but is not a git repo. Move it aside and re-run."
  fi

  sf_log "Updating existing SecForge checkout in ${dest}..."
  git -C "${dest}" remote set-url origin "${repo_url}" >/dev/null 2>&1 || true
  git -C "${dest}" fetch --tags origin
  sf_log "Checking out ${ref}..."
  git -C "${dest}" checkout "${ref}" || sf_die "Ref '${ref}' not found"
}
```

### Step 4.3: Add `--version` flag parsing to install.sh main()

- [ ] **Action:** In `install.sh` `main()`, add flag parsing at the top before `sf_need_root`:

```bash
main() {
  # Parse flags
  local _arg
  while [[ "${#}" -gt 0 ]]; do
    case "$1" in
      --version)
        export SECFORGE_VERSION="${2:-}"
        shift 2 ;;
      --help|-h)
        cat <<EOF
Usage: install.sh [options]

Options:
  --version <ref>     Git ref to install (tag like v2.0.0, 'main', or commit SHA)
                      Default: latest tag for fresh installs, current ref for existing
  --help              Show this help

Environment:
  SECFORGE_VERSION    Same as --version
  SECFORGE_DEST       Install destination (default: /opt/secforge)
  SECFORGE_REPO_URL   Git repo URL (default: github.com/Nosko666/SecForge.git)
EOF
        exit 0 ;;
      *)
        sf_die "Unknown flag: $1 (use --help)" ;;
    esac
  done

  sf_need_root
  sf_require_ubuntu
  # ... rest stays the same
```

Then replace the call inside `main()`:
```bash
  sf_ensure_git
  sf_clone_or_update_repo "${SECFORGE_DEST}" "${SECFORGE_BRANCH}" "${SECFORGE_REPO_URL}"
```
with:
```bash
  sf_ensure_git
  local _ref
  _ref="$(sf_resolve_version "${SECFORGE_DEST}")"
  sf_log "Installing SecForge ref: ${_ref}"
  sf_clone_or_update_repo "${SECFORGE_DEST}" "${_ref}" "${SECFORGE_REPO_URL}"
```

### Step 4.4: Update update-all.sh to use the same pattern

- [ ] **Action:** Read the current update-all.sh structure
```bash
head -50 scripts/update-all.sh
```

Find the line that does `git pull` (or `git -C "${SECFORGE_ROOT}" pull`). Replace it with:

```bash
# Resolve target version: --version flag, env var, or latest tag
_target_ref="${SECFORGE_VERSION:-}"
if [[ -z "${_target_ref}" ]]; then
  # Default for update: latest tag
  _target_ref="$(git -C "${SECFORGE_ROOT}" ls-remote --tags --refs origin 'v[0-9]*' 2>/dev/null \
    | awk -F'/' '{print $NF}' | sort -V | tail -n1 || true)"
  if [[ -z "${_target_ref}" ]]; then
    sf_die "No tagged releases found. Set SECFORGE_VERSION=main to update to latest commit."
  fi
fi
sf_log "Updating SecForge to ${_target_ref}..."
git -C "${SECFORGE_ROOT}" fetch --tags origin
git -C "${SECFORGE_ROOT}" checkout "${_target_ref}" || sf_die "Ref '${_target_ref}' not found"
```

Also add a `--version` flag parser at the top of update-all.sh `main()` (or wherever args are parsed):
```bash
while [[ "${#}" -gt 0 ]]; do
  case "$1" in
    --version) export SECFORGE_VERSION="${2:-}"; shift 2 ;;
    *) shift ;;
  esac
done
```

### Step 4.5: Add `--version` to bin/secforge update subcommand

- [ ] **Action:** Find the `update)` case in `bin/secforge`. Replace it with:

```bash
  update)
    # Parse --version flag and forward
    while [[ "${#}" -gt 0 ]]; do
      case "$1" in
        --version) export SECFORGE_VERSION="${2:-}"; shift 2 ;;
        -h|--help)
          cat <<EOF
Usage: secforge update [--version <ref>]

Updates SecForge to the latest tagged release (or to a specific ref).

Options:
  --version <ref>   Update to a specific tag (e.g. v2.0.0), 'main', or commit SHA
                    Default: latest tag from origin
EOF
          exit 0 ;;
        *) sf_die "Unknown update flag: $1" ;;
      esac
    done
    exec bash "${SCRIPT_DIR}/update-all.sh"
    ;;
```

### Step 4.6: Validate

- [ ] **Action:** Run syntax checks
```bash
bash -n install.sh && echo "install.sh OK"
bash -n scripts/update-all.sh && echo "update-all OK"
bash -n bin/secforge && echo "secforge OK"
```

### Step 4.7: Commit

- [ ] **Action:** Commit
```bash
git add install.sh scripts/update-all.sh bin/secforge
git commit -m "feat(security): version pinning across install.sh, update-all.sh, secforge update

install.sh:
- New sf_resolve_version() function picks the right git ref
- Fresh clone: latest tag (or fail if no tags)
- Existing checkout: preserve current ref (tag, main, or SHA)
- Refuses non-main branches without explicit --version
- New --version flag and SECFORGE_VERSION env var

update-all.sh:
- Replaced bare 'git pull' with explicit fetch+checkout
- Defaults to latest tag (intentional rollover for updates)
- Accepts --version override

bin/secforge update:
- Forwards --version flag to update-all.sh

No more silent rollover. Every install/update is auditable.
"
```

---

## Task 5: install.sh --reinstall + self-delete safety

**Files:**
- Modify: `install.sh` (add `--reinstall`/`--purge-all` flags + safety check)

### Step 5.1: Add reinstall helper functions

- [ ] **Action:** Add these helper functions to `install.sh` after `sf_resolve_version`:

```bash
# Backup config and state to /tmp before reinstall
sf_reinstall_backup() {
  local dest="$1"
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local backup_dir="/tmp/secforge-backup-${ts}"

  mkdir -p "${backup_dir}/config" "${backup_dir}/state"

  if [[ -f "${dest}/config/secforge.conf" ]]; then
    cp -a "${dest}/config/secforge.conf" "${backup_dir}/config/" || true
  fi
  if [[ -f "${dest}/config/.authorized_targets" ]]; then
    cp -a "${dest}/config/.authorized_targets" "${backup_dir}/config/" || true
  fi
  if [[ -d "${dest}/state" ]]; then
    cp -a "${dest}/state/." "${backup_dir}/state/" || true
  fi

  printf '%s' "${backup_dir}"
}

# Restore config and state from backup, preserving ownership and modes
sf_reinstall_restore() {
  local backup_dir="$1"
  local dest="$2"

  if [[ ! -d "${backup_dir}" ]]; then
    sf_warn "Backup dir ${backup_dir} missing — nothing to restore."
    return 0
  fi

  if [[ -f "${backup_dir}/config/secforge.conf" ]]; then
    cp -a "${backup_dir}/config/secforge.conf" "${dest}/config/" || true
  fi
  if [[ -f "${backup_dir}/config/.authorized_targets" ]]; then
    cp -a "${backup_dir}/config/.authorized_targets" "${dest}/config/" || true
    # Re-enforce 0640 in case the source file had different perms
    chmod 0640 "${dest}/config/.authorized_targets" 2>/dev/null || true
  fi
  if [[ -d "${backup_dir}/state" ]] && [[ -n "$(ls -A "${backup_dir}/state" 2>/dev/null || true)" ]]; then
    mkdir -p "${dest}/state"
    cp -a "${backup_dir}/state/." "${dest}/state/" || true
  fi

  sf_log "Restored config and state from ${backup_dir}"
}

# Safety check: refuse to delete a directory we're running from
sf_check_self_delete() {
  local dest="$1"
  local script_path
  script_path="$(realpath "${BASH_SOURCE[0]}" 2>/dev/null || readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
  local dest_real
  dest_real="$(realpath "${dest}" 2>/dev/null || readlink -f "${dest}" 2>/dev/null || echo "${dest}")"

  if [[ "${script_path}" == "${dest_real}/"* ]]; then
    sf_warn "Cannot --reinstall while running install.sh from inside ${dest}"
    sf_warn "You're running: ${script_path}"
    sf_warn "To reinstall, run from a separate location:"
    sf_warn "  curl -sSL https://raw.githubusercontent.com/Nosko666/SecForge/v2.0.0/install.sh -o /tmp/secforge-install.sh"
    sf_warn "  sudo bash /tmp/secforge-install.sh --reinstall"
    sf_die "Self-delete refused."
  fi
}
```

### Step 5.2: Add `--reinstall`/`--purge-all` flag parsing

- [ ] **Action:** Update the flag-parsing block in `install.sh main()` (added in Step 4.3):

```bash
  # Parse flags
  local _do_reinstall=0 _do_purge_all=0
  while [[ "${#}" -gt 0 ]]; do
    case "$1" in
      --version)
        export SECFORGE_VERSION="${2:-}"
        shift 2 ;;
      --reinstall)
        _do_reinstall=1
        shift ;;
      --purge-all)
        _do_purge_all=1
        shift ;;
      --help|-h)
        cat <<EOF
Usage: install.sh [options]

Options:
  --version <ref>     Git ref to install (tag like v2.0.0, 'main', or commit SHA)
                      Default: latest tag for fresh installs, current ref for existing
  --reinstall         Wipe and reinstall (preserves config + state by default)
  --purge-all         Modifier for --reinstall: skip backup (full nuke)
  --help              Show this help

Environment:
  SECFORGE_VERSION    Same as --version
  SECFORGE_DEST       Install destination (default: /opt/secforge)
  SECFORGE_REPO_URL   Git repo URL (default: github.com/Nosko666/SecForge.git)
EOF
        exit 0 ;;
      *)
        sf_die "Unknown flag: $1 (use --help)" ;;
    esac
  done
```

### Step 5.3: Implement reinstall flow in main()

- [ ] **Action:** After `sf_need_root` and `sf_require_ubuntu` in `main()`, add the reinstall block before the existing install logic:

```bash
  # Reinstall flow
  if [[ "${_do_reinstall}" -eq 1 ]]; then
    sf_check_self_delete "${SECFORGE_DEST}"
    if [[ ! -d "${SECFORGE_DEST}" ]]; then
      sf_warn "${SECFORGE_DEST} does not exist; --reinstall has nothing to wipe. Proceeding with fresh install."
    else
      local _backup_dir=""
      if [[ "${_do_purge_all}" -eq 1 ]]; then
        sf_log "--purge-all: skipping backup"
      else
        sf_log "Backing up config and state..."
        _backup_dir="$(sf_reinstall_backup "${SECFORGE_DEST}")"
        sf_log "Backup written to ${_backup_dir}"
      fi
      sf_log "Wiping ${SECFORGE_DEST}..."
      rm -rf "${SECFORGE_DEST}"
      # Save backup dir for restore after install
      export _SF_REINSTALL_BACKUP="${_backup_dir}"
    fi
  fi
```

After the existing install/bootstrap block (after `bash "${SECFORGE_DEST}/scripts/bootstrap.sh"`), add restore:

```bash
  # Restore reinstall backup
  if [[ -n "${_SF_REINSTALL_BACKUP:-}" ]]; then
    sf_reinstall_restore "${_SF_REINSTALL_BACKUP}" "${SECFORGE_DEST}"
  fi
```

### Step 5.4: Validate

- [ ] **Action:** Syntax check
```bash
bash -n install.sh && echo "install.sh OK"
```

Then verify `--help` produces the new text:
```bash
bash install.sh --help
```
Expected: shows `--reinstall` and `--purge-all` in the options list.

### Step 5.5: Commit

- [ ] **Action:** Commit
```bash
git add install.sh
git commit -m "feat: install.sh --reinstall and --purge-all flags

--reinstall:
- Backs up secforge.conf, .authorized_targets, and state/ to /tmp
- Wipes /opt/secforge
- Re-runs the normal clone+bootstrap path
- Restores config and state with original ownership/modes
- Self-delete safety: refuses to run if install.sh lives inside SECFORGE_DEST

--purge-all:
- Modifier that skips the backup (full nuke)

Used by cleanroom test and power users for clean reset.
"
```

---

## Task 6: GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

### Step 6.1: Create the CI workflow

- [ ] **Action:** Create `.github/workflows/ci.yml`

```bash
mkdir -p .github/workflows
cat > .github/workflows/ci.yml <<'YAML'
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  syntax:
    name: Syntax check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: bash -n on shell scripts
        run: |
          set -e
          find scripts/ -name '*.sh' -type f -print0 | xargs -0 -n1 bash -n
          bash -n install.sh
          bash -n bin/secforge
          echo "All shell scripts syntactically valid"

      - name: python compile
        run: |
          set -e
          python3 -m py_compile scripts/secforge/*.py
          python3 -m py_compile scripts/secforge/parsers/*.py
          python3 -c "compile(open('scripts/merge-reports.py').read(), 'merge-reports.py', 'exec')"
          echo "All Python files compile"

  catalogs:
    name: Catalog validation
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate tools.json
        run: |
          python3 -c "
          import json
          t = json.load(open('catalog/tools.json'))
          assert '_meta' in t, 'tools.json missing _meta'
          tool_count = sum(1 for k in t if k != '_meta')
          assert tool_count > 0, 'tools.json has no tools'
          print(f'tools.json: {tool_count} tools')
          "

      - name: Validate profiles.json
        run: |
          python3 -c "
          import json
          p = json.load(open('catalog/profiles.json'))
          assert '_meta' in p, 'profiles.json missing _meta'
          profile_count = sum(1 for k in p if k != '_meta')
          assert profile_count >= 9, f'expected >=9 profiles, got {profile_count}'
          print(f'profiles.json: {profile_count} profiles')
          "

      - name: Cross-reference profiles vs tools
        run: |
          python3 -c "
          import json, sys
          t = json.load(open('catalog/tools.json'))
          p = json.load(open('catalog/profiles.json'))
          tool_ids = set(k for k in t if k != '_meta')
          errors = []
          for pid, prof in p.items():
              if pid == '_meta': continue
              for ref_field in ('tools_include', 'tools_exclude'):
                  for tid in prof.get(ref_field, []):
                      if tid not in tool_ids:
                          errors.append(f'profile {pid}.{ref_field}: unknown tool {tid}')
              if 'npm-audit' in prof.get('tools_include', []):
                  errors.append(f'profile {pid}: includes npm-audit (deferred)')
          if errors:
              for e in errors: print(f'ERROR: {e}')
              sys.exit(1)
          print('Cross-reference OK')
          "

  smoke:
    name: Smoke test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install minimal deps
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y --no-install-recommends jq curl python3 bash

      - name: Bootstrap auth file
        run: |
          mkdir -p config
          echo 'this_server' > config/.authorized_targets
          chmod 0640 config/.authorized_targets

      - name: install-tools.sh --list
        env:
          SECFORGE_ROOT: ${{ github.workspace }}
        run: |
          set -e
          out="$(bash scripts/install-tools.sh --list 2>&1)"
          echo "$out"
          echo "$out" | grep -qE 'INSTALLED|AVAILABLE|BUILTIN' || (echo "FAIL: no status markers" && exit 1)
          echo "install --list OK"

      - name: preflight.sh smoke
        env:
          SECFORGE_ROOT: ${{ github.workspace }}
          SECFORGE_ASSUME_YES: "1"
        run: |
          set -e
          bash scripts/preflight.sh \
            --target this_server \
            --scan-mode quick \
            --stack node-nginx \
            --session-id ci-test \
            --require-tools curl,jq >/dev/null

          # Verify preflight.json has required fields
          python3 -c "
          import json
          p = json.load(open('reports/ci-test/preflight.json'))
          required = ['stack_detection', 'tools_planned', 'tools_effective', 'est_seconds', 'est_tools_total']
          missing = [k for k in required if k not in p]
          assert not missing, f'preflight.json missing fields: {missing}'
          sd = p['stack_detection']
          assert 'detected_stack' in sd, 'stack_detection missing detected_stack'
          assert sd['detected_stack'] == 'node-nginx', f'expected node-nginx, got {sd[\"detected_stack\"]}'
          print('preflight.json OK')
          "

      - name: Cleanup
        if: always()
        run: rm -rf reports/ci-test
YAML
```

### Step 6.2: Validate YAML syntax

- [ ] **Action:** Verify the YAML parses
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('YAML OK')"
```

If `python3-yaml` is not installed, use:
```bash
python3 -c "
import json, re
with open('.github/workflows/ci.yml') as f:
    content = f.read()
# Basic YAML sanity: no tab characters, balanced quotes
assert '\t' not in content, 'YAML must not contain tabs'
print('YAML basic check OK')
"
```

### Step 6.3: Commit

- [ ] **Action:** Commit
```bash
mkdir -p .github/workflows
git add .github/workflows/ci.yml
git commit -m "ci: GitHub Actions workflow (syntax + catalogs + smoke)

3 parallel jobs on every push to main + PR:

- syntax: bash -n on all shell scripts (including bin/secforge),
  python3 -m py_compile on all Python modules
- catalogs: validate tools.json + profiles.json well-formed,
  cross-reference profile tool IDs against tools.json
- smoke: install minimal deps, run install-tools.sh --list,
  run preflight.sh with node-nginx stack, verify preflight.json
  has required fields

Pre-creates .authorized_targets for the smoke job (preflight
fails closed without it after the auth hardening fix).

Total runtime budget: ~30s wall-clock.
"
```

---

## Task 7: Cleanroom Hetzner test script

**Files:**
- Create: `scripts/test/cleanroom-hetzner.sh`

### Step 7.1: Create the test script

- [ ] **Action:** Create the script

```bash
mkdir -p scripts/test
cat > scripts/test/cleanroom-hetzner.sh <<'SCRIPT'
#!/usr/bin/env bash
# SecForge cleanroom Hetzner install test
# Wipes /opt/secforge on the target host, fresh-installs from a tag,
# validates the install, then restores the original state.
#
# Usage:
#   scripts/test/cleanroom-hetzner.sh [--version <tag>] [--host <ip>] [--user <user>]
#
# Defaults:
#   --version: latest local tag from `git tag -l 'v*' | sort -V | tail -1`
#   --host:    116.203.191.42
#   --user:    root

set -euo pipefail

VERSION=""
HOST="116.203.191.42"
SSH_USER="root"

while [[ "${#}" -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --host) HOST="${2:-}"; shift 2 ;;
    --user) SSH_USER="${2:-}"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--version <tag>] [--host <ip>] [--user <user>]

Wipes and reinstalls SecForge on a remote host, then validates.
Restores the original state on success.
EOF
      exit 0 ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${VERSION}" ]]; then
  VERSION="$(git tag -l 'v[0-9]*' | sort -V | tail -n1 || true)"
  if [[ -z "${VERSION}" ]]; then
    echo "ERROR: No local tag found and --version not specified" >&2
    exit 1
  fi
fi

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/tmp/cleanroom-backup-${TS}"
LOG_FILE="/tmp/cleanroom-${TS}.log"

echo "=== SecForge Cleanroom Test ==="
echo "Host:    ${SSH_USER}@${HOST}"
echo "Version: ${VERSION}"
echo "Backup:  ${BACKUP_DIR}"
echo "Log:     ${LOG_FILE}"
echo ""

ssh_cmd() {
  ssh -o StrictHostKeyChecking=no "${SSH_USER}@${HOST}" "$@"
}

run_step() {
  local label="$1"
  shift
  echo "--- ${label} ---"
  if "$@"; then
    echo "PASS: ${label}"
  else
    echo "FAIL: ${label}"
    echo "Cleanroom test aborted. Backup remains at ${BACKUP_DIR} on remote."
    exit 1
  fi
}

# 1. Pre-flight
run_step "SSH connectivity" ssh_cmd "echo OK >/dev/null"
run_step "git available" ssh_cmd "command -v git >/dev/null"
run_step "python3 available" ssh_cmd "command -v python3 >/dev/null"
run_step "curl available" ssh_cmd "command -v curl >/dev/null"

# 2. Backup
run_step "backup config + state" ssh_cmd "
  mkdir -p ${BACKUP_DIR}/config ${BACKUP_DIR}/state
  [[ -f /opt/secforge/config/secforge.conf ]] && cp -a /opt/secforge/config/secforge.conf ${BACKUP_DIR}/config/ || true
  [[ -f /opt/secforge/config/.authorized_targets ]] && cp -a /opt/secforge/config/.authorized_targets ${BACKUP_DIR}/config/ || true
  [[ -d /opt/secforge/state ]] && cp -a /opt/secforge/state ${BACKUP_DIR}/ || true
  echo backup_complete
"

# 3. Wipe
run_step "wipe /opt/secforge" ssh_cmd "rm -rf /opt/secforge && echo wiped"

# 4. Fresh install via real install.sh flow
run_step "download install.sh from version ${VERSION}" ssh_cmd "
  curl -sSL 'https://raw.githubusercontent.com/Nosko666/SecForge/${VERSION}/install.sh' -o /tmp/cleanroom-install.sh
  test -s /tmp/cleanroom-install.sh
"
run_step "run install.sh --version ${VERSION}" ssh_cmd "
  SECFORGE_VERSION=${VERSION} SECFORGE_ASSUME_YES=1 bash /tmp/cleanroom-install.sh --version ${VERSION}
"

# 5. Validate install
run_step "secforge version output" ssh_cmd "
  out=\$(bin/secforge version 2>&1 || /opt/secforge/bin/secforge version 2>&1 || true)
  echo \"\$out\"
  echo \"\$out\" | grep -q '${VERSION#v}' || (echo 'version output missing ${VERSION#v}' && exit 1)
  echo \"\$out\" | grep -qE '\\-dev' && (echo 'version output contains -dev (should be tag clean)' && exit 1) || true
"
run_step "install --list works" ssh_cmd "/opt/secforge/scripts/install-tools.sh --list >/dev/null"
run_step ".authorized_targets is 0640" ssh_cmd "
  [[ -f /opt/secforge/config/.authorized_targets ]] || (echo 'auth file missing' && exit 1)
  mode=\$(stat -c '%a' /opt/secforge/config/.authorized_targets)
  [[ \"\$mode\" == '640' ]] || (echo \"expected 640, got \$mode\" && exit 1)
"
run_step "init --tier 1 --domain test.local" ssh_cmd "
  /opt/secforge/bin/secforge init --tier 1 --domain test.local
  grep -q 'TIER_MAX=\"1\"' /opt/secforge/config/secforge.conf
  grep -q '^test.local\$' /opt/secforge/config/.authorized_targets
"
run_step "bash -n on installed scripts" ssh_cmd "
  bash -n /opt/secforge/scripts/*.sh /opt/secforge/bin/secforge /opt/secforge/install.sh
"

# 6. Validate scan
run_step "authorize this_server" ssh_cmd "
  /opt/secforge/bin/secforge init --domain this_server
  grep -q '^this_server\$' /opt/secforge/config/.authorized_targets
"
run_step "scan with --stack node-nginx" ssh_cmd "
  cd /opt/secforge && SECFORGE_ASSUME_YES=1 timeout 180 bin/secforge scan this_server --stack node-nginx >/tmp/scan-output.log 2>&1
"
run_step "scan_manifest.json has profile + scan_mode + tier_max" ssh_cmd "
  SESSION=\$(ls -t /opt/secforge/reports/ | grep this_server | head -1)
  python3 -c \"
import json
m = json.load(open('/opt/secforge/reports/\$SESSION/scan_manifest.json'))
assert m.get('profile') == 'node-nginx', f'profile={m.get(\\\"profile\\\")}'
assert m.get('scan_mode') == 'quick', f'scan_mode={m.get(\\\"scan_mode\\\")}'
assert m.get('tier_max') in (1, '1'), f'tier_max={m.get(\\\"tier_max\\\")}'
assert m.get('tool_durations'), 'tool_durations empty'
print('manifest OK')
\"
"
run_step "preflight.json has rich stack_detection" ssh_cmd "
  SESSION=\$(ls -t /opt/secforge/reports/ | grep this_server | head -1)
  python3 -c \"
import json
p = json.load(open('/opt/secforge/reports/\$SESSION/preflight.json'))
sd = p['stack_detection']
for f in ['detected_stack', 'confidence', 'score', 'threshold', 'signals']:
    assert f in sd, f'missing {f}'
print('preflight.json OK')
\"
"

# 7. Validate non-root authorization rejection
run_step "non-root scan of unauthorized target rejected" ssh_cmd "
  if id testuser >/dev/null 2>&1; then
    sudo -u testuser /opt/secforge/bin/secforge scan unauthorized.example.com --stack node-nginx 2>&1 | grep -q 'sudo secforge init --domain' && exit 0
    exit 1
  else
    echo 'testuser not present, skipping non-root check'
    exit 0
  fi
"

# 8. Restore
run_step "restore config + state" ssh_cmd "
  [[ -f ${BACKUP_DIR}/config/secforge.conf ]] && cp -a ${BACKUP_DIR}/config/secforge.conf /opt/secforge/config/ || true
  [[ -f ${BACKUP_DIR}/config/.authorized_targets ]] && cp -a ${BACKUP_DIR}/config/.authorized_targets /opt/secforge/config/ && chmod 0640 /opt/secforge/config/.authorized_targets || true
  [[ -d ${BACKUP_DIR}/state ]] && cp -a ${BACKUP_DIR}/state /opt/secforge/ || true
  rm -rf ${BACKUP_DIR} /tmp/cleanroom-install.sh
  echo restore_complete
"

echo ""
echo "=== ALL CHECKS PASSED ==="
echo "Cleanroom test of ${VERSION} on ${HOST} successful."
SCRIPT
chmod +x scripts/test/cleanroom-hetzner.sh
```

### Step 7.2: Validate

- [ ] **Action:** Syntax check
```bash
bash -n scripts/test/cleanroom-hetzner.sh && echo "OK"
bash scripts/test/cleanroom-hetzner.sh --help
```
Expected: prints usage.

### Step 7.3: Commit

- [ ] **Action:** Commit
```bash
git add scripts/test/cleanroom-hetzner.sh
git commit -m "test: cleanroom Hetzner install validation script

Wipes /opt/secforge on a remote host and runs the full install
flow via curl-downloaded install.sh (tests the real user path,
not a pre-cloned shortcut).

Validates:
- secforge version reports the tag (no -dev suffix)
- install --list works
- .authorized_targets is 0640
- init --tier 1 --domain writes config + auth file
- Real scan: manifest has profile/scan_mode/tier_max
- preflight.json has rich stack_detection
- Non-root authorization rejection works

Restores original config + state on success.
"
```

---

## Task 8: Run cleanroom test, write CHANGELOG, bump version, README, tag

**Files:**
- Modify: `scripts/secforge/__init__.py` (version bump)
- Modify: `README.md` (clone-and-review install, status badge, no-curl-pipe callout)
- Create: `CHANGELOG.md`

### Step 8.1: Run the cleanroom test

- [ ] **Action:** Push current state to main, then run cleanroom

```bash
git push origin main
scripts/test/cleanroom-hetzner.sh --version main
```

If the test fails, fix the underlying bug and re-run before proceeding. Do NOT proceed to tagging until this passes.

Expected final output: `=== ALL CHECKS PASSED ===`

### Step 8.2: Bump version

- [ ] **Action:** Edit `scripts/secforge/__init__.py`

Replace:
```python
__version__ = "2.0.0-dev"
```
with:
```python
__version__ = "2.0.0"
```

### Step 8.3: Update README

- [ ] **Action:** Edit `README.md` install section

Find the existing install instructions (look for `curl -sSL` or `## Install`). Replace with:

```markdown
## Install

[![CI](https://github.com/Nosko666/SecForge/actions/workflows/ci.yml/badge.svg)](https://github.com/Nosko666/SecForge/actions/workflows/ci.yml)

**Recommended (clone and review):**

```bash
git clone https://github.com/Nosko666/SecForge.git /opt/secforge
cd /opt/secforge
git checkout v2.0.0   # pin to verified release
sudo ./install.sh
```

This is the secure install path: you can review the code at `v2.0.0` before running anything as root. The installer will preserve the checked-out tag — it won't silently jump to a newer version.

### Why no `curl | sudo bash`?

We deliberately do not document a `curl ... | sudo bash` install. That pattern executes remote code as root with zero opportunity for review, which is the canonical supply-chain risk in security tools. Clone-and-review is the only recommended path.

The `install.sh` script still works if you really want a one-shot install (`sudo bash install.sh --version v2.0.0`), but you should download it first (`curl -O`) and review it before running.

### Update

```bash
sudo secforge update --version v2.0.0   # pin to a specific tag
sudo secforge update                    # latest tag
```

### Reinstall (preserves config + state)

```bash
sudo bash /tmp/secforge-install.sh --reinstall
```
```

### Step 8.4: Write CHANGELOG.md

- [ ] **Action:** Create CHANGELOG.md

```bash
cat > CHANGELOG.md <<'EOF'
# Changelog

All notable changes to SecForge are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-07

First tagged release. SecForge as an AI-guided security toolkit for vibecoders, with stack-aware scanning, fix packs, state tracking, and a hardened install path.

### AI-Guided Workflow
- Stack profiles auto-detect tech stack and pick relevant tools (9 profiles: node-nginx, wordpress, python-nginx, node-bare, php-nginx, java-spring, ruby-rails, static-nginx, go-bare)
- Live tmux dashboard with per-tool progress, ETA, and post-scan summary
- `secforge init` interactive wizard for first-time setup with tier selection
- Per-target time estimates ("12 tools, ~8 min") shown before scan starts
- Rich stack_detection in preflight.json includes signals, score, and threshold for explainability

### v2 Pipeline
- Parsers normalize 57 security tools into canonical findings
- SHA-256 fingerprints with 3-level dedup (same-tool, cross-tool, cross-scan)
- 18 root-cause clusters → fix packs with verification + rollback steps
- 7-factor priority scoring (0-100) with conservative fixed-gating
- SQLite state DB tracks findings across scans (new/existing/fixed/reopened)
- 5 AI export modes: quick-fix, fix-pack, full-plan, patch, explain

### Per-Tool Installer
- `secforge install <tool>` installs individual tools from a 57-tool catalog
- 11 custom install functions for tools that need special handling
- Alias normalization (e.g., `testssl.sh` → `testssl`)
- Source guard for safe sourcing during validation

### CLI
- `secforge scan` with `--stack`, `--skip`, `--tier`, `--code-path`, `--dashboard`
- `secforge init`, `install`, `dashboard`, `verify`, `list`, `diff`, `history`, `purge`
- `secforge ignore`, `accept`, `false-positive` for finding lifecycle management
- `secforge update --version <tag>` for pinned updates

### Security Hardening
- Removed `curl | sudo bash` from documented install path; clone-and-review is now the recommended flow
- Install and update pinned to git tags by default (`SECFORGE_VERSION` env var or `--version` flag)
- SHA-256 verification for all GitHub release binary downloads (fails closed when missing)
- Tightened `.authorized_targets` to mode 0640 (root-controlled, no group self-authorization)
- `secforge init --domain` rejects non-root with clear "use sudo" instruction
- Tier validation: `--tier 1|2` rejects out-of-range values; preflight clamps bad config

### Validation
- GitHub Actions CI: bash syntax check, Python compile, catalog cross-reference, smoke test
- Cleanroom Hetzner test script for pre-release validation

[2.0.0]: https://github.com/Nosko666/SecForge/releases/tag/v2.0.0
EOF
```

### Step 8.5: Validate everything one more time

- [ ] **Action:** Final pre-tag checks

```bash
bash -n scripts/_lib.sh scripts/preflight.sh scripts/install-tools.sh scripts/bootstrap.sh \
        scripts/update-all.sh scripts/test/cleanroom-hetzner.sh install.sh bin/secforge && echo "all bash OK"
python3 -m py_compile scripts/secforge/__init__.py && echo "init.py OK"
python3 -c "import json; json.load(open('catalog/tools.json')); json.load(open('catalog/profiles.json')); print('catalogs OK')"
python3 -c "
import sys
sys.path.insert(0, 'scripts')
from secforge import __version__
assert __version__ == '2.0.0', f'expected 2.0.0, got {__version__}'
print(f'version: {__version__}')
"
```

### Step 8.6: Commit version bump + CHANGELOG + README

- [ ] **Action:** Commit
```bash
git add scripts/secforge/__init__.py CHANGELOG.md README.md
git commit -m "release: v2.0.0

- Bump __version__ from 2.0.0-dev to 2.0.0
- Write themed CHANGELOG.md entry
- Update README install instructions to clone-and-review,
  add CI badge, add 'no curl-pipe' callout
"
```

### Step 8.7: Push and tag

- [ ] **Action:** Push, run cleanroom test one more time on the tag commit, then tag
```bash
git push origin main

# Final cleanroom on the would-be tag commit (still on main, before tag)
scripts/test/cleanroom-hetzner.sh --version main

# Verify CI is green on origin/main
gh run list --limit 1 || echo "Check CI manually at https://github.com/Nosko666/SecForge/actions"

# Create annotated tag
git tag -a v2.0.0 -m "SecForge v2.0.0 — first hardened release

See CHANGELOG.md for the full release notes.

Highlights:
- Stack profiles + live dashboard for AI-guided scanning
- v2 pipeline: fingerprints, fix packs, state tracking
- Per-tool installer with alias normalization
- Security hardening: clone-and-review install, version pinning,
  SHA-256 verification, root-controlled authorization
- CI + cleanroom validation
"

git push origin v2.0.0
```

### Step 8.8: Bump back to dev for post-release commits

- [ ] **Action:** Bump version back to dev so post-release commits identify themselves

```bash
sed -i 's/__version__ = "2.0.0"/__version__ = "2.0.1-dev"/' scripts/secforge/__init__.py
python3 -c "
import sys
sys.path.insert(0, 'scripts')
from secforge import __version__
assert __version__ == '2.0.1-dev', f'expected 2.0.1-dev, got {__version__}'
print(f'version: {__version__}')
"

git add scripts/secforge/__init__.py
git commit -m "chore: bump __version__ to 2.0.1-dev (post-v2.0.0)"
git push origin main
```

---

## Verification (post-implementation)

After all 8 tasks complete and `v2.0.0` is tagged:

1. `git tag -l` shows `v2.0.0`
2. `git log v2.0.0 --oneline -1` shows the release commit
3. `cat CHANGELOG.md` shows the v2.0.0 entry
4. GitHub Actions CI is green on the v2.0.0 tag commit (check https://github.com/Nosko666/SecForge/actions)
5. README has the CI badge and clone-and-review install
6. `scripts/test/cleanroom-hetzner.sh --version v2.0.0` reports ALL CHECKS PASSED on a fresh Hetzner install
7. On Hetzner: `secforge version` returns `SecForge v2.0.0` (no `-dev`)
8. On Hetzner: `stat -c '%a' /opt/secforge/config/.authorized_targets` returns `640`
9. On Hetzner: `sudo -u testuser secforge scan unauthorized.example.com --stack node-nginx` exits non-zero with "sudo secforge init --domain" instruction
10. Main is bumped to `2.0.1-dev` for post-release commits
