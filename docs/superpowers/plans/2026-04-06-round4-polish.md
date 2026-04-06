# SecForge Round 4 — Polish & Spec Compliance

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 4 remaining spec gaps from the Vibecoder UX design spec (docs/superpowers/specs/2026-04-05-vibecoder-ux-design.md).

**Architecture:** All changes are in existing files — no new files. Preflight planner gets richer output, init gets --tier, scan scripts print estimates before starting.

**Tech Stack:** Bash, Python 3 (stdlib only inside heredocs)

---

## Task 1: Rich stack_detection in preflight.json

**Spec:** design spec lines 305-316. preflight.json must include `detected_stack`, `score`, `threshold`, `signals[]`.

**Files:**
- Modify: `scripts/preflight.sh` (PYPLAN heredoc, stack detection section ~line 487 + preflight_data section ~line 775)

- [ ] **Step 1: Collect signals during auto-detection**

In the Python planner's auto-detection loop (around line 528), collect signal descriptions:

```python
# Replace the current scoring loop with one that records signals:
profile_scores = {}
profile_signals = {}  # profile_name -> list of signal strings

for pname, pdata in profiles_catalog.items():
    signals = 0
    signal_list = []

    # Check detect_headers
    detect_hdrs = pdata.get("detect_headers", {})
    for hdr_name, hdr_pattern in detect_hdrs.items():
        hdr_name_lower = hdr_name.lower()
        if hdr_name_lower in resp_headers:
            if not hdr_pattern:
                signals += 1
                signal_list.append(f"header:{hdr_name_lower}")
            elif hdr_pattern.lower() in resp_headers[hdr_name_lower].lower():
                signals += 1
                signal_list.append(f"header:{hdr_name_lower}={hdr_pattern}")

    # Check detect_cookies
    detect_cookies = pdata.get("detect_cookies", [])
    for cookie_pattern in detect_cookies:
        cookie_lower = cookie_pattern.lower()
        for rc in resp_cookies:
            if cookie_lower in rc:
                signals += 1
                signal_list.append(f"cookie:{rc}")
                break

    # Check detect_files
    detect_files = pdata.get("detect_files", [])
    if CODE_PATH and os.path.isdir(CODE_PATH):
        for df in detect_files:
            check = os.path.join(CODE_PATH, df)
            if os.path.exists(check):
                signals += 1
                signal_list.append(f"file:{df}")

    if signals > 0:
        profile_scores[pname] = signals
        profile_signals[pname] = signal_list
```

- [ ] **Step 2: Record score and threshold in confidence gating**

After the confidence gating block (~line 563), save the winner's score and threshold:

```python
_detection_score = 0
_detection_threshold = 2
_detection_signals = []

if profile_scores:
    max_score = max(profile_scores.values())
    winners = [p for p, s in profile_scores.items() if s == max_score]
    _detection_threshold = profiles_catalog.get(winners[0], {}).get("min_detect_signals", 2) if len(winners) == 1 else 2

    if len(winners) == 1 and max_score >= _detection_threshold:
        detected_profile_name = winners[0]
        detect_confidence = "high"
        _detection_score = max_score
        _detection_signals = profile_signals.get(winners[0], [])
    elif len(winners) == 1 and max_score >= 1:
        detect_confidence = "low"
        _detection_score = max_score
        _detection_signals = profile_signals.get(winners[0], [])
    else:
        detect_confidence = "low" if max_score >= 1 else "none"
        if winners:
            _detection_score = max_score
            _detection_signals = profile_signals.get(winners[0], [])
```

- [ ] **Step 3: Update preflight_data stack_detection object**

In the preflight.json writer (~line 790), replace the current minimal object:

```python
"stack_detection": {
    "detected_stack": detected_profile_name,
    "confidence": detect_confidence,
    "score": _detection_score,
    "threshold": _detection_threshold,
    "signals": _detection_signals,
    "stack_override": STACK,
},
```

- [ ] **Step 4: Validate**

```bash
bash -n scripts/preflight.sh && echo "OK"
# Smoke test:
SECFORGE_ROOT=/opt/secforge SECFORGE_ASSUME_YES=1 scripts/preflight.sh --target localhost --stack node-nginx --session-id test-r4-001 >/dev/null 2>/dev/null
python3 -c "import json; p=json.load(open('reports/test-r4-001/preflight.json')); sd=p['stack_detection']; print(f'score={sd[\"score\"]} threshold={sd[\"threshold\"]} signals={sd[\"signals\"]}')"
rm -rf reports/test-r4-001
```

Expected: `score=0 threshold=2 signals=[]` (--stack override skips detection, so score is 0)

- [ ] **Step 5: Commit**

```bash
git add scripts/preflight.sh
git commit -m "feat: rich stack_detection in preflight.json — score, threshold, signals"
```

---

## Task 2: secforge init --tier

**Spec:** design spec lines 216-217 and 629-633. init must accept `--tier 1|2` and write TIER_MAX. Interactive wizard must ask the tier question.

**Files:**
- Modify: `bin/secforge` (init case ~line 600)

- [ ] **Step 1: Add --tier flag parsing**

In the init flag parsing loop (~line 602), add:

```bash
--tier) _sf_tier="${2:-}"; shift 2 ;;
```

Also add `_sf_tier=""` to the variable declarations at the top of the init block.

- [ ] **Step 2: Write TIER_MAX when --tier provided**

After the existing flag-mode block (~line 688), add:

```bash
if [[ -n "${_sf_tier}" ]]; then
  had_flags=1
  sf_cfg_set_value "${cfg}" "TIER_MAX" "${_sf_tier}"
fi
```

- [ ] **Step 3: Add tier question to interactive wizard**

After the payments question (~line 718), add:

```bash
# Tier preference
echo ""
echo "Scanning tiers:"
echo "  1) Tier 1 (recommended): passive/safe checks only"
echo "  2) Tier 2: includes active testing (SQLi, XSS payloads). Best for staging."
local _tier_choice
_tier_choice="$(sf_prompt_tty "Max scanning tier?" "1")"
if [[ "${_tier_choice}" == "2" ]]; then
  sf_cfg_set_value "${cfg}" "TIER_MAX" "2"
else
  sf_cfg_set_value "${cfg}" "TIER_MAX" "1"
fi
```

- [ ] **Step 4: Update help text**

In the init help section (~line 86), add:

```
    --tier 1|2                 Set max scanning tier (1=passive, 2=active)
```

- [ ] **Step 5: Validate**

```bash
bash -n bin/secforge && echo "OK"
```

- [ ] **Step 6: Commit**

```bash
git add bin/secforge
git commit -m "feat: secforge init --tier writes TIER_MAX + interactive tier question"
```

---

## Task 3: Combined estimate display before scan starts

**Spec:** design spec lines 593-598. Scan command must show "N tools, ~M min" before starting.

**Files:**
- Modify: `scripts/scan-quick.sh` (after preflight source, before tool blocks ~line 196)
- Modify: `scripts/scan-all.sh` (same location ~line 386)

- [ ] **Step 1: Add estimate display to scan-quick.sh**

After the `sf_log "Session: ..."` line and before the first tool block, add:

```bash
# Show estimate before starting
local _est_tools="${SECFORGE_EST_TOOLS_TOTAL:-0}"
local _est_secs="${SECFORGE_EST_SECONDS:-0}"
local _est_min=$(( _est_secs / 60 ))
local _est_rem=$(( _est_secs % 60 ))
if [[ "${_est_tools}" -gt 0 ]]; then
  local _est_display
  if [[ "${_est_min}" -gt 0 ]]; then
    _est_display="~${_est_min}m ${_est_rem}s"
  else
    _est_display="~${_est_secs}s"
  fi
  # Check if estimates are historical or first-scan defaults
  local _est_qualifier=""
  if [[ -z "$(find "${SECFORGE_ROOT}/reports" -maxdepth 2 -name 'scan_manifest.json' -path "*${SECFORGE_TARGET_HOST}*" 2>/dev/null | head -1)" ]]; then
    _est_qualifier=" (first scan — rough estimate)"
  fi
  sf_log "${_est_tools} tools, ${_est_display}${_est_qualifier}"
fi
```

- [ ] **Step 2: Add same display to scan-all.sh**

Same code block, after `sf_log "Reports: ..."` and before the first tool section.

- [ ] **Step 3: Validate**

```bash
bash -n scripts/scan-quick.sh scripts/scan-all.sh && echo "OK"
```

- [ ] **Step 4: Commit**

```bash
git add scripts/scan-quick.sh scripts/scan-all.sh
git commit -m "feat: show 'N tools, ~M min' estimate before scan starts"
```

---

## Task 4: Document scan-mode toolset intersection

**Spec:** design spec lines 203-209, 342. The formula is `(tools in scan script) ∩ (tools_include) − ...`

**Analysis:** The intersection is already implemented correctly at runtime — scan scripts have hardcoded tool blocks, each gated by `sf_should_run_tool`. If a profile's `tools_include` lists a tool that scan-quick.sh doesn't have a block for, it simply never runs (the gate passes but there's no code to run it). This is correct behavior.

The missing piece: `SECFORGE_TOOLS_PLANNED` and `SECFORGE_TOOLS_EFFECTIVE` don't reflect the intersection. A profile might include `wapiti` in `tools_include`, but scan-quick.sh doesn't run wapiti — so the estimate and dashboard count would be inflated.

**Files:**
- Modify: `scripts/preflight.sh` (PYPLAN heredoc, tools_effective section)

- [ ] **Step 1: Define scan-mode tool lists in the planner**

After the catalog loading section (~line 420), add the known tool lists for each scan mode:

```python
# Tools that scan-quick.sh actually has blocks for (hardcoded in script)
QUICK_SCAN_TOOLS = {
    "wafw00f", "whatweb", "nuclei", "nmap", "testssl",
    "check-email-dns", "secforge-builtin", "lynis", "ssh-audit",
}

# Tools that scan-all.sh has blocks for (all of quick + tier 1 extras + tier 2)
FULL_SCAN_TOOLS = QUICK_SCAN_TOOLS | {
    "corscanner", "nikto", "ffuf", "observatory", "sslscan",
    "subfinder", "httpx", "interactsh", "masscan",
    "trivy", "trufflehog", "gitleaks", "osv-scanner", "pip-audit",
    "check-mysql", "systemd-analyze", "clamscan", "rkhunter",
    "aide", "aureport", "debsums",
    # Tier 2:
    "zap", "sqlmap", "dalfox", "xsstrike", "commix", "wapiti",
    "hydra", "netexec",
}
```

- [ ] **Step 2: Intersect tools_planned with scan-mode tools**

In the profile expansion section (~line 605), after building `candidate_ids`, intersect:

```python
# Intersect with what the scan script actually runs
scan_mode_tools = QUICK_SCAN_TOOLS if SCAN_MODE == "quick" else FULL_SCAN_TOOLS
candidate_ids = [t for t in candidate_ids if t in scan_mode_tools]
```

- [ ] **Step 3: Intersect tools_effective in no-profile mode too**

In the no-profile else branch (~line 683), filter tools_effective:

```python
scan_mode_tools = QUICK_SCAN_TOOLS if SCAN_MODE == "quick" else FULL_SCAN_TOOLS
# ... existing loop ...
# After building tools_effective, filter:
tools_effective = [t for t in tools_effective if t in scan_mode_tools]
```

- [ ] **Step 4: Validate**

```bash
bash -n scripts/preflight.sh && echo "OK"
# Quick scan should show only tools scan-quick.sh actually runs:
_pf_tmp=$(mktemp) && SECFORGE_ROOT=/opt/secforge SECFORGE_ASSUME_YES=1 scripts/preflight.sh --target localhost --scan-mode quick --stack node-nginx --session-id test-r4-002 >$_pf_tmp 2>/dev/null && source $_pf_tmp && echo "PLANNED=$SECFORGE_TOOLS_PLANNED" && echo "EFFECTIVE=$SECFORGE_TOOLS_EFFECTIVE" && rm -f $_pf_tmp && rm -rf reports/test-r4-002
# EFFECTIVE should NOT contain tools like wapiti, sqlmap, zap (not in quick scan)
```

- [ ] **Step 5: Commit**

```bash
git add scripts/preflight.sh
git commit -m "feat: intersect tools_planned with scan-mode tool sets for accurate estimates"
```

---

## Verification

After all 4 tasks:

1. `bash -n scripts/preflight.sh scripts/scan-quick.sh scripts/scan-all.sh bin/secforge`
2. On Hetzner: `SECFORGE_ASSUME_YES=1 scripts/preflight.sh --target ikeacustomerflow.com --scan-mode quick --session-id test-r4` then check `reports/test-r4/preflight.json` has rich stack_detection
3. `bin/secforge init --tier 1 --domain example.com` then `grep TIER_MAX config/secforge.conf`
4. Run a quick scan — should show "N tools, ~M min" line before first tool starts
5. Quick scan with `--stack node-nginx` — TOOLS_EFFECTIVE should not include full-scan-only tools

## Success Criteria

1. `preflight.json.stack_detection` has: `detected_stack`, `score`, `threshold`, `signals[]`
2. `secforge init --tier 2` writes `TIER_MAX=2` to config
3. Interactive init wizard asks tier question
4. Quick scan prints "N tools, ~Mm Ns" before first tool runs
5. First scan shows "(first scan — rough estimate)" qualifier
6. `--stack node-nginx` quick scan: TOOLS_EFFECTIVE only contains tools scan-quick.sh actually has blocks for
