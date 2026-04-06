#!/usr/bin/env bash
# SecForge — Live TUI dashboard renderer.
# Two-process model: scanner writes JSON events to a status file,
# this script reads and renders them in a loop.
#
# Usage:
#   dashboard.sh --start [<session-dir>]   Monitor status file (watches for events)
#   dashboard.sh --last                     Monitor the latest status file
#   dashboard.sh --select                   Interactive tool selection (gum choose)
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SECFORGE_ROOT="${SECFORGE_ROOT:-$DEFAULT_ROOT}"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

# --- Gum detection ---
_HAS_GUM=0
if command -v gum >/dev/null 2>&1 || [[ -x "${SECFORGE_ROOT}/bin/gum" ]]; then
  _HAS_GUM=1
fi

# --- ANSI helpers ---
_B=$'\033[1m' _D=$'\033[2m' _R=$'\033[0m'
_RED=$'\033[31m' _GRN=$'\033[32m' _YLW=$'\033[33m'
_BLU=$'\033[34m' _CYN=$'\033[36m'

# --- Terminal helpers ---
_tw() { tput cols 2>/dev/null || printf '80'; }
_th() { tput lines 2>/dev/null || printf '24'; }
_cls() { printf '\033[H\033[2J'; }
_hcur() { printf '\033[?25l'; }
_scur() { printf '\033[?25h'; }

_STATUS_FILE="" _SESSION_DIR=""

_resolve_status_file() {
  local mode="$1" session_arg="${2:-}"
  case "${mode}" in
    start)
      if [[ -n "${session_arg}" ]]; then
        _STATUS_FILE="/tmp/secforge-dashboard-$(basename -- "${session_arg}").status"
        _SESSION_DIR="${session_arg}"
      else
        _STATUS_FILE="/tmp/secforge-dashboard-latest.status"
      fi ;;
    last) _STATUS_FILE="/tmp/secforge-dashboard-latest.status" ;;
  esac
  [[ -L "${_STATUS_FILE}" ]] && _STATUS_FILE="$(readlink -f "${_STATUS_FILE}" 2>/dev/null || echo "${_STATUS_FILE}")"
}

# --- State parsing — reads JSON lines, outputs key=value for bash eval ---
_parse_status() {
  python3 - "$1" <<'PY'
import json, sys, os
sf = sys.argv[1]
if not os.path.isfile(sf):
    print("STATE=waiting"); sys.exit(0)
events = []
try:
    with open(sf) as f:
        for ln in f:
            ln = ln.strip()
            if ln:
                try: events.append(json.loads(ln))
                except json.JSONDecodeError: pass
except IOError:
    print("STATE=waiting"); sys.exit(0)
if not events:
    print("STATE=waiting"); sys.exit(0)

st="waiting"; tgt=""; prof=""; smode=""; ttot=0; esec=0
ctool=""; cidx=0; tlist=[]; tmap={}; t2=""
sdur=0; tfind=0; sev={}
itot=0; itools=[]
vpk=""; vtot=0; vpas=0; vfail=0

for ev in events:
    e = ev.get("event","")
    if e=="scan_start":
        st="scanning"; tgt=ev.get("target",""); prof=ev.get("profile","")
        smode=ev.get("scan_mode",""); ttot=ev.get("tools_total",0); esec=ev.get("est_seconds",0)
    elif e=="tool_start":
        st="scanning"; nm=ev.get("tool",""); ix=ev.get("index",len(tlist)+1)
        tmap[ix]=len(tlist); tlist.append({"n":nm,"ix":ix,"s":"running","d":0,"f":0,"e":""})
        ctool=nm; cidx=ix
    elif e=="tool_done":
        nm=ev.get("tool",""); ix=ev.get("index",0); d=ev.get("duration",0); fi=ev.get("findings",0)
        if ix in tmap:
            p=tmap[ix]; tlist[p]["s"]="ok"; tlist[p]["d"]=d; tlist[p]["f"]=fi
        else:
            tlist.append({"n":nm,"ix":ix,"s":"ok","d":d,"f":fi,"e":""})
        if ctool==nm: ctool=""
    elif e=="tool_fail":
        nm=ev.get("tool",""); ix=ev.get("index",0); er=ev.get("error","")
        if ix in tmap:
            p=tmap[ix]; tlist[p]["s"]="fail"; tlist[p]["e"]=er
        else:
            tlist.append({"n":nm,"ix":ix,"s":"fail","d":0,"f":0,"e":er})
        if ctool==nm: ctool=""
    elif e=="tier2_prompt": t2="prompt"
    elif e=="tier2_approved": t2="approved"
    elif e=="tier2_skipped": t2="skipped"
    elif e=="scan_done":
        st="done"; sdur=ev.get("duration",0); tfind=ev.get("total_findings",0)
        sev=ev.get("severity",{})
    elif e=="install_start": st="installing"; itot=ev.get("tools_total",0)
    elif e=="install_done":
        nm=ev.get("tool",""); s2=ev.get("status","ok"); d=ev.get("duration",0)
        itools.append({"n":nm,"s":s2,"d":d})
        if itot>0 and len(itools)>=itot and all(t["s"] in ("ok","fail") for t in itools):
            st="install_complete"
    elif e=="verify_start": st="verifying"; vpk=ev.get("pack",""); vtot=ev.get("checks_total",0)
    elif e=="verify_done":
        st="verify_complete"; vpk=ev.get("pack",vpk)
        vpas=ev.get("passed",0); vfail=ev.get("failed",0)

def q(s): return str(s).replace("'","'\\''")
print(f"STATE='{q(st)}'"); print(f"TARGET='{q(tgt)}'"); print(f"PROFILE='{q(prof)}'")
print(f"SCAN_MODE='{q(smode)}'"); print(f"TOOLS_TOTAL={ttot}"); print(f"EST_SECONDS={esec}")
print(f"CURRENT_TOOL='{q(ctool)}'"); print(f"CURRENT_INDEX={cidx}")
print(f"TIER2_STATE='{q(t2)}'"); print(f"SCAN_DURATION={sdur}"); print(f"TOTAL_FINDINGS={tfind}")
for sv in ("critical","high","medium","low","info"):
    print(f"SEV_{sv.upper()}={sev.get(sv,0)}")
print(f"TOOL_COUNT={len(tlist)}")
for i,t in enumerate(tlist):
    print(f"TOOL_{i}_NAME='{q(t['n'])}'"); print(f"TOOL_{i}_STATUS='{q(t['s'])}'")
    print(f"TOOL_{i}_DUR={t['d']}"); print(f"TOOL_{i}_FINDINGS={t['f']}")
    print(f"TOOL_{i}_ERROR='{q(t.get('e',''))}'")
print(f"INSTALL_TOTAL={itot}"); print(f"INSTALL_COUNT={len(itools)}")
for i,t in enumerate(itools):
    print(f"INST_{i}_NAME='{q(t['n'])}'"); print(f"INST_{i}_STATUS='{q(t['s'])}'")
    print(f"INST_{i}_DUR={t['d']}")
print(f"VERIFY_PACK='{q(vpk)}'"); print(f"VERIFY_TOTAL={vtot}")
print(f"VERIFY_PASSED={vpas}"); print(f"VERIFY_FAILED={vfail}")
PY
}

# --- Progress bar ---
_pbar() {
  local cur="$1" tot="$2" w="${3:-20}"
  if [[ "${tot}" -le 0 ]]; then printf '[-]'; return; fi
  local filled=$(( (cur * w) / tot )) i bar=""
  [[ "${filled}" -gt "${w}" ]] && filled="${w}"
  for (( i=0; i<filled; i++ )); do bar+="█"; done
  for (( i=filled; i<w; i++ )); do bar+="░"; done
  printf '%s' "${bar}"
}

_fmtdur() {
  local s="$1"
  if [[ "${s}" -ge 3600 ]]; then printf '%dh %dm %ds' $(( s/3600 )) $(( (s%3600)/60 )) $(( s%60 ))
  elif [[ "${s}" -ge 60 ]]; then printf '%dm %ds' $(( s/60 )) $(( s%60 ))
  else printf '%ds' "${s}"; fi
}

# --- Header ---
_render_header() {
  local target="$1" profile="$2" mode="$3" w
  w="$(_tw)"
  if [[ "${_HAS_GUM}" -eq 1 ]]; then
    gum style --bold --foreground 220 "SecForge" --width "${w}" 2>/dev/null || \
      printf '%s%sSecForge%s' "${_B}" "${_YLW}" "${_R}"
  else
    printf '%s%sSecForge%s' "${_B}" "${_YLW}" "${_R}"
  fi
  printf '\n'
  if [[ -n "${target}" ]]; then
    printf '%sTarget:%s %s' "${_D}" "${_R}" "${target}"
    [[ -n "${profile}" ]] && printf '  %sProfile:%s %s' "${_D}" "${_R}" "${profile}"
    [[ -n "${mode}" ]] && printf '  %sMode:%s %s' "${_D}" "${_R}" "${mode}"
    printf '\n'
  fi
  local sep="" i sw=$(( w < 60 ? w : 60 ))
  for (( i=0; i<sw; i++ )); do sep+="─"; done
  printf '%s%s%s\n' "${_D}" "${sep}" "${_R}"
}

# --- Waiting view ---
_render_waiting() {
  printf '\n  %sWaiting for scan to start...%s\n\n' "${_D}" "${_R}"
  printf '  Status file: %s\n' "${_STATUS_FILE}"
  printf '  %sThe scanner will create this file when it begins.%s\n\n' "${_D}" "${_R}"
  printf '  Press %sq%s to quit.\n' "${_B}" "${_R}"
}

# --- Tool line renderer (shared by scan + install views) ---
_tool_line() {
  local st="$1" name="$2" dur="$3" finds="${4:-0}" err="${5:-}"
  case "${st}" in
    ok)
      printf '  %s✓%s %-20s %s(%ss' "${_GRN}" "${_R}" "${name}" "${_D}" "${dur}"
      [[ "${finds}" -gt 0 ]] && printf ', %d findings' "${finds}"
      printf ')%s\n' "${_R}" ;;
    fail)
      printf '  %s✗%s %-20s' "${_RED}" "${_R}" "${name}"
      [[ -n "${err}" ]] && printf ' %s%s%s' "${_RED}" "${err}" "${_R}"
      printf '\n' ;;
    running)
      printf '  %s●%s %-20s %s...running%s\n' "${_CYN}" "${_R}" "${name}" "${_D}" "${_R}" ;;
    installing)
      printf '  %s●%s %-20s %s...installing%s\n' "${_CYN}" "${_R}" "${name}" "${_D}" "${_R}" ;;
    *)
      printf '  %s○%s %s\n' "${_D}" "${_R}" "${name}" ;;
  esac
}

# --- Scan progress view ---
_render_scanning() {
  local done=0 i
  for (( i=0; i<TOOL_COUNT; i++ )); do
    local sv="TOOL_${i}_STATUS"
    [[ "${!sv}" == "ok" || "${!sv}" == "fail" ]] && (( done++ ))
  done
  local total="${TOOLS_TOTAL}"; [[ "${total}" -le 0 ]] && total="${TOOL_COUNT}"
  local compact=0; [[ "$(_tw)" -lt 60 ]] && compact=1

  printf '\n'
  if [[ "${compact}" -eq 0 ]]; then
    printf '  %s[%d/%d]%s %s ' "${_B}" "${done}" "${total}" "${_R}" "$(_pbar "${done}" "${total}" 20)"
    [[ "${EST_SECONDS}" -gt 0 ]] && printf '  Est: ~%s' "$(_fmtdur "${EST_SECONDS}")"
    printf '\n\n'
  else
    printf '  [%d/%d] %s\n\n' "${done}" "${total}" "$(_pbar "${done}" "${total}" 12)"
  fi

  # Tier 2 banner
  if [[ "${TIER2_STATE}" == "prompt" ]]; then
    local bw=$(( $(_tw) < 50 ? $(_tw) - 4 : 45 )) border="" j
    for (( j=0; j<bw; j++ )); do border+="═"; done
    printf '\n  %s%s%s%s\n' "${_YLW}" "${_B}" "${border}" "${_R}"
    printf '  %s%s  TIER 2 ACTIVE TESTING%s\n' "${_YLW}" "${_B}" "${_R}"
    printf '  %s  Type YES in the main pane to proceed%s\n' "${_D}" "${_R}"
    printf '  %s%s%s%s\n\n' "${_YLW}" "${_B}" "${border}" "${_R}"
  fi

  # Tool list (capped to terminal height)
  local mx=$(( $(_th) - 10 )); [[ "${mx}" -lt 5 ]] && mx=5
  for (( i=0; i<TOOL_COUNT && i<mx; i++ )); do
    local nv="TOOL_${i}_NAME" sv="TOOL_${i}_STATUS" dv="TOOL_${i}_DUR"
    local fv="TOOL_${i}_FINDINGS" ev="TOOL_${i}_ERROR"
    _tool_line "${!sv}" "${!nv}" "${!dv}" "${!fv}" "${!ev:-}"
  done
  [[ "${total}" -gt "${TOOL_COUNT}" ]] && \
    printf '  %s... %d more pending%s\n' "${_D}" $(( total - TOOL_COUNT )) "${_R}"
}

# --- Scan done / summary ---
_render_done() {
  printf '\n  %s%sScan Complete!%s' "${_GRN}" "${_B}" "${_R}"
  [[ "${SCAN_DURATION}" -gt 0 ]] && printf ' (%s)' "$(_fmtdur "${SCAN_DURATION}")"
  printf '\n\n'

  if [[ "${TOTAL_FINDINGS}" -gt 0 ]]; then
    printf '  %d findings:\n' "${TOTAL_FINDINGS}"
    [[ "${SEV_CRITICAL:-0}" -gt 0 ]] && printf '    %s%s■%s %d critical\n' "${_RED}" "${_B}" "${_R}" "${SEV_CRITICAL}"
    [[ "${SEV_HIGH:-0}" -gt 0 ]]     && printf '    %s■%s %d high\n' "${_RED}" "${_R}" "${SEV_HIGH}"
    [[ "${SEV_MEDIUM:-0}" -gt 0 ]]   && printf '    %s■%s %d medium\n' "${_YLW}" "${_R}" "${SEV_MEDIUM}"
    [[ "${SEV_LOW:-0}" -gt 0 ]]      && printf '    %s■%s %d low\n' "${_BLU}" "${_R}" "${SEV_LOW}"
    [[ "${SEV_INFO:-0}" -gt 0 ]]     && printf '    %s■%s %d info\n' "${_D}" "${_R}" "${SEV_INFO}"
  else
    printf '  %sNo findings reported yet. Run merge-reports to generate findings.%s\n' "${_D}" "${_R}"
  fi

  # Tool summary
  if [[ "${TOOL_COUNT}" -gt 0 ]]; then
    local ok=0 fail=0 i
    for (( i=0; i<TOOL_COUNT; i++ )); do
      local sv="TOOL_${i}_STATUS"
      case "${!sv}" in ok) (( ok++ )) ;; fail) (( fail++ )) ;; esac
    done
    printf '\n  Tools: %d ran' "${TOOL_COUNT}"
    [[ "${fail}" -gt 0 ]] && printf ', %s%d failed%s' "${_RED}" "${fail}" "${_R}"
    printf '\n'
  fi

  printf '\n  %sNext steps:%s\n' "${_B}" "${_R}"
  printf '    Tell Claude: %s"show me the results"%s\n' "${_CYN}" "${_R}"
  printf '    Or run: %ssecforge list%s / %ssecforge export --mode full-plan%s\n\n' \
    "${_CYN}" "${_R}" "${_CYN}" "${_R}"
}

# --- Install progress ---
_render_installing() {
  local total="${INSTALL_TOTAL}"; [[ "${total}" -le 0 ]] && total=1
  printf '\n  %sInstalling %d tools...%s\n\n  %s\n\n' \
    "${_B}" "${total}" "${_R}" "$(_pbar "${INSTALL_COUNT}" "${total}" 20)"
  local i
  for (( i=0; i<INSTALL_COUNT; i++ )); do
    local nv="INST_${i}_NAME" sv="INST_${i}_STATUS" dv="INST_${i}_DUR"
    _tool_line "${!sv}" "${!nv}" "${!dv}"
  done
  local rem=$(( total - INSTALL_COUNT ))
  [[ "${rem}" -gt 0 ]] && printf '  %s... %d remaining%s\n' "${_D}" "${rem}" "${_R}"
}

# --- Verification ---
_render_verifying() {
  printf '\n  %sVerifying%s %s' "${_B}" "${_R}" "${VERIFY_PACK}"
  [[ "${VERIFY_TOTAL}" -gt 0 ]] && printf ' (%d checks)' "${VERIFY_TOTAL}"
  printf '\n\n  %sChecking...%s\n' "${_D}" "${_R}"
}

_render_verify_complete() {
  printf '\n  %sVerification Complete:%s %s\n\n' "${_B}" "${_R}" "${VERIFY_PACK}"
  [[ "${VERIFY_PASSED}" -gt 0 ]] && printf '  %s✓ %d passed%s\n' "${_GRN}" "${VERIFY_PASSED}" "${_R}"
  [[ "${VERIFY_FAILED}" -gt 0 ]] && printf '  %s✗ %d failed%s\n' "${_RED}" "${VERIFY_FAILED}" "${_R}"
  local tot=$(( VERIFY_PASSED + VERIFY_FAILED ))
  [[ "${tot}" -le 0 ]] && tot="${VERIFY_TOTAL}"
  [[ "${tot}" -gt 0 ]] && printf '\n  Results: %d/%d passed\n' "${VERIFY_PASSED}" "${tot}"
  printf '\n'
}

# --- Main render dispatch ---
render_dashboard() {
  _cls
  eval "$(_parse_status "${_STATUS_FILE}")"
  _render_header "${TARGET:-}" "${PROFILE:-}" "${SCAN_MODE:-}"
  case "${STATE:-waiting}" in
    waiting)          _render_waiting ;;
    scanning)         _render_scanning ;;
    done)             _render_done ;;
    installing|install_complete) _render_installing ;;
    verifying)        _render_verifying ;;
    verify_complete)  _render_verify_complete ;;
    *)                _render_waiting ;;
  esac
  printf '\n%s  Press q to quit%s\n' "${_D}" "${_R}"
}

# --- Tool selection (--select) ---
_run_select() {
  local tools_json="${SECFORGE_ROOT}/catalog/tools.json"
  [[ ! -r "${tools_json}" ]] && sf_die "Cannot read ${tools_json}"

  if [[ "${_HAS_GUM}" -eq 1 ]]; then
    local choices selected ids
    choices="$(python3 - "${tools_json}" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
for tid, info in sorted(data.items()):
    if tid.startswith("_"): continue
    print(f"{tid}\t{info.get('title',tid)} (tier {info.get('tier',1)}) — {info.get('description','')[:50]}")
PY
)"
    selected="$(echo "${choices}" | gum choose --no-limit \
      --header "Select tools to install (space to toggle, enter to confirm)" \
      --cursor-prefix "[ ] " --selected-prefix "[x] " \
      --unselected-prefix "[ ] " 2>/dev/null || true)"
    if [[ -z "${selected}" ]]; then echo "No tools selected."; return 0; fi
    ids="$(echo "${selected}" | awk -F'\t' '{print $1}')"
    local sel_file="/tmp/secforge-dashboard-$$.selection"
    echo "${ids}" > "${sel_file}"
    echo "Selected: $(echo "${ids}" | tr '\n' ' ')"
    echo "Selection written to: ${sel_file}"
  else
    # Plain text numbered list
    echo ""; echo "Available tools:"; echo ""
    local tool_ids=() tool_titles=()
    while IFS=$'\t' read -r tid title; do
      tool_ids+=("${tid}"); tool_titles+=("${title}")
    done < <(python3 - "${tools_json}" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
for tid, info in sorted(data.items()):
    if tid.startswith("_"): continue
    print(f"{tid}\t{info.get('title',tid)} (tier {info.get('tier',1)})")
PY
)
    local i
    for (( i=0; i<${#tool_ids[@]}; i++ )); do
      printf '  %3d) %s\n' $(( i + 1 )) "${tool_titles[$i]}"
    done
    echo ""; printf 'Enter numbers separated by spaces (e.g. "1 3 5"), or "all": '
    local reply
    if [[ -r /dev/tty ]]; then read -r reply < /dev/tty || true
    else read -r reply || true; fi
    if [[ -z "${reply}" ]]; then echo "No tools selected."; return 0; fi

    local ids=""
    if [[ "${reply}" == "all" ]]; then
      ids="${tool_ids[*]}"
    else
      for num in ${reply}; do
        if [[ "${num}" =~ ^[0-9]+$ ]]; then
          local idx=$(( num - 1 ))
          [[ "${idx}" -ge 0 && "${idx}" -lt "${#tool_ids[@]}" ]] && ids+="${tool_ids[$idx]} "
        fi
      done
    fi
    ids="$(echo "${ids}" | xargs)"
    if [[ -z "${ids}" ]]; then echo "No valid tools selected."; return 0; fi
    local sel_file="/tmp/secforge-dashboard-$$.selection"
    # Write one tool ID per line (matches install-tools.sh --from-selection format)
    printf '%s\n' ${ids} > "${sel_file}"
    echo ""; echo "Selected: ${ids}"; echo "Selection written to: ${sel_file}"
  fi
}

# --- Lifecycle ---
_cleanup() { _scur; }
trap _cleanup EXIT
trap 'render_dashboard 2>/dev/null || true' WINCH

_run_monitor() {
  [[ -n "${TMUX:-}" ]] && tmux select-pane -T secforge-dashboard 2>/dev/null || true
  _hcur; render_dashboard
  local last_mt="" last_sz=""
  while true; do
    if read -rsn1 -t 0.8 key 2>/dev/null; then
      [[ "${key}" == "q" || "${key}" == "Q" ]] && { _cls; _scur; printf 'Dashboard closed.\n'; exit 0; }
    fi
    local mt="" sz=""
    if [[ -f "${_STATUS_FILE}" ]]; then
      mt="$(stat -c %Y "${_STATUS_FILE}" 2>/dev/null || echo 0)"
      sz="$(stat -c %s "${_STATUS_FILE}" 2>/dev/null || echo 0)"
    fi
    [[ "${mt}" != "${last_mt}" || "${sz}" != "${last_sz}" ]] && { render_dashboard; last_mt="${mt}"; last_sz="${sz}"; }
  done
}

# --- CLI dispatch ---
case "${1:---start}" in
  --start) shift 2>/dev/null || true; _resolve_status_file "start" "${1:-}"; _run_monitor ;;
  --last)  _resolve_status_file "last"; _run_monitor ;;
  --select) _run_select ;;
  -h|--help)
    cat <<'EOF'
SecForge Dashboard — Live TUI Renderer

Usage:
  dashboard.sh --start [<session-dir>]   Monitor scan progress
  dashboard.sh --last                     Monitor latest scan
  dashboard.sh --select                   Interactive tool selection

Controls:  q / Q  Quit dashboard
Environment:  SECFORGE_ROOT  Override SecForge install path
EOF
    ;;
  *) sf_die "Unknown dashboard command: $1. Use --start, --last, or --select." ;;
esac
