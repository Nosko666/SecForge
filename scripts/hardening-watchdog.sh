#!/usr/bin/env bash
set -euo pipefail

umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=/dev/null
. "${SCRIPT_DIR}/_lib.sh"

sf_usage() {
  cat >&2 <<'EOF'
Usage:
  hardening-watchdog.sh --heartbeat <file> --timeout-seconds <n> --map-file <file>

The watchdog reverts critical config files if the heartbeat stops being updated.

Map file format (one per line):
  DEST_PATH|BACKUP_PATH|SERVICE

Example:
  /etc/ssh/sshd_config|/opt/secforge/backups/SESSION/sshd_config.bak|sshd
  /etc/fail2ban/jail.local|/opt/secforge/backups/SESSION/jail.local.bak|fail2ban

Heartbeat usage:
  touch <heartbeat_file> periodically while hardening is in progress.
EOF
}

sf_file_mtime_epoch() {
  local path="$1"
  python3 - "$path" <<'PY'
import os, sys
try:
  print(int(os.path.getmtime(sys.argv[1])))
except Exception:
  print(0)
PY
}

sf_now_epoch() {
  date +%s
}

main() {
  sf_need_root

  local heartbeat="" timeout_s="" map_file=""

  while [[ "${#}" -gt 0 ]]; do
    case "$1" in
      --heartbeat) heartbeat="${2:-}"; shift 2 ;;
      --timeout-seconds) timeout_s="${2:-}"; shift 2 ;;
      --map-file) map_file="${2:-}"; shift 2 ;;
      -h|--help) sf_usage; exit 0 ;;
      *) sf_warn "Unknown argument: $1"; sf_usage; exit 2 ;;
    esac
  done

  if [[ -z "${heartbeat}" || -z "${timeout_s}" || -z "${map_file}" ]]; then
    sf_usage
    exit 2
  fi

  if [[ ! -r "${map_file}" ]]; then
    sf_die "Map file not readable: ${map_file}"
  fi

  if [[ ! -e "${heartbeat}" ]]; then
    sf_warn "Heartbeat file missing; creating: ${heartbeat}"
    : >"${heartbeat}"
  fi

  sf_log "Hardening watchdog started (timeout=${timeout_s}s, heartbeat=${heartbeat})"

  while true; do
    local now mtime delta
    now="$(sf_now_epoch)"
    mtime="$(sf_file_mtime_epoch "${heartbeat}")"
    delta=$((now - mtime))

    if [[ "${delta}" -gt "${timeout_s}" ]]; then
      sf_warn "Heartbeat stale (${delta}s > ${timeout_s}s). Reverting mapped configs..."

      while IFS='|' read -r dest backup svc; do
        [[ -z "${dest}" || "${dest}" == \#* ]] && continue
        if [[ -r "${backup}" ]]; then
          sf_log "Reverting ${dest} from ${backup}"
          cp -f "${backup}" "${dest}" || sf_warn "Failed to restore ${dest}"
          if [[ -n "${svc}" ]] && sf_has_cmd systemctl; then
            systemctl restart "${svc}" >/dev/null 2>&1 || sf_warn "Failed to restart ${svc}"
          fi
        else
          sf_warn "Backup missing for ${dest}: ${backup}"
        fi
      done <"${map_file}"

      sf_warn "Revert complete. Exiting watchdog."
      exit 0
    fi

    sleep 5
  done
}

main "$@"

