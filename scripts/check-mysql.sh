#!/usr/bin/env bash
set -euo pipefail

umask 022

now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mysql_bin="${MYSQL_BIN:-mysql}"
if ! command -v "${mysql_bin}" >/dev/null 2>&1; then
  python3 - <<PY
import json
print(json.dumps({
  "timestamp_utc": ${now!r},
  "status": "error",
  "error": "mysql client not found",
  "hint": "Install default-mysql-client (SecForge Category 13).",
}, indent=2, sort_keys=True))
PY
  exit 0
fi

mysql_cmd=("${mysql_bin}" --batch --skip-column-names)

if [[ -n "${MYSQL_DEFAULTS_FILE:-}" && -r "${MYSQL_DEFAULTS_FILE}" ]]; then
  mysql_cmd+=("--defaults-extra-file=${MYSQL_DEFAULTS_FILE}")
fi

if [[ -n "${MYSQL_SOCKET:-}" ]]; then
  mysql_cmd+=(--protocol=socket "--socket=${MYSQL_SOCKET}")
fi
if [[ -n "${MYSQL_HOST:-}" ]]; then
  mysql_cmd+=("-h" "${MYSQL_HOST}")
fi
if [[ -n "${MYSQL_PORT:-}" ]]; then
  mysql_cmd+=("-P" "${MYSQL_PORT}")
fi
if [[ -n "${MYSQL_USER:-}" ]]; then
  mysql_cmd+=("-u" "${MYSQL_USER}")
fi

mysql_query() {
  local q="$1"
  if [[ -n "${MYSQL_PASSWORD:-}" ]]; then
    MYSQL_PWD="${MYSQL_PASSWORD}" "${mysql_cmd[@]}" -e "${q}" 2>/dev/null || true
  else
    "${mysql_cmd[@]}" -e "${q}" 2>/dev/null || true
  fi
}

conn_test="$(mysql_query "SELECT 1;")"
if [[ "${conn_test}" != "1" ]]; then
  python3 - <<PY
import json
print(json.dumps({
  "timestamp_utc": ${now!r},
  "status": "error",
  "error": "could not connect to MySQL with current credentials/method",
  "hints": [
    "If MySQL uses unix_socket auth, re-run as root (or with sudo) so it can connect locally.",
    "Or set MYSQL_DEFAULTS_FILE to a readable .cnf file with credentials.",
    "Or set MYSQL_USER and MYSQL_PASSWORD (avoid putting passwords in shell history).",
  ],
}, indent=2, sort_keys=True))
PY
  exit 0
fi

version="$(mysql_query "SELECT VERSION();" | head -n1 || true)"

has_col() {
  local col="$1"
  local n
  n="$(mysql_query "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='mysql' AND table_name='user' AND column_name='${col}';" | head -n1 || true)"
  [[ "${n}" =~ ^[0-9]+$ ]] && [[ "${n}" -gt 0 ]]
}

has_table() {
  local tbl="$1"
  local n
  n="$(mysql_query "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='mysql' AND table_name='${tbl}';" | head -n1 || true)"
  [[ "${n}" =~ ^[0-9]+$ ]] && [[ "${n}" -gt 0 ]]
}

anonymous_count="$(mysql_query "SELECT COUNT(*) FROM mysql.user WHERE User='';" | head -n1 || echo "")"
remote_root_count="$(mysql_query "SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" | head -n1 || echo "")"

users_no_pass_count=""
if has_col "authentication_string" && has_col "plugin"; then
  users_no_pass_count="$(mysql_query "SELECT COUNT(*) FROM mysql.user WHERE User<>'' AND plugin NOT LIKE '%socket%' AND (authentication_string IS NULL OR authentication_string='');" | head -n1 || true)"
elif has_col "Password"; then
  users_no_pass_count="$(mysql_query "SELECT COUNT(*) FROM mysql.user WHERE User<>'' AND (Password IS NULL OR Password='');" | head -n1 || true)"
fi

test_db_count="$(mysql_query "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='test' OR schema_name LIKE 'test\\_%';" | head -n1 || echo "")"

require_secure_transport_val=""
rst_line="$(mysql_query "SHOW VARIABLES LIKE 'require_secure_transport';" | head -n1 || true)"
if [[ -n "${rst_line}" ]]; then
  require_secure_transport_val="$(awk '{print $2}' <<<"${rst_line}" || true)"
fi

super_non_root_count=""
if has_col "Super_priv"; then
  super_non_root_count="$(mysql_query "SELECT COUNT(*) FROM mysql.user WHERE User<>'root' AND Super_priv='Y';" | head -n1 || true)"
elif has_table "global_grants"; then
  # MySQL 8+ may store SUPER-like rights here (best-effort).
  super_non_root_count="$(mysql_query "SELECT COUNT(*) FROM mysql.global_grants WHERE USER<>'root' AND PRIV IN ('SUPER','SYSTEM_USER');" | head -n1 || true)"
fi

python3 - <<PY
import json

def to_int_or_none(v):
  try:
    return int(v)
  except Exception:
    return None

data = {
  "timestamp_utc": ${now!r},
  "status": "ok",
  "mysql_version": ${version!r},
  "checks": {
    "anonymous_accounts_count": to_int_or_none(${anonymous_count!r}),
    "remote_root_accounts_count": to_int_or_none(${remote_root_count!r}),
    "users_without_password_count": to_int_or_none(${users_no_pass_count!r}),
    "test_databases_count": to_int_or_none(${test_db_count!r}),
    "require_secure_transport": ${require_secure_transport_val!r} or None,
    "non_root_super_priv_count": to_int_or_none(${super_non_root_count!r}),
  },
  "notes": [
    "This script does not output password hashes or sensitive table data.",
    "Some MySQL privilege details vary by version; SUPER checks are best-effort.",
  ],
}

print(json.dumps(data, indent=2, sort_keys=True))
PY

