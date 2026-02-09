#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ACLGUARD_LDAP_URI:-}" || -z "${ACLGUARD_BIND_DN:-}" || -z "${ACLGUARD_BIND_PW:-}" || -z "${ACLGUARD_BASE_DN:-}" ]]; then
  echo "[SKIP] LDAP environment not configured. Set ACLGUARD_LDAP_URI, ACLGUARD_BIND_DN, ACLGUARD_BIND_PW, ACLGUARD_BASE_DN." >&2
  exit 0
fi

echo "[*] Building..."
make clean && make

echo "[*] Running LDAP status..."
./aclguard status --json | grep -q '"summary"'

echo "[*] Running LDAP alerts..."
./aclguard alerts --recent --json | grep -q '"summary"'

echo "[*] Running LDAP correlate..."
./aclguard correlate --attack kerberoasting --json | grep -q '"summary"'

echo "[*] Running LDAP analyze..."
./aclguard analyze --incident latest --json | grep -q '"summary"'

echo "[*] Running LDAP metrics..."
./aclguard metrics --throughput --json | grep -q '"summary"'

exit 0
