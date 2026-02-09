#!/usr/bin/env bash
set -euo pipefail

# Minimal smoke test for ACLGuard mock CLI
# - builds
# - runs mock subcommands
# - validates JSON output shape

echo "[*] Building..."
make clean && make

echo "[*] Running mock status..."
OUT="$(./aclguard --mock status --json)"
echo "$OUT" | grep -q "\"summary\""
echo "$OUT" | grep -q "\"data\""

echo "[*] Running mock alerts..."
OUT="$(./aclguard --mock alerts --recent --json)"
echo "$OUT" | grep -q "\"summary\""
echo "$OUT" | grep -q "\"recent\""

echo "[*] Running mock correlate..."
OUT="$(./aclguard --mock correlate --attack kerberoasting --json)"
echo "$OUT" | grep -q "\"summary\""
echo "$OUT" | grep -q "\"incident_id\""

echo "[*] Running mock analyze..."
OUT="$(./aclguard --mock analyze --incident latest --json)"
echo "$OUT" | grep -q "\"summary\""
echo "$OUT" | grep -q "\"title\""

echo "[*] Running mock metrics..."
OUT="$(./aclguard --mock metrics --throughput --json)"
echo "$OUT" | grep -q "\"summary\""
echo "$OUT" | grep -q "\"metric\""

echo "[*] Running simulation script..."
python3 scripts/simulate_kerberoasting.py >/dev/null
OUT="$(./aclguard --mock alerts --recent --json)"
echo "$OUT" | grep -q "AL-1004"

# exit success (so test doesn't fail your CI by default)
exit 0
