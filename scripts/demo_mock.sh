#!/usr/bin/env bash
set -euo pipefail

make clean && make

./aclguard --mock status
./aclguard --mock alerts --recent
./aclguard --mock correlate --attack kerberoasting
./aclguard --mock analyze --incident latest
./aclguard --mock metrics --throughput

# JSON samples
./aclguard --mock status --json
./aclguard --mock alerts --recent --json
