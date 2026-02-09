# ACLGuard — Offense-Led AD ACL Risk Discovery

ACLGuard helps red team operators surface **Active Directory ACL misconfigurations** that frequently enable real-world escalation paths (for example: `GenericAll`, `WriteDACL`, `WriteOwner`).

It’s designed to be **lightweight, scriptable, and report-friendly**:
enumerate → flag high-risk relationships → export structured output for triage and writeups.

> Authorized testing only. Do not run ACLGuard against systems you do not own or have explicit permission to assess.

---

## Why this exists

In enterprise AD, “small” delegation mistakes can become quiet, reliable privilege escalation paths.
ACLGuard’s goal is to make those paths easier to **identify, validate, and explain** during offensive assessments.

What I optimize for:
- **Operator speed**: fast enumeration + usable on-screen summary
- **Clear artifacts**: CSV/JSON you can drop into reporting workflows
- **Repeatable methodology**: consistent steps and assumptions

---

## What it does

- Enumerates AD objects and associated ACLs via LDAP
- Flags high-risk permissions commonly associated with escalation primitives
- Exports results to **CSV** and/or **JSON**
- Prints a concise summary for quick review

---

## Quickstart (Mock)
```bash
make clean && make
./aclguard --mock status
./aclguard --mock alerts --recent
./aclguard --mock correlate --attack kerberoasting
./aclguard --mock analyze --incident latest
./aclguard --mock metrics --throughput
```

## Quickstart (LDAP)
```bash
# configure env vars (see .env.example)
source config.env

./aclguard status
./aclguard alerts --recent
./aclguard correlate --attack kerberoasting
./aclguard analyze --incident latest
./aclguard metrics --throughput
```

## JSON Output
All subcommands support `--json` and emit pure JSON with a `summary` field.
```bash
./aclguard status --json
./aclguard --mock alerts --recent --json
```

## External Alert Inputs (LDAP)
You can merge alerts from an external source by providing a JSON file.
```bash
export ACLGUARD_ALERTS_FILE=/path/to/alerts.json
./aclguard alerts --recent --json
```
Accepted formats:
- `{"data": {"recent": [ ... ]}}`
- `[ ... ]`

## Metrics Overrides (LDAP)
Set calibrated metrics explicitly if you have known values.
```bash
export ACLGUARD_METRIC_ACCURACY=0.92
export ACLGUARD_METRIC_PRECISION=0.90
export ACLGUARD_METRIC_RECALL=0.88
./aclguard metrics --accuracy --json
```
Note: default accuracy is coverage (percent of users classified), not ground-truth precision.

## Deterministic Scan Time (LDAP)
Provide a fixed scan time for consistent outputs.
```bash
export ACLGUARD_SCAN_TIME="2026-02-01T09:00:00Z"
./aclguard status --json
```

---

## Demo Script
```bash
scripts/demo_mock.sh
```

## Simulation Script
The simulator deterministically updates the mock fixtures and changes the alerts flow.
```bash
scripts/simulate_kerberoasting.py
./aclguard --mock alerts --recent
```

## Tests
```bash
make test
```

## LDAP Mode (Legacy Export)
Legacy LDAP export flags still work, but are deprecated in favor of the new CLI.
```bash
./aclguard --export-csv --export-json
```

---

## Output
ACLGuard generates artifacts suitable for reporting and attack surface review:
- `aclguard_results.csv`
- `aclguard_results.json`

If you publish output, sanitize it first (domains, hostnames, DNs, usernames, GUIDs/SIDs, etc.).

Example (sanitized):
```text
[SUMMARY]
Objects scanned: 1,247
Findings: 19 high-risk relationships

[TOP FINDINGS]
- User: jdoe -> Group: HelpdeskTier1 (WriteDACL)
- Group: AppAdmins -> Computer: SQL01 (GenericAll)
- User: svc_backup -> OU: Workstations (WriteOwner)
```

---

## Limitations
- AD ACL interpretation is nuanced; treat findings as leads to verify, not automatic exploitation.
- Some edge cases (inheritance, protected objects, unusual delegation patterns) require manual validation.
- Large environments may require scoping to reduce noise and runtime.

## Roadmap (minimal, credible)
- v1.1: improve output clarity (grouping/sorting), add “why risky” context per finding
- v1.2: optional scoping (OU base DN, object class filters), better summary statistics
- v2.0: optional graph export integration for visual review (kept modular)

## Documentation
- Legacy documentation: README_v1.0.md
- Wiki: wiki/

## Disclaimer
ACLGuard is intended for educational use and authorized security testing only.
All examples and outputs in this repo should be sanitized before publication.

## License
MIT — see MIT_LICENSE.
