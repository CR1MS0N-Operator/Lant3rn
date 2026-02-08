# ACLGuard — Offense-Led AD ACL Risk Discovery

ACLGuard helps red team operators surface **Active Directory ACL misconfigurations** that frequently enable
real-world escalation paths (for example: `GenericAll`, `WriteDACL`, `WriteOwner`).

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

## Quick start

### Build

```bash
make clean && make
```

### Configure
Copy the example config and edit placeholders:

```bash
cp examples/config.example.env .env
$EDITOR .env
```
Load the env vars into your shell and run:
```bash
set -a
source .env
set +a
./aclguard
```

### Export results
```bash
./aclguard --export-csv --export-json
```

### Output
**ACLGuard generates artifacts suitable for reporting and attack surface review:**

- aclguard_results.csv

- aclguard_results.json

If you publish output, sanitize it first (domains, hostnames, DNs, usernames, GUIDs/SIDs, etc.).

#### Example (sanitized)
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

### Docs
- Usage
- Methodology

#### Disclaimer
ACLGuard is intended for educational use and authorized security testing only.
All examples and outputs in this repo should be sanitized before publication.

#### License
MIT — see MIT_LICENSE.
