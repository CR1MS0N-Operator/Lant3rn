# ACLGuard

C-based Active Directory ACL analyzer for privilege escalation path enumeration.

## Overview

ACLGuard analyzes Discretionary Access Control List (DACL) configurations in Active Directory environments to identify permission relationships that enable privilege escalation. It is designed for red team operators and security assessors who need fast, reliable ACL enumeration without the overhead of larger frameworks like BloodHound.

The tool focuses on **repeatable, consistent output** — critical for regression testing, continuous assessment workflows, and evidence-based reporting.

## What It Does

- Enumerates high-risk permission relationships (GenericAll, WriteDacl, WriteOwner, etc.)
- Identifies direct and transitive privilege escalation paths from low-privilege to high-privilege principals
- Exports findings in CSV (for Excel/Splunk) and JSON (for programmatic consumption)
- Single C binary with no runtime dependencies beyond standard libraries and LDAP

## Why ACLGuard

Most AD security tools are either:
- **Heavy frameworks** (BloodHound, ADRecon) that require .NET, neo4j, or extensive setup
- **One-off scripts** that are not reproducible or testable

ACLGuard is intentionally lightweight: compile once, run anywhere you have LDAP access. The CSV/JSON output is designed for integration into larger assessment workflows — import into Splunk, feed into CI/CD security gates, or diff against previous runs to detect permission drift.

## Build

```bash
gcc -o aclguard aclguard.c -lldap
```

## Usage

```bash
# JSON output for programmatic processing
./aclguard -d CORP.DOMAIN.COM -o findings.json

# CSV output for reporting and spreadsheet analysis
./aclguard -d CORP.DOMAIN.COM -c findings.csv
```

## Output Format

**JSON** (for automation):
```json
{
  "domain": "CORP.DOMAIN.COM",
  "timestamp": "2026-05-20T12:00:00Z",
  "findings": [
    {
      "type": "GenericAll",
      "source": "CN=HelpDesk,OU=Groups,DC=CORP,DC=DOMAIN,DC=COM",
      "target": "CN=Domain Admins,CN=Users,DC=CORP,DC=DOMAIN,DC=COM",
      "exploitation_path": "HelpDesk group has full control over Domain Admins"
    }
  ]
}
```

**CSV** (for reporting):
```csv
Type,Source,Target,ExploitationPath
GenericAll,CN=HelpDesk...,CN=Domain Admins...,HelpDesk group has full control over Domain Admins
```

## Use Cases

- **Penetration testing**: Quick ACL enumeration during internal assessments
- **Continuous validation**: Scheduled runs to detect permission drift between assessments
- **Red team operations**: Lightweight enumeration on compromised endpoints where .NET/neo4j are unavailable
- **Compliance evidence**: Consistent, timestamped output for audit trails

## Design Principles

- **Minimal dependencies**: Standard C library + LDAP. No .NET, no Java, no database.
- **Consistent output**: Same input → same output. Essential for diffing and regression testing.
- **Toolchain-agnostic exports**: CSV and JSON are universal. Integrate with whatever stack you already use.
- **Read-only operations**: ACLGuard only queries AD. It does not modify permissions, create objects, or authenticate beyond the initial bind.

## Security Note

ACLGuard performs LDAP queries against Active Directory. You need valid domain credentials with read access to the directory. The tool does not exploit vulnerabilities — it reveals misconfigurations in existing permission structures. Use only on systems you own or have explicit authorization to test.

## License

MIT
