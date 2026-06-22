# ACLGuard

C-based Active Directory group membership and permission analyzer for security posture assessment.

## Overview

ACLGuard connects to Active Directory via LDAP, enumerates users and their group memberships, and identifies risky permission assignments (admin access, password reset rights, ACL modification, etc.). It is designed for **detection engineers, system administrators, and purple teams** who need fast, reliable AD permission visibility without the overhead of larger frameworks like BloodHound or PingCastle.

The tool focuses on **repeatable, consistent output** — critical for regression testing, continuous assessment workflows, and evidence-based reporting.

## What It Does

- Enumerates high-risk group memberships and permission configurations
- Identifies direct privilege escalation paths from low-privilege to high-privilege principals (note: transitive/nested group resolution is not yet implemented)
- Exports findings in CSV and JSON (for programmatic consumption)
- Single C binary with no runtime dependencies beyond standard libraries and LDAP

## Why ACLGuard

Most AD security tools are either:
- **Heavy frameworks** (BloodHound, ADRecon) that require .NET, neo4j, or extensive setup
- **One-off scripts** that are not reproducible or testable

ACLGuard is intentionally lightweight: compile once, run anywhere you have LDAP access. The CSV/JSON output is designed for integration into larger assessment workflows — import into Splunk, feed into CI/CD security gates, or diff against previous runs to detect permission drift.

## Build

```bash
make clean && make
```

Or compile directly:
```bash
gcc -Isrc -Iinclude -o aclguard src/*.c -lldap -llber -ljson-c
```



## Configuration

Set environment variables:
```bash
export ACLGUARD_LDAP_URI="ldap://your-ad-server:389"
export ACLGUARD_BIND_DN="CN=Administrator,CN=Users,DC=corp,DC=domain,DC=com"
export ACLGUARD_BIND_PW="your_password"
export ACLGUARD_BASE_DN="DC=corp,DC=domain,DC=com"
```

Or source a config file:
```bash
source config.env
```

## Usage

```bash
# Run with mock data (no AD server needed)
./aclguard --mock status
./aclguard --mock alerts --recent

# Connect to AD and export findings
source config.env && ./aclguard --export-csv findings.csv
source config.env && ./aclguard --export-json findings.json

# New CLI subcommands (requires AD connection)
./aclguard status
./aclguard alerts --recent
./aclguard metrics --throughput

# JSON output for programmatic processing
./aclguard status --json
```

**JSON** (for automation):
```json
[
  {
    "username": "jdoe",
    "cn": "John Doe",
    "email": "jdoe@corp.com",
    "groups": "CN=Domain Admins,CN=Users,DC=corp,DC=com",
    "isAdmin": 1,
    "canResetPasswords": 0,
    "canModifyACLs": 0,
    "canDelegateAuth": 0,
    "hasServiceAcct": 0,
    "canReadSecrets": 0,
    "canWriteSecrets": 0,
    "risk": 40,
    "mitre_attack_id": "T1078.002",
    "mitre_attack_name": "Valid Accounts: Domain Accounts"
  }
]
```

**CSV** (for reporting):
```csv
Username,CN,Email,Groups,IsAdmin,CanResetPass,CanModifyACL,CanDelegate,HasServiceAcct,CanReadSecrets,CanWriteSecrets,Risk,MITRE_Attack_ID,MITRE_Attack_Name
jdoe,John Doe,jdoe@corp.com,"CN=Domain Admins,CN=Users,DC=corp,DC=com",1,0,0,0,0,0,0,40,T1078.002,Valid Accounts: Domain Accounts
```


## CI/CD Integration

ACLGuard's 55K binary, zero runtime dependencies, and deterministic output make it ideal for CI/CD security gates.

**GitHub Actions example — fail build if high-risk admin accounts found:**
```yaml
name: AD Permission Audit
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6 AM UTC
  workflow_dispatch:      # Manual trigger

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Check out ACLGuard
        uses: actions/checkout@v4
      - name: Install dependencies
        run: sudo apt-get update && sudo apt-get install -y libldap2-dev libjson-c-dev
      - name: Build
        run: make clean && make
      - name: Run AD permission audit
        run: |
          ./aclguard --export-json audit.json
        env:
          ACLGUARD_LDAP_URI: ${{ secrets.AD_LDAP_URI }}
          ACLGUARD_BIND_DN: ${{ secrets.AD_BIND_DN }}
          ACLGUARD_BIND_PW: ${{ secrets.AD_BIND_PW }}
          ACLGUARD_BASE_DN: ${{ secrets.AD_BASE_DN }}
      - name: Check for high-risk findings
        run: |
          HIGH_RISK=$(jq '[.[] | select(.risk >= 60)] | length' audit.json)
          if [ "$HIGH_RISK" -gt 0 ]; then
            echo "FAIL: $HIGH_RISK high-risk accounts found!"
            exit 1
          fi
          echo "PASS: No high-risk accounts detected."
```

## MITRE ATT&CK Mapping

ACLGuard maps each user's highest-risk permission to a MITRE ATT&CK technique:

| Permission | MITRE ID | Technique |
|------------|----------|-----------|
| Admin (Domain/Enterprise Admins) | T1078.002 | Valid Accounts: Domain Accounts |
| Password Reset | T1098 | Account Manipulation |
| ACL Modification | T1484 | Domain Policy Modification |
| Authentication Delegation | T1484.001 | Group Policy Modification |
| Service Account | T1558.003 | Kerberoasting |
| Write Secrets | T1098 | Account Manipulation |
| Read Secrets | T1552 | Unsecured Credentials |

This enables detection engineers to:
- Map audit findings directly to alerting rules
- Prioritize remediation by technique prevalence
- Cross-reference with existing SIEM detections

## Where ACLGuard Fits

| Tool | Deployment | ACL Depth | Transitive | CI/CD Ready |
|------|-----------|-----------|------------|-------------|
| **ACLGuard** | Single 55K binary | Group analysis | No | Yes |
| BloodHound CE | Neo4j + Electron | Full ACE | Yes | No |
| PingCastle | .NET Runtime | Full | Yes | Partial |
| PurpleKnight | SaaS | Full | Yes | Yes |
| ADRecon | PowerShell | Partial | No | No |

**ACLGuard's niche**: Lightweight, dependency-free AD security auditing for CI/CD pipelines. Run it in seconds — no database, no runtime, no SaaS setup.

## Current Limitations

- **Group-based analysis only**: Does not parse raw DACL/ACE entries (no GenericAll, WriteDacl, WriteOwner detection)
- **Direct paths only**: No transitive/nested group membership resolution
- **AD only**: No Entra ID / Azure AD support
- **No LDAPS**: Credentials sent in cleartext (use in trusted networks only)
- **Single domain**: No multi-forest or cross-domain queries


## Use Cases

- **Detection engineering**: Permission analysis output helps write targeted detection rules (Sigma, Splunk) for specific AD abuse techniques (T1098, T1484, etc.)
- **Purple team assessments**: Identify over-privileged accounts and weak permission boundaries
- **Continuous validation**: Scheduled runs to detect permission drift between assessments
- **CI/CD security gates**: Run in pipeline, fail build if risk threshold exceeded
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
