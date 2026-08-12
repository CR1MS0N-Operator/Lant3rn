# Lantern (ACLGuard)

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Language: C](https://img.shields.io/badge/language-C-555555.svg)
![Version: v2.0.0](https://img.shields.io/badge/version-v2.0.0-informational.svg)

**Lightweight Active Directory permission auditor.** BloodHound-inspired, but smaller and composable: a single static binary, no Neo4j, no .NET. Query AD over LDAP, flag over-privileged principals, score risk 0–100 against MITRE ATT&CK techniques, and export deterministic JSON/CSV for CI gates, SIEM, or research. Part of the [CR1MS0N continuous adversarial validation platform](https://github.com/CR1MS0N-Operator/veil).

Codename **Lantern** marks the next-generation rewrite: a **Go** implementation with a **CLI + TUI** surface and a queryable permission graph (users, groups, computers, and typed privilege edges). The repository currently ships the original C implementation (v2.0.0 "Purple"), which remains the working baseline while the Go rewrite lands incrementally.

## Status

| Aspect | Status |
|--------|--------|
| Current implementation | C, v2.0.0 "Purple" (working baseline) |
| Next generation | **Lantern** — Go rewrite in progress |
| Interfaces | CLI subcommands + JSON/CSV export; TUI planned |
| AD access | LDAP (read-only), mock mode for offline runs |
| CI | GitHub Actions planned (build, vet, tests) |

## Vision

Most AD security tooling is either a heavyweight framework (BloodHound CE: Neo4j + Electron; ADRecon: PowerShell) or a one-off script with no reproducibility. Lantern sits between them:

- **Graph-first**: model principals (users, groups, computers) and the edges that matter (membership, password reset, ACL write, delegation, secret access) as a small, queryable graph — a BloodHound-style picture without the BloodHound footprint.
- **Composable**: every stage is a separate step — collect, build graph, analyze, emit. Pipe JSON between stages, or run the whole pipeline in one command.
- **Two surfaces, one core**: a scriptable CLI for CI/automation and a TUI for interactive exploration of the permission graph.
- **Small by design**: single static binary, zero runtime dependencies, deterministic output. Run it in seconds; diff runs to detect permission drift.

## Portfolio Role — Continuous Adversarial Validation

Lantern is the **identity exposure validation** component of the [CR1MS0N continuous adversarial validation platform](https://github.com/CR1MS0N-Operator/veil): continuous AD permission validation instead of point-in-time audits.

| Framework | Lantern's Role |
|-----------|----------------|
| **CTEM** (Continuous Threat Exposure Management) | **Discover** — LDAP permission enumeration maps the identity attack surface. **Prioritize** — risk scoring (0–100) ranks exposure. **Validate** — privilege-escalation paths confirm which over-permissions are actually exploitable. |
| **TID** (Threat-Informed Defense) | Every finding maps to a MITRE ATT&CK technique (T1078.002, T1098, T1484, T1484.001, T1552, T1558.003) — the vocabulary of threat-informed defense. |
| **FAIR** (Factor Analysis of Information Risk) | High-value principals and escalation paths are **loss magnitude** inputs; exposure likelihood feeds **loss event frequency** — risk = LEF × LM. |
| **AEV** (Adversarial Exposure Validation) | Deterministic JSON and a single static binary make it CI/CD-schedulable: permission-drift detection runs continuously and feeds the agentic validation loop. |

Sibling projects: [Veil](https://github.com/CR1MS0N-Operator/veil) (validation substrate) · [C4](https://github.com/CR1MS0N-Operator/c4) (validation engine) · [NightForge](https://github.com/CR1MS0N-Operator/nightforge) (measurement & mobilization).

## Current Features (C implementation)

- Enumerates AD users and group memberships over LDAP
- Flags high-risk permissions: admin membership, password reset, ACL modification, authentication delegation, service accounts, read/write of sensitive attributes
- Risk scoring (0–100) mapped to MITRE ATT&CK techniques (T1078.002, T1098, T1484, T1484.001, T1552, T1558.003)
- Deterministic JSON/CSV output for regression testing and pipeline integration
- Offline **mock mode** (`--mock`) for development and CI without an AD server

## Quick Start

### Build (C baseline)

```bash
make clean && make
```

Requires `gcc`, `libldap`/`liblber` (OpenLDAP), and `libjson-c` development headers.

### Try it offline (mock mode)

```bash
./aclguard --mock status
./aclguard --mock alerts --recent
./aclguard --mock correlate --attack kerberoasting
./aclguard --mock analyze --incident latest
./aclguard --mock metrics --throughput
```

### Connect to a real directory

```bash
export ACLGUARD_LDAP_URI="ldap://your-ad-server:389"
export ACLGUARD_BIND_DN="CN=Administrator,CN=Users,DC=corp,DC=local"
export ACLGUARD_BIND_PW="your_password"
export ACLGUARD_BASE_DN="DC=corp,DC=local"

./aclguard status
./aclguard alerts --recent
./aclguard correlate --attack kerberoasting
./aclguard analyze --incident latest
./aclguard metrics --throughput
```

Every subcommand accepts `--json` for structured output. Legacy export flags (`--export-csv`/`--export-json`) still work but are deprecated.

## CLI Reference

```
aclguard status [--json]
aclguard alerts --recent [--json]
aclguard correlate --attack <name> [--json]
aclguard analyze --incident <latest|id> [--json]
aclguard metrics --throughput|--accuracy|--scale [--json]
aclguard --mock <subcommand> ...      # offline, no AD required
```

| Subcommand | Purpose |
|------------|---------|
| `status` | Current AD permission posture summary |
| `alerts --recent` | Recent high-risk findings |
| `correlate --attack <name>` | Map findings to a MITRE ATT&CK technique |
| `analyze --incident <latest\|id>` | Incident-style breakdown of a finding |
| `metrics --throughput\|--accuracy\|--scale` | Scan performance/quality metrics |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the planned Go CLI contract and graph model.

## Output

JSON (for automation):

```json
[
  {
    "username": "jdoe",
    "cn": "John Doe",
    "email": "jdoe@corp.local",
    "groups": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
    "isAdmin": 1,
    "canResetPasswords": 0,
    "canModifyACLs": 0,
    "canDelegateAuth": 0,
    "hasServiceAcct": 0,
    "canReadSecrets": 0,
    "mitre_attack_id": "T1078.002",
    "mitre_attack_name": "Valid Accounts: Domain Accounts",
    "canWriteSecrets": 0,
    "risk": 40
  }
]
```

CSV (for reporting): same fields, comma-separated with proper escaping.

## Configuration

All configuration is environment-driven (no config file in the C baseline; the Go rewrite will support a config file):

| Variable | Purpose |
|----------|---------|
| `ACLGUARD_LDAP_URI` | LDAP server URI (e.g. `ldap://host:389`) |
| `ACLGUARD_BIND_DN` | Bind DN for read access |
| `ACLGUARD_BIND_PW` | Bind password |
| `ACLGUARD_BASE_DN` | Base DN for searches |

See [.env.example](.env.example). Never commit real credentials — see [SECURITY.md](SECURITY.md).

## MITRE ATT&CK Mapping

| Permission | MITRE ID | Technique |
|------------|----------|-----------|
| Admin (Domain/Enterprise Admins) | T1078.002 | Valid Accounts: Domain Accounts |
| Password Reset | T1098 | Account Manipulation |
| ACL Modification | T1484 | Domain Policy Modification |
| Authentication Delegation | T1484.001 | Group Policy Modification |
| Service Account | T1558.003 | Kerberoasting |
| Write Secrets | T1098 | Account Manipulation |
| Read Secrets | T1552 | Unsecured Credentials |

## Current Limitations

- **Group-based analysis only**: does not parse raw DACL/ACE entries (no GenericAll, WriteDacl, WriteOwner detection) — full ACE parsing is a Lantern goal
- **Direct paths only**: no transitive/nested group resolution
- **AD only**: no Entra ID / Azure AD
- **No LDAPS yet**: credentials travel in cleartext on `ldap://` — use only on trusted networks; LDAPS/GSSAPI planned
- **Single domain**: no multi-forest or cross-domain queries

## Use Cases

- Detection engineering (Sigma/Splunk rules from MITRE-mapped findings)
- Purple team assessments and AD permission boundary reviews
- Continuous validation (CTEM) — scheduled runs catch permission drift between assessments, closing the Discover → Validate loop for identity
- CI/CD security gates — fail the build above a risk threshold
- Security research — reproducible evidence with MITRE attribution (see [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md))

## Roadmap

- **Go rewrite (Lantern)**: static Go binary, standard library + one LDAP client dep, `go build` anywhere
- **Permission graph**: nodes (users, groups, computers, OUs) and typed edges, queryable via CLI and TUI
- **TUI**: interactive graph exploration (BloodHound-inspired, terminal-native)
- **ACE/DACL parsing**: move beyond group-membership heuristics to real access-control entries
- **Transitive path resolution**: shortest privilege-escalation paths
- **Integration contracts**: feed NightForge harness, C4, Veil lab, and security-research pipelines

## Related Projects

- [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) — NightForge harness, C4, Veil, security-research
- [ARCHITECTURE.md](ARCHITECTURE.md) — architecture and integration contracts
- [CONTRIBUTING.md](CONTRIBUTING.md) — build, test, and contribution guide
- [CHANGELOG.md](CHANGELOG.md) — release history
- [SECURITY.md](SECURITY.md) — security scope and disclosure
- [AGENTS.md](AGENTS.md) — guidance for AI coding agents

## License

MIT — see [MIT_LICENSE](MIT_LICENSE).
