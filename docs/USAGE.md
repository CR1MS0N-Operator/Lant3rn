# ACLGuard usage guide

[Back to the project](../README.md) · [Architecture](../ARCHITECTURE.md) · [Security policy](../SECURITY.md)

This guide describes the **C v2.0.0 “Purple”** baseline. The Lantern Go CLI, graph, and TUI are planned; their target contract is separate in [ARCHITECTURE.md](../ARCHITECTURE.md).

## Build

Requirements: GCC, Make, OpenLDAP (`libldap`/`liblber`), and JSON-C development headers. For Ubuntu/Debian:

```bash
sudo apt install build-essential libldap2-dev libjson-c-dev
make clean && make
```

The resulting binary is `./aclguard` and links system libraries; this is not a static Go build. Run the following commands from the repository root.

## Try it offline

```bash
./aclguard --mock status
./aclguard --mock alerts --recent
./aclguard --mock correlate --attack kerberoasting
./aclguard --mock analyze --incident latest
./aclguard --mock metrics --throughput
```

Mock mode reads bundled synthetic JSON fixtures from `data/mock/`. It demonstrates command and output behavior, not a live directory scan. Every subcommand accepts `--json`:

```bash
./aclguard --mock status --json
```

The status response has a `summary` string and a `data` object. Alert counts, fixture version, and timestamps reflect the fixture contents, not measurements of a live environment. See the [status fixture](../data/mock/status.json) for a complete example.

For the scripted demonstration, use `./scripts/demo_mock.sh`. It also runs `scripts/simulate_kerberoasting.py`, which adds a synthetic alert and updates fixture status; inspect any resulting fixture changes before committing.

## Connect to a directory

Use only systems you own or are authorized to assess, with a dedicated read-only account. The C baseline uses plain `ldap://`, exposing bind credentials on the network; keep it within a trusted lab or protected tunnel. LDAPS/GSSAPI is planned, not provided by these instructions. Read the [credential and data boundaries](../SECURITY.md) first.

All connection settings come from the environment; there is no config-file loader in the C baseline.

| Variable | Purpose |
| --- | --- |
| `ACLGUARD_LDAP_URI` | LDAP URI, for example `ldap://ad.lab.example:389` |
| `ACLGUARD_BIND_DN` | Distinguished name of a read-only bind account |
| `ACLGUARD_BIND_PW` | Bind password |
| `ACLGUARD_BASE_DN` | Base DN for directory searches |

Use [.env.example](../.env.example) as a reference, never a place for real credentials. Example setup in Bash, with a password prompt instead of a literal in shell history:

```bash
export ACLGUARD_LDAP_URI="ldap://ad.lab.example:389"
export ACLGUARD_BIND_DN="CN=AuditReader,CN=Users,DC=lab,DC=example"
export ACLGUARD_BASE_DN="DC=lab,DC=example"
read -r -s -p "LDAP bind password: " ACLGUARD_BIND_PW
echo
export ACLGUARD_BIND_PW

./aclguard status --json
unset ACLGUARD_BIND_PW
```

Omit `--mock` to query LDAP. Treat live output as sensitive directory intelligence; redact usernames, DNs, and domain names before publication.

## CLI reference

```text
aclguard status [--json]
aclguard alerts --recent [--json]
aclguard correlate --attack <name> [--json]
aclguard analyze --incident <latest|id> [--json]
aclguard metrics --throughput|--accuracy|--scale [--json]
aclguard --mock <subcommand> ...
```

| Command | Purpose |
| --- | --- |
| `status` | Directory posture summary |
| `alerts --recent` | Recent high-risk findings |
| `correlate --attack kerberoasting` | Correlate signals for a named attack |
| `analyze --incident latest` | Break down the latest incident-style finding |
| `metrics --throughput` | Scan throughput view |
| `metrics --accuracy` | Accuracy view; not independent detection validation |
| `metrics --scale` | Scale view |

Use `./aclguard --help` for the built-in syntax reference. Mock views use fixture data; they do not validate detection accuracy or performance.

## JSON and legacy exports

Subcommand JSON is an object with `summary` and `data` fields; the fields inside `data` depend on the command. Prefer this interface for automation:

```bash
./aclguard --mock alerts --recent --json > alerts.json
```

Legacy exports remain available but are deprecated. They query live LDAP and write per-user records, not the subcommand envelope:

```bash
./aclguard --export-json aclguard_users.json
./aclguard --export-csv aclguard_users.csv
```

The JSON export is an array containing identity fields (`username`, `cn`, `email`, `groups`), permission flags, a risk score, and ATT&CK identifiers. The CSV export has corresponding columns, but the current writer does **not** quote or escape delimiters. Group DNs commonly contain commas; prefer JSON when field boundaries matter. Do not assume live runs are byte-identical: scan timestamps and timings can vary.

## Interpret the risk score

The C implementation infers permission flags by matching group-name strings; it does not read effective ACLs. It adds weights for matching groups and caps the total at 100. The ATT&CK label follows the implementation's permission-priority order, not a complete list of every technique a principal might enable.

| Signal | Weight per matching group | Current ATT&CK mapping |
| --- | --- | --- |
| Admin membership | 40 | T1078.002 — Valid Accounts: Domain Accounts |
| Write secrets | 35 | T1098 — Account Manipulation |
| Authentication delegation | 30 | T1484.001 — Group Policy Modification |
| Password reset | 25 | T1098 — Account Manipulation |
| Read secrets | 20 | T1552 — Unsecured Credentials |
| ACL modification | 20 | T1484 — Domain Policy Modification |
| Service account | 15 | T1558.003 — Kerberoasting |

These are the tool's existing mappings, not confirmation of exploitability. Direct group-name heuristics can produce false positives or miss real permissions. There is no nested-group resolution, raw DACL/ACE parsing, Entra ID support, or multi-forest analysis.

## Verify the baseline

```bash
make test
```

This runs the offline smoke test and the live LDAP smoke test. The latter skips unless all four `ACLGUARD_*` connection variables are set. The offline test rebuilds the CLI and runs the alert simulation, which can modify mock fixtures. A passing offline run is not evidence of a successful LDAP connection.

For development conventions, see [CONTRIBUTING.md](../CONTRIBUTING.md). For future graph and integration work, see [ARCHITECTURE.md](../ARCHITECTURE.md) and [integration targets](INTEGRATIONS.md).
