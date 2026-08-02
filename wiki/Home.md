# Lantern (ACLGuard) Wiki

Welcome to the documentation wiki for **Lantern** — codename for the minimal Active Directory permission graph and audit tool (repository name: ACLGuard).

The wiki documents the current C baseline and the planned Go rewrite. See the [root README](../README.md) for the project overview, [ARCHITECTURE.md](../ARCHITECTURE.md) for the architecture (including the Lantern Go target), and [CHANGELOG.md](../CHANGELOG.md) for release history.

## Table of Contents

### Getting Started
- [Getting Started Guide](Getting-Started.md) — quick setup and first run
- [Lab Setup Guide](Lab-Setup-Guide.md) — setting up test environments
- [Beginners Guide](BEGINNERS_GUIDE.md) — AD and permission concepts for newcomers

### Technical Documentation
- [Architecture Overview](ARCHITECTURE.md) — C baseline design (legacy; the [root ARCHITECTURE.md](../ARCHITECTURE.md) covers the Lantern Go target)
- [ACL Concepts Explained](ACL-Concepts-Explained.md) — Active Directory permission model
- [Development Log](Development-Log.md) — project development history

### Advanced Topics
- [White Paper](WHITE_PAPER.md) — technical deep dive (status: placeholder)

## What is Lantern?

A **BloodHound-inspired but smaller** AD permission auditor: query Active Directory over LDAP, flag over-privileged principals, and emit deterministic JSON/CSV findings for CI gates, SIEM, and research. Current implementation is C (v2.0.0 "Purple"); the Lantern Go rewrite adds a permission graph model and a CLI + TUI surface.

## Quick Start

```bash
make clean && make
./aclguard --mock status           # offline demo, no AD required
source config.env && ./aclguard status
```

## Current Features

- LDAP enumeration of users and group memberships (read-only)
- High-risk permission flags: admin, password reset, ACL modification, delegation, service accounts, secret access
- Risk scoring (0–100) with MITRE ATT&CK mapping
- Deterministic JSON/CSV output; offline mock mode

## Security

- Read-only tool for authorized assessments only
- Credentials via environment variables only — never on the command line or in git
- No LDAPS yet (cleartext on `ldap://`) — trusted networks only
- See [SECURITY.md](../SECURITY.md) for the full policy

## Support

- Issues: report bugs via GitHub issues; security findings go to the maintainers privately (see [SECURITY.md](../SECURITY.md))
- Documentation: the wiki pages above
- Contributing: [CONTRIBUTING.md](../CONTRIBUTING.md)
