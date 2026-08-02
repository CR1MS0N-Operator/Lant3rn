# Changelog

All notable changes to Lantern (ACLGuard). Format follows [Keep a Changelog](https://keepachangelog.com/); versioning is semantic. Commit hashes reference `main`.

## [Unreleased]

### Planned (Lantern — Go rewrite)

- Go implementation: single static binary, stdlib-first, `internal/{collect,graph,analyze,output,config,pipeline}` layout
- Permission graph model: `User`/`Group`/`Computer`/`OU` nodes with typed edges (`MemberOf`, `ForceChangePassword`, `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `AllExtendedRights`, `HasSession`)
- CLI + TUI surfaces over one core; `--format json` with stable, diff-friendly output
- ACE/DACL parsing and transitive privilege path resolution (beyond group-membership heuristics)
- LDAPS/GSSAPI support; credentials off the plaintext wire
- Graph/JSON export contracts for external tooling

## [2.0.0] — 2026-06-21

Current baseline (C, codename "Purple").

### Fixed
- Memory leaks: `ADUser` struct fields now freed (`37b98ac`)
- Hardcoded DN, missing NULL checks; removed dead `risk_engine` code (`f50958a`)
- Duplicated `handle_legacy()` logic deduplicated (`37b98ac`)

### Changed
- README overhaul with MITRE ATT&CK mapping and wiki filename fixes (`053cf55`)

## [1.1.0] — 2026-02-08

Development snapshot.

### Added
- Mock fixtures (`data/mock/`) and offline `--mock` mode for all subcommands
- LDAP insights subcommands: `status`, `alerts --recent`, `correlate --attack`, `analyze --incident`, `metrics` (`6b8a7c4`)
- Tests updated for the new CLI surface (`6b8a7c4`)

### Changed
- README revised for project update (`905bf5b`)

## [1.0.0] — 2025-09-09

First release — complete cybersecurity tool (`6b298d9`).

### Added
- LDAP connectivity and user enumeration (`66fd97d`, 2025-08-05)
- Permission analysis and risk scoring engine (`e051e20`, 2025-08-08)
- CSV and JSON export (`4cea112`, 2025-08-12)
- CLI interface and user experience enhancements (`1fea774`, 2025-08-15)
- Comprehensive testing and validation (`349de4b`, 2025-08-20)
- Comprehensive documentation and guides (`24a79d1`, 2025-08-25)
- Final testing, polish, and v1.0 preparation (`7442e70`, 2025-08-30)

### Changed
- README revised with output section and disclaimer (`4c2f834`, `f08ba71`, 2025-12-13)

## Development history (pre-release)

- `10a3484` — 2025-07-31: initial commit, project setup
- `66fd97d` — 2025-08-05: LDAP connectivity and user fetching
- `e051e20` — 2025-08-08: permission analysis and risk scoring engine
- `4cea112` — 2025-08-12: CSV/JSON export
- `1fea774` — 2025-08-15: CLI enhancements
- `349de4b` — 2025-08-20: testing and validation
- `24a79d1` — 2025-08-25: documentation and guides
- `7442e70` — 2025-08-30: final testing, polish
