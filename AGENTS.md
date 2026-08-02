# AGENTS.md

Guidance for AI coding agents working in this repository. Human contributors see [CONTRIBUTING.md](CONTRIBUTING.md).

## Project identity

- Codename **Lantern**; repository/product name remains **ACLGuard** until an operator-owned rename.
- Current implementation: **C v2.0.0 "Purple"**. The **Go rewrite (Lantern)** is planned and documented in [ARCHITECTURE.md](ARCHITECTURE.md) — do not assume Go code exists.
- Docs describe both layers. Keep the distinction honest: never present planned Lantern behavior as implemented.

## Commands

```bash
# Build (C baseline)
make clean && make

# Tests — run before every commit
make test
./tests/smoke_test.sh            # offline, mock mode
./tests/ldap_smoke_test.sh       # live; skips without ACLGUARD_* env

# Offline demo
./scripts/demo_mock.sh

# Go (only when cmd/ exists — Lantern rewrite in progress)
go build ./cmd/lantern/
go vet ./...
go test ./...
```

## Repository layout

```
src/            C sources (main, ldap, ldap_insights, config, export, error_handler, mock)
include/        C headers (types, config, ldap, export, insights, mock)
tests/          shell smoke tests + C test runner
scripts/        demo_mock.sh, simulate_kerberoasting.py
data/mock/      synthetic LDAP fixtures for --mock
wiki/           GitHub-wiki-style docs (legacy v1.0-era, partially stale)
docs/           current documentation (integrations)
README_v1.0.md  archived v1.0 snapshot — historical, do not treat as current
```

## Conventions

- **Commits**: Conventional Commits, one logical change per commit (micro-commits). Never mix docs and code in one commit.
- **C code**: `gcc -Wall -Wextra -pedantic` clean; explicit memory management with free paths; no new globals.
- **Docs**: update README/ARCHITECTURE when behavior or CLI changes. Never use emojis in new docs.
- **No fabricated state**: mark planned/unimplemented features as planned. Current facts live in code, headers (`config.h` version macros), and `CHANGELOG.md`.

## Guardrails

- **Do not push.** Commits stay local unless the operator approves.
- **Do not delete the demo layer**: `scripts/demo_mock.sh`, `data/mock/`, `README_v1.0.md`, legacy wiki pages. Separate operator-owned cleanup pass.
- **Do not rename** the repo, binary, or `ACLGuard*` identifiers.
- **Preserve code structure**; the Go rewrite replaces internals, not layout.
- **Documentation-only tasks** stay documentation-only.

## Context for doc edits

- Version/codename truth: `include/config.h` (`ACLGUARD_VERSION "2.0.0"`, `ACLGUARD_CODENAME "Purple"`).
- CLI truth: `print_usage()` in `src/main.c`.
- MITRE mapping: README table (T1078.002, T1098, T1484, T1484.001, T1552, T1558.003).
- Integration targets (NightForge harness, C4, Veil, security-research): [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).
