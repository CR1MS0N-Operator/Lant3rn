# Contributing to Lantern (ACLGuard)

Thanks for contributing. This project is mid-transition: the working baseline is C (v2.0.0 "Purple"), and the Lantern Go rewrite is landing incrementally. Keep both toolchains working; don't break the C build before the Go CLI is drop-in.

## Development setup

### Go (Lantern rewrite)

```bash
# Go 1.26+ (go.mod targets 1.26)
go version

# Build the CLI
go build ./cmd/lantern/

# Vet + test
go vet ./...
go test ./...
```

The Go module is stdlib-first; the only planned external dependency is `github.com/go-ldap/ldap/v3`.

### C (current baseline)

```bash
# Arch
sudo pacman -S base-devel openldap openldap-devel gcc make json-c

# Ubuntu/Debian
sudo apt install build-essential libldap2-dev liblber-dev libjson-c-dev

make clean && make
```

## Building and testing

```bash
# Build
make clean && make

# Offline smoke test (mock mode, no AD required)
make test            # runs tests/smoke_test.sh + tests/ldap_smoke_test.sh
./tests/smoke_test.sh

# Live smoke test (requires ACLGUARD_* env vars; skips otherwise)
./tests/ldap_smoke_test.sh

# Demo
./scripts/demo_mock.sh
```

Run `make test` before every commit. If you change LDAP or output logic, also run the live smoke test against a lab domain.

## CI

GitHub Actions workflow (`.github/workflows/ci.yml`) runs:

| Job | Command |
|-----|---------|
| Go build + vet | `go build ./cmd/lantern/` + `go vet ./...` |
| Go tests | `go test ./...` |
| C build | `make clean && make` (with `libldap2-dev libjson-c-dev`) |
| C smoke | `./tests/smoke_test.sh` |
| Shell | `shellcheck` + `bash -n` on changed `.sh` scripts |

Add or update this workflow when you add Go packages or scripts.

## Code style

### Go

- `gofmt`/`gofumpt` clean, `go vet` clean, no lint suppressions without a comment.
- Errors are values: wrap with `fmt.Errorf("...: %w", err)`; never swallow errors silently.
- Package layout follows the [ARCHITECTURE.md](ARCHITECTURE.md) structure (`internal/collect`, `internal/graph`, ...).
- Public types (graph nodes/edges, findings) live in `pkg/graph` — they are the integration contract.

### C

- `gcc -Wall -Wextra -pedantic` clean.
- Manual memory management: every `malloc`/`strdup` has a matching free path; use `strndup`/`snprintf` for bounds safety.
- No new global state; pass structs explicitly.

### Shell

- `set -euo pipefail` at the top of every script.
- `shellcheck` clean.

## Commit conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
docs: add integration targets for NightForge harness
fix: free ADUser struct fields on export path
feat(collect): add LDAP pagination
```

- **Micro-commits**: one logical change per commit (one doc, one fix, one feature). No mixed-purpose commits.
- Subject ≤ 72 chars, imperative mood, no trailing period.
- Body explains *why* when the subject isn't enough.
- Do not push without explicit approval.

## Branches and PRs

1. Create a feature branch from `main` (`git checkout -b feat/<name>`).
2. Make micro-commits.
3. Verify: `go build ./... && go vet ./... && go test ./... && make clean && make && make test`.
4. Review the diff (e.g. `hunk diff`) before committing/PRing.
5. Open a PR against `main` with a summary of what changed and verification evidence.

## Scope guardrails

- **Documentation-only changes** are welcome and expected to stay documentation-only.
- Do not delete the demo layer (mock scripts, `README_v1.0.md`, `data/mock/`) — separate cleanup pass, operator-owned.
- Do not rename the repository or the `ACLGuard` identifiers — separate operator action.
- Preserve the existing code structure; the rewrite replaces internals, not layout.

## Reporting issues

- Bugs: include the command run, environment, and the exact output.
- Security findings: do **not** file a public issue — follow [SECURITY.md](SECURITY.md).
