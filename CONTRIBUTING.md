# Contributing to Lantern (ACLGuard)

Thanks for contributing. The working baseline is C (v2.0.0 "Purple"); the Lantern Go rewrite is planned. Start with the [usage guide](docs/USAGE.md) for the working CLI, and keep documentation clear about current versus target behavior.

## Development setup

### Go (planned Lantern rewrite)

There is no Go module or `cmd/lantern/` implementation in this baseline. Do not run Go build/test commands until those sources exist. See [ARCHITECTURE.md](ARCHITECTURE.md#2-lantern-go-target) for the target design: stdlib-first, with `github.com/go-ldap/ldap/v3` as the planned LDAP dependency.

### C (current baseline)

```bash
# Arch
sudo pacman -S base-devel openldap openldap-devel gcc make json-c

# Ubuntu/Debian
sudo apt install build-essential libldap2-dev libjson-c-dev

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

The checked-in [Lint Commits workflow](.github/workflows/commitlint.yml) calls the shared Conventional Commits check. It does not run C builds, smoke tests, or a Go toolchain. Run the build and smoke tests locally before submitting changes; automated build/test jobs remain future work.

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
3. Verify the current baseline: `make clean && make && make test`. Add Go checks only once Go sources exist.
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
