# Security Policy

## Scope

Lantern (ACLGuard) is a **read-only** Active Directory permission auditor. It queries AD over LDAP, analyzes permission assignments, and reports findings. It does not:

- modify permissions, objects, or configuration
- create or delete AD objects
- exploit vulnerabilities
- authenticate beyond the initial bind

The tool surfaces misconfigurations; it does not weaponize them. Use it only on systems you own or have explicit authorization to assess.

## Supported versions

| Version | Status |
|---------|--------|
| C v2.0.0 "Purple" (current baseline) | Supported |
| v1.0 | Archived (see README_v1.0.md) |

## Reporting a vulnerability

- **Do not open a public GitHub issue** for security findings.
- Report privately to the maintainers with:
  - affected version and commit
  - reproduction steps (redacted of real credentials/domain names)
  - impact assessment
  - suggested remediation
- Maintainers will acknowledge within 7 days and coordinate a fix before any public disclosure.
- If you find a vulnerability while using the tool against an authorized target, include the engagement context; findings are handled under the same confidentiality as the engagement.

## Credential handling

- Credentials are accepted **only via environment variables** (`ACLGUARD_LDAP_URI`, `ACLGUARD_BIND_DN`, `ACLGUARD_BIND_PW`, `ACLGUARD_BASE_DN`) or a `0600` config file (planned in the Go rewrite).
- Never put credentials on the command line — they are visible in process listings and shell history.
- Never commit credentials or real configs. `.gitignore` excludes `config_*.env`, `config.cfg`, `.env`, and `*.csv`/`*.json` outputs. Use `.env.example` as the template only.
- The C baseline connects over plain `ldap://` — **cleartext credentials on the wire**. Restrict to trusted networks or use a VPN/tunnel. LDAPS/GSSAPI is a planned Lantern feature; until then, treat bind passwords as exposed on the LDAP path.

## Engagement data boundary

- Scan output (JSON/CSV exports, graph exports) contains real directory data: usernames, group memberships, DNs, permission flags. Treat it as **sensitive AD intelligence**, not generic tool output.
- Store exports under the engagement's data boundary (encrypted at rest where the engagement requires it).
- Do not upload findings to public services, sample repos, or issue trackers unless anonymized (replace DNs, usernames, and domain names with placeholders).
- Delete or archive exports when the engagement ends per its retention policy.
- `--mock` mode uses bundled synthetic fixtures (`data/mock/`) and is the safe default for demos, CI, and documentation.

## Recommended operational posture

- Use a dedicated, read-only bind account with least privilege — not a Domain Admin account.
- Prefer LDAP-over-TLS or a VPN; never run plaintext-LDAP scans across untrusted segments.
- Scope base DNs to the smallest subtree the assessment needs.
- Run scans from a controlled host (see [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) for lab topology) and keep the binary's provenance (build from source, checksummed).

## Dependency and supply chain

- C baseline links `libldap`/`liblber` (system OpenLDAP) and `libjson-c` — keep these patched from your distribution.
- The Go rewrite is stdlib-first with one planned external dependency (`go-ldap/ldap/v3`); pin versions and review dependency diffs in PRs.
- Build from source; do not trust prebuilt binaries from unverified channels.
