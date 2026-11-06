# Changelog

## 1.2.0 — unreleased

### Added
- `a2aops card diff OLD NEW`: breaking-change report between two AgentCards
  (removed skills/interfaces/input modes, capabilities turned off, auth newly
  required, new required extensions, version-bump discipline). Exit 1 on
  breaking changes. Codes `D5xx`/`D6xx`/`D7xx`.
- `card check`, `auth` and `compat` accept a local JSON file or `-` (stdin), not
  just a URL — lint a card before you deploy it.
- `--format json|sarif` for `card check`, `card diff` and `auth`
  (`--format json` for `compat`). SARIF 2.1.0 output validates against the
  official schema and uploads to GitHub code scanning.
- `--strict`: warnings fail the run too.
- `--card-path` for agents that serve their card outside `/.well-known`.
- `auth --allow-private` to opt out of the new SSRF guard on local stacks.

### Security
- SSRF guard for card-supplied URLs (OIDC discovery): HTTPS only, no embedded
  credentials, public addresses only (blocks loopback, RFC 1918, link-local /
  cloud metadata, reserved, multicast, IPv4-mapped IPv6), every redirect hop
  re-checked. A refused fetch is reported as `W307`.
- Plain-HTTP `openIdConnectUrl` values are reported (`E302`) but no longer fetched.
- Response size caps: 2 MiB for network JSON, 16 MiB for local files/stdin.
- Terminal-safe output: control characters, ANSI escapes and bidi overrides in
  card or task text are escaped before printing.

### Fixed
- `compat <file>` with a malformed JSON file no longer silently retries the
  file name as a URL; it reports the JSON error (exit 2).
- User-Agent now reports the real package version instead of `a2aops/1.0`.

### Changed
- Removed committed build artefacts (`build/`, `*.egg-info`, `__pycache__/`)
  from git and added a `.gitignore`. `build/lib` was already out of sync with
  `src/` in 1.1.0 (`__init__.py` and `cli.py` differed), so it could only
  mislead.
- README: accurate install line (the package is on PyPI), CI recipe,
  diagnostic code table, security section, sourced comparison table.

## 1.1.0

- Initial public release.
