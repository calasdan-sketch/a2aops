# Changelog

## 1.3.0 — unreleased

Verified against A2A 1.0.0 (spec page) / proto 1.0.1, and against the official
Python SDK 1.3.0 running as a real v1.0 server.

### Fixed (behaviour changes)
- **Client tools spoke pre-1.0.** `task poll`, `stream` and the playground used
  `tasks/get`, `tasks/resubscribe` and `/v1/...` paths. They now use the v1.0
  PascalCase methods (`GetTask`, `SubscribeToTask`, ...), REST paths without a
  version prefix, the `A2A-Version` header, and the `SendMessageResponse` /
  `StreamResponse` wrappers. `--legacy` style behaviour remains for old agents.
- `E105` no longer flags gRPC `host:port` targets or custom-binding URIs (spec 5.8).
- `W204` removed; `I209`, `W212`, `W213` added for the v1.0 shapes.
- Mock agent is now strict v1.0 by default (`legacy=True` for the old behaviour),
  serves `Cache-Control`/`ETag`/304 on the card and an HTTP+JSON interface.
- Subscribing to an already-final task no longer loops.

### Added
- `a2aops conformance`: 49 live checks (15 active), spec-referenced, text/JSON/JUnit/SARIF.
- `a2aops card verify`: pure-Python JWS verification with the attack list refused (`alg` none/HS*, `jku` as attacker input, key/alg family mismatch).
- Proto-derived structure checks (`E120`-`E125`, `W210`, `W211`, `W216`) and security lint (`S801`-`S808`).
- `card diff --semver` / `--enforce-semver` (`D610`, `D611`); `--format junit`.
- `bench/`: card corpus, mutation benchmark, semver benchmark, `RESULTS.json`.
- `action.yml`: composite GitHub Action wrapping `card check` and `conformance`.

### Known gaps
- No gRPC probes; JWS limited to ES*/RS*; official TCK mutation comparison not completed (unverified).

## 1.2.0 — unreleased

### Fixed after independent panel review (synapse-1)
- **securityRequirements shape (high).** Card, auth, compat and diff now read the
  A2A v1.0 wire shape from `a2a.proto` — `[{"schemes": {"oidc": {"list": [...]}}}]` —
  at card and skill level. Previously only the OpenAPI shape was understood,
  so spec-shaped cards got a false `E341 undeclared scheme 'schemes'`, a false
  `W202`, and `card diff` missed auth changes entirely. The OpenAPI shape and
  the v0.3 `security` field are still accepted, and flagged (`I207`, `I208`,
  compat actions). New `E115` for malformed entries. Fixtures moved to the
  spec shape.
- **SSRF guard.** Now blocks carrier-grade NAT (`100.64.0.0/10`, incl. Alibaba
  Cloud metadata `100.100.100.200`) and judges NAT64, 6to4 and Teredo addresses
  by the IPv4 address they reach. Uses an explicit range list plus `is_global`,
  so results are identical on Python 3.10–3.13 (tested on all four).
- **Terminal safety.** `stream` notes (which can echo server event ids), task
  inspect errors and playground task lines now go through `clean()`, and
  `clean()` also escapes bidi marks (U+200E/F, U+061C), zero-width characters,
  U+2028/9, word joiners, soft hyphen and the BOM.
- **Missing files.** A path-like source that doesn't exist (`*.json`, `./x`,
  `/x`, `~/x`, `C:\x`) is "file not found" instead of a DNS lookup of the file
  name. Malformed URLs (bad port, bad IPv6 literal, bad IDNA) give exit 2
  with a message instead of a traceback.
- **card diff gaps.** Flags an existing extension becoming `required`, a skill
  narrowing the default modes it inherited, skill-level auth changes
  (`D510`/`D511`/`D705`/`D609`), understands v0.3 `security` and
  `additionalInterfaces` (no false `D508` when migrating), and includes
  `tenant` in the interface identity.
- **SARIF URIs** are percent-encoded and relative to the working directory
  (absolute `file://` URIs outside it); Windows paths no longer look like a
  `c:` scheme.
- **Content-Length precheck** now actually rejects oversize responses before
  reading (the `ResponseTooLarge` was swallowed by an `except ValueError`).
- **Single read.** Local cards are read once, capped, and that same text is
  reused for SARIF line lookup (no second uncapped read, no check/use race).

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
