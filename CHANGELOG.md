# Changelog

## 1.3.0 — unreleased

### Round 5 (field experts: A2A SDK maintainer, AppSec, conformance tester, QA methodology, release manager)

Findings, proving commands and the scored idea list are in `docs/ROUND5.md`; release steps in `PUBLISH-CHECKLIST.md`. Tests: `tests/test_round5.py`.

**Behaviour changes to know about (both can turn a green run red)**
- `conformance` no longer probes card interfaces that point at loopback, private or cloud-metadata addresses when the card itself was fetched from a public host. They are listed as "not probed" and the checks that needed them are skipped. Before, a hostile card could make the tester POST to `http://169.254.169.254/...` or to an internal admin port (22 requests in the reproduction, including one real `SendMessage` with `--active`). The same guard applies to every redirect a probe meets (a public endpoint answering `307 -> http://localhost:PORT/` would otherwise bounce a GET probe inward). Pass `--allow-private-endpoints` to restore the old behaviour; testing a local URL is unaffected.
- `card check` now type-checks `securitySchemes` and the scope lists in `securityRequirements` (new `E120` paths such as `securitySchemes.key.apiKeySecurityScheme.name`, new warning `W217`). The official SDK's parser rejects these cards; before, a2aops said "OK". Found by differential testing against `a2a-sdk` 1.3.0: of 3083 mutated cards the SDK refused, a2aops showed no error on 431 before and 40 after (the rest are unknown fields, which never fail by design).

**Fixed**
- `card diff` crashed with `TypeError: unhashable type` when an extension's `uri` was an object or an array (found by the new property tests; the earlier 6000-input fuzz did not reach it).
- SARIF no longer links to a GitHub repository whose visibility is not ours to claim: `informationUri` is the product site, each rule's help text says `a2aops explain CODE`.

**Added**
- `--output FILE` for `card check|diff|verify` and `conformance`: UTF-8, LF, no BOM, written via a temp file, exit code unchanged, nothing written if the run itself failed (exit 2). PowerShell 5 `>` writes UTF-16, which GitHub's SARIF upload rejects.
- Conformance `RPC-30` / `REST-30` (SHOULD, not in the A2A spec): the endpoint must not echo an arbitrary `Origin` together with `Access-Control-Allow-Credentials: true`. 49 -> 51 checks; a matching injected fault (33 total).
- Author line "Calas Automations Inc." in `__author__`, `--help` footer, SARIF `tool.driver.organization` and the JUnit properties; a test pins it everywhere.
- `bench/mutate_source.py` (breaks a2aops itself in 29 ways and requires the tests to notice), `bench/sdk_server.py` (the official SDK as a live v1.0 server, so the "44 of 51" claim is reproducible), golden-file tests for every output format, seeded property tests.

**Tests** 302 -> 336. Benchmarks: see `bench/RESULTS.json`.

### Round 4 (the first hour after `pip install`)

Panel notes and the scored idea list are in `docs/ROUND4.md`; release steps in `PUBLISH-CHECKLIST.md`. Regression tests: `tests/test_round4.py`.

**Fixed**
- **`--header` credentials followed redirects to other hosts.** `conformance --header "Authorization: ..."` was documented as host-bound, but a server that answered 302 to another host or port received the header too (`urllib` copies request headers on redirect). Cross-origin redirects now keep only `Accept`, `User-Agent`, `A2A-Version`, `Cache-Control`, `Accept-Language`. Verified before and after with two local servers.
- **`file://`, `ftp://` and other schemes** typed as a source were handed to `urllib` (and a redirect could reach `ftp://`). Only `http`/`https` are accepted now, with a plain message.
- `user:password@` in a URL was echoed in error messages and in the JSON `base_url`; it is refused (`urllib` cannot use it anyway) and shown as `***@`.
- `play demo --log <unwritable>` and `play run` with a malformed scenario ended in a Python traceback (`FileNotFoundError`, `KeyError`); both are now one-line exit-2 errors. A scenario file may start with a BOM, uses the strict JSON loader and is read with a 16 MiB cap.
- `--timeout 0`, `-5`, `nan`, `inf` were accepted (a zero or negative timeout behaves unpredictably); they are usage errors now. Same for negative `--max-reconnects` / `--max-events` and non-positive `--interval`.
- `task inspect` on a missing file said `[Errno 2] ...`; a non-numeric `ts` raised `TypeError`. Both are plain exit-2 messages.
- `--write-baseline` is written to a temp file and renamed, so a crash or two parallel CI jobs cannot leave half a baseline (falls back to an in-place write if the rename is refused, e.g. on Windows). Playground logs always use `\n` line endings.
- Removed three unused `json` imports and a duplicated set member found by `ruff --select F,B`.

**Packaging**
- Added `LICENSE` (the README said MIT but the file was missing from the repo and from both artifacts), `py.typed`, `MANIFEST.in` (the sdist now carries CHANGELOG, LICENSE, tests with fixtures, `bench/` and `action.yml`), SPDX `license = "MIT"` (needs setuptools >= 77 at build time), Python 3.10-3.13 and `Typing :: Typed` classifiers, more keywords and a shorter PyPI summary.
- A test now fails if `pyproject.toml`, `__version__` and the top CHANGELOG heading disagree, or if LICENSE / `py.typed` go missing.

**Docs**
- README install section states plainly that PyPI currently has 1.1.0, which lacks most of what the README describes, and what has and has not been tested (Linux only; Windows, macOS and Python 3.10 not run).

**Tests** 284 -> 302. Benchmarks unchanged (see `bench/RESULTS.json`).

**Not done / unverified:** nothing was run on Windows, macOS or Python 3.10; no `Repository`/`Issues` project URLs because the public repository address is not known to this checkout; composite action still not run on a GitHub runner.

### Round 3 (hostile input, adoption, honesty of exit codes)

Found by hand-testing as an attacker, a CI engineer, an auditor and a first-time
user; each item has a regression test in `tests/test_round3.py`.

**Fixed**
- **Crash on deep JSON.** A card nested 100,000 levels deep (from a file or a hostile server) raised `RecursionError` with a traceback in `card check`, `compat`, `auth`, `card diff`, `task poll` and `conformance`. All untrusted JSON now goes through `net.loads_strict`: clean one-line error.
- **Duplicate keys were silently accepted** (last one wins; other parsers keep the first). They are now rejected everywhere untrusted JSON is parsed, including JWS protected headers (`{"alg":"ES256","alg":"none"}`). `NaN`/`Infinity` are rejected too. Behaviour change: such a card is exit 2, not a finding.
- **Crash on lone surrogates.** A card with `"\ud800"` in a skill id made `card diff` die with `UnicodeEncodeError` (text and JUnit). `clean()` escapes surrogates and the CLI switches stdout/stderr to backslash-escape fallback, which also fixes cp1252/ASCII consoles meeting characters such as the em dash.
- **`--timeout` did not bound a slow server.** A body dripping bytes was read for as long as the server liked (30 s observed with `--timeout 3`). `read_capped` now stops after 30 s in total.
- **`conformance --only TYPO` exited 0 having checked nothing.** Unknown `--only`/`--skip` ids, a `--binding` the card does not offer, and a run where every check was skipped are now exit 2.
- **`stream` exited 0 after giving up.** It now exits 1. A single SSE line over 4 MiB ends the connection (it used to be read without limit) and the dedupe set is capped at 100,000 ids. The unused per-event list was removed.
- SARIF annotations for `skills[2].tags` landed on the first skill's `tags`; paths (including `skills[id=x]`) are now resolved by a tokenizer, and a missing key points at the object that lacks it.
- `inputModes: [3]` reported "array of strings, got array"; it now says "got array containing number".
- A broken pipe (`a2aops ... | head`) no longer prints a traceback.

**Added**
- `--ignore CODE|PREFIX`, `--baseline FILE`, `--write-baseline FILE` for `card check`, `card diff`, `card verify`, `auth`. Hidden findings are counted, never silent; bad baselines fail closed.
- `a2aops explain [CODE]` for all 109 diagnostic codes, with a test that fails if a check emits a code that has no entry (and the reverse).
- `conformance --skip ID`.
- SARIF `partialFingerprints` (stable per code+path, disambiguated for repeats).
- `action.yml` inputs `ignore`, `baseline`, `old-card` (runs `card diff`); runs every step and reports the worst exit code; empty-array safe on bash 3.2.
- `bench/fuzz.py`: seeded hostile-input fuzz (`python -m bench.fuzz`), recorded in `bench/RESULTS.json` (6000 inputs, 0 crashes).

**Tests** 243 -> 284. Benchmark numbers unchanged (cards 1.00/1.00, 32/32 injected faults, 25/25 semver); the committed file additionally records the fuzz run.

**Not done / unverified:** the composite action was run against a stub CLI, not on a GitHub runner; Python 3.10 was not available here (3.11-3.13 pass); no gRPC probes; JWS still ES*/RS* only; the official TCK mutation comparison is still missing.

### Round 2

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
