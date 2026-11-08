# a2aops — operational toolkit for the A2A protocol

**Lint, diff, verify and conformance-test A2A agents from one zero-dependency
CLI — and catch breaking AgentCard changes in CI before your clients do.**

`a2aops` is an operational toolkit for the Agent-to-Agent (A2A) protocol
(v1.0, Linux Foundation / AAIF): AgentCard validation and lint, **breaking-change
diffs between two cards**, v0.x → v1.0 migration reports, read-only auth-surface
checks, task lifecycle inspection, SSE streaming with spec-correct
resubscription, and a local multi-agent playground. Output is human text,
JSON, or **SARIF** for GitHub code scanning.

**Zero dependencies.** Standard library only, Python 3.10+. It runs in
locked-down CI, behind corporate proxies, and anywhere `pip install`
is a procurement conversation.

## Install

```bash
pip install "a2aops>=1.3"
# or from a source checkout (no network needed):
pip install ./a2aops
```

Check `a2aops --version` afterwards. As of 2026-11-07 the newest release on
PyPI is **1.1.0**, which predates `card diff`, `conformance`, `card verify`,
`explain`, baselines and SARIF line locations described below; those need 1.3.0
or newer. Until 1.3.0 is published, install from a checkout of this repository.
Supported: Python 3.10 to 3.13 on Linux (tested on 3.11, 3.12 and 3.13). macOS
and Windows are expected to work (standard library only, no shell calls) but
have **not been run**; Python 3.10 has not been run in this release either.

## 60-second tour

```bash
# 1. Is that agent's card valid? (URL, local file, or '-' for stdin)
a2aops card check https://agent.example.com
a2aops card check ./agent-card.json --strict

# 2. Will my card change break existing clients?
a2aops card diff https://agent.example.com ./agent-card.json --semver

# 2b. Does the agent actually speak v1.0? (51 checks with spec references)
a2aops conformance https://agent.example.com --active

# 2c. Is the card signed by a key you trust?
a2aops card verify https://agent.example.com --jwks trusted-keys.json

# 2d. Adopting on a card that already has findings? Fail only on new ones.
a2aops card check ./agent-card.json --write-baseline .a2aops-baseline.json
a2aops card check ./agent-card.json --baseline .a2aops-baseline.json

# 3. Still on the pre-1.0 shape? Get the migration checklist.
a2aops compat https://agent.example.com

# 4. Does the card's auth story match reality? (read-only — never touches credentials)
a2aops auth https://agent.example.com

# 5. Watch a task, auto-resubscribing through SSE drops:
a2aops stream https://agent.example.com task-0001

# 6. Spin up two local agents and watch them talk:
a2aops play demo

# 7. What does finding E341 mean, and how do I fix it?
a2aops explain E341
```

What `card diff` looks like (the fixture card with one interface removed,
streaming turned off, a tag dropped, and only a minor version bump):

```text
$ a2aops card diff tests/fixtures/card_v1_valid.json new-card.json
diff tests/fixtures/card_v1_valid.json -> new-card.json
ERROR D501 [supportedInterfaces]: interface removed: HTTP+JSON https://hotels.example.com/a2a/json — clients with this endpoint cached will fail
ERROR D506 [capabilities.streaming]: capability 'streaming' was turned off — clients relying on it break
WARNING D603 [skills[id=search-and-book].tags]: skill 'search-and-book' dropped tags ['hotel']; tag-based routers may stop matching it
WARNING D608 [version]: breaking changes found but major version did not increase (2.3.0 -> 2.4.0)
```

## Use it in CI

Lint the card you are about to deploy, and fail the pull request on any
breaking change versus what is live:

```yaml
# .github/workflows/agent-card.yml  (example — adapt paths and URLs)
jobs:
  a2a-card:
    runs-on: ubuntu-latest
    permissions: { security-events: write, contents: read }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install a2aops
      - run: a2aops card check agent-card.json --format sarif > a2aops.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: a2aops.sarif }
      - run: a2aops card check agent-card.json --strict --baseline .a2aops-baseline.json
      - run: a2aops card diff https://agent.example.com agent-card.json
```

Or use the bundled composite action (`action.yml`; inputs `card`, `agent-url`,
`strict`, `ignore`, `baseline`, `old-card`). The action's shell logic was run
locally against a stub CLI; it has not been run on a GitHub runner.

On Windows PowerShell 5, `>` writes UTF-16, which SARIF upload rejects; use
`--output a2aops.sarif` instead of the redirect. For pre-commit, `.pre-commit-hooks.yaml`
defines a `a2aops-card-check` hook (you pass the card path in `args`; the hook file
has been parsed but pre-commit itself has not been run against it). `.github/workflows/ci.yml`
runs the test suite on Linux 3.10-3.13, one Windows and one macOS job; it has not run yet.
Cost note: on a private repository GitHub counts macOS minutes at 10x and Windows at 2x against the
free allowance.

SARIF annotations point at the line of the offending key when the source is a
local file (a small tokenizer maps `skills[2].tags` or `skills[id=x].tags` to
the right element; if a key is missing the annotation lands on the object that
lacks it; files over 4 MiB fall back to line 1), carry a stable
`partialFingerprints` value so code scanning keeps an alert open when lines
move, and always carry the JSON path
(`skills[0].tags`) as a logical location. File locations are written as
percent-encoded URIs relative to the working directory (`cards/my%20card.json`),
which is what GitHub needs to map them to repository files; files outside the
working directory become absolute `file://` URIs.

## Commands

| Command | What it does |
|---|---|
| `a2aops card check <src>` | `src` is a base URL, a JSON file, or `-`. For URLs: fetch `/.well-known/agent-card.json` (falls back to legacy `/.well-known/agent.json` and tells you). Validate against the A2A v1.0 schema and lint for robustness. Exit 1 on errors (`--strict`: on warnings too). |
| `a2aops card diff <old> <new>` | Breaking-change report between two cards (each a URL, file, or one `-`). Errors = breaks existing clients (removed skill/interface/input mode — including a skill narrowing the modes it used to inherit — capability turned off, auth newly required or an auth alternative removed at card or skill level, an extension becoming required, an interface's `tenant` changing); warnings = risky (preferred interface reordered, tags dropped, version not bumped, breaking change without a major bump); infos = additive. |
| `a2aops explain [CODE]` | What a diagnostic code means and how to fix it; without a code, lists them all. A test fails if the checks emit a code that has no entry. |
| `a2aops card fetch <base>` | Print the raw card JSON. |
| `a2aops conformance <url>` | Live A2A v1.0 protocol checks (51 checks, each with a MUST/SHOULD/MAY level and a spec section): card serving and caching, JSON-RPC and HTTP+JSON error shapes, `A2A-Version`, push-notification and extension gates, SSE framing, auth enforcement, leak checks. Passive by default; `--active` also sends one harmless message (15 checks need it). Fails closed: an unreachable agent exits non-zero. `--format text\|json\|junit\|sarif`, `--binding`, `--only`, `--skip` (an unknown check id is an error, not a green empty run), `--header` (sent only to the card's host), `--output FILE`. A card served from a public host cannot aim the probes at your own network: interfaces that point at loopback, private or cloud-metadata addresses are skipped and named, unless you pass `--allow-private-endpoints` (or the URL you gave is itself local). Two browser-safety checks (`RPC-30`, `REST-30`; not in the A2A spec) warn when an endpoint echoes any `Origin` together with `Allow-Credentials: true`. Exits 2 if `--binding` names an interface the card does not offer, or if every check was skipped. |
| `a2aops card verify <src> --jwks KEYS` | Verify the card's JWS signatures (ES256/384, RS256/384/512) against keys you trust, in pure Python. `alg` none/HS* are refused, the key decides the algorithm family, and `jku` is never followed unless you pass `--trust-jku` and it is on the card's own host. |
| `a2aops compat <src>` | Detect the card version and print a v0.x → v1.0 migration checklist. Exit 1 if migration actions remain. `--format json` available. |
| `a2aops auth <src>` | Check the declared auth surface: every `securityRequirements` entry must reference a declared scheme; OIDC discovery documents must resolve and expose a `token_endpoint`; OAuth2 flows need token URLs. Read-only. `--offline` skips remote fetches. Card-supplied URLs pass an SSRF guard (see Security). |
| `a2aops task poll <base> <task-id>` | Poll a task to a terminal state (`--binding rest\|jsonrpc`), printing each transition and any lifecycle violations. |
| `a2aops task inspect <events.jsonl>` | Offline inspection of a JSONL event log (`{"task_id":…, "state":…, "message"?}` per line) — or a playground wire log straight from `a2aops play demo --log`. Flags transitions out of terminal states, `UNSPECIFIED`/unknown states, and `INPUT_REQUIRED` with no guidance. |
| `a2aops stream <base> <task-id>` | SSE stream with exponential-backoff resubscribe (`SubscribeToTask`, or the REST `/tasks/{id}:subscribe` path; GET then POST fallback because the spec proto and prose disagree on the verb), event-id deduping, and clean close on terminal states. Reconnects and duplicates are reported, never hidden. |
| `a2aops play demo` | Run the built-in two-agent scenario on localhost; writes a timestamped JSONL wire log. |
| `a2aops play run <scenario.json>` | Run your own scenario: `{"agents": [{"name":…}], "script": [{"from":…, "to":…, "text":…}]}`. |

Common options: `--ignore CODE` (a code such as `W203` or a prefix such as `S8`; repeatable or comma-separated),
`--baseline FILE` / `--write-baseline FILE` (`card check`, `card diff`, `card verify`, `auth`), `--format text|json|sarif` (`card check`, `card diff`, `auth`),
`--format junit` (`conformance`, `card check`), `--output FILE` (write the report as UTF-8 with LF line ends instead of stdout; matters for PowerShell 5, whose `>` writes UTF-16; the exit code is unchanged and nothing is written when the run itself fails), `--strict`, `--timeout`, and `--card-path /custom/card.json` for agents that
serve their card outside `/.well-known`.

**Suppression and baselines.** `--write-baseline FILE` records today's findings
and exits 0. `--baseline FILE` then hides exactly those (same code at the same
card path; the wording is not part of the identity, so upgrading a2aops does not
resurrect them) and fails only on anything new. Everything hidden is counted in
the output (`hidden by --ignore/--baseline`, `"suppressed"` in JSON), an
unreadable or malformed baseline is exit 2, and an `--ignore` that is not a code
is exit 2. Baselines cover card findings, not `conformance` checks.

Exit codes: `0` clean · `1` findings reported · `2` usage/operational failure.

Source resolution is explicit: `-` is stdin; a path that exists on disk is read
as a file, exactly once and size-capped (a malformed file is an error, never
silently retried as a URL); something that *looks* like a path (`*.json`, `./x`,
`/x`, `~/x`, `C:\x`) but does not exist is "file not found" — the name is never
sent to DNS; anything else is treated as a URL (`https://` is assumed if no
scheme is given).

Security requirements are read in the A2A v1.0 wire shape from `a2a.proto`
(`SecurityRequirement { map<string, StringList> schemes }`):

```json
"securityRequirements": [{"schemes": {"oidc": {"list": ["bookings:write"]}}}]
```

at card level and on individual skills. The pre-1.0 OpenAPI shape
(`[{"oidc": ["bookings:write"]}]`) and the v0.3 `security` field are still
understood, and are flagged (`I207`/`I208`, plus a `compat` action) so you can
migrate.

## Diagnostic codes

| Range | Meaning |
|---|---|
| `E0xx`–`E1xx` | Card schema errors (missing required fields, bad shapes, duplicate skill ids) |
| `W2xx` / `I2xx` | Card lint (plain-HTTP endpoint, unused scheme, thin description, …) |
| `E3xx` / `W3xx` / `I3xx` | Auth surface (`E341` ghost scheme, `E303` unreachable OIDC discovery, `W307` fetch refused by SSRF guard, …) |
| `T4xx` | Task lifecycle (terminal escape, `UNSPECIFIED`, removed `unknown` state) |
| `D5xx` | `card diff`: breaking for existing clients (`D510`/`D511`: skill-level auth) |
| `D6xx` | `card diff`: risky / likely to surprise clients |
| `D7xx` | `card diff`: additive or informational |
| `D610` / `D611` | `card diff --semver`: version moved less than the changes need / version is not semver |
| `E120`–`E125`, `W210`, `W211`, `W216`, `W217` | Proto-derived structure: wrong type (including inside `securitySchemes` and requirement scope lists), empty required array (spec 5.7), snake_case field (5.5), near-miss field name, non-media-type mode, scope list without `list` |
| `S8xx` | Security lint: `S801` hidden/bidi characters, `S802` prompt-injection phrasing (heuristic), `S803` renderer-fetch markup, `S804` loopback/private/metadata URL, `S805` endpoint on a different host than the card, `S807` credentials in URL, `S808` secret-shaped text |
| `G9xx` | Card signatures (`G902` verified, `G903` failed, `G906` `jku` ignored, `G907` algorithm refused) |
| conformance ids | `CARD-*`, `RPC-*`, `REST-*`, `SSE-*`, `SEC-*` etc. in `conformance` output, each with a spec section |

## Security

AgentCards are attacker-controllable input, so `a2aops` treats them that way:

- **SSRF guard.** URLs you type are trusted. URLs that come *from a card*
  (e.g. an OIDC `openIdConnectUrl`) must be HTTPS, must not embed credentials,
  and must resolve only to public addresses — loopback, private, link-local
  (cloud metadata `169.254.169.254`), carrier-grade NAT `100.64.0.0/10`
  (includes Alibaba Cloud's `100.100.100.200` metadata), benchmarking,
  documentation, reserved and multicast ranges are refused. IPv6 addresses that
  tunnel to IPv4 (IPv4-mapped, NAT64 `64:ff9b::/96`, 6to4, Teredo) are judged
  by the IPv4 address they reach, and decimal/hex IP spellings are resolved
  first. The ranges are listed explicitly, so results are the same on Python
  3.10–3.13 (whose built-in `is_global` tables differ). Every redirect hop is
  re-checked. `--allow-private` turns this off for local development stacks.
- **Credentials stay on one host.** URLs you type must be `http` or `https`
  (`file://` and `ftp://` are refused, as are redirects to them). If a server
  redirects to a different host or port, everything except `Accept`,
  `User-Agent` and `A2A-Version` is dropped, so a `--header "Authorization: ..."`
  is never replayed to wherever the server points. `user:password@` in a URL is
  refused and shown as `***@` in messages.
- **Size caps.** Network JSON bodies are capped at 2 MiB, local files and stdin
  at 16 MiB.
- **Strict JSON.** Every untrusted document (cards, discovery documents, JWKS,
  JWS headers, task and SSE payloads) is parsed by a strict loader: duplicate
  object keys are rejected (parsers disagree on which value wins, so a card -
  or a JWS header with two `alg` keys - could show a reviewer one value and a
  client another), as are `NaN`/`Infinity`, nesting deeper than 100 levels, and
  oversized integers. A 100,000-deep array is a one-line error, not a traceback.
  Cost: a card with a duplicate key is exit 2 rather than a lint finding.
- **Wall-clock read limit.** `--timeout` is a per-read socket timeout, so a
  server dripping one byte every few seconds used to hold a run for as long as it
  liked. Bodies are now also cut off after 30 s in total.
- **Stream limits.** `stream` stops a connection whose single SSE line exceeds
  4 MiB, remembers at most 100,000 event ids, and exits 1 when it gives up
  reconnecting (it used to exit 0).
- **Terminal-safe output.** Control characters, ANSI escapes, Unicode bidi
  marks/overrides/isolates, zero-width characters and line separators from
  card, task and stream text are escaped before printing, so a hostile card can't
  rewrite your terminal or fake an "OK". Lone UTF-16 surrogates are escaped as
  well, and stdout/stderr fall back to backslash escapes when the console cannot
  encode a character (cp1252, ASCII), so echoed card text can no longer crash a
  run with a `UnicodeEncodeError`. JSON/SARIF output is JSON-escaped.

## How it compares

Facts below come from each project's own page as of 2026-11-06 (a2a-lint's
PyPI page re-read on 2026-11-07: still 0.1.1, documents `--live`, `--strict`,
`--json`, and no baseline, ignore or SARIF option; the other rows were not
re-read and may have changed); follow the
links to check them. "Not documented" means the page does not mention it, not
that the feature cannot exist.

| Tool | What it is | Standout strengths | Notes |
|---|---|---|---|
| [A2A Inspector](https://github.com/a2aproject/a2a-inspector) (official) | Web UI | Live chat with an agent, raw JSON-RPC debug console, basic card checks | Needs Python + uv + Node/npm, or Docker; CLI/CI mode not documented |
| [a2a-tck](https://github.com/a2aproject/a2a-tck) (official) | Conformance test kit | MUST/SHOULD/MAY test levels across JSON-RPC, gRPC and HTTP+JSON; JUnit/HTML reports | Python 3.11+ and uv; tests a running agent rather than a card file |
| [a2a-lint](https://pypi.org/project/a2a-lint/) | Python CLI + GitHub Action | Live `message/send` and SSE probes, A–F grade, `--json`, `--strict`, badge | Depends on `httpx`; SARIF not documented |
| [capiscio/validate-a2a](https://awesome.ecosyste.ms/projects/github.com%2Fcapiscio%2Fvalidate-a2a) | GitHub Action | JWS signature verification, compliance/trust/availability scores | Page states it targets the A2A v0.3.0 spec |
| [a2a-compliance](https://awesome.ecosyste.ms/projects/github.com%2FUltraSkye%2Fa2a-compliance) | TypeScript CLI, Action, dashboard | Security probes (SSRF, CORS, DNS rebinding), JSON/JUnit/SARIF, snapshot baselines | Node toolchain |
| [a2acli](https://pkg.go.dev/github.com/ghchinoy/a2acli@v1.3.0) | Go CLI | `send`/`watch`/`get` with a streaming TUI, JSON/NDJSON output | Client tool; card validation not documented |
| **a2aops** | Python CLI + library | Card-to-card breaking-change diff with a semver recommendation, v1.0 live conformance suite (49 checks, spec-referenced), pure-Python JWS card verification, security lint, v0.x → v1.0 migration report, SARIF/JUnit, baselines and `--ignore` for adopting on an existing card, `explain` for every code, SSE resubscribe, local playground | Zero dependencies; conformance is a smaller suite than the official TCK (see below); no gRPC probes; JWS verifier is not constant-time |

### Measured, not just described

Everything below is reproducible with `python -m bench.make_results` and is
committed in `bench/RESULTS.json`. Read the caveats: the card corpus (78 cards,
39 valid and 39 deliberately broken) was written by the same people who wrote
the checker, so a2aops' own score is **optimistic by construction**. The
official Inspector's validator was scored on the same cards after the corpus
was frozen; its misses show where the corpus differs from what it targets, not
that it is wrong. About ten cards were relabeled after the first run, after
checking the spec text (the relabeling is in the git history of `bench/cards.py`).

| Task | Checker | Precision | Recall | Notes |
|---|---|---|---|---|
| Is this card invalid? (78 cards) | a2aops 1.3.0 | 1.00 | 1.00 | own corpus, see caveat |
| | a2aops 1.2.0 (previous release) | 0.83 | 0.64 | 5 valid v1.0 cards flagged, 14 broken ones missed |
| | official a2a-inspector `validate` v1.0.0-alpha.1 | 1.00 | 0.92 | Go package, run through a throwaway test harness |
| | a2a-lint 0.1.1 | 0.49 | 0.97 | A2A 0.3 only: it flags every v1.0 card (no `url`) |
| Does the conformance suite catch a broken agent? | a2aops conformance vs 33 injected faults (fault-injecting proxy in front of the strict mock) | n/a | 33 / 33 | clean agent: 0 false alarms in 51 checks (5 skipped) |
| Does hostile input crash it? (seeded fuzz, 6000 mutated cards through check, diff, compat, auth, SARIF/JSON/JUnit) | `python -m bench.fuzz` | n/a | 0 crashes | 2983 inputs rejected with a clean error, 3017 processed; the two crash classes found by hand before this run (deep JSON, lone surrogates) are regression tests, not fuzz finds |
| Right semver bump for a card change? (25 labeled pairs) | `card diff --semver` | n/a | 25 / 25 exact | "any difference is major" snapshot test: 14 / 25 |

The same suite passes 44 of 51 checks against the official Python SDK
(`a2a-sdk` 1.3.0) acting as a real v1.0 server (reproduce with
`python -m bench.sdk_server`, which needs `pip install "a2a-sdk[http-server]==1.3.0" uvicorn`);
every MUST-level check passed, 5 were skipped because the sample agent has no
auth or push gates to test.
The two SHOULD-level warnings were a missing `Cache-Control` on the card and
no `application/a2a+json` content type on errors. The mutation run of the
official a2a-tck through the same proxy did not finish in this session, so there
is no TCK-versus-a2aops detection comparison: **unverified**.

Official TCK facts (from its repository at the time of writing): pytest-based,
458 tests, run with `./run_tck.py --sut-host URL --transport jsonrpc,http_json`.
It is far broader than `a2aops conformance` and also covers gRPC; use it for
certification-grade testing. a2aops conformance is for fast CI feedback with
no install.

## Design decisions (from the expert panel)

- **Strict on schema, lenient on extensions.** Unknown fields and `extensions`
  content never fail validation — a linter that red-flags valid-but-unusual
  cards trains users to ignore it.
- **Auth checks are read-only.** `a2aops` never requests tokens, never stores
  credentials, never performs OAuth flows. It compares the card's *declared*
  auth surface against the metadata the card itself points to.
- **The inspector observes; it doesn't prosecute.** The spec fixes the state
  set and terminal immutability but publishes no normative transition table,
  so only terminal-escape, `UNSPECIFIED`, unknown strings, and messageless
  `INPUT_REQUIRED` are flagged. Unusual-but-legal transitions are reported as
  an observed graph.
- **The playground is a conformance harness, not a simulation.** Mock agents
  are wire-correct scripted fixtures for testing *your client code* — they
  don't predict what a real agent will say.
- **Spec knowledge is a pinned data file** (`src/a2aops/spec_snapshot.json`,
  currently A2A 1.0.0), not scattered string literals. To track a new spec
  version: update that file, bump the pin, re-run the suite.

## Limitations (read before betting on this)

1. **Timing risk is real.** A2A v1.0 is young (released 2026-03-12) and most
   deployed agents are still on pre-1.0 card shapes. This tool bets the
   protocol standardizes rather than fragments; the compat checker is the
   hedge — it's useful *today* precisely because the ecosystem is mid-migration.
2. **The playground tests client code, not agents.** Mock agents are scripted
   fixtures. They won't catch business-logic bugs, model-behavior drift, or
   anything that requires a real counterparty.
3. **No credential-level auth testing, by design.** If the card and the
   discovery doc agree but the token endpoint rejects your client, that's
   outside this tool's scope.
4. **The spec snapshot is hand-maintained.** There is no automated spec-diff;
   if A2A 1.1 changes required fields, update `spec_snapshot.json` and re-run
   the suite.
5. **`.well-known` resolution.** `card check` resolves the well-known path
   under the base URL you give, including any path prefix. If an agent serves
   its card at domain root but is addressed by subpath, you'll get a 404 —
   the error names both probed paths so it's diagnosable. Use `--card-path`
   for non-standard locations.
6. **`card diff` is structural.** It knows the rules listed above; it does not
   understand skill descriptions or examples, so a skill that keeps its id but
   changes behaviour is invisible to it. A clean diff means "no known-breaking
   structural change", not "identical".
7. **SSRF guard limits.** The host is resolved for the check and again by the
   HTTP client to connect, so a DNS-rebinding attacker with a very short TTL can
   race it. `conformance` has the same gap: it resolves an interface name once, before probing, to decide whether it points into a private network. Use `--offline` for cards you do not trust at all. `stream` caps one SSE
   line at 4 MiB (conformance: 1 MiB per line, 8 MiB per stream), so a
   legitimately larger single event is reported as a broken stream.
8. **Signature verification is narrow.** `card verify` handles ES256/384 and
   RS256/384/512 only (no PS*, EdDSA, `crit`), is written for correctness and
   not constant-time, and the official Python SDK canonicalizes differently
   from spec section 8.4 (RFC 8785); a2aops accepts either and says which
   matched (`G909`). It proves the card matches a key you trust, nothing about
   the operator.
9. **Conformance is black-box and v1.0 only.** 51 checks, no gRPC, no
   multi-tenant probes. The prompt-injection lint (`S802`) is a phrase
   heuristic: it will miss paraphrases and sometimes flag harmless prose.
   Subscribe uses GET then POST because the spec proto and prose disagree.

## Development

```bash
cd a2aops
PYTHONPATH=src python3 -m unittest discover -s tests   # 336 tests, zero deps
PYTHONPATH=src python3 -m bench.fuzz 6000                # hostile-input fuzz, exit 1 on any crash
PYTHONPATH=src python3 -m bench.mutate_source            # breaks a2aops in 29 ways; the tests must notice (about 6 min)
python3 -m compileall -q src tests
```

Layout: `src/a2aops/` — `card.py` (fetch/validate/lint), `compat.py`,
`authcheck.py`, `states.py` (wire-vocabulary normalization), `sse.py`,
`tasks.py` (inspector + poll), `playground.py` (mock agents + scenarios),
`diff.py` (breaking-change rules), `secreq.py` (security-requirement shapes),
`report.py` (JSON/SARIF/JUnit), `locate.py` (finding path to source line), `suppress.py`
(`--ignore`, baselines), `explain.py` (code catalogue), `net.py` (size caps, strict
JSON, SSRF guard, terminal-safe output), `cli.py`, `spec.py` +
`spec_snapshot.json` (pinned spec knowledge).

License: MIT. Built by Calas Automations Inc.
