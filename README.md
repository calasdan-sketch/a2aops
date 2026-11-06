# a2aops — operational toolkit for the A2A protocol

**Lint, diff and debug A2A agents from one zero-dependency CLI — and catch
breaking AgentCard changes in CI before your clients do.**

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
pip install a2aops
# or from a source checkout (no network needed):
pip install ./a2aops
```

## 60-second tour

```bash
# 1. Is that agent's card valid? (URL, local file, or '-' for stdin)
a2aops card check https://agent.example.com
a2aops card check ./agent-card.json --strict

# 2. Will my card change break existing clients?
a2aops card diff https://agent.example.com ./agent-card.json

# 3. Still on the pre-1.0 shape? Get the migration checklist.
a2aops compat https://agent.example.com

# 4. Does the card's auth story match reality? (read-only — never touches credentials)
a2aops auth https://agent.example.com

# 5. Watch a task, auto-resubscribing through SSE drops:
a2aops stream https://agent.example.com task-0001

# 6. Spin up two local agents and watch them talk:
a2aops play demo
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
      - run: a2aops card check agent-card.json --strict
      - run: a2aops card diff https://agent.example.com agent-card.json
```

SARIF annotations point at the line of the offending key when the source is a
local file (best-effort key lookup) and always carry the JSON path
(`skills[0].tags`) as a logical location. Use a repo-relative path so GitHub can
map it to the file.

## Commands

| Command | What it does |
|---|---|
| `a2aops card check <src>` | `src` is a base URL, a JSON file, or `-`. For URLs: fetch `/.well-known/agent-card.json` (falls back to legacy `/.well-known/agent.json` and tells you). Validate against the A2A v1.0 schema and lint for robustness. Exit 1 on errors (`--strict`: on warnings too). |
| `a2aops card diff <old> <new>` | Breaking-change report between two cards (each a URL, file, or one `-`). Errors = breaks existing clients (removed skill/interface/input mode, capability turned off, auth newly required, new required extension); warnings = risky (preferred interface reordered, tags dropped, version not bumped, breaking change without a major bump); infos = additive. |
| `a2aops card fetch <base>` | Print the raw card JSON. |
| `a2aops compat <src>` | Detect the card version and print a v0.x → v1.0 migration checklist. Exit 1 if migration actions remain. `--format json` available. |
| `a2aops auth <src>` | Check the declared auth surface: every `securityRequirements` entry must reference a declared scheme; OIDC discovery documents must resolve and expose a `token_endpoint`; OAuth2 flows need token URLs. Read-only. `--offline` skips remote fetches. Card-supplied URLs pass an SSRF guard (see Security). |
| `a2aops task poll <base> <task-id>` | Poll a task to a terminal state (`--binding rest\|jsonrpc`), printing each transition and any lifecycle violations. |
| `a2aops task inspect <events.jsonl>` | Offline inspection of a JSONL event log (`{"task_id":…, "state":…, "message"?}` per line) — or a playground wire log straight from `a2aops play demo --log`. Flags transitions out of terminal states, `UNSPECIFIED`/unknown states, and `INPUT_REQUIRED` with no guidance. |
| `a2aops stream <base> <task-id>` | SSE stream with exponential-backoff resubscribe (`tasks/resubscribe` or `POST /v1/tasks/{id}:subscribe`), event-id deduping, and clean close on terminal states. Reconnects and duplicates are reported, never hidden. |
| `a2aops play demo` | Run the built-in two-agent scenario on localhost; writes a timestamped JSONL wire log. |
| `a2aops play run <scenario.json>` | Run your own scenario: `{"agents": [{"name":…}], "script": [{"from":…, "to":…, "text":…}]}`. |

Common options: `--format text|json|sarif` (`card check`, `card diff`, `auth`),
`--strict`, `--timeout`, and `--card-path /custom/card.json` for agents that
serve their card outside `/.well-known`.

Exit codes: `0` clean · `1` findings reported · `2` usage/operational failure.

Source resolution is explicit: `-` is stdin; a path that exists on disk is read
as a file (a malformed file is an error, never silently retried as a URL);
anything else is treated as a URL (`https://` is assumed if no scheme is given).

## Diagnostic codes

| Range | Meaning |
|---|---|
| `E0xx`–`E1xx` | Card schema errors (missing required fields, bad shapes, duplicate skill ids) |
| `W2xx` / `I2xx` | Card lint (plain-HTTP endpoint, unused scheme, thin description, …) |
| `E3xx` / `W3xx` / `I3xx` | Auth surface (`E341` ghost scheme, `E303` unreachable OIDC discovery, `W307` fetch refused by SSRF guard, …) |
| `T4xx` | Task lifecycle (terminal escape, `UNSPECIFIED`, removed `unknown` state) |
| `D5xx` | `card diff`: breaking for existing clients |
| `D6xx` | `card diff`: risky / likely to surprise clients |
| `D7xx` | `card diff`: additive or informational |

## Security

AgentCards are attacker-controllable input, so `a2aops` treats them that way:

- **SSRF guard.** URLs you type are trusted. URLs that come *from a card*
  (e.g. an OIDC `openIdConnectUrl`) must be HTTPS, must not embed credentials,
  and must resolve only to public addresses — loopback, private, link-local
  (cloud metadata `169.254.169.254`), reserved and multicast ranges are refused,
  including IPv4-mapped IPv6 and decimal/hex IP tricks. Every redirect hop is
  re-checked. `--allow-private` turns this off for local development stacks.
- **Size caps.** Network JSON bodies are capped at 2 MiB, local files and stdin
  at 16 MiB.
- **Terminal-safe output.** Control characters, ANSI escapes and Unicode bidi
  overrides from card text are escaped before printing, so a hostile card can't
  rewrite your terminal or fake an "OK". JSON/SARIF output is JSON-escaped.

## How it compares

Facts below come from each project's own page as of 2026-11-06; follow the
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
| **a2aops** | Python CLI + library | Card-to-card breaking-change diff, v0.x → v1.0 migration report, SARIF, SSRF-guarded auth checks, SSE resubscribe, local playground | Zero dependencies; no JWS signature check or live conformance probe yet (see Limitations) |

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
   race it. Use `--offline` for cards you do not trust at all. SSE stream lines
   are not size-capped (long-lived streams legitimately carry large artifacts).
8. **No signed-card verification yet.** `signatures` on a card are accepted but
   not cryptographically verified (that needs a crypto dependency this release
   avoids).

## Development

```bash
cd a2aops
PYTHONPATH=src python3 -m unittest discover -s tests   # 145 tests, zero deps
python3 -m compileall -q src tests
```

Layout: `src/a2aops/` — `card.py` (fetch/validate/lint), `compat.py`,
`authcheck.py`, `states.py` (wire-vocabulary normalization), `sse.py`,
`tasks.py` (inspector + poll), `playground.py` (mock agents + scenarios),
`diff.py` (breaking-change rules), `report.py` (JSON/SARIF), `net.py` (size
caps, SSRF guard, terminal-safe output), `cli.py`, `spec.py` +
`spec_snapshot.json` (pinned spec knowledge).

License: MIT. Built by Calas Automations Inc.
