# a2aops — operational toolkit for the A2A protocol

`a2aops` is the missing operational layer for Google's Agent-to-Agent (A2A)
protocol (v1.0, Linux Foundation / AAIF): AgentCard validation and lint,
v0.x → v1.0 migration reports, read-only auth-surface checks, task lifecycle
inspection, SSE streaming with spec-correct resubscription, and a local
multi-agent playground. Think "Docker Compose for A2A" — for the debugging
and conformance work the reference SDKs don't cover.

**Zero dependencies.** Standard library only, Python 3.10+. It runs in
locked-down CI, behind corporate proxies, and anywhere `pip install`
is a procurement conversation.

## Install

```bash
pip install a2aops          # (not yet published — see Limitations)
# or from source:
pip install ./a2aops        # local path install, no network needed
```

## 60-second tour

```bash
# 1. Is that agent's card valid?
a2aops card check https://agent.example.com

# 2. Is it still on the pre-1.0 shape? Get the migration checklist.
a2aops compat https://agent.example.com

# 3. Does the card's auth story match reality? (read-only — never touches credentials)
a2aops auth https://agent.example.com

# 4. Watch a task, auto-resubscribing through SSE drops:
a2aops stream https://agent.example.com task-0001

# 5. Spin up two local agents and watch them talk:
a2aops play demo
```

## Commands

| Command | What it does |
|---|---|
| `a2aops card check <base>` | Fetch `/.well-known/agent-card.json` (falls back to legacy `/.well-known/agent.json` and tells you), validate against the A2A v1.0 schema, lint for robustness. Exit 1 on errors. |
| `a2aops card fetch <base>` | Print the raw card JSON. |
| `a2aops compat <base\|file\|->` | Detect the card version and print a v0.x → v1.0 migration checklist. Accepts a base URL, a JSON file, or `-` for stdin. Exit 1 if migration actions remain. |
| `a2aops auth <base>` | Check the declared auth surface: every `securityRequirements` entry must reference a declared scheme; OIDC discovery documents must resolve and expose a `token_endpoint`; OAuth2 flows need token URLs. Read-only. `--offline` skips remote fetches. |
| `a2aops task poll <base> <task-id>` | Poll a task to a terminal state (`--binding rest\|jsonrpc`), printing each transition and any lifecycle violations. |
| `a2aops task inspect <events.jsonl>` | Offline inspection of a JSONL event log (`{"task_id":…, "state":…, "message"?}` per line) — or a playground wire log straight from `a2aops play demo --log`. Flags transitions out of terminal states, `UNSPECIFIED`/unknown states, and `INPUT_REQUIRED` with no guidance. |
| `a2aops stream <base> <task-id>` | SSE stream with exponential-backoff resubscribe (`tasks/resubscribe` or `POST /v1/tasks/{id}:subscribe`), event-id deduping, and clean close on terminal states. Reconnects and duplicates are reported, never hidden. |
| `a2aops play demo` | Run the built-in two-agent scenario on localhost; writes a timestamped JSONL wire log. |
| `a2aops play run <scenario.json>` | Run your own scenario: `{"agents": [{"name":…}], "script": [{"from":…, "to":…, "text":…}]}`. |

Exit codes: `0` clean · `1` findings reported · `2` usage/operational failure.

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
5. **Not yet published.** The `a2aops` name is verified free on PyPI and npm,
   but no release has been cut. Pin your install to a source checkout until
   then.
6. **`.well-known` resolution.** `card check` resolves the well-known path
   under the base URL you give, including any path prefix. If an agent serves
   its card at domain root but is addressed by subpath, you'll get a 404 —
   the error names both probed paths so it's diagnosable.

## Development

```bash
cd a2aops
PYTHONPATH=src python3 -m unittest discover -s tests   # 107 tests, zero deps
python3 -m compileall -q src tests
```

Layout: `src/a2aops/` — `card.py` (fetch/validate/lint), `compat.py`,
`authcheck.py`, `states.py` (wire-vocabulary normalization), `sse.py`,
`tasks.py` (inspector + poll), `playground.py` (mock agents + scenarios),
`cli.py`, `spec.py` + `spec_snapshot.json` (pinned spec knowledge).

License: MIT. Built by Calas Automations Inc.
