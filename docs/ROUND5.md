# Round 5: field experts

Branch `expert-2`. Nothing was published, uploaded, tagged or pushed.

## How this review was done (honest)

No sub-agent tool was available, so **one reviewer played every role in turn**; these are angles, not independent people. Each finding names the command that showed it. Baseline before any change: 302 tests OK, card corpus 78 cards precision 1.00 / recall 1.00, 32 / 32 injected server faults caught (49 checks, 0 false alarms), 25 / 25 semver pairs, fuzz 6000 inputs / 0 crashes.

## Author line

Already "Calas Automations Inc." in `pyproject.toml` and `LICENSE` from round 4; this round added `__author__`, the `--help` footer, SARIF `tool.driver.organization` and a JUnit property, and `tests/test_round5.py::TestAuthorLine` pins all of them and fails on the old GitHub handle or the old company name anywhere in docs, source, README, LICENSE. Proof from a freshly built wheel and sdist: `unzip -p dist/*.whl a2aops-1.3.0.dist-info/METADATA | grep Author` and `tar xzf dist/*.tar.gz -O a2aops-1.3.0/PKG-INFO | grep Author` both print `Author: Calas Automations Inc.`. No email was added. No repository URL is published in the package metadata (repository visibility is unknown here; GitHub is blocked), only `https://calasautomations.com`. The SARIF output used to link to a GitHub address; it no longer does.

## Specialist findings

| Specialist | Finding | Proving command |
|---|---|---|
| A2A SDK maintainer | **`card check` said OK to cards the official SDK refuses.** `securitySchemes` and requirement scope lists were never type-checked (an API key `name` of `7`, `scopes` holding arrays, a scheme that is a string). Of 3083 single-mutation cards the SDK rejected (seed 5), a2aops reported no error on 431 (14%) before and 40 (1.3%) after; the 40 left are unknown fields, which never fail by design. Fixed (`E120` paths, new `W217`). Left deliberately: unknown fields never fail. | `bench`-style differential: `ParseDict(card, AgentCard())` from `a2a-sdk` 1.3.0 against `check_card` over 6000 seeded mutations; now `tests/test_round5.py::TestSecuritySchemeTypes::test_agrees_with_official_sdk_parser_when_installed` (skipped when the SDK is absent) |
| A2A SDK maintainer | The README's "42 of 49 checks pass against the official SDK" could not be reproduced from the repo. Added `bench/sdk_server.py`; today it is **44 of 51** (0 failed, 2 SHOULD warnings: missing `Cache-Control`, `application/json` content type on REST errors; 5 skipped). | `python -m bench.sdk_server 8765` (in a venv with `a2a-sdk[http-server]==1.3.0 uvicorn`), `a2aops conformance http://127.0.0.1:8765 --active` |
| A2A SDK maintainer | Cards signed by the SDK's own signer verify with `card verify`: 17 of 17 random (including spec-noncompliant mutated) cards, ES256/ES384/RS256. | scratch script using `a2a.utils.signing.create_agent_card_signer` + `jws.verify_signature` |
| AppSec reviewer | **`conformance` was a request cannon.** It probes every interface URL in the card, whatever the host. A card served from a public host listing `http://169.254.169.254/...` or an internal admin port made the tester send 22 requests there (25 with `--active`, including a real `SendMessage`). Fixed: such interfaces are skipped and named unless `--allow-private-endpoints`; a local tested URL is unaffected. | two local servers, one pretending to be the metadata host: 22 hits before, 0 after (`tests/test_round5.py::TestConformanceDoesNotProbeInward`) |
| AppSec reviewer | **Same hole through redirects**: a public endpoint answering `307 -> http://localhost:PORT/` moved a GET probe inward. Fixed with a redirect guard installed for the duration of a run. | `TestRedirectsCannotReachInward` |
| AppSec reviewer | No problem found: CRLF / NUL in `--header` (refused), ESC / OSC / bidi / NUL in scheme names and skill names (escaped in text, JSON, SARIF; JUnit still parses as XML), 70 MB file and stdin (capped at 16 MiB), 100,000-digit integer (clean error), 100,000-deep JSON (clean error), spaces / non-ASCII / `C:\` paths, `LC_ALL=C PYTHONIOENCODING=ascii`. | commands in the scratch log; golden and property tests keep them from regressing |
| API conformance tester | No check covered browser safety. Added `RPC-30` / `REST-30` (SHOULD, labelled "not in the A2A spec"): an endpoint must not echo an arbitrary `Origin` with `Allow-Credentials: true`. 49 -> 51 checks; new injected fault `cors-reflect-credentials` (33 faults, all detected, 0 false alarms on the clean agent). The competitor `a2a-compliance` advertises CORS checks; this closes that gap for the credentialed-reflection case only (no TLS or preflight checks). | `python -m bench.run_mutants`; `TestCorsProbe` |
| QA / test methodology | **Property tests found a crash the fuzzer missed**: `card diff` died with `TypeError: unhashable type` when an extension `uri` was an object or array. Fixed. Added seeded property tests (never raises, deterministic, key order irrelevant, self-diff silent, removal breaking / re-adding not, baseline round-trip, SARIF line in range, JCS canonicalisation against `json.dumps`, strict loader against `json.loads`). | `tests/test_round5.py::TestProperties`; `hypothesis` was installed in a scratch venv only for the fuzz script, not made a dependency |
| QA / test methodology | **Mutation sanity**: `bench/mutate_source.py` breaks a2aops itself in 29 places (redirect credentials, size caps, duplicate keys, SSRF ranges, `--strict`, breaking-change severities, exit codes, ...) and requires the suite to fail. Result: see `bench/RESULTS.json` (`source_mutants`). Three first-draft mutants did not apply (pattern text drifted); they were corrected rather than counted as kills. | `python -m bench.mutate_source` (about 6 minutes) |
| QA / test methodology | **Golden files** for text / JSON / SARIF / JUnit of `card check` and `card diff` on 3 + 2 fixtures, plus `compat`, `auth`, `explain`: 25 files in `tests/golden/`. | `A2AOPS_UPDATE_GOLDEN=1 python -m unittest tests.test_round5` regenerates after an intended change |
| Release manager | Upgrade path from the only release on the registry (1.1.0, `pip download a2aops==1.1.0 --no-deps`): logs written by 1.1.0 `play demo` / `play run` are read identically by this tree's `task inspect` (diff of outputs empty); a 1.1.0 scenario file runs; no command-line option of 1.1.0 was removed (compared `--help` of 8 subcommands); `card check`, `card fetch`, `compat`, `auth` against the same server give the same exit codes, and the new output is only added findings (`S805`, `I215`, `I216`) and a version string. No state or config file from 1.1.0 needed migration. | scripts in scratch, outputs diffed |
| Release manager | The sdist did not carry text golden files; `MANIFEST.in` fixed. Tests pass from the extracted sdist against the installed wheel in a clean venv (336 tests). A GitHub Actions workflow (`.github/workflows/ci.yml`) and a pre-commit hook file (`.pre-commit-hooks.yaml`) were added; **neither has run** (YAML parsed only). | `tar xzf ... && python -m unittest discover -s tests` in the clean venv |
| Technical writer / first-time user | Every README command that can run offline was run from the freshly built, non-editable wheel in a clean venv against a local mock agent (14 commands, all behave; exit codes as documented). Counts in the README (51 checks, 33 faults, 336 tests, 44 of 51) were wrong or unreproducible and are fixed. | `readme/run.py` in scratch |
| Performance engineer | 7 MB card with 40,000 skills, 20,000 security schemes, 5,000 requirements: `card check --format json` 1.3 s CPU, `card diff` of it against itself 0.8 s CPU. No quadratic behaviour. | `time a2aops card check huge.json` |
| Competitor maintainer (read-only) | `a2a-lint` still 0.1.1, `a2a-sdk` 1.3.0 (`pip index versions`). `a2a-tck` is not on PyPI and GitHub is blocked here: **unverified**. PyPI has an `a2a-inspector 0.1.0` that is an empty placeholder (one `main.py`, not the official inspector). `a2a-compliance` (TypeScript) is indexed with SSRF / TLS / CORS checks, last pushed 2026-05-18 per ecosyste.ms; not on npm. | `pip index versions`, `npm view`, `curl` of the ecosyste.ms page |

## Debug pass

`ruff check --select F,B,E9`: clean apart from six B023 notes in `jws.py` (closures used inside the loop iteration that creates them: false positives, left). `mypy src/a2aops --ignore-missing-imports`: **51 errors in 11 files**, mostly Optional narrowing in `conformance.Ctx`; `py.typed` is therefore still a marker, not a verified claim. Python 3.10 syntax: `ast.parse(feature_version=(3,10))` over src, tests and bench passes; no 3.10 interpreter available. Tests pass on 3.11, 3.12 and 3.13 (336, 1 skipped without the SDK).

## Scored idea list

Scores 1-5 (5 = best for value and differentiation; for effort and risk 5 = costly or risky).

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Conformance refuses probes (and redirects) into private networks | 5 | 4 | 2 | 2 | DONE |
| 2 | Type-check `securitySchemes` / scope lists (SDK differential) | 5 | 3 | 2 | 2 | DONE |
| 3 | Fix `card diff` crash on hostile extension `uri` | 4 | 1 | 1 | 1 | DONE |
| 4 | `--output FILE` (UTF-8, LF, atomic) | 4 | 2 | 2 | 1 | DONE (PowerShell itself not run) |
| 5 | CORS credential-reflection check `RPC-30` / `REST-30` | 3 | 4 | 2 | 1 | DONE |
| 6 | Reproducible SDK-as-server harness | 3 | 3 | 2 | 1 | DONE |
| 7 | Mutation sanity of a2aops's own source | 4 | 4 | 2 | 1 | DONE |
| 8 | Golden files for every output format | 4 | 2 | 2 | 1 | DONE |
| 9 | Seeded property tests + SDK differential test | 4 | 3 | 2 | 1 | DONE |
| 10 | Author pinned in package, SARIF, JUnit, help; old handle banned | 3 | 1 | 1 | 1 | DONE |
| 11 | CI matrix incl. Windows and macOS (cost note: 2x / 10x minutes on private repos) | 5 | 2 | 1 | 1 | DONE as a file; not run |
| 12 | `.pre-commit-hooks.yaml` (path passed via `args`) | 3 | 3 | 1 | 1 | DONE as a file; pre-commit not run |
| 13 | Project URLs in package metadata | 4 | 1 | 1 | 1 | NOT-DONE: repository visibility unknown, Dan decides |
| 14 | Trusted publishing (OIDC) workflow | 4 | 1 | 2 | 2 | NOT-DONE: needs PyPI project settings |
| 15 | Make mypy pass so `py.typed` is earned | 3 | 1 | 3 | 1 | NOT-DONE: 51 errors measured |
| 16 | Move the `read <path>` banner to stderr | 2 | 1 | 1 | 3 | NOT-DONE: changes stdout for scripts |
| 17 | gRPC probes | 3 | 4 | 5 | 3 | NOT-DONE: needs a dependency |
| 18 | EdDSA / PS* in `card verify` | 2 | 2 | 3 | 3 | NOT-DONE |
| 19 | Official a2a-tck mutation comparison | 4 | 3 | 3 | 1 | NOT-DONE: GitHub blocked |
| 20 | TLS checks in conformance (certificate, protocol version) | 3 | 3 | 3 | 2 | NOT-DONE: needs a live TLS fixture |
| 21 | Pin the resolved IP for probes (closes the DNS-rebinding gap) | 3 | 3 | 4 | 3 | NOT-DONE: needs a custom connection class |
| 22 | `card check` accepts several files (better pre-commit) | 3 | 1 | 3 | 2 | NOT-DONE: report formats with several sources need a design |
| 23 | Multi-tenant conformance probes | 2 | 3 | 4 | 2 | NOT-DONE |
| 24 | Shell completion | 1 | 1 | 2 | 1 | NOT-DONE |
| 25 | Hash-pinned build requirements | 2 | 1 | 2 | 2 | NOT-DONE |

## What could not be tested

- Windows, macOS: never run (the new CI file would be the first run). PowerShell's UTF-16 redirect, which motivated `--output`, was reasoned about, not reproduced.
- Python 3.10: syntax only.
- The CI workflow, the pre-commit hook, the composite GitHub Action on a real runner.
- `a2a-tck` and the official Inspector (GitHub blocked).
- The SDK differential and SDK-as-server numbers were measured with `a2a-sdk` 1.3.0 only.
- The CORS check against a browser: only the header logic against a fault-injecting proxy and the SDK server.
- DNS-based inward detection depends on the resolver of the machine running the tests; the tests use literal addresses and `localhost`.
- Publishing: not attempted; `twine check` passes on both artifacts (a format check only).
