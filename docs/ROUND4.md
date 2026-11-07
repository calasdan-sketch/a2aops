# Round 4: the first hour after `pip install`

Scope: what a stranger gets from `pip install a2aops`. Branch `expert-2`. Nothing was published, uploaded, tagged or pushed.

## How this review was done (honest)

No sub-agent tool was available in this session, so **one reviewer played every role in turn**; these are angles, not independent people, and the same blind spots apply to all of them. Each finding below names the command that showed it. Baseline before any change: 284 tests OK (about 9.5 s), benchmark run clean, fuzz 6000 inputs / 0 crashes.

## Specialist findings

| Angle | Finding | Proof |
|---|---|---|
| Release engineer | Repo and both artifacts had **no LICENSE file** although pyproject and README say MIT. No `py.typed`; sdist had no CHANGELOG, no test fixtures; PyPI summary was a 300-character paragraph; one classifier-less Python range. | `python -m build`, `unzip -l *.whl`, `tar tzf *.tar.gz` |
| Release engineer | PyPI has only **1.1.0** (`pip index versions a2aops`, and the JSON API: home page and project URLs show only calasautomations.com). README documented ~half a dozen commands that 1.1.0 does not have. | `pip index versions a2aops` |
| First-time user (clean venv, not editable, from the built wheel) | Every README command that can run offline works from a fresh 3.11, 3.12 and 3.13 venv; installed package has zero dependencies (`pip freeze` shows only itself); `--version`, `--help`, `python -m a2aops` work; README `card diff` sample output reproduced byte for byte; full suite passes against the installed wheel on all three. | commands in PUBLISH-CHECKLIST.md |
| Supply chain | `conformance --header "Authorization: ..."` is documented as sent to one host only, but **a 302 to another host/port received the token** (urllib copies headers on redirect). Reproduced with two local servers, fixed, test added. | `tests/test_round4.py::TestRedirectsDoNotLeakCredentials` |
| Supply chain | `file://` and `ftp://` typed as a card source were passed to urllib; a redirect could point at `ftp://`. `user:pw@host` was echoed in errors and JSON. | `a2aops card check file:///...`, `http://u:p@127.0.0.1:1/` |
| Hostile input | `play demo --log <bad dir>` and `play run` with `{"script":[{"from":"a"}]}` or a JSON list ended in tracebacks; `task inspect` with `"ts": null` raised TypeError. | run each; now exit 2 with one line |
| CI integrator | `--timeout 0`, `-5`, `nan`, `inf` accepted. `--write-baseline` wrote in place (two parallel jobs or a crash can leave half a file). | `a2aops card check x --timeout -5` |
| Performance | 8.7 MB card with 40,000 skills: check 1.9 s CPU, diff of two such cards 0.7 s CPU; startup 0.07 s CPU. No quadratic behaviour found. (Wall time on this shared box was 3-4x the CPU time; not investigated.) | `time a2aops card check big.json` |
| Docs/DX | README "from a checkout" install line was the only honest hint about the version gap; test count in README drifts. | now stated explicitly; a test checks the count within a tolerance |
| Competitor's maintainer | a2a-lint is still 0.1.1 and a2a-sdk 1.3.0 on PyPI today (read-only `pip index versions`). a2a-tck and a2a-inspector could **not** be re-read (GitHub access blocked here): unverified, left as the 2026-11-06 values in the README. | `pip index versions a2a-lint a2a-sdk` |

## Windows (static review only, nothing was run on Windows)

Checked by reading the source and by simulating the failure modes on Linux:

- `shell=True`, `signal`, `fork`, `os.getuid`: none used. Servers bind `127.0.0.1`.
- Console encoding (cp1252): `main()` already switches stdout/stderr to `backslashreplace`; reproduced with `PYTHONIOENCODING=ascii`.
- Stdin is read as bytes, so cards piped in UTF-8 are not mangled by the console code page. BOM and CRLF cards parse (tested with a BOM file and a CRLF file).
- Windows drive paths (`C:\x`) are recognised as paths, never sent to DNS; SARIF has a `file:///C:/...` branch (existing tests).
- Fixed: baseline write now uses temp-file plus `os.replace` with an in-place fallback if Windows refuses the rename (file open elsewhere). Playground log forced to `\n` newlines (was platform default, so CRLF on Windows).
- Not verifiable here: real console behaviour, antivirus locking, long-path limits, `python -m a2aops` through the `py` launcher.

## Scored idea list

Scores 1-5 (5 = best for value and differentiation; for effort and risk 5 = costly/risky). Status is as of this commit.

| # | Idea | User value | Differentiation | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Stop `--header` credentials following cross-host redirects | 5 | 3 | 2 | 1 | DONE |
| 2 | http(s)-only sources and redirects | 4 | 2 | 1 | 1 | DONE |
| 3 | Redact `user:pw@` in output | 3 | 1 | 1 | 1 | DONE |
| 4 | Add LICENSE to repo and artifacts | 5 | 1 | 1 | 1 | DONE |
| 5 | `py.typed` + Typing classifier | 2 | 1 | 1 | 1 | DONE (marker only; no type checker is configured or run, so "typed" is a promise about annotations, not a verified claim) |
| 6 | SPDX license expression, classifiers, keywords, short summary | 3 | 1 | 1 | 2 | DONE (needs setuptools >= 77 at build time; pip fetches it automatically) |
| 7 | sdist carries CHANGELOG, tests, fixtures, bench, action.yml | 3 | 1 | 1 | 1 | DONE |
| 8 | Clean-error handling for play/log/scenario/inspect | 3 | 1 | 2 | 1 | DONE |
| 9 | Validate `--timeout/--interval/--max-*` | 3 | 1 | 1 | 1 | DONE |
| 10 | Atomic baseline write | 3 | 1 | 1 | 1 | DONE |
| 11 | Metadata drift test (pyproject, `__version__`, CHANGELOG head) | 4 | 2 | 1 | 1 | DONE |
| 12 | README states registry/repo gap, tested platforms | 5 | 2 | 1 | 1 | DONE |
| 13 | Project URLs (Repository, Issues, Changelog) | 4 | 1 | 1 | 1 | NOT-DONE: public repo address unknown to this checkout; Dan decides |
| 14 | Windows CI job (GitHub Actions matrix incl. windows-latest, macOS, 3.10) | 5 | 2 | 2 | 1 | NOT-DONE: needs the real repo and runners; would turn the biggest "unverified" into a fact |
| 15 | Trusted publishing (OIDC) workflow instead of an API token | 4 | 1 | 2 | 2 | NOT-DONE: needs the PyPI project settings |
| 16 | Type-check in CI (mypy/pyright) so `py.typed` is earned | 3 | 1 | 3 | 1 | NOT-DONE |
| 17 | `--output FILE` for sarif/json so shells that re-encode redirects (PowerShell 5 writes UTF-16) cannot corrupt reports | 4 | 2 | 2 | 1 | NOT-DONE (real Windows pain for SARIF upload; not testable here) |
| 18 | Move the `read <path>` banner from stdout to stderr in text mode | 2 | 1 | 1 | 3 | NOT-DONE: changes stdout for scripts that already parse it |
| 19 | gRPC probes in `conformance` | 3 | 4 | 5 | 3 | NOT-DONE (needs a dependency or hand-written HTTP/2; against the zero-dependency promise) |
| 20 | EdDSA / PS* in `card verify` | 2 | 2 | 3 | 3 | NOT-DONE |
| 21 | Run official a2a-tck mutation comparison | 4 | 3 | 3 | 1 | NOT-DONE (blocked: GitHub unreachable here) |
| 22 | `card check --watch` / pre-commit hook config (`.pre-commit-hooks.yaml`) | 3 | 3 | 1 | 1 | NOT-DONE: cheap, worth doing next round |
| 23 | Shell completion | 1 | 1 | 2 | 1 | NOT-DONE |
| 24 | Make installs reproducible: hash-pinned build requirements | 2 | 1 | 2 | 2 | NOT-DONE |

## What could not be tested

- Windows, macOS: never run. Python 3.10: syntax checked with `ast.parse(feature_version=(3,10))` only; 3.10 interpreter not available (the 1.2.0 notes say 3.10 passed then; not re-confirmed).
- The composite GitHub Action on a real runner.
- Read-only filesystem: the sandbox user is root, so permission-denied paths were exercised only through "directory does not exist" and "path under /proc".
- a2a-tck and a2a-inspector re-check (network to GitHub blocked).
- Publishing: deliberately not attempted; `twine check` passed on both artifacts, which is a format check only.
