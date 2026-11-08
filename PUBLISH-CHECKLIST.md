# Publish checklist for a2aops (read this first, then decide)

Nothing below has been run. Claude did not publish, tag or push anything. The upload step is yours: you are signed in to PyPI, Claude never runs it.

**Version to release: 1.3.0.** PyPI currently has only 1.1.0 (checked 2026-11-08), so 1.2.0 was never released and 1.3.0 includes everything from rounds 2 to 5. The number is already set in `pyproject.toml`, `src/a2aops/__init__.py` and `CHANGELOG.md`, and a test fails if they disagree. Moving from 1.1.0 is a minor release, but behaviour changed in four ways, all listed in the CHANGELOG: a card with duplicate keys now stops with exit 2; `file://` and `ftp://` sources are refused; a zero or negative `--timeout` is refused; and (new in round 5) `conformance` will not probe card addresses that point into a private network unless you add `--allow-private-endpoints`, and `card check` now reports wrong types inside `securitySchemes`. Any of these can turn a previously green CI run red, which is the point, but worth one sentence in the release notes.

## Check these first (plain words)

1. **Decide the public repository address.** Then add `Repository`, `Issues` and `Changelog` lines under `[project.urls]` in `pyproject.toml`. Today only calasautomations.com is listed, because nobody here could confirm whether the GitHub repository is public. Do not add the address if the repository is private.
2. **Look at the copyright line** in `LICENSE` ("Copyright (c) 2026 Calas Automations Inc."). The author name is the same in `pyproject.toml`. No email address is published anywhere; add one only if you want it public.
3. **Turn on the test workflow once** (`.github/workflows/ci.yml`). It runs the tests on Linux (Python 3.10 to 3.13), Windows and macOS. Windows and macOS have never been run, so this is the first real proof. On a private repository GitHub counts macOS minutes at 10 times and Windows at 2 times against your free allowance; the file keeps it to one job each. If anything fails there, fix it before releasing.
4. After 1.3.0 is live, delete the sentence in the README Install section that says "Until 1.3.0 is published, install from a checkout".
5. Optional: run `python -m bench.mutate_source` (about 6 minutes). Every line should say `killed`.

## Commands (from the repository folder)

```bash
python -m pip install --upgrade build twine
rm -rf dist build
python -m build                      # makes dist/a2aops-1.3.0.tar.gz and .whl
python -m twine check dist/*         # both must say PASSED
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl
/tmp/try/bin/a2aops --version        # must print: a2aops 1.3.0
unzip -p dist/*.whl 'a2aops-1.3.0.dist-info/METADATA' | grep '^Author'   # must print: Author: Calas Automations Inc.
# optional: upload to the test index first
python -m twine upload --repository testpypi dist/*
# the real upload (needs your PyPI account or token; cannot be undone, versions cannot be reused)
python -m twine upload dist/*
git tag v1.3.0 && git push origin v1.3.0
```

On Windows replace `/tmp/try/bin/` with `C:\path\to\venv\Scripts\` and `unzip -p` with any zip tool.
