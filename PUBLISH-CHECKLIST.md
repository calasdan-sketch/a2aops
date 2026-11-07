# Publish checklist for a2aops (read this first, then decide)

Nothing below has been run. Claude did not publish, tag or push anything.

**Version to release: 1.3.0.** PyPI currently has only 1.1.0 (checked 2026-11-07), so 1.2.0 was never released and 1.3.0 includes everything from both. The version number is already set to 1.3.0 in `pyproject.toml`, `src/a2aops/__init__.py` and `CHANGELOG.md`. Moving from 1.1.0 is a minor release, not a major one, but three behaviours changed and are listed in the CHANGELOG: a card with duplicate keys now stops with exit 2, `file://`/`ftp://` sources are refused, and a zero or negative `--timeout` is refused.

## Check these first

1. Decide the public repository address and add `Repository`, `Issues` and `Changelog` lines under `[project.urls]` in `pyproject.toml`. Right now only calasautomations.com is listed.
2. Check that the copyright line in `LICENSE` ("Calas Automations Inc.", 2026) is what you want.
3. If you can, run the tests once on Windows and on macOS (or add a CI job with those runners). They have never been run there. The README says so.
4. Remove the line in the README that says "Until 1.3.0 is published, install from a checkout" once 1.3.0 is live.

## Commands (from the repository folder)

```bash
python -m pip install --upgrade build twine
rm -rf dist build
python -m build                      # makes dist/a2aops-1.3.0.tar.gz and .whl
python -m twine check dist/*         # both must say PASSED
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl
/tmp/try/bin/a2aops --version        # must print: a2aops 1.3.0
# optional: upload to the test index first
python -m twine upload --repository testpypi dist/*
# the real upload (needs your PyPI account or token; cannot be undone, versions cannot be reused)
python -m twine upload dist/*
git tag v1.3.0 && git push origin v1.3.0
```

On Windows replace `/tmp/try/bin/` with `C:\path\to\venv\Scripts\`.
