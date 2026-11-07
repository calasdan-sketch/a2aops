"""Machine-readable output: JSON and SARIF 2.1.0.

SARIF is the format GitHub code scanning, GitLab and most CI dashboards ingest,
so ``a2aops card check card.json --format sarif > a2aops.sarif`` turns card
findings into annotations on a pull request with no extra tooling.

Card findings carry a JSON path (``skills[2].tags``), not a source line. For
local files we look up the line of the first matching key so annotations land
near the right place; otherwise they point at line 1 and carry the JSON path as
a SARIF logical location.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from pathlib import Path, PurePath, PureWindowsPath
from typing import Iterable, Optional

from . import __version__
from .card import ERROR, INFO, WARNING, Diagnostic
from .locate import LineIndex
from .suppress import fingerprint

_SARIF_LEVEL = {ERROR: "error", WARNING: "warning", INFO: "note"}
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/calasdan-sketch/a2aops"


def failed(diags: Iterable[Diagnostic], strict: bool = False) -> bool:
    """True when findings should fail the run (errors; warnings too if strict)."""
    bad = {ERROR, WARNING} if strict else {ERROR}
    return any(d.severity in bad for d in diags)


def to_json(diags: list[Diagnostic], *, command: str, source: str,
            strict: bool = False, extra: Optional[dict] = None) -> str:
    counts = {s: sum(1 for d in diags if d.severity == s) for s in (ERROR, WARNING, INFO)}
    doc = {
        "tool": "a2aops", "version": __version__, "command": command,
        "source": source, "strict": strict, "ok": not failed(diags, strict),
        "counts": counts, "findings": [d.to_dict() for d in diags],
    }
    if extra:
        doc.update(extra)
    return json.dumps(doc, indent=2)


def path_to_uri(path: str, cwd: Optional[str] = None) -> str:
    """Turn a local path into a SARIF ``artifactLocation.uri``.

    Paths under the working directory become relative, percent-encoded URI
    references (``cards/my%20card.json``) that GitHub code scanning maps to
    repository files. Anything else becomes an absolute ``file://`` URI.
    Windows paths (``C:\\x\\card.json``) never leak a fake ``c:`` scheme.
    """
    base = Path(cwd or os.getcwd()).resolve()
    p = Path(os.path.expanduser(path))
    try:
        absolute = (p if p.is_absolute() else base / p).resolve()
    except (OSError, RuntimeError):
        absolute = base / p
    try:
        rel: PurePath = absolute.relative_to(base)
        return urllib.parse.quote(rel.as_posix(), safe="/")
    except ValueError:
        pass
    try:
        return absolute.as_uri()
    except ValueError:
        # not absolute on this OS (e.g. a Windows path seen on POSIX)
        win = PureWindowsPath(path)
        if win.drive:
            return "file:///" + urllib.parse.quote(win.as_posix(), safe="/:")
        return urllib.parse.quote(PurePath(path).as_posix(), safe="/")


def _last_key(path: str) -> Optional[str]:
    # "skills[2].tags" -> "tags"; "securitySchemes.oidc" -> "oidc"; "skills[id=x]" -> "skills"
    m = re.findall(r"[A-Za-z_][A-Za-z0-9_\-]*", re.sub(r"\[[^\]]*\]", "", path))
    return m[-1] if m else None


def _line_for(path: str, text: Optional[str], index=None) -> int:
    if not text or not path:
        return 1
    if index is not None:
        found = index.line(path)
        if found:
            return found
    key = _last_key(path)
    if not key:
        return 1
    idx = text.find(json.dumps(key) + ":")
    if idx < 0:
        idx = text.find(json.dumps(key))
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _unique_fp(d: Diagnostic, seen: dict) -> str:
    """Fingerprint, disambiguated when one run has several findings with the same code and path
    (code scanning treats equal fingerprints as the same alert)."""
    fp = fingerprint(d)
    n = seen.get(fp, 0)
    seen[fp] = n + 1
    return fp if n == 0 else f"{fp}:{n}"


def to_sarif(diags: list[Diagnostic], *, command: str, artifact_uri: str,
             source_text: Optional[str] = None) -> str:
    rules: dict[str, dict] = {}
    results = []
    index = LineIndex(source_text) if source_text else None
    seen_fp: dict[str, int] = {}
    for d in diags:
        rules.setdefault(d.code, {
            "id": d.code,
            "name": d.code,
            "shortDescription": {"text": d.message.split(" — ")[0][:200]},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(d.severity, "note")},
            "helpUri": _INFO_URI + "#diagnostic-codes",
        })
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
                "region": {"startLine": _line_for(d.path, source_text, index)},
            },
        }
        if d.path:
            loc["logicalLocations"] = [{"fullyQualifiedName": d.path, "kind": "member"}]
        results.append({
            "ruleId": d.code,
            "level": _SARIF_LEVEL.get(d.severity, "note"),
            "message": {"text": d.message},
            "locations": [loc],
            # lets code scanning keep an alert open as the line moves
            "partialFingerprints": {"a2aopsFinding/v1": _unique_fp(d, seen_fp)},
        })
    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "a2aops", "version": __version__,
                "informationUri": _INFO_URI, "rules": list(rules.values()),
            }},
            "automationDetails": {"id": f"a2aops/{command}/"},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def to_junit(diags: list[Diagnostic], *, command: str, source: str, strict: bool = False) -> str:
    """JUnit XML: one failing testcase per error (and per warning with ``strict``)."""
    from xml.sax.saxutils import escape, quoteattr
    from .net import clean   # control/bidi characters are not even legal XML 1.0
    bad = {ERROR, WARNING} if strict else {ERROR}
    diags = [Diagnostic(d.severity, d.code, clean(d.message), clean(d.path)) for d in diags]
    source = clean(source)
    cases = []
    for d in diags:
        name = f"{d.code} {d.path}".strip()
        if d.severity in bad:
            cases.append(f'    <testcase classname={quoteattr("a2aops." + command)} name={quoteattr(name)}>'
                         f'<failure type={quoteattr(d.severity)} message={quoteattr(d.message[:300])}>'
                         f'{escape(d.message)}</failure></testcase>')
        else:
            cases.append(f'    <testcase classname={quoteattr("a2aops." + command)} name={quoteattr(name)}>'
                         f'<system-out>{escape(d.severity + ": " + d.message)}</system-out></testcase>')
    if not cases:
        cases.append(f'    <testcase classname={quoteattr("a2aops." + command)} name="no findings"/>')
    fails = sum(1 for d in diags if d.severity in bad)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuites><testsuite name={quoteattr("a2aops " + command + " " + source)} '
            f'tests="{len(cases)}" failures="{fails}">\n' + "\n".join(cases) + '\n  </testsuite></testsuites>')
