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
import re
from typing import Iterable, Optional

from . import __version__
from .card import ERROR, INFO, WARNING, Diagnostic

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


def _last_key(path: str) -> Optional[str]:
    # "skills[2].tags" -> "tags"; "securitySchemes.oidc" -> "oidc"; "skills[id=x]" -> "skills"
    m = re.findall(r"[A-Za-z_][A-Za-z0-9_\-]*", re.sub(r"\[[^\]]*\]", "", path))
    return m[-1] if m else None


def _line_for(path: str, text: Optional[str]) -> int:
    if not text or not path:
        return 1
    key = _last_key(path)
    if not key:
        return 1
    idx = text.find(json.dumps(key) + ":")
    if idx < 0:
        idx = text.find(json.dumps(key))
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def to_sarif(diags: list[Diagnostic], *, command: str, artifact_uri: str,
             source_text: Optional[str] = None) -> str:
    rules: dict[str, dict] = {}
    results = []
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
                "region": {"startLine": _line_for(d.path, source_text)},
            },
        }
        if d.path:
            loc["logicalLocations"] = [{"fullyQualifiedName": d.path, "kind": "member"}]
        results.append({
            "ruleId": d.code,
            "level": _SARIF_LEVEL.get(d.severity, "note"),
            "message": {"text": d.message},
            "locations": [loc],
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
