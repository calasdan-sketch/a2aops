"""Suppressing known findings: ``--ignore`` and baselines.

Adopting a linter on an existing card usually means "fail on new problems
only". ``--write-baseline FILE`` records today's findings; ``--baseline FILE``
then hides exactly those (same code at the same card path) and fails only on
anything new. ``--ignore CODE`` hides a code or a prefix (``S8`` hides every
``S8xx``). Everything hidden is counted and reported, never silently dropped,
and an unreadable or malformed baseline is an error (fail closed).
"""

from __future__ import annotations

import hashlib
import os
import json
import re
from typing import Iterable, Optional

from . import __version__
from .card import Diagnostic
from .net import loads_strict

BASELINE_VERSION = 1
_PREFIX = re.compile(r"^[EWIDSGT][0-9]{0,3}$")


class SuppressError(ValueError):
    pass


def parse_ignore(values: Optional[Iterable[str]]) -> list[str]:
    out: list[str] = []
    for v in values or ():
        for part in str(v).split(","):
            part = part.strip().upper()
            if not part:
                continue
            if not _PREFIX.match(part):
                raise SuppressError(f"--ignore {part!r}: expected a code such as W203 or a prefix such as S8")
            out.append(part)
    return out


def fingerprint(d: Diagnostic) -> str:
    """Stable id of a finding: its code and card path (not its wording)."""
    return hashlib.sha256(f"{d.code}\0{d.path}".encode("utf-8", "surrogatepass")).hexdigest()[:16]


def write_baseline(path: str, diags: list[Diagnostic]) -> int:
    rows = sorted({fingerprint(d): {"id": fingerprint(d), "code": d.code, "path": d.path}
                   for d in diags}.values(), key=lambda r: (r["code"], r["path"]))
    doc = {"a2aops_baseline": BASELINE_VERSION, "written_by": f"a2aops {__version__}", "findings": rows}
    # Write a sibling temp file, then rename it over the target, so a crash or
    # two CI jobs writing at once never leave a half-written baseline. If the
    # rename is refused (Windows: target open elsewhere; some network shares),
    # fall back to writing in place.
    tmp = f"{path}.{os.getpid()}.tmp"
    payload = json.dumps(doc, indent=2) + "\n"
    try:
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as f:
                f.write(payload)
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(payload)
    except OSError as e:
        raise SuppressError(f"cannot write baseline {path}: {e}") from e
    return len(rows)


def load_baseline(path: str) -> set[str]:
    try:
        with open(path, "rb") as f:
            data = f.read((8 << 20) + 1)
        if len(data) > 8 << 20:
            raise ValueError("file is larger than 8 MiB")
        doc = loads_strict(data.decode("utf-8-sig"))
    except (OSError, ValueError) as e:
        raise SuppressError(f"cannot read baseline {path}: {e}") from e
    if not isinstance(doc, dict) or doc.get("a2aops_baseline") != BASELINE_VERSION \
            or not isinstance(doc.get("findings"), list):
        raise SuppressError(f"{path} is not an a2aops baseline (version {BASELINE_VERSION})")
    ids = set()
    for row in doc["findings"]:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise SuppressError(f"{path}: malformed baseline entry")
        ids.add(row["id"])
    return ids


def apply(diags: list[Diagnostic], ignore: list[str], baseline: Optional[set[str]]
          ) -> tuple[list[Diagnostic], int]:
    kept: list[Diagnostic] = []
    hidden = 0
    for d in diags:
        if any(d.code.upper().startswith(p) for p in ignore) or (baseline is not None and fingerprint(d) in baseline):
            hidden += 1
        else:
            kept.append(d)
    return kept, hidden
