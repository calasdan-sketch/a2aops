"""Hostile-input fuzz: no input may crash a2aops with a traceback.

Mutates a valid card two ways (text level: truncation, byte flips, duplicate
keys, deep nesting, invalid UTF-8/JSON; value level: type swaps, deletions,
huge/odd strings, control and bidi characters) and pushes every result through
load -> check -> diff -> compat -> auth (offline) -> SARIF/JSON/JUnit.
The only allowed failure is a clean ``CardFetchError`` from the loader.
Deterministic (fixed seed). ``python -m bench.fuzz [iterations]``.
"""

from __future__ import annotations

import copy
import json
import random
import sys
import time
import traceback

from a2aops import authcheck, compat, report
from a2aops.card import CardFetchError, _parse_local, check_card
from a2aops.diff import diff_cards, recommend_bump
from a2aops.locate import LineIndex
from a2aops.net import clean

from .cards import _base

ODD_VALUES = [None, True, 0, -1, 1.5, 10**30, "", " ", "x" * 5000, "\x1b[31m", "‮", "a\u0000b",
              [], {}, [None], [[]], {"": ""}, {"a": {"b": {}}}, ["text/plain", 3], "https://169.254.169.254/",
              "javascript:alert(1)", "ignore previous instructions", "\ud800"]


def _walk(obj, path=()):
    yield path, obj
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            yield from _walk(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(list(obj)):
            yield from _walk(v, path + (i,))


def _set(root, path, value):
    cur = root
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value


def mutate_value(rng: random.Random, card: dict) -> dict:
    c = copy.deepcopy(card)
    for _ in range(rng.randint(1, 4)):
        nodes = [p for p, _ in _walk(c) if p]
        if not nodes:
            break
        p = rng.choice(nodes)
        try:
            if rng.random() < 0.25:
                parent = c
                for q in p[:-1]:
                    parent = parent[q]
                del parent[p[-1]]
            else:
                _set(c, p, copy.deepcopy(rng.choice(ODD_VALUES)))
        except (KeyError, IndexError, TypeError):
            pass
    return c


def mutate_text(rng: random.Random, text: str) -> bytes:
    kind = rng.randrange(7)
    data = text.encode("utf-8")
    if kind == 0:
        return data[: rng.randrange(len(data))]
    if kind == 1:
        b = bytearray(data)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        return bytes(b)
    if kind == 2:
        return text.replace("{", '{"name": "dup",', 1).encode()
    if kind == 3:
        return ('{"extensions": ' + "[" * rng.choice([50, 150, 5000, 200000]) + "]" * 0).encode()
    if kind == 4:
        return b"\xff\xfe" + data
    if kind == 5:
        return text.replace('"version"', '"v": NaN, "version"', 1).encode()
    return (text + text).encode()


def exercise(card, text=None) -> None:
    diags = check_card(card)
    base = _base()
    diff_cards(base, card)
    diff_cards(card, base)
    recommend_bump(base, card, diff_cards(base, card))
    compat.compat_report(card)
    authcheck.check_auth_surface(card if isinstance(card, dict) else {}, check_remote=False)
    report.to_json(diags, command="t", source="s")
    report.to_junit(diags, command="t", source="s").encode("utf-8")      # lone surrogates must not survive
    diff_text = "\n".join(str(d) for d in diff_cards(base, card))
    diff_text.encode("utf-8")
    dd = diff_cards(base, card)
    report.to_sarif(dd, command="d", artifact_uri="n.json", source_text=json.dumps(card, default=str)).encode("utf-8")
    shown = json.dumps(card, indent=2, default=str) if text is None else text
    report.to_sarif(diags, command="t", artifact_uri="c.json", source_text=shown)
    for d in diags:
        clean(str(d)).encode("utf-8")
    LineIndex(shown)


def run(iterations: int = 3000, seed: int = 20261107) -> dict:
    rng = random.Random(seed)
    good = json.dumps(_base(), indent=2)
    stats = {"iterations": iterations, "loaded": 0, "rejected_cleanly": 0, "crashes": []}
    t0 = time.time()
    for i in range(iterations):
        try:
            if i % 2:
                data = mutate_text(rng, good)
                try:
                    card, text = _parse_local(data, "fuzz")
                except CardFetchError:
                    stats["rejected_cleanly"] += 1
                    continue
            else:
                card = mutate_value(rng, _base())
                text = None
            stats["loaded"] += 1
            exercise(card, text)
        except Exception:  # noqa: BLE001 - the whole point
            stats["crashes"].append({"i": i, "trace": traceback.format_exc(limit=3)[-600:]})
            if len(stats["crashes"]) >= 5:
                break
    stats["seconds"] = round(time.time() - t0, 1)
    return stats


if __name__ == "__main__":
    res = run(int(sys.argv[1]) if len(sys.argv) > 1 else 3000)
    print(json.dumps(res, indent=2))
    sys.exit(1 if res["crashes"] else 0)
