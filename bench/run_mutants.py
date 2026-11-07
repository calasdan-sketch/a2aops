"""Mutation benchmark for ``a2aops conformance``.

    python -m bench.run_mutants                 # reference agent + 32 injected faults
    python -m bench.run_mutants --upstream http://127.0.0.1:9999   # any v1.0 agent instead

Reports (a) false alarms on the clean agent and (b) how many injected faults
are detected (a MUST failing or a SHOULD warning among the mutant's expected
check ids).
"""

from __future__ import annotations

import json
import sys
import time

from a2aops import conformance as conf
from a2aops.playground import MockAgent

from .mutants import MUTANTS, MutantProxy


def _status_map(results):
    return {r.id: r.status for r in results}


def run(upstream=None, timeout=3.0, only=None):
    agents = []
    try:
        if upstream is None:
            strict = MockAgent("ref", legacy=False).start()
            legacy = MockAgent("ref-legacy", legacy=True).start()
            agents += [strict, legacy]
            bases = {"strict": strict.base_url, "legacy": legacy.base_url}
        else:
            bases = {"strict": upstream, "legacy": upstream}

        def go(base, mutant=None):
            px = MutantProxy(base, mutant).start()
            try:
                t0 = time.time()
                _, res = conf.run(px.url, active=True, timeout=timeout)
                return res, time.time() - t0
            finally:
                px.stop()

        clean, clean_s = go(bases["strict"])
        base_status = _status_map(clean)
        clean_bad = [r.id for r in clean if r.status in (conf.FAIL, conf.WARN)]
        rows = []
        for m in MUTANTS:
            if only and m.name not in only:
                continue
            res, secs = go(bases.get(m.base, bases["strict"]), m)
            ref = base_status          # always judged against the clean *strict* agent
            now = _status_map(res)
            flagged = {i for i, s in now.items() if s in (conf.FAIL, conf.WARN) and ref.get(i) not in (conf.FAIL, conf.WARN)}
            rows.append({"mutant": m.name, "why": m.why, "expect": sorted(m.expect),
                         "detected": bool(flagged & m.expect), "flagged": sorted(flagged),
                         "seconds": round(secs, 1)})
        det = sum(r["detected"] for r in rows)
        return {"clean_agent": {"false_alarms": clean_bad, "checks_run": len(clean),
                                "skipped": sum(r.status == conf.SKIP for r in clean),
                                "seconds": round(clean_s, 1)},
                "mutants": {"total": len(rows), "detected": det,
                            "recall": round(det / max(1, len(rows)), 3),
                            "missed": [r["mutant"] for r in rows if not r["detected"]]},
                "rows": rows}
    finally:
        for a in agents:
            a.stop()


if __name__ == "__main__":
    up = None
    if "--upstream" in sys.argv:
        up = sys.argv[sys.argv.index("--upstream") + 1]
    print(json.dumps(run(up), indent=2))
