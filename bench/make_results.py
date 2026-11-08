"""Regenerate bench/RESULTS.json (python -m bench.make_results). a2a-lint is run when installed;
the Inspector and baseline figures were measured once by hand and are recorded as such."""

import json
import sys
from pathlib import Path

from . import fuzz, mutate_source, run_cards, run_diff, run_mutants

MEASURED_ONCE = {
    "a2aops 1.2.0 (round 1, commit 53fe4c9) on the same cards": {
        "tp": 25, "fp": 5, "fn": 14, "tn": 34, "precision": 0.833, "recall": 0.641},
    "official a2a-inspector validate package v1.0.0-alpha.1 (Go test harness over the same cards)": {
        "tp": 36, "fp": 0, "fn": 3, "tn": 39, "precision": 1.0, "recall": 0.923},
}


def main() -> None:
    res = {"cards": run_cards.run("--no-competitors" not in sys.argv),
           "mutants": run_mutants.run() if hasattr(run_mutants, "run") else None,
           "diff": run_diff.run(), "fuzz": fuzz.run(6000), "measured_once": MEASURED_ONCE}
    if "--source-mutants" in sys.argv:       # slow: runs the whole test suite once per mutant
        res["source_mutants"] = mutate_source.run(verbose=False)
    else:                                    # keep the last recorded figure rather than dropping it
        old = Path(__file__).with_name("RESULTS.json")
        if old.exists():
            res["source_mutants"] = json.loads(old.read_text()).get("source_mutants")
    Path(__file__).with_name("RESULTS.json").write_text(json.dumps(res, indent=2) + "\n")


if __name__ == "__main__":
    main()
