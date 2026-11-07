"""Card-corpus benchmark: precision/recall of card checkers on good and broken cards.

    python -m bench.run_cards            # a2aops only (no dependencies)
    python -m bench.run_cards --competitors   # also a2a-lint if installed (pip install a2a-lint)

Positive class = "the spec says this card is invalid" (label valid=False).
A checker predicts invalid when it reports an error. For a2aops, errors from
the security lint (``S...``) are excluded from that decision: a card with a
suspicious sentence is legal; those are scored separately as "code recall".
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import threading
import http.server
from pathlib import Path

from a2aops.card import ERROR, check_card

from . import cards as corpus


def a2aops_eval(items):
    rows = []
    for name, card, label in items:
        diags = check_card(card)
        codes = {d.code for d in diags}
        errs = [d for d in diags if d.severity == ERROR and not d.code.startswith("S")]
        rows.append({"name": name, "label_valid": label["valid"], "pred_invalid": bool(errs),
                     "codes": sorted(codes), "expect": label["expect"],
                     "expect_hit": all(c in codes for c in label["expect"])})
    return rows


def confusion(rows, key="pred_invalid"):
    tp = sum(1 for r in rows if not r["label_valid"] and r[key])
    fp = sum(1 for r in rows if r["label_valid"] and r[key])
    fn = sum(1 for r in rows if not r["label_valid"] and not r[key])
    tn = sum(1 for r in rows if r["label_valid"] and not r[key])
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}


class _Serve(http.server.BaseHTTPRequestHandler):
    root: Path

    def log_message(self, *a):
        pass

    def do_GET(self):
        # /<name>/.well-known/agent-card.json
        parts = self.path.strip("/").split("/")
        f = self.root / (parts[0] + ".json") if parts and parts[0] else None
        if f is not None and f.exists() and self.path.endswith("/.well-known/agent-card.json"):
            body = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def a2a_lint_eval(items, exe):
    tmp = Path(tempfile.mkdtemp(prefix="a2aops-bench-"))
    try:
        corpus.write_corpus(tmp)
        handler = type("H", (_Serve,), {"root": tmp})
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        rows = []
        for name, card, label in items:
            if not isinstance(card, dict):
                continue    # a2a-lint needs a JSON object card
            p = subprocess.run([exe, f"http://127.0.0.1:{srv.server_address[1]}/{name}", "--json"],
                               capture_output=True, text=True, timeout=60)
            try:
                doc = json.loads(p.stdout)
                errs = doc["summary"]["errors"]
            except (ValueError, KeyError):
                errs = 1 if p.returncode else 0
            rows.append({"name": name, "label_valid": label["valid"], "pred_invalid": errs > 0})
        srv.shutdown()
        return rows
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run(competitors=False) -> dict:
    items = corpus.build()
    rows = a2aops_eval(items)
    res = {"corpus": {"cards": len(items), "valid": sum(r["label_valid"] for r in rows),
                      "invalid": sum(not r["label_valid"] for r in rows)},
           "a2aops": {"invalid_detection": confusion(rows),
                      "code_recall": round(sum(r["expect_hit"] for r in rows if r["expect"]) /
                                           max(1, sum(1 for r in rows if r["expect"])), 3),
                      "false_positive_cards": [r["name"] for r in rows if r["label_valid"] and r["pred_invalid"]],
                      "missed_cards": [r["name"] for r in rows if not r["label_valid"] and not r["pred_invalid"]],
                      "code_misses": [r["name"] for r in rows if r["expect"] and not r["expect_hit"]]}}
    if competitors:
        exe = shutil.which("a2a-lint")
        if exe:
            lrows = a2a_lint_eval(items, exe)
            res["a2a-lint"] = {"invalid_detection": confusion(lrows), "cards_scored": len(lrows),
                               "note": "a2a-lint targets A2A 0.3 (requires `url`), so every v1.0 card is flagged; "
                                       "numbers show the cost of a 0.3-only checker on 1.0 cards"}
        else:
            res["a2a-lint"] = "not installed"
    return res


if __name__ == "__main__":
    out = run("--competitors" in sys.argv)
    print(json.dumps(out, indent=2))
