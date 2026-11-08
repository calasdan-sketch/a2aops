"""Mutation sanity check of the checker itself (``python -m bench.mutate_source``).

``bench/mutants.py`` breaks a *server* to see whether ``conformance`` notices. This
breaks *a2aops* instead: each entry below flips one safety-relevant condition in a
scratch copy of ``src/``, runs the unit tests against that copy, and expects the suite
to fail. A mutant that survives is a condition no test depends on.

Writes nothing inside the repository; the copy lives in a temporary directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (file, exact text, replacement, why it matters)
MUTANTS = [
    ("net.py", "if new is not None and _origin(full) != _origin(req.full_url):", "if False:", "credentials follow cross-host redirects"),
    ("net.py", 'if urllib.parse.urlsplit(full).scheme.lower() not in ("http", "https"):', "if False:", "redirects to ftp/file allowed"),
    ("net.py", '    if scheme not in ("http", "https"):', "    if False:", "ftp/file card sources allowed"),
    ("conformance.py", 'if acac == "true" and acao.strip() == _PROBE_ORIGIN:', "if False:", "CORS reflection check never fires"),
    ("net.py", "if declared is not None and declared > limit:", "if False:", "Content-Length cap ignored"),
    ("net.py", "if total > limit:", "if False:", "streamed size cap ignored"),
    ("net.py", "if k in out:", "if False:", "duplicate JSON keys accepted"),
    ("net.py", "if ip.is_multicast or not ip.is_global:", "if ip.is_multicast:", "non-global addresses treated as public"),
    ("net.py", 'if parts.scheme != "https":', "if False:", "plain-http card URLs fetched by SSRF-guarded paths"),
    ("net.py", "if parts.username or parts.password:", "if False:", "credentials in URL accepted"),
    ("net.py", 'return (p.scheme, (p.hostname or "").lower(), port)', 'return (p.scheme, "", port)', "origin ignores host"),
    ("suppress.py", "[:16]", "[:1]", "baseline fingerprints collide"),
    ("report.py", "bad = {ERROR, WARNING} if strict else {ERROR}\n    return", "bad = {ERROR}\n    return", "--strict ignored"),
    ("diff.py", 'out.append(_d(ERROR, "D502"', 'out.append(_d(INFO, "D502"', "removed skill no longer breaking"),
    ("diff.py", 'out.append(_d(ERROR, "D501"', 'out.append(_d(INFO, "D501"', "removed interface no longer breaking"),
    ("diff.py", 'out.append(_d(ERROR, "D506"', 'out.append(_d(INFO, "D506"', "capability switched off no longer breaking"),
    ("schema.py", 'out.append(Diagnostic(\n                ERROR, "E124"', 'out.append(Diagnostic(\n                WARNING, "E124"', "empty skills tolerated"),
    ("schema.py", "if req and key in obj and t == STR", "if False and req and key in obj and t == STR", "empty required string tolerated"),
    ("schema.py", "return isinstance(v, dict) and all(isinstance(x, str) for x in v.values())", "return isinstance(v, dict)", "OAuth scopes not type-checked"),
    ("schema.py", '_typed(inner, fields, f"{base}.{kind}", out)', "pass", "security scheme members not type-checked"),
    ("card.py", 'if tags is not None and (not isinstance(tags, list) or not tags', 'if False and (not isinstance(tags, list) or not tags', "empty skill tags accepted"),
    ("cardsec.py", 'return "public-or-name" if _is_public_ip(str(ip)) else "private"', 'return "public-or-name"', "private IPs classed public"),
    ("conformance.py", "if not host or host == ctx._host or ctx.allow_private_endpoints or _is_local(ctx.base):\n        return False",
     "return False", "card can aim probes at private hosts"),
    ("conformance.py", "return dict(self.user_headers) if host == self._host else {}", "return dict(self.user_headers)", "credentials sent to other hosts"),
    ("net.py", "        if redirect_guard is not None:\n", "        if False:\n", "a public endpoint can redirect a probe into the private network"),
    ("cli.py", "return 1 if report_mod.failed(diags, strict) else 0", "return 0", "findings never fail the build"),
    ("cli.py", "return 1 if conf.failed(results, args.strict) else 0", "return 0", "conformance failures never fail the build"),
    ("states.py", 'key in v1', 'False', "v1 task states not recognised"),
    ("jws.py", "if _is_default(v) and flag not in (R, OPT):", "if False:", "default-value pruning removed (signature payload changes)"),
]


def run(verbose: bool = True) -> dict:
    killed, survived, skipped = [], [], []
    tmp = Path(tempfile.mkdtemp(prefix="a2aops-mut-"))
    try:
        base = tmp / "base"                   # snapshot once so edits made while this runs do not leak in
        shutil.copytree(ROOT / "src", base / "src", ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
        shutil.copytree(ROOT / "tests", base / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        for n, (fname, old, new, why) in enumerate(MUTANTS):
            work = tmp / f"m{n}"
            shutil.copytree(base / "src", work / "src")
            shutil.copytree(base / "tests", work / "tests")
            target = work / "src" / "a2aops" / fname
            text = target.read_text(encoding="utf-8")
            if text.count(old) != 1:
                skipped.append({"file": fname, "why": why, "reason": f"pattern found {text.count(old)} times"})
                shutil.rmtree(work, ignore_errors=True)
                continue
            target.write_text(text.replace(old, new), encoding="utf-8")
            t0 = time.monotonic()
            r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-f", "-q"],
                               cwd=work, env={**os.environ, "PYTHONPATH": str(work / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
                               capture_output=True, text=True, timeout=600)
            row = {"file": fname, "why": why, "seconds": round(time.monotonic() - t0, 1)}
            (killed if r.returncode != 0 else survived).append(row)
            if verbose:
                print(("killed   " if r.returncode else "SURVIVED ") + f"{fname}: {why}", flush=True)
            shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"total": len(MUTANTS), "killed": len(killed), "survived": survived, "skipped": skipped}


if __name__ == "__main__":
    res = run()
    print(json.dumps({k: v for k, v in res.items()}, indent=2))
    sys.exit(1 if res["survived"] or res["skipped"] else 0)
