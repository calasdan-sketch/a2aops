"""Contract-diff benchmark: does ``card diff`` recommend the right semver bump?

Each pair is (name, change function, expected bump). The expected bump is the
one a client author would call fair: removing something a client may rely on
is ``major``; adding a capability/skill/interface is ``minor``; editing prose
is ``patch``; touching nothing is ``none``. The baseline column is the
strategy "any difference at all is a major bump" which is what a plain
snapshot test (hash or deep-equal) amounts to.
"""

from __future__ import annotations

import copy
import json

from a2aops.diff import BUMP_ORDER, recommend_bump

from .cards import _base


def _c():
    c = _base()
    c["skills"].append({"id": "sum", "name": "Summarise", "description": "Summarise text.", "tags": ["nlp", "text"]})
    c["capabilities"].update(pushNotifications=True, extendedAgentCard=True)
    c["securitySchemes"] = {"b": {"httpAuthSecurityScheme": {"scheme": "Bearer"}},
                            "k": {"apiKeySecurityScheme": {"location": "header", "name": "X-K"}}}
    c["securityRequirements"] = [{"schemes": {"b": {"list": []}}}, {"schemes": {"k": {"list": []}}}]
    return c


def _p(fn):
    def go(c):
        fn(c)
        return c
    return go


CASES = [
    ("identical", lambda c: None, "none"),
    ("description-edit", lambda c: c.update(description="A new, longer description of the agent."), "patch"),
    ("skill-description-edit", lambda c: c["skills"][0].update(description="Reworded."), "patch"),
    ("example-added", lambda c: c["skills"][0]["examples"].append("Another example"), "patch"),
    ("provider-change", lambda c: c.update(provider={"organization": "New Corp", "url": "https://new.example.com"}), "patch"),
    ("docs-url-change", lambda c: c.update(documentationUrl="https://example.com/new-docs"), "patch"),
    ("skill-added", lambda c: c["skills"].append({"id": "x", "name": "X", "description": "New skill.", "tags": ["x"]}), "minor"),
    ("tag-added", lambda c: c["skills"][0]["tags"].append("extra"), "minor"),
    ("interface-added", lambda c: c["supportedInterfaces"].append(
        {"url": "grpc.example.com:443", "protocolBinding": "GRPC", "protocolVersion": "1.0"}), "minor"),
    ("capability-enabled", lambda c: c["capabilities"].update(streaming=True) if not c["capabilities"].get("streaming") else c["capabilities"].update(extensions=[{"uri": "https://e.example/x"}]), "minor"),
    ("input-mode-added", lambda c: c["defaultInputModes"].append("application/json"), "minor"),
    ("auth-alternative-added", lambda c: c["securityRequirements"].append({"schemes": {"b": {"list": ["extra"]}}}), "minor"),
    ("skill-removed", lambda c: c["skills"].pop(), "major"),
    ("interface-removed", lambda c: c["supportedInterfaces"].pop(), "major"),
    ("streaming-off", lambda c: c["capabilities"].update(streaming=False), "major"),
    ("push-off", lambda c: c["capabilities"].update(pushNotifications=False), "major"),
    ("extended-card-off", lambda c: c["capabilities"].update(extendedAgentCard=False), "major"),
    ("input-mode-removed", lambda c: c.update(defaultInputModes=["application/json"]), "major"),
    ("output-mode-removed", lambda c: c.update(defaultOutputModes=["application/json"]), "major"),
    ("extension-now-required", lambda c: c["capabilities"].update(extensions=[{"uri": "https://e.example/x", "required": True}]), "major"),
    ("auth-alternative-removed", lambda c: c["securityRequirements"].pop(), "major"),
    ("auth-newly-required", lambda c: c.update(securityRequirements=[{"schemes": {"b": {"list": ["admin"]}}}]), "major"),
    ("tag-removed", lambda c: c["skills"][1]["tags"].pop(), "major"),
    ("tenant-changed", lambda c: c["supportedInterfaces"][0].update(tenant="acme"), "major"),
    ("skill-narrows-modes", lambda c: c["skills"][1].update(inputModes=["image/png"]), "major"),
]


def run() -> dict:
    rows = []
    for name, fn, want in CASES:
        old = _c()
        new = copy.deepcopy(old)
        fn(new)
        got = recommend_bump(old, new)
        naive = "none" if old == new else "major"
        rows.append({"case": name, "expected": want, "a2aops": got, "snapshot-diff": naive})
    acc = lambda k: round(sum(r[k] == r["expected"] for r in rows) / len(rows), 3)       # noqa: E731
    under = sum(BUMP_ORDER[r["a2aops"]] < BUMP_ORDER[r["expected"]] for r in rows)
    over = sum(BUMP_ORDER[r["a2aops"]] > BUMP_ORDER[r["expected"]] for r in rows)
    return {"pairs": len(rows), "accuracy": {"a2aops": acc("a2aops"), "snapshot-diff (any change = major)": acc("snapshot-diff")},
            "a2aops_under_recommended": under, "a2aops_over_recommended": over,
            "wrong": [r for r in rows if r["a2aops"] != r["expected"]]}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
