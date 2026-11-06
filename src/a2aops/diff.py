"""Breaking-change detection between two AgentCards.

``a2aops card diff OLD NEW`` answers the question a reviewer actually has when
a card changes in a pull request: *will clients that worked yesterday break
tomorrow?* Findings use the shared Diagnostic type:

* ``error``   (D5xx) — breaking for existing clients
* ``warning`` (D6xx) — risky / likely to surprise clients
* ``info``    (D7xx) — additive or cosmetic change

Rules are conservative and structural. Anything not listed is not reported,
so a clean diff means "no known-breaking structural change", not "identical".
"""

from __future__ import annotations

from typing import Any

from .card import ERROR, INFO, WARNING, Diagnostic


def _d(sev: str, code: str, msg: str, path: str = "") -> Diagnostic:
    return Diagnostic(sev, code, msg, path)


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _strs(v: Any) -> list[str]:
    return [x for x in _as_list(v) if isinstance(x, str)]


def _skills_by_id(card: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for s in _as_list(card.get("skills")):
        if isinstance(s, dict) and isinstance(s.get("id"), str):
            out.setdefault(s["id"], s)
    return out


def _iface_key(iface: dict) -> tuple[str, str]:
    return (str(iface.get("protocolBinding", "")), str(iface.get("url", "")))


def _interfaces(card: dict) -> list[dict]:
    """v1.0 supportedInterfaces, or the v0.x url/preferredTransport pair."""
    ifaces = [i for i in _as_list(card.get("supportedInterfaces")) if isinstance(i, dict)]
    if ifaces:
        return ifaces
    if isinstance(card.get("url"), str):
        return [{"url": card["url"],
                 "protocolBinding": str(card.get("preferredTransport", "JSONRPC")).upper()}]
    return []


def _req_alternatives(card: dict) -> set[frozenset[str]]:
    """securityRequirements as a set of alternatives (OR of ANDs)."""
    alts = set()
    for entry in _as_list(card.get("securityRequirements")):
        if isinstance(entry, dict):
            alts.add(frozenset(entry.keys()))
    return alts


def _semver(v: Any) -> tuple[int, ...] | None:
    if not isinstance(v, str):
        return None
    core = v.split("-", 1)[0].split("+", 1)[0].split(".")
    if not core or not all(p.isdigit() for p in core):
        return None
    return tuple(int(p) for p in core)


def diff_cards(old: Any, new: Any) -> list[Diagnostic]:
    """Compare two cards; return breaking (error), risky (warning), info findings."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return [_d(ERROR, "D500", "both cards must be JSON objects")]
    out: list[Diagnostic] = []

    # --- interfaces ----------------------------------------------------
    old_if, new_if = _interfaces(old), _interfaces(new)
    new_keys = {_iface_key(i) for i in new_if}
    old_keys = {_iface_key(i) for i in old_if}
    for i in old_if:
        k = _iface_key(i)
        if k not in new_keys:
            out.append(_d(ERROR, "D501",
                          f"interface removed: {k[0]} {k[1]} — clients with this endpoint cached will fail",
                          "supportedInterfaces"))
    for i in new_if:
        k = _iface_key(i)
        if k not in old_keys:
            out.append(_d(INFO, "D701", f"interface added: {k[0]} {k[1]}", "supportedInterfaces"))
    if old_if and new_if and _iface_key(old_if[0]) != _iface_key(new_if[0]) \
            and _iface_key(old_if[0]) in new_keys:
        out.append(_d(WARNING, "D601",
                      f"preferred interface changed from {' '.join(_iface_key(old_if[0]))} "
                      f"to {' '.join(_iface_key(new_if[0]))}",
                      "supportedInterfaces[0]"))
    old_pv = {_iface_key(i): i.get("protocolVersion") for i in old_if}
    for i in new_if:
        k = _iface_key(i)
        if k in old_pv and old_pv[k] != i.get("protocolVersion"):
            out.append(_d(WARNING, "D602",
                          f"protocolVersion for {k[0]} {k[1]} changed {old_pv[k]!r} -> {i.get('protocolVersion')!r}",
                          "supportedInterfaces"))

    # --- skills ----------------------------------------------------------
    old_sk, new_sk = _skills_by_id(old), _skills_by_id(new)
    for sid in old_sk:
        if sid not in new_sk:
            out.append(_d(ERROR, "D502", f"skill removed: '{sid}' — callers routing to it will fail",
                          f"skills[id={sid}]"))
    for sid in new_sk:
        if sid not in old_sk:
            out.append(_d(INFO, "D702", f"skill added: '{sid}'", f"skills[id={sid}]"))
    for sid in old_sk.keys() & new_sk.keys():
        o, n = old_sk[sid], new_sk[sid]
        p = f"skills[id={sid}]"
        for field, code in (("inputModes", "D503"), ("outputModes", "D504")):
            if field in o and field in n:
                gone = sorted(set(_strs(o[field])) - set(_strs(n[field])))
                if gone:
                    out.append(_d(ERROR, code, f"skill '{sid}' no longer accepts/produces {gone} ({field})",
                                  f"{p}.{field}"))
        lost_tags = sorted(set(_strs(o.get("tags"))) - set(_strs(n.get("tags"))))
        if lost_tags:
            out.append(_d(WARNING, "D603", f"skill '{sid}' dropped tags {lost_tags}; tag-based routers may stop matching it",
                          f"{p}.tags"))

    # --- default modes ---------------------------------------------------
    for field, code, sev in (("defaultInputModes", "D505", ERROR),
                             ("defaultOutputModes", "D604", WARNING)):
        gone = sorted(set(_strs(old.get(field))) - set(_strs(new.get(field))))
        if gone:
            out.append(_d(sev, code, f"{field} no longer includes {gone}", field))

    # --- capabilities ----------------------------------------------------
    oc, nc = _as_dict(old.get("capabilities")), _as_dict(new.get("capabilities"))
    for cap in ("streaming", "pushNotifications", "extendedAgentCard"):
        if oc.get(cap) is True and nc.get(cap) is not True:
            out.append(_d(ERROR, "D506", f"capability '{cap}' was turned off — clients relying on it break",
                          f"capabilities.{cap}"))
        elif oc.get(cap) is not True and nc.get(cap) is True:
            out.append(_d(INFO, "D703", f"capability '{cap}' enabled", f"capabilities.{cap}"))
    old_ext = {e.get("uri") for e in _as_list(oc.get("extensions")) if isinstance(e, dict)}
    new_ext = {e.get("uri"): e for e in _as_list(nc.get("extensions")) if isinstance(e, dict)}
    for uri, ext in new_ext.items():
        if ext.get("required") is True and uri not in old_ext:
            out.append(_d(ERROR, "D507", f"new required extension {uri!r} — clients that don't speak it are rejected",
                          "capabilities.extensions"))

    # --- security ----------------------------------------------------------
    o_alts, n_alts = _req_alternatives(old), _req_alternatives(new)
    if not o_alts and n_alts:
        out.append(_d(ERROR, "D508",
                      "agent now requires authentication (securityRequirements added) — anonymous clients break",
                      "securityRequirements"))
    elif o_alts and n_alts:
        for alt in sorted(o_alts - n_alts, key=sorted):
            out.append(_d(ERROR, "D509",
                          f"security alternative {sorted(alt)} removed — clients authenticating that way break",
                          "securityRequirements"))
        for alt in sorted(n_alts - o_alts, key=sorted):
            out.append(_d(INFO, "D704", f"security alternative {sorted(alt)} added", "securityRequirements"))
    if o_alts and not n_alts and "securityRequirements" in old:
        out.append(_d(WARNING, "D605", "authentication requirements were removed; confirm this is intentional",
                      "securityRequirements"))
    os_, ns_ = _as_dict(old.get("securitySchemes")), _as_dict(new.get("securitySchemes"))
    for name in os_.keys() & ns_.keys():
        if os_[name] != ns_[name]:
            out.append(_d(WARNING, "D606", f"security scheme '{name}' definition changed (URLs, flows or scopes)",
                          f"securitySchemes.{name}"))

    # --- version discipline -----------------------------------------------
    breaking = any(d.severity == ERROR for d in out)
    changed = old != new
    ov, nv = old.get("version"), new.get("version")
    if changed and ov == nv:
        out.append(_d(WARNING, "D607", f"card changed but 'version' is still {ov!r}; bump it so clients can tell",
                      "version"))
    elif breaking and _semver(ov) and _semver(nv) and _semver(nv)[0] <= _semver(ov)[0]:
        out.append(_d(WARNING, "D608",
                      f"breaking changes found but major version did not increase ({ov} -> {nv})",
                      "version"))

    order = {ERROR: 0, WARNING: 1, INFO: 2}
    out.sort(key=lambda d: (order.get(d.severity, 3), d.code))
    return out
