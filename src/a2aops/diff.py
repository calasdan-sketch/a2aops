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

from typing import Any, Optional

from . import secreq
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


def _ext_key(ext: dict) -> str:
    """Extensions are matched by uri; a non-string uri (hostile or broken card) must not crash the diff."""
    uri = ext.get("uri")
    return uri if isinstance(uri, str) else repr(uri)


def _iface_key(iface: dict) -> tuple[str, str, str]:
    # tenant is part of the address: clients MUST send it on every request
    return (str(iface.get("protocolBinding", "")), str(iface.get("url", "")),
            str(iface.get("tenant") or ""))


def _fmt_key(k: tuple[str, str, str]) -> str:
    return f"{k[0]} {k[1]}" + (f" (tenant {k[2]})" if k[2] else "")


def _interfaces(card: dict) -> list[dict]:
    """v1.0 supportedInterfaces, or the v0.x url/preferredTransport (+ additionalInterfaces)."""
    ifaces = [i for i in _as_list(card.get("supportedInterfaces")) if isinstance(i, dict)]
    if ifaces:
        return ifaces
    out: list[dict] = []
    if isinstance(card.get("url"), str):
        out.append({"url": card["url"],
                    "protocolBinding": str(card.get("preferredTransport", "JSONRPC")).upper()})
    for extra in _as_list(card.get("additionalInterfaces")):
        if isinstance(extra, dict) and isinstance(extra.get("url"), str):
            iface = {"url": extra["url"],
                     "protocolBinding": str(extra.get("transport", "JSONRPC")).upper()}
            if _iface_key(iface) not in {_iface_key(i) for i in out}:
                out.append(iface)
    return out


def _diff_security(old: Any, new: Any, path: str, who: str,
                   codes: tuple[str, str, str, str]) -> list[Diagnostic]:
    """Compare requirement alternatives (OR of ANDs) between two owners."""
    c_added, c_removed, c_new_alt, c_dropped = codes
    out: list[Diagnostic] = []
    o_alts, n_alts = secreq.alternative_keys(old), secreq.alternative_keys(new)
    if not o_alts and n_alts:
        out.append(_d(ERROR, c_added,
                      f"{who} now requires authentication — anonymous clients break", path))
    elif o_alts and n_alts:
        for alt in sorted(o_alts - n_alts, key=sorted):
            out.append(_d(ERROR, c_removed,
                          f"{who}: security alternative {sorted(alt)} removed — clients authenticating that way break",
                          path))
        for alt in sorted(n_alts - o_alts, key=sorted):
            out.append(_d(INFO, c_new_alt, f"{who}: security alternative {sorted(alt)} added", path))
    elif o_alts and not n_alts:
        out.append(_d(WARNING, c_dropped,
                      f"{who}: authentication requirements were removed; confirm this is intentional", path))
    return out


def _effective_modes(skill: dict, card: dict, field: str, default_field: str) -> tuple[set[str], bool]:
    """Modes a skill really accepts: its own list, else the card defaults."""
    if field in skill:
        return set(_strs(skill[field])), True
    return set(_strs(card.get(default_field))), False


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
                          f"interface removed: {_fmt_key(k)} — clients with this endpoint cached will fail",
                          "supportedInterfaces"))
    for i in new_if:
        k = _iface_key(i)
        if k not in old_keys:
            out.append(_d(INFO, "D701", f"interface added: {_fmt_key(k)}", "supportedInterfaces"))
    if old_if and new_if and _iface_key(old_if[0]) != _iface_key(new_if[0]) \
            and _iface_key(old_if[0]) in new_keys:
        out.append(_d(WARNING, "D601",
                      f"preferred interface changed from {_fmt_key(_iface_key(old_if[0]))} "
                      f"to {_fmt_key(_iface_key(new_if[0]))}",
                      "supportedInterfaces[0]"))
    old_pv = {_iface_key(i): i.get("protocolVersion") for i in old_if}
    for i in new_if:
        k = _iface_key(i)
        if k in old_pv and old_pv[k] != i.get("protocolVersion"):
            out.append(_d(WARNING, "D602",
                          f"protocolVersion for {_fmt_key(k)} changed {old_pv[k]!r} -> {i.get('protocolVersion')!r}",
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
        for field, default_field, code in (("inputModes", "defaultInputModes", "D503"),
                                           ("outputModes", "defaultOutputModes", "D504")):
            o_modes, o_explicit = _effective_modes(o, old, field, default_field)
            n_modes, n_explicit = _effective_modes(n, new, field, default_field)
            if not (o_explicit or n_explicit):
                continue  # both inherit: the card-level default check covers it
            gone = sorted(o_modes - n_modes)
            if gone:
                verb = "accepts" if field == "inputModes" else "produces"
                out.append(_d(ERROR, code, f"skill '{sid}' no longer {verb} {gone} ({field})",
                              f"{p}.{field}"))
        out.extend(_diff_security(o, n, f"{p}.securityRequirements", f"skill '{sid}'",
                                  ("D510", "D511", "D705", "D609")))
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
    old_ext = {_ext_key(e): e for e in _as_list(oc.get("extensions")) if isinstance(e, dict)}
    new_ext = {_ext_key(e): e for e in _as_list(nc.get("extensions")) if isinstance(e, dict)}
    for uri, ext in new_ext.items():
        if ext.get("required") is True and _as_dict(old_ext.get(uri)).get("required") is not True:
            what = "is now required" if uri in old_ext else "is new and required"
            out.append(_d(ERROR, "D507", f"extension {uri!r} {what} — clients that don't speak it are rejected",
                          "capabilities.extensions"))

    # --- security (v1 securityRequirements, either JSON shape, or v0.3 security)
    out.extend(_diff_security(old, new, "securityRequirements", "agent",
                              ("D508", "D509", "D704", "D605")))
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


# --------------------------------------------------------------------------
# Semver recommendation
# --------------------------------------------------------------------------

BUMP_ORDER = {"none": 0, "patch": 1, "minor": 2, "major": 3}

#: card fields whose change cannot affect how a client calls the agent
_COSMETIC_TOP = ("name", "description", "version", "documentationUrl", "iconUrl", "provider", "signatures")
_COSMETIC_SKILL = ("name", "description", "examples")


def _contract_view(card: dict) -> dict:
    c = {k: v for k, v in card.items() if k not in _COSMETIC_TOP}
    skills = c.get("skills")
    if isinstance(skills, list):
        c["skills"] = [{k: v for k, v in s.items() if k not in _COSMETIC_SKILL} if isinstance(s, dict) else s
                       for s in skills]
    return c


def recommend_bump(old: Any, new: Any, diags: Optional[list[Diagnostic]] = None) -> str:
    """The semver bump these two cards deserve: ``major`` | ``minor`` | ``patch`` | ``none``.

    * ``major`` - at least one finding breaks existing clients (``D5xx`` errors, or
      a ``D6xx`` finding that removes something clients matched on);
    * ``minor`` - the contract grew or changed without breaking anyone (``D7xx``
      additions, other ``D6xx`` notes, any contract-field difference);
    * ``patch`` - only cosmetic fields differ (name, descriptions, examples,
      provider, docs/icon URLs, signatures);
    * ``none`` - identical apart from ``version``.
    """
    if not isinstance(old, dict) or not isinstance(new, dict):
        return "major"
    diags = diff_cards(old, new) if diags is None else diags
    removal_codes = {"D603", "D604", "D605", "D609"}
    if any(d.severity == ERROR or d.code in removal_codes for d in diags):
        return "major"
    if any(d.code not in ("D607", "D608") and d.severity in (WARNING, INFO) for d in diags):
        return "minor"
    if _contract_view(old) != _contract_view(new):
        return "minor"
    rest_old = {k: v for k, v in old.items() if k != "version"}
    rest_new = {k: v for k, v in new.items() if k != "version"}
    return "patch" if rest_old != rest_new else "none"


def actual_bump(old_version: Any, new_version: Any) -> str:
    """How the ``version`` string moved: major/minor/patch/none, or ``unknown``/``downgrade``."""
    a, b = _semver(old_version), _semver(new_version)
    if a is None or b is None:
        return "unknown"
    a, b = (a + (0, 0, 0))[:3], (b + (0, 0, 0))[:3]
    if b < a:
        return "downgrade"
    if b == a:
        return "none"
    return "major" if b[0] > a[0] else "minor" if b[1] > a[1] else "patch"


def check_bump(old: Any, new: Any, diags: Optional[list[Diagnostic]] = None) -> list[Diagnostic]:
    """``D610`` when the version moved less than :func:`recommend_bump` says it must."""
    if not isinstance(old, dict) or not isinstance(new, dict):
        return []
    want = recommend_bump(old, new, diags)
    got = actual_bump(old.get("version"), new.get("version"))
    if got in ("unknown",):
        return [_d(WARNING, "D611", f"versions {old.get('version')!r} -> {new.get('version')!r} are not semver; "
                   f"cannot compare with the recommended '{want}' bump", "version")]
    if got == "downgrade" or BUMP_ORDER[got] < BUMP_ORDER[want]:
        return [_d(ERROR, "D610",
                   f"these changes need a '{want}' version bump; version went {old.get('version')} -> "
                   f"{new.get('version')} ({got})", "version")]
    return []
