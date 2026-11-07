"""Proto-derived structural checks for an AgentCard.

The tables below mirror ``message AgentCard`` and its children in
``a2a.proto`` (package ``lf.a2a.v1``, spec 1.0.x), field names in their JSON
(lowerCamelCase) form [spec 5.5]. ``REQUIRED`` marks fields annotated
``google.api.field_behavior = REQUIRED``; spec 5.7 says required arrays must
contain at least one element.

Policy (unchanged from earlier releases): unknown fields never fail
validation. A key that is a near-miss of a known field (``skill`` for
``skills``) or the snake_case spelling of one is only a *warning*, because a
silently ignored typo is the most common reason a field "does nothing".
"""

from __future__ import annotations

import difflib
import re
from typing import Any

from .card import ERROR, WARNING, Diagnostic

STR, BOOL, OBJ, ARR_STR, ARR_OBJ = "string", "boolean", "object", "array of strings", "array of objects"

# message -> {jsonName: (type, required)}
SCHEMA: dict[str, dict[str, tuple[str, bool]]] = {
    "AgentCard": {
        "name": (STR, True), "description": (STR, True), "supportedInterfaces": (ARR_OBJ, True),
        "provider": (OBJ, False), "version": (STR, True), "documentationUrl": (STR, False),
        "capabilities": (OBJ, True), "securitySchemes": (OBJ, False),
        "securityRequirements": (ARR_OBJ, False), "defaultInputModes": (ARR_STR, True),
        "defaultOutputModes": (ARR_STR, True), "skills": (ARR_OBJ, True),
        "signatures": (ARR_OBJ, False), "iconUrl": (STR, False),
    },
    "AgentProvider": {"url": (STR, True), "organization": (STR, True)},
    "AgentCapabilities": {"streaming": (BOOL, False), "pushNotifications": (BOOL, False),
                          "extensions": (ARR_OBJ, False), "extendedAgentCard": (BOOL, False)},
    "AgentExtension": {"uri": (STR, False), "description": (STR, False),
                       "required": (BOOL, False), "params": (OBJ, False)},
    "AgentInterface": {"url": (STR, True), "protocolBinding": (STR, True), "tenant": (STR, False),
                       "protocolVersion": (STR, True)},
    "AgentSkill": {"id": (STR, True), "name": (STR, True), "description": (STR, True),
                   "tags": (ARR_STR, True), "examples": (ARR_STR, False),
                   "inputModes": (ARR_STR, False), "outputModes": (ARR_STR, False),
                   "securityRequirements": (ARR_OBJ, False)},
    "AgentCardSignature": {"protected": (STR, True), "signature": (STR, True), "header": (OBJ, False)},
}

#: v0.3-era / deprecated top-level fields: reported by ``compat``, not as typos here.
_LEGACY_CARD_KEYS = frozenset({
    "url", "preferredTransport", "protocolVersion", "additionalInterfaces", "security",
    "supportsAuthenticatedExtendedCard", "supportsAuthenticatedExtendedCard",
})
_SNAKE = re.compile(r"[a-z]+(_[a-z0-9]+)+$")
_MEDIA = re.compile(r"^[A-Za-z0-9!#$&^_.+*-]+/[A-Za-z0-9!#$&^_.+*-]+(\s*;.*)?$")


def _snake_to_camel(k: str) -> str:
    head, *rest = k.split("_")
    return head + "".join(p[:1].upper() + p[1:] for p in rest)


def _kind(v: Any) -> str:
    if isinstance(v, list):
        inner = sorted({_kind(x) for x in v})
        return "array containing " + "/".join(inner) if inner else "array"
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    return {str: "string", list: "array", dict: "object"}.get(type(v), type(v).__name__)


def _type_ok(v: Any, t: str) -> bool:
    if t == STR:
        return isinstance(v, str)
    if t == BOOL:
        return isinstance(v, bool)
    if t == OBJ:
        return isinstance(v, dict)
    if t == ARR_STR:
        return isinstance(v, list) and all(isinstance(x, str) for x in v)
    if t == ARR_OBJ:
        return isinstance(v, list) and all(isinstance(x, dict) for x in v)
    return True


def _check_message(msg: str, obj: dict, path: str, out: list[Diagnostic]) -> None:
    table = SCHEMA[msg]
    prefix = path + "." if path else ""
    for key, value in obj.items():
        if not isinstance(key, str):
            continue
        if key in table:
            t, _req = table[key]
            if not _type_ok(value, t):
                # existing structural codes (E102/E107/E108/E109/E112) own the common cases
                if (msg, key) in {("AgentCard", "supportedInterfaces"), ("AgentCard", "capabilities"),
                                  ("AgentCard", "defaultInputModes"), ("AgentCard", "defaultOutputModes"),
                                  ("AgentCard", "skills"), ("AgentSkill", "tags"),
                                  ("AgentCard", "securityRequirements"),
                                  ("AgentSkill", "securityRequirements")}:
                    continue
                out.append(Diagnostic(ERROR, "E120",
                                      f"'{key}' must be {_article(t)}, got {_kind(value)}", f"{prefix}{key}"))
            continue
        if msg == "AgentCard" and key in _LEGACY_CARD_KEYS:
            continue
        if key in ("securitySchemes",):
            continue
        # unknown key: only warn when it is evidently a mistake
        if _SNAKE.match(key) and _snake_to_camel(key) in table:
            out.append(Diagnostic(
                ERROR, "E125",
                f"'{key}' is the proto spelling; JSON field names MUST be camelCase "
                f"('{_snake_to_camel(key)}', spec 5.5) - clients that follow the spec ignore this field",
                f"{prefix}{key}"))
            continue
        close = difflib.get_close_matches(key, list(table), n=1, cutoff=0.8)
        if close:
            out.append(Diagnostic(
                WARNING, "W210", f"unknown field '{key}' is ignored by clients - did you mean '{close[0]}'?",
                f"{prefix}{key}"))
    for key, (t, req) in table.items():
        if req and key in obj and t == STR and isinstance(obj[key], str) and not obj[key].strip() \
                and key != "description":
            out.append(Diagnostic(ERROR, "E122", f"required field '{key}' is empty", f"{prefix}{key}"))


def _article(t: str) -> str:
    return ("an " if t[0] in "aeiou" else "a ") + t


def validate_structure(card: Any) -> list[Diagnostic]:
    """Type, required-nested-field, and typo checks driven by :data:`SCHEMA`."""
    out: list[Diagnostic] = []
    if not isinstance(card, dict):
        return out
    _check_message("AgentCard", card, "", out)

    prov = card.get("provider")
    if isinstance(prov, dict):
        _check_message("AgentProvider", prov, "provider", out)
        for k, (_t, req) in SCHEMA["AgentProvider"].items():
            if req and k not in prov:
                out.append(Diagnostic(ERROR, "E121", f"missing required field '{k}'", f"provider.{k}"))

    caps = card.get("capabilities")
    if isinstance(caps, dict):
        _check_message("AgentCapabilities", caps, "capabilities", out)
        exts = caps.get("extensions")
        if isinstance(exts, list):
            for n, ext in enumerate(exts):
                p = f"capabilities.extensions[{n}]"
                if not isinstance(ext, dict):
                    out.append(Diagnostic(ERROR, "E120", "extension must be an object", p))
                    continue
                _check_message("AgentExtension", ext, p, out)
                if not isinstance(ext.get("uri"), str) or not ext.get("uri"):
                    out.append(Diagnostic(WARNING, "W216", "extension has no 'uri' (optional in the proto, but it is "
                                          "how clients request it via A2A-Extensions)", f"{p}.uri"))

    ifaces = card.get("supportedInterfaces")
    if isinstance(ifaces, list):
        for n, iface in enumerate(ifaces):
            if isinstance(iface, dict):
                _check_message("AgentInterface", iface, f"supportedInterfaces[{n}]", out)

    skills = card.get("skills")
    if isinstance(skills, list):
        if not skills:
            out.append(Diagnostic(
                ERROR, "E124", "'skills' is required and must contain at least one element (spec 5.7)",
                "skills"))
        for n, sk in enumerate(skills):
            if isinstance(sk, dict):
                _check_message("AgentSkill", sk, f"skills[{n}]", out)
                for f in ("inputModes", "outputModes"):
                    _media_types(sk.get(f), f"skills[{n}].{f}", out)

    sigs = card.get("signatures")
    if isinstance(sigs, list):
        for n, sg in enumerate(sigs):
            p = f"signatures[{n}]"
            if not isinstance(sg, dict):
                out.append(Diagnostic(ERROR, "E120", "signature must be an object", p))
                continue
            _check_message("AgentCardSignature", sg, p, out)
            for k, (_t, req) in SCHEMA["AgentCardSignature"].items():
                if req and k not in sg:
                    out.append(Diagnostic(ERROR, "E121", f"missing required field '{k}'", f"{p}.{k}"))

    for f in ("defaultInputModes", "defaultOutputModes"):
        _media_types(card.get(f), f, out)
    return out


def _media_types(modes: Any, path: str, out: list[Diagnostic]) -> None:
    if not isinstance(modes, list):
        return
    for n, m in enumerate(modes):
        if isinstance(m, str) and m and not _MEDIA.match(m):
            out.append(Diagnostic(
                WARNING, "W211",
                f"'{m}' is not a media type (expected type/subtype such as text/plain); "
                "the spec defines these modes as media types",
                f"{path}[{n}]"))


def interface_url_ok(url: Any, binding: Any) -> bool:
    """Is ``url`` plausible for ``binding``?

    JSONRPC / HTTP+JSON need an absolute http(s) URL. GRPC may also be a bare
    ``host:port`` target (what the official Python SDK emits) or a URL with
    another scheme (``dns:///host``, ``grpcs://``). A custom binding
    (identified by a URI, spec 5.8) may use any scheme (``wss://``).
    """
    from urllib.parse import urlparse
    if not isinstance(url, str) or not url.strip() or url != url.strip():
        return False
    if binding in ("JSONRPC", "HTTP+JSON") or not isinstance(binding, str):
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    if binding == "GRPC":
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:(//|[^0-9/])", url):
            return True
        return bool(re.match(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):\d{1,5}$", url))
    p = urlparse(url)           # custom binding: any scheme with something after it
    return bool(p.scheme) and bool(p.netloc or p.path)


def binding_is_custom_uri(binding: Any) -> bool:
    return isinstance(binding, str) and bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$", binding))
