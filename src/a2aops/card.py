"""AgentCard fetch, validate, and lint.

Fetch resolves ``/.well-known/agent-card.json`` per A2A v1.0, falling back to
the pre-0.3 ``/.well-known/agent.json`` path so version drift is *detected*,
not hidden.

Validation is strict about spec-required structure and deliberately lenient
about everything else: unknown fields and ``extensions`` content never produce
errors (panel decision D2).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

from .spec import load_spec

ERROR = "error"
WARNING = "warning"
INFO = "info"


@dataclass
class Diagnostic:
    severity: str   # error | warning | info
    code: str       # e.g. "E101", "W201", "I301"
    message: str
    path: str = ""  # dotted path into the card, e.g. "skills[2].tags"

    def __str__(self) -> str:
        loc = f" [{self.path}]" if self.path else ""
        return f"{self.severity.upper()} {self.code}{loc}: {self.message}"


@dataclass
class FetchInfo:
    base_url: str
    resolved_url: str
    path_used: str          # which well-known path resolved
    legacy_fallback: bool   # True if the modern path 404'd and legacy resolved
    status: int
    elapsed_ms: int
    content_type: str = ""


class CardFetchError(RuntimeError):
    """Raised when the AgentCard cannot be fetched or parsed."""


def fetch_card(base_url: str, timeout: float = 10.0) -> tuple[dict, FetchInfo]:
    """Fetch an AgentCard from a base URL.

    ``base_url`` may be an origin (``https://agent.example.com``) or include a
    path prefix (``https://example.com/agents/weather``). Returns the parsed
    card and fetch metadata. Raises CardFetchError on any failure.
    """
    spec = load_spec()
    base = base_url.rstrip("/")
    if "://" not in base:
        base = "https://" + base

    candidates = [spec["card_path"]] + list(spec["legacy_card_paths"])
    last_error: Optional[Exception] = None
    saw_404_on_modern = False

    for i, path in enumerate(candidates):
        url = base + path
        started = time.monotonic()
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "a2aops/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404 and i == 0:
                saw_404_on_modern = True
                continue  # try the legacy path before giving up
            raise CardFetchError(f"GET {url} -> HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise CardFetchError(f"GET {url} failed: {e.reason}") from e
        except (TimeoutError, OSError) as e:
            raise CardFetchError(f"GET {url} failed: {e}") from e

        elapsed_ms = int((time.monotonic() - started) * 1000)
        try:
            text = body.decode("utf-8-sig")  # tolerate a BOM
            card = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise CardFetchError(f"GET {url} returned non-JSON body: {e}") from e
        if not isinstance(card, dict):
            raise CardFetchError(f"GET {url} returned a JSON {type(card).__name__}, not an object")

        info = FetchInfo(
            base_url=base,
            resolved_url=url,
            path_used=path,
            legacy_fallback=(i > 0 and saw_404_on_modern),
            status=status,
            elapsed_ms=elapsed_ms,
            content_type=content_type,
        )
        return card, info

    raise CardFetchError(
        f"No AgentCard found at {base}{spec['card_path']} "
        f"or legacy {base}{spec['legacy_card_paths'][0]}"
    ) from last_error


def _is_abs_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = urllib.parse.urlparse(value)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _is_loopback(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return False
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def validate_card(card: Any) -> list[Diagnostic]:
    """Validate an AgentCard against the pinned A2A v1.0 schema.

    Errors = spec-required structure violations. Anything the spec leaves
    open (unknown fields, extensions content) is never an error.
    """
    spec = load_spec()
    diags: list[Diagnostic] = []

    if not isinstance(card, dict):
        return [Diagnostic(ERROR, "E001", "AgentCard must be a JSON object", "")]

    # --- required top-level fields -------------------------------------
    for f in spec["required_card_fields"]:
        if f not in card:
            diags.append(Diagnostic(ERROR, "E101", f"missing required field '{f}'", f))

    # --- supportedInterfaces -------------------------------------------
    ifaces = card.get("supportedInterfaces")
    if ifaces is not None:
        if not isinstance(ifaces, list) or not ifaces:
            diags.append(Diagnostic(
                ERROR, "E102", "'supportedInterfaces' must be a non-empty array",
                "supportedInterfaces"))
        else:
            for n, iface in enumerate(ifaces):
                p = f"supportedInterfaces[{n}]"
                if not isinstance(iface, dict):
                    diags.append(Diagnostic(ERROR, "E103", "interface must be an object", p))
                    continue
                for f in spec["interface_required_fields"]:
                    if f not in iface:
                        diags.append(Diagnostic(ERROR, "E104", f"missing required field '{f}'", f"{p}.{f}"))
                url = iface.get("url")
                if url is not None and not _is_abs_url(url):
                    diags.append(Diagnostic(ERROR, "E105", "'url' must be an absolute URL", f"{p}.url"))
                binding = iface.get("protocolBinding")
                if binding is not None and binding not in spec["protocol_bindings"]:
                    diags.append(Diagnostic(
                        ERROR, "E106",
                        f"unknown protocolBinding '{binding}' (expected one of {', '.join(spec['protocol_bindings'])})",
                        f"{p}.protocolBinding"))

    # --- capabilities ----------------------------------------------------
    caps = card.get("capabilities")
    if caps is not None and not isinstance(caps, dict):
        diags.append(Diagnostic(ERROR, "E107", "'capabilities' must be an object", "capabilities"))

    # --- input/output modes ----------------------------------------------
    for f in ("defaultInputModes", "defaultOutputModes"):
        modes = card.get(f)
        if modes is not None and (not isinstance(modes, list) or not modes
                                  or not all(isinstance(m, str) and m for m in modes)):
            diags.append(Diagnostic(ERROR, "E108", f"'{f}' must be a non-empty array of strings", f))

    # --- skills ------------------------------------------------------------
    skills = card.get("skills")
    if skills is not None:
        if not isinstance(skills, list):
            diags.append(Diagnostic(ERROR, "E109", "'skills' must be an array", "skills"))
        else:
            seen_ids: set[str] = set()
            for n, skill in enumerate(skills):
                p = f"skills[{n}]"
                if not isinstance(skill, dict):
                    diags.append(Diagnostic(ERROR, "E110", "skill must be an object", p))
                    continue
                for f in spec["required_skill_fields"]:
                    if f not in skill:
                        diags.append(Diagnostic(ERROR, "E111", f"missing required field '{f}'", f"{p}.{f}"))
                tags = skill.get("tags")
                if tags is not None and (not isinstance(tags, list) or not tags
                                        or not all(isinstance(t, str) and t for t in tags)):
                    diags.append(Diagnostic(ERROR, "E112", "'tags' must be a non-empty array of strings", f"{p}.tags"))
                sid = skill.get("id")
                if isinstance(sid, str):
                    if sid in seen_ids:
                        diags.append(Diagnostic(ERROR, "E113", f"duplicate skill id '{sid}'", f"{p}.id"))
                    seen_ids.add(sid)

    # --- securityRequirements shape ----------------------------------------
    reqs = card.get("securityRequirements")
    if reqs is not None and not isinstance(reqs, list):
        diags.append(Diagnostic(ERROR, "E114", "'securityRequirements' must be an array", "securityRequirements"))

    return diags


def lint_card(card: dict) -> list[Diagnostic]:
    """Style/robustness lint. Warnings and infos only — never errors.

    Every check here is defensible against valid-but-unusual cards.
    """
    diags: list[Diagnostic] = []
    if not isinstance(card, dict):
        return diags

    # W201: preferred interface should be HTTPS outside loopback
    ifaces = card.get("supportedInterfaces")
    if isinstance(ifaces, list) and ifaces and isinstance(ifaces[0], dict):
        url = ifaces[0].get("url")
        if isinstance(url, str) and url.startswith("http://") and not _is_loopback(url):
            diags.append(Diagnostic(
                WARNING, "W201",
                "preferred interface uses plain HTTP; production cards should be HTTPS",
                "supportedInterfaces[0].url"))

    # W202: declared schemes that are never required
    schemes = card.get("securitySchemes")
    reqs = card.get("securityRequirements")
    if isinstance(schemes, dict) and schemes:
        referenced: set[str] = set()
        if isinstance(reqs, list):
            for entry in reqs:
                if isinstance(entry, dict):
                    referenced.update(entry.keys())
        for name in schemes:
            if name not in referenced:
                diags.append(Diagnostic(
                    WARNING, "W202",
                    f"security scheme '{name}' is declared but never required — clients will not send credentials for it",
                    f"securitySchemes.{name}"))

    # W203: thin descriptions hurt discovery
    desc = card.get("description")
    if isinstance(desc, str) and len(desc.strip()) < 10:
        diags.append(Diagnostic(WARNING, "W203", "description is very short; routers and humans match on it", "description"))

    # W204: empty skills array — valid, but a card advertising nothing
    skills = card.get("skills")
    if isinstance(skills, list) and not skills:
        diags.append(Diagnostic(WARNING, "W204", "'skills' is empty; the agent advertises no abilities", "skills"))

    # W205: streaming without any fallback signal
    caps = card.get("capabilities")
    if isinstance(caps, dict):
        if caps.get("streaming") is True and not caps.get("pushNotifications"):
            diags.append(Diagnostic(
                INFO, "I205",
                "streaming is enabled but pushNotifications is not; clients behind SSE-blocking proxies will need polling fallback",
                "capabilities"))

    # I206: version looks non-semver — informational only, many teams use date versions
    ver = card.get("version")
    if isinstance(ver, str) and ver and not _looks_semver(ver):
        diags.append(Diagnostic(INFO, "I206", f"version '{ver}' is not semver; fine if intentional (e.g. date-based)", "version"))

    return diags


def _looks_semver(v: str) -> bool:
    parts = v.split(".")
    return len(parts) >= 2 and all(p.split("-")[0].split("+")[0].isdigit() for p in parts[:3] if p)


def check_card(card: Any) -> list[Diagnostic]:
    """Validate + lint in one pass (validate first so errors sort first)."""
    return validate_card(card) + lint_card(card if isinstance(card, dict) else {})


def has_errors(diags: list[Diagnostic]) -> bool:
    return any(d.severity == ERROR for d in diags)


def format_diagnostics(diags: list[Diagnostic]) -> str:
    if not diags:
        return "OK: no issues found."
    return "\n".join(str(d) for d in diags)
