"""AgentCard fetch, validate, and lint.

Fetch resolves ``/.well-known/agent-card.json`` per A2A v1.0, falling back to
the pre-0.3 ``/.well-known/agent.json`` path so version drift is *detected*,
not hidden.

Validation is strict about spec-required structure and deliberately lenient
about everything else: unknown fields and ``extensions`` content never produce
errors (panel decision D2).
"""

from __future__ import annotations

import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

from . import secreq
from .net import USER_AGENT, ResponseTooLarge, clean, loads_strict, read_capped
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
        # message/path can echo attacker-controlled card text: escape controls
        loc = f" [{clean(self.path)}]" if self.path else ""
        return f"{self.severity.upper()} {self.code}{loc}: {clean(self.message)}"

    def to_dict(self) -> dict:
        return {"severity": self.severity, "code": self.code,
                "message": self.message, "path": self.path}


@dataclass
class FetchInfo:
    base_url: str
    resolved_url: str
    path_used: str          # which well-known path resolved
    legacy_fallback: bool   # True if the modern path 404'd and legacy resolved
    status: int
    elapsed_ms: int
    content_type: str = ""
    cache_control: str = ""
    etag: str = ""


class CardFetchError(RuntimeError):
    """Raised when the AgentCard cannot be fetched or parsed."""


def fetch_card(base_url: str, timeout: float = 10.0,
               card_path: Optional[str] = None) -> tuple[dict, FetchInfo]:
    """Fetch an AgentCard from a base URL.

    ``base_url`` may be an origin (``https://agent.example.com``) or include a
    path prefix (``https://example.com/agents/weather``). Returns the parsed
    card and fetch metadata. Raises CardFetchError on any failure.

    ``card_path`` overrides discovery (e.g. ``/cards/weather.json``) for agents
    that serve their card somewhere non-standard; no legacy fallback is tried.
    Bodies over 2 MiB are refused.
    """
    spec = load_spec()
    base = base_url.rstrip("/")
    if "://" not in base:
        base = "https://" + base
    if card_path is not None:
        if not card_path.startswith("/") or "://" in card_path:
            raise CardFetchError(f"--card-path must be an absolute path like /x/card.json, got {card_path!r}")
        candidates = [card_path]
    else:
        candidates = [spec["card_path"]] + list(spec["legacy_card_paths"])
    last_error: Optional[Exception] = None
    saw_404_on_modern = False

    for i, path in enumerate(candidates):
        url = base + path
        started = time.monotonic()
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")
                cache_control = resp.headers.get("Cache-Control", "")
                etag = resp.headers.get("ETag", "")
                body = read_capped(resp)
        except ResponseTooLarge as e:
            raise CardFetchError(f"GET {url}: {e}") from e
        except urllib.error.HTTPError as e:
            if e.code == 404 and i == 0 and len(candidates) > 1:
                saw_404_on_modern = True
                continue  # try the legacy path before giving up
            raise CardFetchError(f"GET {url} -> HTTP {e.code}") from e
        except urllib.error.URLError as e:
            raise CardFetchError(f"GET {url} failed: {e.reason}") from e
        except (TimeoutError, OSError) as e:
            raise CardFetchError(f"GET {url} failed: {e}") from e
        except (ValueError, http.client.HTTPException) as e:
            # http.client.InvalidURL (an HTTPException, not a ValueError), bad
            # IDNA labels (UnicodeError), bad IPv6 literals, unknown URL types,
            # and protocol-level garbage (BadStatusLine, IncompleteRead)
            raise CardFetchError(f"GET {url!r} failed: {e}") from e

        elapsed_ms = int((time.monotonic() - started) * 1000)
        try:
            text = body.decode("utf-8-sig")  # tolerate a BOM
            card = loads_strict(text)
        except (UnicodeDecodeError, ValueError) as e:
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
            cache_control=cache_control,
            etag=etag,
        )
        return card, info

    if card_path is not None:
        raise CardFetchError(f"No AgentCard found at {base}{card_path}")
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
                from . import schema as _schema
                url = iface.get("url")
                binding = iface.get("protocolBinding")
                if (url is not None and binding == "GRPC" and isinstance(url, str) and url.strip()
                        and not _schema.interface_url_ok(url, binding)):
                    diags.append(Diagnostic(
                        WARNING, "W213", "gRPC address should be 'hostname:port' (proto AgentInterface.url)",
                        f"{p}.url"))
                elif url is not None and not _schema.interface_url_ok(url, binding):
                    want = ("host:port or a URL" if binding == "GRPC" else
                            "an absolute URL" if isinstance(binding, str) and binding not in spec["protocol_bindings"]
                            else "an absolute http(s) URL")
                    diags.append(Diagnostic(ERROR, "E105", f"'url' must be {want}", f"{p}.url"))
                if binding is not None and binding not in spec["protocol_bindings"]:
                    if _schema.binding_is_custom_uri(binding):
                        diags.append(Diagnostic(
                            INFO, "I209",
                            f"custom protocolBinding '{binding}' (spec 5.8): standard clients will skip this interface",
                            f"{p}.protocolBinding"))
                    elif isinstance(binding, str):
                        diags.append(Diagnostic(
                            WARNING, "W212",
                            f"unknown protocolBinding '{binding}' (standard: {', '.join(spec['protocol_bindings'])}; "
                            "custom bindings should be identified by a URI, spec 5.8)",
                            f"{p}.protocolBinding"))
                    else:
                        diags.append(Diagnostic(ERROR, "E106", "'protocolBinding' must be a string",
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

    # --- securityRequirements shape (card and skill level) -------------------
    for prefix, owner in secreq.owners(card):
        reqs = owner.get("securityRequirements")
        if reqs is None:
            continue
        if not isinstance(reqs, list):
            diags.append(Diagnostic(ERROR, "E114", "'securityRequirements' must be an array",
                                    f"{prefix}securityRequirements"))
            continue
        for alt in secreq.parse(reqs):
            if alt.shape == secreq.INVALID:
                diags.append(Diagnostic(
                    ERROR, "E115",
                    'requirement entry must be {"schemes": {"<scheme>": {"list": [scopes]}}}',
                    f"{prefix}securityRequirements[{alt.index}]"))

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

    # I207: pre-1.0 OpenAPI-shaped requirements ({"oidc": [...]})
    for prefix, owner in secreq.owners(card):
        field = secreq.requirements_field(owner)
        if field is None:
            continue
        if field == "security":
            diags.append(Diagnostic(
                INFO, "I208", "v0.3 'security' field; v1.0 calls it 'securityRequirements'",
                f"{prefix}security"))
        if any(a.shape == secreq.LEGACY for a in secreq.alternatives(owner)):
            diags.append(Diagnostic(
                INFO, "I207",
                'requirements use the pre-1.0 OpenAPI shape {"<scheme>": [scopes]}; v1.0 '
                'is {"schemes": {"<scheme>": {"list": [scopes]}}}',
                f"{prefix}{field}"))

    # W202: declared schemes that are never required (card or skill level)
    schemes = card.get("securitySchemes")
    if isinstance(schemes, dict) and schemes:
        referenced = secreq.referenced_schemes(card)
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

    # (an empty 'skills' array is now error E124 - spec 5.7 requires at least one element)

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


def check_card(card: Any, local_origin: bool = False) -> list[Diagnostic]:
    """Validate + lint in one pass (validate first so errors sort first)."""
    from . import schema as _schema
    base = validate_card(card)
    # structural checks only add to what validate_card already reports
    seen = {(d.code, d.path) for d in base}
    extra = [d for d in _schema.validate_structure(card) if (d.code, d.path) not in seen]
    from . import cardsec as _cardsec
    return base + extra + lint_card(card if isinstance(card, dict) else {}) + _cardsec.lint_security(card, local_origin=local_origin)


def has_errors(diags: list[Diagnostic]) -> bool:
    return any(d.severity == ERROR for d in diags)


def format_diagnostics(diags: list[Diagnostic]) -> str:
    if not diags:
        return "OK: no issues found."
    return "\n".join(str(d) for d in diags)


@dataclass
class CardSource:
    """A loaded card plus where it came from."""
    card: Any
    info: Optional[FetchInfo]   # set for URLs
    kind: str                   # url | file | stdin
    text: Optional[str] = None  # raw text for file/stdin (read once)


_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def looks_like_path(source: str) -> bool:
    """True for inputs that are clearly meant as local files, not URLs.

    Used so a typo'd file name is reported as "file not found" instead of being
    sent to DNS and the network as a host name.
    """
    if "://" in source:
        return False
    return (source.lower().endswith(".json")
            or source.startswith((".", "/", "~", "\\"))
            or "\\" in source
            or bool(_WIN_DRIVE.match(source)))


def _parse_local(data: bytes, label: str) -> tuple[Any, str]:
    if len(data) > MAX_LOCAL_BYTES:
        raise CardFetchError(f"{label} exceeds the {MAX_LOCAL_BYTES}-byte cap")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise CardFetchError(f"{label} is not UTF-8: {e}") from e
    try:
        return loads_strict(text), text
    except ValueError as e:
        raise CardFetchError(f"{label} is not valid JSON: {e}") from e


def read_card_source(source: str, timeout: float = 10.0, card_path: Optional[str] = None,
                     stdin=None) -> CardSource:
    """Load a card from ``-`` (stdin), a local file, or a base URL.

    Resolution order is explicit:

    1. ``-`` -> stdin;
    2. an existing file -> that file, read exactly once with a size cap (a
       malformed file is an error, never silently retried as a URL);
    3. something that looks like a path (``*.json``, ``./x``, ``/x``, ``~/x``,
       ``C:\\x``) but does not exist -> "file not found", no network access;
    4. anything else -> :func:`fetch_card`.

    Raises CardFetchError on failure.
    """
    import os
    import sys

    if source == "-":
        stream = stdin if stdin is not None else sys.stdin
        raw = getattr(stream, "buffer", None)
        data = raw.read(MAX_LOCAL_BYTES + 1) if raw is not None else \
            stream.read(MAX_LOCAL_BYTES + 1).encode("utf-8")
        card, text = _parse_local(data, "stdin")
        return CardSource(card, None, "stdin", text)
    path = os.path.expanduser(source)
    if os.path.isdir(path):
        raise CardFetchError(f"{source} is a directory, not a card file")
    if os.path.isfile(path):
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_LOCAL_BYTES + 1)
        except OSError as e:
            raise CardFetchError(f"cannot read {source}: {e}") from e
        card, text = _parse_local(data, source)
        return CardSource(card, None, "file", text)
    if looks_like_path(source):
        raise CardFetchError(
            f"file not found: {source} (for a URL, include the scheme, e.g. https://{source.lstrip('./')})")
    card, info = fetch_card(source, timeout=timeout, card_path=card_path)
    return CardSource(card, info, "url")


def load_card_source(source: str, timeout: float = 10.0, card_path: Optional[str] = None,
                     stdin=None) -> tuple[Any, Optional[FetchInfo]]:
    """Back-compatible wrapper around :func:`read_card_source`: (card, info)."""
    src = read_card_source(source, timeout=timeout, card_path=card_path, stdin=stdin)
    return src.card, src.info


#: Local files and stdin get a larger cap than network bodies (you chose them).
MAX_LOCAL_BYTES = 16 * 1024 * 1024
