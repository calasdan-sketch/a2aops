"""Security lint for AgentCards (offline, heuristic where stated).

An AgentCard is attacker-controllable input twice over: clients fetch URLs out
of it, and routers/LLMs read its prose (skill names, descriptions, examples)
as context. This module flags the patterns a security reviewer looks for:

======  =====================================================================
S801    invisible / bidi / control characters in a text field (hides content)
S802    instruction-like text aimed at a model (prompt-injection heuristic)
S803    markup that makes a renderer fetch or run something (images, scripts)
S804    card URL aimed at loopback / private / link-local / metadata space
S805    interface endpoint on a different host than the card (set by the CLI)
S806    unusually long prose field (large model-context payload)
S807    credentials embedded in a URL
S808    secret-looking string in card text
======  =====================================================================

Heuristics (S802, S808) can miss and can over-match; they are reported as
warnings and say so. Nothing here fetches anything.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from typing import Any, Iterator, Optional

from .card import ERROR, INFO, WARNING, Diagnostic
from .net import _is_public_ip

#: cloud-metadata addresses that no legitimate card endpoint uses.
_METADATA_HOSTS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal"}

_INVISIBLE = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f­؜᠎​-‏"
    "‪-‮⁠-⁯  ﻿￹-￻\U000e0000-\U000e007f]")

_INJECTION = [re.compile(p, re.I) for p in (
    r"ignore (all |any |the )?(previous|prior|above|earlier|preceding) (instructions|prompts?|rules|messages)",
    r"disregard (all |any |the )?(previous|prior|above|earlier|your) (instructions|prompts?|rules)",
    r"(forget|override) (all |your |the )?(previous |prior |earlier )?(instructions|rules|guidelines)",
    r"\b(system|developer) (prompt|message|instructions?)\b",
    r"you (must|should|will) (now )?(always |first )?(call|use|send|forward|route|prefer|choose|select) (this|me|it)\b",
    r"(always|only) (route|send|prefer|choose|select|use) (this|me|my) (agent|skill|tool)",
    r"do not (tell|inform|mention|reveal|show)[^.\n]{0,40}(user|human|operator)",
    r"(send|forward|post|upload|exfiltrate|leak)[^.\n]{0,60}(credentials?|tokens?|secrets?|api[ _-]?keys?|passwords?|conversation|history|system prompt)",
    r"<\|(im_start|im_end|system|assistant|user)\|>|\[/?INST\]|<<SYS>>",
    r"^\s*(assistant|system|developer)\s*:",
    r"</?(important|system|instructions?)>",
    r"\bact as\b[^.\n]{0,30}\b(admin|root|system|developer)\b",
)]

_MARKUP = [
    (re.compile(r"!\[[^\]]*\]\(\s*https?://", re.I), "markdown image with a remote URL (fetched when rendered)"),
    (re.compile(r"<\s*(script|iframe|object|embed|img|link|svg|style|form)\b", re.I), "HTML tag"),
    (re.compile(r"javascript\s*:|data\s*:text/html", re.I), "script/HTML URL scheme"),
    (re.compile(r"\]\(\s*https?://[^)\s]*[?&][^)\s]*(\{\{|\$\{|%7B%7B)", re.I), "link with a template placeholder in its query"),
]

# Secret-looking tokens are matched by shape, never by listing a real value.
_SECRETS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id shape"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub token shape"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"), "API key shape (sk-...)"),
    (re.compile(r"\bBearer\s+eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "bearer JWT"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}\b"), "Slack token shape"),
]

_LONG_FIELD = 4000


def _text_fields(card: dict) -> Iterator[tuple[str, str]]:
    """Yield (json path, text) for every prose-bearing string in the card."""
    def s(path: str, v: Any):
        if isinstance(v, str) and v:
            yield path, v

    for k in ("name", "description", "version"):
        yield from s(k, card.get(k))
    prov = card.get("provider")
    if isinstance(prov, dict):
        yield from s("provider.organization", prov.get("organization"))
    skills = card.get("skills")
    if isinstance(skills, list):
        for i, sk in enumerate(skills):
            if not isinstance(sk, dict):
                continue
            for k in ("id", "name", "description"):
                yield from s(f"skills[{i}].{k}", sk.get(k))
            for k in ("tags", "examples"):
                vals = sk.get(k)
                if isinstance(vals, list):
                    for j, v in enumerate(vals):
                        yield from s(f"skills[{i}].{k}[{j}]", v)
    caps = card.get("capabilities")
    if isinstance(caps, dict) and isinstance(caps.get("extensions"), list):
        for i, ext in enumerate(caps["extensions"]):
            if isinstance(ext, dict):
                yield from s(f"capabilities.extensions[{i}].description", ext.get("description"))
    schemes = card.get("securitySchemes")
    if isinstance(schemes, dict):
        for name, sc in schemes.items():
            if isinstance(sc, dict):
                for inner in sc.values():
                    if isinstance(inner, dict):
                        yield from s(f"securitySchemes.{name}.description", inner.get("description"))


def _urls(card: dict) -> Iterator[tuple[str, str, Optional[str]]]:
    """Yield (path, url, binding) for every URL a client may follow."""
    ifaces = card.get("supportedInterfaces")
    if isinstance(ifaces, list):
        for i, f in enumerate(ifaces):
            if isinstance(f, dict) and isinstance(f.get("url"), str):
                yield f"supportedInterfaces[{i}].url", f["url"], f.get("protocolBinding")
    for k in ("documentationUrl", "iconUrl"):
        if isinstance(card.get(k), str):
            yield k, card[k], None
    prov = card.get("provider")
    if isinstance(prov, dict) and isinstance(prov.get("url"), str):
        yield "provider.url", prov["url"], None
    schemes = card.get("securitySchemes")
    if isinstance(schemes, dict):
        for name, sc in schemes.items():
            if not isinstance(sc, dict):
                continue
            for kind, inner in sc.items():
                if not isinstance(inner, dict):
                    continue
                for key in ("openIdConnectUrl", "oauth2MetadataUrl"):
                    if isinstance(inner.get(key), str):
                        yield f"securitySchemes.{name}.{kind}.{key}", inner[key], None
                flows = inner.get("flows")
                if isinstance(flows, dict):
                    for fname, fl in flows.items():
                        if isinstance(fl, dict):
                            for key in ("authorizationUrl", "tokenUrl", "refreshUrl", "deviceAuthorizationUrl"):
                                if isinstance(fl.get(key), str):
                                    yield f"securitySchemes.{name}.{kind}.flows.{fname}.{key}", fl[key], None


def _host_of(url: str, binding: Optional[str]) -> Optional[str]:
    try:
        if binding == "GRPC" and "://" not in url and not re.match(r"^[a-z]+:/", url, re.I):
            host = url.rsplit(":", 1)[0].strip("[]")
        else:
            host = urllib.parse.urlparse(url).hostname or ""
    except ValueError:
        return None
    return host.lower() or None


def classify_host(host: str) -> str:
    """'metadata' | 'private' | 'public-or-name' for a host string (no DNS)."""
    if host in _METADATA_HOSTS:
        return "metadata"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".corp")):
            return "private"
        return "public-or-name"
    return "public-or-name" if _is_public_ip(str(ip)) else "private"


def lint_security(card: Any, local_origin: bool = False) -> list[Diagnostic]:
    """Offline security lint of a card. Returns warnings/errors, no network.

    ``local_origin`` says the card itself was fetched from a loopback/private
    host (a dev stack), where private endpoints are expected and S804 is
    reported only for cloud-metadata addresses.
    """
    out: list[Diagnostic] = []
    if not isinstance(card, dict):
        return out

    for path, text in _text_fields(card):
        if _INVISIBLE.search(text):
            n = len(_INVISIBLE.findall(text))
            out.append(Diagnostic(
                WARNING, "S801",
                f"{n} invisible/bidi/control character(s) in text; they can hide instructions from "
                "reviewers while a model still reads them", path))
        for rx in _INJECTION:
            m = rx.search(text)
            if m:
                out.append(Diagnostic(
                    WARNING, "S802",
                    "text reads like an instruction to a model "
                    "(heuristic: prompt-injection pattern); card prose is untrusted data", path))
                break
        for rx, what in _MARKUP:
            if rx.search(text):
                out.append(Diagnostic(WARNING, "S803", f"{what} in card text; renderers may fetch or run it", path))
                break
        for rx, what in _SECRETS:
            if rx.search(text):
                out.append(Diagnostic(ERROR, "S808", f"secret-looking {what} in a public card", path))
                break
        if len(text) > _LONG_FIELD:
            out.append(Diagnostic(
                INFO, "S806",
                f"{len(text)} characters of prose; routers put card text into model context, "
                "long fields are where injected instructions hide", path))

    for path, url, binding in _urls(card):
        try:
            parts = urllib.parse.urlparse(url)
        except ValueError:
            continue
        if parts.username or parts.password:
            out.append(Diagnostic(ERROR, "S807", "URL embeds credentials (user:password@host)", path))
        host = _host_of(url, binding)
        if not host:
            continue
        kind = classify_host(host)
        if kind == "metadata":
            out.append(Diagnostic(
                ERROR, "S804",
                f"URL points at cloud-metadata address '{host}'; a client that follows it leaks instance credentials",
                path))
        elif kind == "private" and not local_origin:
            out.append(Diagnostic(
                WARNING, "S804",
                f"URL host '{host}' is loopback/private/internal; a public card should not send clients there "
                "(SSRF pivot if the client runs inside a network)", path))
    return out


def lint_origin(card: Any, source_url: str) -> list[Diagnostic]:
    """S805: interface endpoints on a different host than the card was served from."""
    out: list[Diagnostic] = []
    if not isinstance(card, dict):
        return out
    try:
        src_host = (urllib.parse.urlparse(source_url).hostname or "").lower()
    except ValueError:
        return out
    ifaces = card.get("supportedInterfaces")
    if not src_host or not isinstance(ifaces, list):
        return out
    has_auth = bool(card.get("securitySchemes"))
    for i, f in enumerate(ifaces):
        if not isinstance(f, dict) or not isinstance(f.get("url"), str):
            continue
        host = _host_of(f["url"], f.get("protocolBinding"))
        if host and host != src_host:
            out.append(Diagnostic(
                WARNING if has_auth else INFO, "S805",
                f"card served from '{src_host}' sends clients to '{host}'"
                + ("; credentials for the declared auth schemes would go there - verify you trust it "
                   "(or verify a card signature)" if has_auth else ""),
                f"supportedInterfaces[{i}].url"))
    return out
