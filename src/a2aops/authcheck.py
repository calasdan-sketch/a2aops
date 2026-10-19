"""Read-only auth-surface consistency checks.

Compares what the AgentCard *declares* (securitySchemes / securityRequirements)
against what the referenced metadata actually says (OIDC discovery documents,
OAuth2 flow definitions). This catches the classic "auth drift" failure — the
card promises a token endpoint that moved or never existed — without ever
requesting a token or touching credentials (panel decision D3).

Network use is limited to fetching public metadata documents already named in
the card. No credentials are sent, stored, or logged.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Optional

from .card import ERROR, INFO, WARNING, Diagnostic

# Discriminated-union keys used by A2A v1.0 security scheme objects.
SCHEME_KINDS = {
    "openIdConnectSecurityScheme": "oidc",
    "oauth2SecurityScheme": "oauth2",
    "httpAuthSecurityScheme": "http",
    "apiKeySecurityScheme": "apikey",
    "mtlsSecurityScheme": "mtls",
}


def _fetch_json(url: str, timeout: float) -> tuple[Optional[dict], Optional[str]]:
    """GET a JSON metadata document. Returns (doc, error)."""
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "a2aops/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            return json.loads(resp.read().decode("utf-8-sig")), None
    except Exception as e:  # metadata fetch must never crash a check run
        return None, str(e)


def _check_oidc(name: str, cfg: dict, timeout: float) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    url = cfg.get("openIdConnectUrl")
    path = f"securitySchemes.{name}"
    if not url or not isinstance(url, str):
        diags.append(Diagnostic(ERROR, "E301", "OIDC scheme lacks 'openIdConnectUrl'", path))
        return diags
    if not url.startswith("https://"):
        diags.append(Diagnostic(ERROR, "E302", "openIdConnectUrl must be an absolute HTTPS URL", path))

    doc, err = _fetch_json(url, timeout)
    if err is not None:
        diags.append(Diagnostic(
            ERROR, "E303",
            f"auth drift: card declares OIDC at {url} but the discovery document is unreachable ({err})",
            path))
        return diags
    if not isinstance(doc, dict):
        diags.append(Diagnostic(ERROR, "E304", "discovery document is not a JSON object", path))
        return diags
    if "token_endpoint" not in doc:
        diags.append(Diagnostic(
            ERROR, "E305",
            "auth drift: discovery document exposes no 'token_endpoint' — clients cannot complete the flow the card advertises",
            path))
    issuer = doc.get("issuer")
    if isinstance(issuer, str):
        expected_origin = urllib.parse.urlparse(url).scheme + "://" + urllib.parse.urlparse(url).netloc
        if not (issuer == expected_origin or issuer.startswith(expected_origin + "/")):
            diags.append(Diagnostic(
                WARNING, "W306",
                f"discovery 'issuer' ({issuer}) does not match the discovery URL origin ({expected_origin}); token validation may fail",
                path))
    return diags


def _check_oauth2(name: str, cfg: dict) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    path = f"securitySchemes.{name}"
    flows = cfg.get("flows")
    if not isinstance(flows, dict) or not flows:
        diags.append(Diagnostic(ERROR, "E311", "OAuth2 scheme must define at least one flow in 'flows'", path))
        return diags
    for flow_name, flow in flows.items():
        if not isinstance(flow, dict):
            diags.append(Diagnostic(ERROR, "E312", f"flow '{flow_name}' must be an object", f"{path}.flows.{flow_name}"))
            continue
        if flow_name in ("authorizationCode", "clientCredentials", "password") and not flow.get("tokenUrl"):
            diags.append(Diagnostic(
                ERROR, "E313",
                f"auth drift: OAuth2 flow '{flow_name}' declares no 'tokenUrl' — the card's auth surface points nowhere",
                f"{path}.flows.{flow_name}"))
    return diags


def _check_http(name: str, cfg: dict) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    path = f"securitySchemes.{name}"
    if cfg.get("scheme", "").lower() == "bearer" and not cfg.get("bearerFormat"):
        diags.append(Diagnostic(
            INFO, "I321",
            "bearer auth without 'bearerFormat' (e.g. JWT); clients must guess the token shape",
            path))
    return diags


def _check_apikey(name: str, cfg: dict) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    path = f"securitySchemes.{name}"
    if not cfg.get("name") or cfg.get("in") not in ("header", "query", "cookie"):
        diags.append(Diagnostic(
            ERROR, "E331",
            "API-key scheme must declare 'name' and 'in' (header | query | cookie)",
            path))
    return diags


def check_auth_surface(card: dict, timeout: float = 10.0,
                       check_remote: bool = True) -> list[Diagnostic]:
    """Check the card's declared auth surface for drift and inconsistency.

    ``check_remote=False`` skips fetching OIDC discovery documents (offline mode).
    """
    diags: list[Diagnostic] = []
    if not isinstance(card, dict):
        return [Diagnostic(ERROR, "E300", "card must be a JSON object", "")]

    schemes = card.get("securitySchemes") or {}
    reqs = card.get("securityRequirements") or []
    if not isinstance(schemes, dict):
        return [Diagnostic(ERROR, "E300", "'securitySchemes' must be an object", "securitySchemes")]

    # 1. every requirement must reference a declared scheme
    if isinstance(reqs, list):
        for n, entry in enumerate(reqs):
            p = f"securityRequirements[{n}]"
            if not isinstance(entry, dict):
                diags.append(Diagnostic(ERROR, "E340", "requirement entry must be an object", p))
                continue
            for scheme_name in entry:
                if scheme_name not in schemes:
                    diags.append(Diagnostic(
                        ERROR, "E341",
                        f"auth drift: requirement references undeclared scheme '{scheme_name}' — "
                        "clients cannot satisfy it",
                        p))

    # 2. per-scheme checks
    for name, scheme in schemes.items():
        path = f"securitySchemes.{name}"
        if not isinstance(scheme, dict):
            diags.append(Diagnostic(ERROR, "E342", "scheme must be an object", path))
            continue
        kinds = [k for k in scheme if k in SCHEME_KINDS]
        if not kinds:
            diags.append(Diagnostic(
                WARNING, "W343",
                f"scheme '{name}' uses an unrecognized shape; skipping deep checks "
                f"(known shapes: {', '.join(sorted(SCHEME_KINDS))})",
                path))
            continue
        if len(kinds) > 1:
            diags.append(Diagnostic(WARNING, "W344",
                                    f"scheme declares multiple kinds {kinds}; using '{kinds[0]}'", path))
        kind, cfg = kinds[0], scheme[kinds[0]]
        if not isinstance(cfg, dict):
            diags.append(Diagnostic(ERROR, "E345", f"'{kinds[0]}' must be an object", path))
            continue
        if SCHEME_KINDS[kind] == "oidc":
            if check_remote:
                diags.extend(_check_oidc(name, cfg, timeout))
            elif not cfg.get("openIdConnectUrl"):
                diags.append(Diagnostic(ERROR, "E301", "OIDC scheme lacks 'openIdConnectUrl'", path))
        elif SCHEME_KINDS[kind] == "oauth2":
            diags.extend(_check_oauth2(name, cfg))
        elif SCHEME_KINDS[kind] == "http":
            diags.extend(_check_http(name, cfg))
        elif SCHEME_KINDS[kind] == "apikey":
            diags.extend(_check_apikey(name, cfg))
        # mtls: nothing further to check from the card alone

    return diags
