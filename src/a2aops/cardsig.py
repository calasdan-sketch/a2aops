"""``a2aops card verify``: check AgentCard JWS signatures against keys you trust.

Codes
=====  ==========================================================================
G901   card has no ``signatures`` (nothing to verify)
G902   a signature verified (info; names the canonicalization profile that matched)
G903   every signature present failed verification
G904   signature uses something this tool cannot verify (PS*, EdDSA, ``crit``)
G905   no trusted key matches the signature's ``kid``
G906   ``jku`` in a protected header was ignored (or refused) - it is attacker input
G907   algorithm refused (``none``, ``HS*``, or header/key algorithm mismatch)
G908   malformed signature entry or key
G909   verified, but only under the Python-SDK canonicalization profile, which
       differs from the spec's default-value rules: other verifiers may reject it
=====  ==========================================================================
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Optional

from . import jws
from .card import ERROR, INFO, WARNING, Diagnostic
from .net import UnsafeURL, clean, loads_strict, open_untrusted, read_capped


def _fetch_jwks(url: str, timeout: float) -> Any:
    with open_untrusted(url, timeout) as resp:
        return loads_strict(read_capped(resp).decode("utf-8-sig"))


def verify_card(card: Any, keys: list[dict], *, card_host: Optional[str] = None,
                trust_jku: bool = False, timeout: float = 10.0,
                fetch=_fetch_jwks) -> list[Diagnostic]:
    """Verify ``card['signatures']`` against ``keys`` (trusted JWKs)."""
    out: list[Diagnostic] = []
    if not isinstance(card, dict):
        return [Diagnostic(ERROR, "E001", "AgentCard must be a JSON object", "")]
    sigs = card.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return [Diagnostic(ERROR, "G901", "card has no signatures; its origin and integrity cannot be verified",
                           "signatures")]
    any_valid = False
    for i, sg in enumerate(sigs):
        path = f"signatures[{i}]"
        if not isinstance(sg, dict):
            out.append(Diagnostic(ERROR, "G908", "signature entry is not an object", path))
            continue
        try:
            hdr = loads_strict(jws.b64u_decode(sg.get("protected", "")))
        except (ValueError, jws.JwsError, TypeError):
            hdr = {}
        use_keys = list(keys)
        jku = hdr.get("jku") if isinstance(hdr, dict) else None
        if isinstance(jku, str) and jku:
            host = (urllib.parse.urlparse(jku).hostname or "").lower()
            if trust_jku and card_host and host == card_host.lower():
                try:
                    use_keys += jws.load_jwks(fetch(jku, timeout))
                except (UnsafeURL, OSError, ValueError, jws.JwsError) as e:
                    out.append(Diagnostic(WARNING, "G906", f"jku fetch failed: {clean(e)}", path))
            else:
                out.append(Diagnostic(
                    INFO, "G906",
                    f"ignored jku '{clean(jku)}' in the protected header: it is attacker-controlled, so keys are "
                    "taken only from --jwks"
                    + ("" if trust_jku else " (--trust-jku fetches it when it is on the card's own host)"),
                    path))
        outcome, detail = jws.verify_signature(card, sg, use_keys)
        if outcome == jws.Outcome.VALID:
            any_valid = True
            if detail.startswith("spec"):
                out.append(Diagnostic(INFO, "G902", f"signature verified (canonicalization: {detail})", path))
            else:
                out.append(Diagnostic(
                    WARNING, "G909",
                    f"signature verified only under the '{detail}' canonicalization profile, not the spec's "
                    "default-value rules (8.4.1); strict verifiers in other SDKs may reject this card", path))
        else:
            code = {"unsupported": "G904", "no-key": "G905", "refused": "G907",
                    "malformed": "G908"}.get(outcome, "G903")
            sev = WARNING if outcome in ("unsupported", "no-key") else ERROR
            out.append(Diagnostic(sev, code, f"signature not verified: {clean(detail)}", path))
    if not any_valid and not any(d.code == "G903" for d in out):
        out.append(Diagnostic(ERROR, "G903", "no signature on this card could be verified with the trusted keys", ""))
    return out
