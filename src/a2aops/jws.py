"""AgentCard signature verification (spec 8.4), standard library only.

What the spec requires of a verifier [8.4.3]:

1. take a signature from ``signatures``;
2. get the public key by ``kid`` (+ ``jku``) **or from a trusted key store**;
3. remove default-valued properties and the ``signatures`` field;
4. canonicalize with RFC 8785 (JCS);
5. verify the JWS over ``BASE64URL(protected) "." BASE64URL(payload)``.

Design decisions, each one a known JWS foot-gun:

* **Keys come from you, not from the card.** A ``jku`` URL in the protected
  header is attacker-controlled; trusting it proves only "signed by whoever
  hosts that URL". It is therefore never fetched unless ``trust_jku`` is set,
  and then only over the SSRF guard and only if the key URL has the same host
  as the card.
* **The key decides the algorithm family**, never the header: an EC key only
  verifies ``ES256/ES384``, an RSA key only ``RS256/RS384/RS512``. ``none`` and
  ``HS*`` are refused (a symmetric secret on a public card is not a signature).
* ES256/ES384 (pure-Python ECDSA over P-256/P-384, constant-time is *not* a goal
  because verification touches only public data) and RS256/384/512 (RSASSA-
  PKCS1-v1_5). ``PS*`` and ``EdDSA`` are reported as unsupported, not failed.
* **Canonicalization profiles.** The spec prose (default-value removal driven by
  ``REQUIRED`` / ``optional``) and the official Python SDK's signer (which drops
  every empty string/list/object) produce different bytes for some cards. The
  verifier tries each profile and reports which one matched, so a
  spec-vs-signer mismatch is visible instead of a silent "invalid".
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
from decimal import Decimal
from typing import Any, Optional

MAX_DEPTH = 128


class JwsError(ValueError):
    pass


# --------------------------------------------------------------------------
# base64url + JCS (RFC 8785)
# --------------------------------------------------------------------------

def b64u_decode(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise JwsError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_str(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        elif 0xD800 <= ord(ch) <= 0xDFFF:
            raise JwsError("lone surrogate in string")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_num(v: Any) -> str:
    if isinstance(v, int):
        if abs(v) > 2 ** 53:
            raise JwsError("integer outside the IEEE-754 safe range (RFC 8785 3.2.2.3)")
        return str(v)
    if math.isnan(v) or math.isinf(v):
        raise JwsError("NaN/Infinity are not JSON")
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    d = Decimal(repr(abs(v)))
    digits = "".join(map(str, d.as_tuple().digits)).rstrip("0") or "0"
    k = len(digits)
    n = d.adjusted() + 1                       # value = 0.DIGITS x 10^n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits[0] + ("." + digits[1:] if k > 1 else "")
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def canonicalize(v: Any, _depth: int = 0) -> str:
    """RFC 8785 serialization of a parsed JSON value."""
    if _depth > MAX_DEPTH:
        raise JwsError("nesting too deep")
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _jcs_num(v)
    if isinstance(v, str):
        return _jcs_str(v)
    if isinstance(v, list):
        return "[" + ",".join(canonicalize(x, _depth + 1) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_jcs_str(k) + ":" + canonicalize(x, _depth + 1) for k, x in items) + "}"
    raise JwsError(f"cannot canonicalize {type(v).__name__}")


# --------------------------------------------------------------------------
# Default-value removal (spec 8.4.1) driven by a.proto field annotations
# --------------------------------------------------------------------------

R, OPT = "required", "optional"       # flags; "" = ordinary proto3 field
S, B, I = "scalar", "scalar", "scalar"

# message -> {jsonName: (kind, child, flag)}
#   kind: scalar | msg | rep | map | struct
_T: dict[str, dict[str, tuple]] = {
    "AgentCard": {
        "name": ("scalar", None, R), "description": ("scalar", None, R),
        "supportedInterfaces": ("rep", "AgentInterface", R), "provider": ("msg", "AgentProvider", ""),
        "version": ("scalar", None, R), "documentationUrl": ("scalar", None, OPT),
        "capabilities": ("msg", "AgentCapabilities", R), "securitySchemes": ("map", "SecurityScheme", ""),
        "securityRequirements": ("rep", "SecurityRequirement", ""),
        "defaultInputModes": ("rep", None, R), "defaultOutputModes": ("rep", None, R),
        "skills": ("rep", "AgentSkill", R), "iconUrl": ("scalar", None, OPT),
    },
    "AgentProvider": {"url": ("scalar", None, R), "organization": ("scalar", None, R)},
    "AgentCapabilities": {"streaming": ("scalar", None, OPT), "pushNotifications": ("scalar", None, OPT),
                          "extensions": ("rep", "AgentExtension", ""),
                          "extendedAgentCard": ("scalar", None, OPT)},
    "AgentExtension": {"uri": ("scalar", None, ""), "description": ("scalar", None, ""),
                       "required": ("scalar", None, ""), "params": ("struct", None, "")},
    "AgentInterface": {"url": ("scalar", None, R), "protocolBinding": ("scalar", None, R),
                       "tenant": ("scalar", None, ""), "protocolVersion": ("scalar", None, R)},
    "AgentSkill": {"id": ("scalar", None, R), "name": ("scalar", None, R), "description": ("scalar", None, R),
                   "tags": ("rep", None, R), "examples": ("rep", None, ""), "inputModes": ("rep", None, ""),
                   "outputModes": ("rep", None, ""), "securityRequirements": ("rep", "SecurityRequirement", "")},
    "SecurityRequirement": {"schemes": ("map", "StringList", "")},
    "StringList": {"list": ("rep", None, "")},
    "SecurityScheme": {"apiKeySecurityScheme": ("msg", "APIKeySecurityScheme", ""),
                       "httpAuthSecurityScheme": ("msg", "HTTPAuthSecurityScheme", ""),
                       "oauth2SecurityScheme": ("msg", "OAuth2SecurityScheme", ""),
                       "openIdConnectSecurityScheme": ("msg", "OpenIdConnectSecurityScheme", ""),
                       "mtlsSecurityScheme": ("msg", "MutualTlsSecurityScheme", "")},
    "APIKeySecurityScheme": {"description": ("scalar", None, ""), "location": ("scalar", None, R),
                             "name": ("scalar", None, R)},
    "HTTPAuthSecurityScheme": {"description": ("scalar", None, ""), "scheme": ("scalar", None, R),
                               "bearerFormat": ("scalar", None, "")},
    "OAuth2SecurityScheme": {"description": ("scalar", None, ""), "flows": ("msg", "OAuthFlows", R),
                             "oauth2MetadataUrl": ("scalar", None, "")},
    "OpenIdConnectSecurityScheme": {"description": ("scalar", None, ""),
                                    "openIdConnectUrl": ("scalar", None, R)},
    "MutualTlsSecurityScheme": {"description": ("scalar", None, "")},
    "OAuthFlows": {"authorizationCode": ("msg", "AuthorizationCodeOAuthFlow", ""),
                   "clientCredentials": ("msg", "ClientCredentialsOAuthFlow", ""),
                   "implicit": ("msg", "ImplicitOAuthFlow", ""), "password": ("msg", "PasswordOAuthFlow", ""),
                   "deviceCode": ("msg", "DeviceCodeOAuthFlow", "")},
    "AuthorizationCodeOAuthFlow": {"authorizationUrl": ("scalar", None, R), "tokenUrl": ("scalar", None, R),
                                   "refreshUrl": ("scalar", None, ""), "scopes": ("map", None, R),
                                   "pkceRequired": ("scalar", None, "")},
    "ClientCredentialsOAuthFlow": {"tokenUrl": ("scalar", None, R), "refreshUrl": ("scalar", None, ""),
                                   "scopes": ("map", None, R)},
    "ImplicitOAuthFlow": {"authorizationUrl": ("scalar", None, ""), "refreshUrl": ("scalar", None, ""),
                          "scopes": ("map", None, "")},
    "PasswordOAuthFlow": {"tokenUrl": ("scalar", None, ""), "refreshUrl": ("scalar", None, ""),
                          "scopes": ("map", None, "")},
    "DeviceCodeOAuthFlow": {"deviceAuthorizationUrl": ("scalar", None, R), "tokenUrl": ("scalar", None, R),
                            "refreshUrl": ("scalar", None, ""), "scopes": ("map", None, R)},
}

PROFILES = ("spec", "sdk", "raw")


def _is_default(v: Any) -> bool:
    if v is None:
        return True
    if isinstance(v, bool):
        return v is False
    if isinstance(v, (int, float)):
        return v == 0
    if isinstance(v, (str, list, dict)):
        return len(v) == 0
    return False


def _prune_spec(msg: str, obj: Any, drop_unknown: bool) -> Any:
    if not isinstance(obj, dict):
        return obj
    table = _T[msg]
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if k not in table:
            if not drop_unknown:
                out[k] = v
            continue
        kind, child, flag = table[k]
        if kind == "struct":
            if not _is_default(v) or flag:
                out[k] = v
            continue
        if kind == "msg":
            out[k] = _prune_spec(child, v, drop_unknown)       # presence is meaningful
            continue
        if kind == "rep":
            items = v if isinstance(v, list) else v
            if isinstance(items, list) and child:
                items = [_prune_spec(child, x, drop_unknown) for x in items]
            if (isinstance(items, list) and not items) and flag != R:
                continue
            out[k] = items
            continue
        if kind == "map":
            items = v
            if isinstance(items, dict) and child:
                items = {mk: _prune_spec(child, mv, drop_unknown) for mk, mv in items.items()}
            if (isinstance(items, dict) and not items) and flag != R:
                continue
            out[k] = items
            continue
        # scalar
        if _is_default(v) and flag not in (R, OPT):
            continue
        out[k] = v
    return out


def _prune_sdk(obj: Any) -> Any:
    """Mirror of the official Python SDK signer: drop empty strings/lists/objects."""
    if isinstance(obj, dict):
        d = {k: c for k, v in obj.items() if (c := _prune_sdk(v)) is not None}
        return d or None
    if isinstance(obj, list):
        li = [c for v in obj if (c := _prune_sdk(v)) is not None]
        return li or None
    if isinstance(obj, str) and not obj:
        return None
    return obj


def canonical_payload(card: dict, profile: str = "spec", drop_unknown: bool = False) -> bytes:
    """The bytes a signer signed, under one of the candidate profiles."""
    body = {k: v for k, v in card.items() if k != "signatures"}
    if profile == "spec":
        body = _prune_spec("AgentCard", copy.deepcopy(body), drop_unknown)
    elif profile == "sdk":
        body = _prune_sdk(copy.deepcopy(body)) or {}
    elif profile != "raw":
        raise ValueError(profile)
    return canonicalize(body).encode("utf-8")


# --------------------------------------------------------------------------
# ECDSA P-256 / P-384 verification
# --------------------------------------------------------------------------

class _Curve:
    def __init__(self, p, a, b, gx, gy, n, size):
        self.p, self.a, self.b, self.g, self.n, self.size = p, a, b, (gx, gy), n, size

    def on_curve(self, pt) -> bool:
        if pt is None:
            return True
        x, y = pt
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        (x1, y1), (x2, y2) = p1, p2
        p = self.p
        if x1 == x2:
            if (y1 + y2) % p == 0:
                return None
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    def mul(self, k: int, pt):
        res = None
        while k:
            if k & 1:
                res = self.add(res, pt)
            pt = self.add(pt, pt)
            k >>= 1
        return res


P256 = _Curve(
    0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, -3,
    0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551, 32)
P384 = _Curve(
    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff, -3,
    0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973, 48)

_HASH = {"256": hashlib.sha256, "384": hashlib.sha384, "512": hashlib.sha512}


def ecdsa_verify(curve: _Curve, pub: tuple[int, int], msg: bytes, sig: bytes, hashfn) -> bool:
    if len(sig) != 2 * curve.size or not curve.on_curve(pub) or pub is None:
        return False
    r, s = int.from_bytes(sig[:curve.size], "big"), int.from_bytes(sig[curve.size:], "big")
    n = curve.n
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(hashfn(msg).digest(), "big")
    shift = hashfn().digest_size * 8 - n.bit_length()
    if shift > 0:
        e >>= shift
    w = pow(s, -1, n)
    pt = curve.add(curve.mul(e * w % n, curve.g), curve.mul(r * w % n, pub))
    return pt is not None and pt[0] % n == r


def ecdsa_sign_for_tests(curve: _Curve, d: int, msg: bytes, hashfn, k: int) -> bytes:
    """Deterministic-by-argument signer used only by the test-suite."""
    n = curve.n
    e = int.from_bytes(hashfn(msg).digest(), "big")
    shift = hashfn().digest_size * 8 - n.bit_length()
    if shift > 0:
        e >>= shift
    r = curve.mul(k, curve.g)[0] % n
    s = pow(k, -1, n) * (e + r * d) % n
    return r.to_bytes(curve.size, "big") + s.to_bytes(curve.size, "big")


# --------------------------------------------------------------------------
# RSASSA-PKCS1-v1_5
# --------------------------------------------------------------------------

_DIGEST_INFO = {
    "256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def rsa_verify(n: int, e: int, msg: bytes, sig: bytes, bits: str) -> bool:
    k = (n.bit_length() + 7) // 8
    if n.bit_length() < 2048 or e < 3 or e % 2 == 0 or len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _DIGEST_INFO[bits] + _HASH[bits](msg).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    # constant-time-ish equality is unnecessary: everything here is public
    return em == expected


# --------------------------------------------------------------------------
# JWK handling + signature check
# --------------------------------------------------------------------------

def _int(b64: str) -> int:
    return int.from_bytes(b64u_decode(b64), "big")


def load_jwks(doc: Any) -> list[dict]:
    """Accept a JWKS (``{"keys": [...]}``) or a single JWK object."""
    if isinstance(doc, dict) and isinstance(doc.get("keys"), list):
        keys = doc["keys"]
    elif isinstance(doc, dict) and "kty" in doc:
        keys = [doc]
    else:
        raise JwsError("not a JWK or JWK Set")
    return [k for k in keys if isinstance(k, dict)]


_CURVES = {"P-256": (P256, "ES256", "256"), "P-384": (P384, "ES384", "384")}


class Outcome:
    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"
    NO_KEY = "no-key"
    REFUSED = "refused"
    MALFORMED = "malformed"


def verify_signature(card: dict, sig: dict, keys: list[dict], *, profiles=PROFILES) -> tuple[str, str]:
    """Check one ``AgentCardSignature``. Returns ``(Outcome, detail)``.

    ``detail`` names the matching canonicalization profile on success.
    """
    try:
        prot_b64, sig_b64 = sig["protected"], sig["signature"]
        header = json.loads(b64u_decode(prot_b64))
        signature = b64u_decode(sig_b64)
    except (KeyError, TypeError, ValueError, JwsError):
        return Outcome.MALFORMED, "protected/signature are not base64url JSON"
    if not isinstance(header, dict):
        return Outcome.MALFORMED, "protected header is not an object"
    alg = header.get("alg")
    if not isinstance(alg, str):
        return Outcome.MALFORMED, "protected header has no alg"
    if alg.lower() == "none" or alg.startswith("HS"):
        return Outcome.REFUSED, f"alg {alg!r} is refused (unsigned or shared-secret signatures prove nothing on a public card)"
    if "crit" in header:
        return Outcome.UNSUPPORTED, "protected header uses 'crit' extensions"
    kid = header.get("kid")
    candidates = list(keys) if kid is None else [k for k in keys if k.get("kid") == kid]
    if not candidates:
        return Outcome.NO_KEY, f"no trusted key with kid {kid!r}"
    sig_input_prefix = prot_b64 + "."
    last = (Outcome.INVALID, "signature does not match")
    for jwk in candidates:
        kty = jwk.get("kty")
        try:
            if kty == "EC":
                spec = _CURVES.get(jwk.get("crv"))
                if spec is None:
                    last = (Outcome.UNSUPPORTED, f"curve {jwk.get('crv')!r}")
                    continue
                curve, want_alg, bits = spec
                if alg != want_alg:
                    last = (Outcome.REFUSED, f"key is {jwk.get('crv')} but header says {alg}")
                    continue
                pub = (_int(jwk["x"]), _int(jwk["y"]))
                check = lambda payload: ecdsa_verify(curve, pub, payload, signature, _HASH[bits])  # noqa: E731
            elif kty == "RSA":
                if alg not in ("RS256", "RS384", "RS512"):
                    last = ((Outcome.UNSUPPORTED if alg.startswith(("PS",)) else Outcome.REFUSED),
                            f"RSA key cannot verify alg {alg}")
                    continue
                n, e, bits = _int(jwk["n"]), _int(jwk["e"]), alg[2:]
                check = lambda payload: rsa_verify(n, e, payload, signature, bits)  # noqa: E731
            else:
                last = (Outcome.UNSUPPORTED, f"key type {kty!r} (EdDSA/OKP not supported)")
                continue
        except (KeyError, TypeError, ValueError, JwsError):
            last = (Outcome.MALFORMED, "malformed JWK")
            continue
        for profile in profiles:
            for drop_unknown in ((False, True) if profile == "spec" else (False,)):
                try:
                    payload = canonical_payload(card, profile, drop_unknown)
                except JwsError as e:
                    return Outcome.INVALID, f"card cannot be canonicalized: {e}"
                if check((sig_input_prefix + b64u_encode(payload)).encode("ascii")):
                    name = profile + ("+drop-unknown" if drop_unknown else "")
                    return Outcome.VALID, name
    return last


def key_fingerprint(jwk: dict) -> str:
    """RFC 7638 thumbprint (SHA-256) of an EC or RSA public JWK."""
    if jwk.get("kty") == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif jwk.get("kty") == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise JwsError("unsupported key type")
    return b64u_encode(hashlib.sha256(json.dumps(members, sort_keys=True, separators=(",", ":")).encode()).digest())
