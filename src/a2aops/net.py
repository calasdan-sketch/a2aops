"""Hardened network and output helpers shared by every a2aops command.

Three defences, all standard library:

* **Size caps.** Every HTTP body a2aops parses is read through
  :func:`read_capped`, so a hostile or broken server cannot exhaust memory by
  streaming an endless "AgentCard".
* **SSRF guard for card-supplied URLs.** URLs *you* type are trusted. URLs that
  come *from a fetched card* (e.g. an OIDC ``openIdConnectUrl``) are not: a
  malicious card could point a CI runner at ``169.254.169.254`` or an internal
  admin port. :func:`check_public_url` refuses non-HTTPS URLs and hosts that
  resolve to loopback, private, link-local, reserved or multicast addresses,
  and :func:`open_untrusted` re-checks every redirect hop.
* **Terminal-safe output.** Card fields are attacker-controlled text. Printing
  them raw lets a card inject ANSI escape sequences (rewrite your terminal,
  fake a green "OK"). :func:`clean` escapes control characters.

Known limit: the SSRF check resolves the hostname and then lets urllib resolve
it again to connect, so a DNS-rebinding attacker with a very short TTL can win
that race. Use ``--offline`` when auditing cards you do not trust at all.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional

from . import __version__

USER_AGENT = f"a2aops/{__version__}"

#: Default cap for any JSON document a2aops downloads (AgentCards, OIDC
#: discovery docs, task objects). Real cards are a few KB; 2 MiB is generous.
MAX_DOC_BYTES = 2 * 1024 * 1024


class ResponseTooLarge(ValueError):
    """Raised when a response body exceeds the configured cap."""


class UnsafeURL(ValueError):
    """Raised when a card-supplied URL fails the SSRF guard."""


def read_capped(resp, limit: int = MAX_DOC_BYTES) -> bytes:
    """Read at most ``limit`` bytes from ``resp``; raise if there is more."""
    headers = getattr(resp, "headers", None)
    declared_raw = headers.get("Content-Length") if headers else None
    declared: Optional[int] = None
    if declared_raw is not None:
        try:
            declared = int(declared_raw)
        except ValueError:
            declared = None  # malformed header: rely on the counted read
    if declared is not None and declared > limit:
        raise ResponseTooLarge(f"response declares {declared} bytes, over the {limit}-byte cap")
    body = resp.read(limit + 1)
    if len(body) > limit:
        raise ResponseTooLarge(f"response exceeds the {limit}-byte cap")
    return body


# ---------------------------------------------------------------- SSRF guard

Resolver = Callable[[str], list[str]]


def _default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


# Special-purpose ranges, listed explicitly so the verdict does not depend on
# the running Python's ``ipaddress`` tables (they changed across 3.10-3.13).
_BLOCKED_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4")]
_BLOCKED_V6 = [ipaddress.ip_network(n) for n in (
    "::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001::/23",
    "2001:db8::/32", "3fff::/20", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8")]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _embedded_v4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """IPv4 address an IPv6 address tunnels to (mapped, NAT64, 6to4, Teredo)."""
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]  # the client endpoint the tunnel delivers to
    return None


def _is_public_ip(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])  # drop IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_v4(ip)
        if inner is not None:
            ip = inner
    if ip.is_multicast or not ip.is_global:
        return False
    blocked = _BLOCKED_V4 if isinstance(ip, ipaddress.IPv4Address) else _BLOCKED_V6
    return not any(ip in net for net in blocked)


def check_public_url(url: str, resolver: Optional[Resolver] = None) -> None:
    """Raise :class:`UnsafeURL` unless ``url`` is HTTPS to a public address."""
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError as e:
        raise UnsafeURL(f"malformed URL {url!r}: {e}") from e
    if parts.scheme != "https":
        raise UnsafeURL(f"refusing non-HTTPS URL {url!r}")
    if not host:
        raise UnsafeURL(f"URL {url!r} has no host")
    if parts.username or parts.password:
        raise UnsafeURL("refusing URL with embedded credentials")
    try:
        addrs = (resolver or _default_resolver)(host)
    except (OSError, UnicodeError) as e:
        raise UnsafeURL(f"cannot resolve {host}: {e}") from e
    if not addrs:
        raise UnsafeURL(f"{host} did not resolve to any address")
    for addr in addrs:
        try:
            public = _is_public_ip(addr)
        except ValueError as e:
            raise UnsafeURL(f"{host} resolved to unparseable address {addr!r}") from e
        if not public:
            raise UnsafeURL(
                f"{host} resolves to non-public address {addr}; "
                "refusing to fetch a card-supplied URL into a private network "
                "(use --allow-private to override)")


class _GuardedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, resolver: Optional[Resolver]):
        super().__init__()
        self._resolver = resolver

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_public_url(newurl, self._resolver)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_untrusted(url: str, timeout: float, *, allow_private: bool = False,
                   resolver: Optional[Resolver] = None,
                   headers: Optional[dict] = None):
    """Open a URL that came from untrusted card content.

    Every hop (including redirects) must pass :func:`check_public_url` unless
    ``allow_private`` is set. Raises :class:`UnsafeURL` on refusal.
    """
    hdrs = {"Accept": "application/json", "User-Agent": USER_AGENT, **(headers or {})}
    req = urllib.request.Request(url, headers=hdrs)
    if allow_private:
        return urllib.request.urlopen(req, timeout=timeout)
    check_public_url(url, resolver)
    opener = urllib.request.build_opener(_GuardedRedirects(resolver))
    return opener.open(req, timeout=timeout)


# ------------------------------------------------------------ safe output

# C0 controls except TAB and LF, DEL, C1 controls, bidi marks/overrides/
# isolates ("Trojan Source" spoofing), zero-width and invisible format
# characters, line/paragraph separators, and the BOM. Written as escapes so
# the source file itself contains no invisible characters.
_UNSAFE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f"
    "\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb]")


def clean(text: object) -> str:
    """Return ``text`` with terminal control characters escaped.

    ``"\\x1b[32mOK"`` becomes ``"\\\\x1b[32mOK"`` — visible, inert.
    Newlines are escaped too, so one finding is always one output line.
    """
    s = str(text).replace("\n", "\\n")
    return _UNSAFE.sub(lambda m: "\\u%04x" % ord(m.group()) if ord(m.group()) > 0xFF
                       else "\\x%02x" % ord(m.group()), s)
