"""Black-box A2A v1.0 conformance probes: ``a2aops conformance <url>``.

Given an agent URL, run a battery of protocol checks against the live agent
and report PASS / FAIL / WARN / SKIP for each, with the spec section and the
RFC 2119 level that justifies it. Every check cites ``spec`` (section numbers
of https://a2a-protocol.org/latest/specification/) so a failure is a pointer
to text, not an opinion.

Levels follow the spec's own words: a failed MUST is ``fail`` (exit 1), a
failed SHOULD is ``warn`` (exit 1 only with ``--strict``), MAY checks never
fail. A check that does not apply (capability not declared, binding not
offered, state-changing probes not enabled) is ``skip`` with the reason.

Safety
------
* Default mode is **passive**: card, error paths, capability gating, a
  read-only ``ListTasks``. It never sends a message, so it cannot start a task
  or spend model tokens. ``--active`` adds ``SendMessage`` /
  ``SendStreamingMessage`` / ``GetTask`` / ``CancelTask`` / ``SubscribeToTask``
  probes, which create a real task on the agent (a harmless text message).
* Credentials you pass with ``--header`` are sent only to the interface URLs
  the card declares **on the same host as the URL you gave**, and are never
  printed. The "is auth enforced" probe deliberately sends *no* credentials.
* No fuzzing, no payload that exceeds a few hundred bytes, one request per
  check (streams are capped at 50 events / 10 s).
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from xml.sax.saxutils import escape, quoteattr

from . import wire
from .card import ERROR, WARNING, Diagnostic, check_card, has_errors
from .net import clean

PASS, FAIL, WARN, SKIP = "pass", "fail", "warn", "skip"
MUST, SHOULD, MAY = "MUST", "SHOULD", "MAY"

_ISO_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")


@dataclass
class Check:
    id: str
    title: str
    level: str
    spec: str
    group: str             # card | jsonrpc | rest | sse | security
    fn: Callable
    active: bool = False   # creates a task on the agent


@dataclass
class Result:
    id: str
    title: str
    level: str
    spec: str
    group: str
    status: str
    detail: str = ""
    elapsed_ms: int = 0

    def to_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "level": self.level, "spec": self.spec,
                "group": self.group, "status": self.status, "detail": self.detail,
                "elapsedMs": self.elapsed_ms}


class _Skip(Exception):
    pass


class _Fail(Exception):
    pass


def skip(msg: str):
    raise _Skip(msg)


def fail(msg: str):
    raise _Fail(msg)


def require(cond: Any, msg: str):
    if not cond:
        raise _Fail(msg)


REGISTRY: list[Check] = []


def check(id: str, title: str, level: str, spec: str, group: str, active: bool = False):
    def deco(fn):
        REGISTRY.append(Check(id, title, level, spec, group, fn, active))
        return fn
    return deco


# --------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------

class Ctx:
    def __init__(self, base: str, *, timeout: float = 10.0, active: bool = False,
                 headers: Optional[dict] = None, card_path: Optional[str] = None,
                 bindings: Optional[set] = None):
        self.base = base.rstrip("/")
        if "://" not in self.base:
            self.base = "https://" + self.base
        self.timeout = timeout
        self.active = active
        self.user_headers = dict(headers or {})
        self.card_path = card_path
        self.only = bindings
        self.card_http: Optional[wire.Http] = None
        self.card: Any = None
        self.card_url = ""
        self.jsonrpc: Optional[dict] = None   # selected interface dicts
        self.rest: Optional[dict] = None
        self.sent: Optional[dict] = None       # {"task": ..., "message": ..., "kind": ...}
        self.sent_rest: Optional[dict] = None
        self._host = (urllib.parse.urlparse(self.base).hostname or "").lower()

    # headers are only attached to interface URLs on the host the user asked about
    def _hdrs(self, url: str, authed: bool = True) -> dict:
        if not authed:
            return {}
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        return dict(self.user_headers) if host == self._host else {}

    @property
    def caps(self) -> dict:
        c = self.card.get("capabilities") if isinstance(self.card, dict) else None
        return c if isinstance(c, dict) else {}

    def cap(self, name: str) -> bool:
        return self.caps.get(name) is True

    def tenant(self, iface: dict) -> str:
        t = iface.get("tenant")
        return t if isinstance(t, str) else ""

    # -- JSON-RPC --
    def rpc(self, method: str, params: Optional[dict] = None, *, version: Optional[str] = wire.A2A_VERSION,
            authed: bool = True, raw_body: Optional[bytes] = None, rid: Any = 1) -> wire.RpcResult:
        if not self.jsonrpc:
            skip("no JSONRPC 1.x interface in the card")
        url = self.jsonrpc["url"]
        if params is not None and self.tenant(self.jsonrpc):
            params = {"tenant": self.tenant(self.jsonrpc), **params}
        return wire.jsonrpc_call(url, method, params, version=version, rid=rid, timeout=self.timeout,
                                 headers=self._hdrs(url, authed), raw_body=raw_body)

    # -- REST --
    def rest_url(self) -> str:
        if not self.rest:
            skip("no HTTP+JSON 1.x interface in the card")
        url = self.rest["url"].rstrip("/")
        t = self.tenant(self.rest)
        return f"{url}/{urllib.parse.quote(t, safe='')}" if t else url

    def restc(self, op: str, body: Any = None, *, task_id: str = "", config_id: str = "",
              version: Optional[str] = wire.A2A_VERSION, authed: bool = True,
              raw_body: Optional[bytes] = None) -> wire.RestResult:
        verb, path = wire.rest_path(op, task_id, config_id)
        base = self.rest_url()
        return wire.rest_call(base, verb, path, body, version=version, timeout=self.timeout,
                              headers=self._hdrs(base, authed), raw_body=raw_body)


# --------------------------------------------------------------------------
# helpers shared by checks
# --------------------------------------------------------------------------

def _is_auth_wall(http: wire.Http) -> bool:
    return http.status in (401, 403)


def _expect_rpc_error(rr: wire.RpcResult, name: str):
    if _is_auth_wall(rr.http):
        skip(f"agent requires credentials (HTTP {rr.http.status}); pass --header 'Authorization: ...'")
    require(not rr.http.error, f"transport error: {rr.http.error}")
    code = wire.ERRORS[name][0]
    require(isinstance(rr.envelope, dict),
            f"HTTP {rr.http.status}: body is not a JSON object")
    require(rr.error is not None,
            f"expected {name} ({code}); got " + ("a result" if rr.result is not None else f"HTTP {rr.http.status} without a JSON-RPC error"))
    require(rr.code == code, f"expected {name} (code {code}); got code {rr.code} ({clean(rr.error.get('message'))!r})")


def _expect_rest_error(rs: wire.RestResult, name: str):
    if _is_auth_wall(rs.http):
        skip(f"agent requires credentials (HTTP {rs.http.status}); pass --header 'Authorization: ...'")
    require(not rs.http.error, f"transport error: {rs.http.error}")
    _code, status, reason = wire.ERRORS[name]
    require(rs.http.status == status, f"expected HTTP {status} for {name}; got HTTP {rs.http.status}")
    require(rs.error is not None, "error body is not {\"error\": {...}}")
    require(rs.reason == reason, f"expected ErrorInfo reason {reason}; got {rs.reason or 'none'}")
    dom = wire.error_domain(rs.error, rest=True)
    require(dom == wire.ERRORINFO_DOMAIN, f"ErrorInfo domain should be {wire.ERRORINFO_DOMAIN}; got {dom or 'none'}")


def _validate_task(task: Any, where: str):
    require(isinstance(task, dict), f"{where}: task is not an object")
    require(isinstance(task.get("id"), str) and task["id"], f"{where}: task.id missing or empty")
    st = task.get("status")
    require(isinstance(st, dict), f"{where}: task.status missing")
    state = st.get("state")
    require(state in wire.TASK_STATES, f"{where}: status.state {state!r} is not a TaskState name")
    require(state != "TASK_STATE_UNSPECIFIED", f"{where}: status.state is TASK_STATE_UNSPECIFIED")
    ts = st.get("timestamp")
    if ts is not None:
        require(isinstance(ts, str) and _ISO_Z.match(ts), f"{where}: status.timestamp {ts!r} is not ISO 8601 UTC with 'Z' (spec 5.6.1)")
    msg = st.get("message")
    if msg is not None:
        _validate_message(msg, f"{where}: status.message")
    for i, h in enumerate(task.get("history") or []):
        _validate_message(h, f"{where}: history[{i}]")
    for i, a in enumerate(task.get("artifacts") or []):
        require(isinstance(a, dict) and isinstance(a.get("artifactId"), str) and a["artifactId"],
                f"{where}: artifacts[{i}].artifactId missing")
        require(isinstance(a.get("parts"), list) and a["parts"], f"{where}: artifacts[{i}].parts must be non-empty")


def _validate_message(msg: Any, where: str):
    require(isinstance(msg, dict), f"{where} is not an object")
    require(isinstance(msg.get("messageId"), str) and msg["messageId"], f"{where}.messageId missing")
    require(msg.get("role") in ("ROLE_USER", "ROLE_AGENT"), f"{where}.role {msg.get('role')!r} is not ROLE_USER/ROLE_AGENT")
    parts = msg.get("parts")
    require(isinstance(parts, list) and parts, f"{where}.parts must be a non-empty array")
    for i, p in enumerate(parts):
        require(isinstance(p, dict) and any(k in p for k in ("text", "raw", "url", "data")),
                f"{where}.parts[{i}] needs one of text/raw/url/data (v1.0 parts have no 'kind')")


def _validate_send_payload(payload: Any, where: str) -> tuple[str, dict]:
    require(isinstance(payload, dict), f"{where}: response is not an object")
    present = [k for k in ("task", "message") if k in payload]
    require(len(present) == 1,
            f"{where}: SendMessageResponse must hold exactly one of task|message; keys={sorted(payload)[:6]}")
    kind = present[0]
    if kind == "task":
        _validate_task(payload["task"], where)
    else:
        _validate_message(payload["message"], where)
    return kind, payload[kind]


# ============================================================ CARD ==========

@check("CARD-01", "AgentCard is served at /.well-known/agent-card.json with HTTP 200", MUST, "8.2", "card")
def c_card_served(ctx: Ctx):
    h = ctx.card_http
    require(h is not None, "card was not fetched")
    require(not h.error, f"transport error: {h.error}")
    require(h.status == 200, f"HTTP {h.status} from {ctx.card_url}")
    require(isinstance(ctx.card, dict), "body is not a JSON object")
    return f"{ctx.card_url} ({h.elapsed_ms} ms)"


@check("CARD-02", "Card validates against the v1.0 structure (no schema errors)", MUST, "4.4.1, 5.7", "card")
def c_card_valid(ctx: Ctx):
    require(isinstance(ctx.card, dict), "no card")
    diags = check_card(ctx.card, local_origin=_is_local(ctx.card_url))
    errs = [d for d in diags if d.severity == ERROR and not d.code.startswith("S")]
    require(not errs, "; ".join(f"{d.code} {d.path}" for d in errs[:6]) + (f" (+{len(errs) - 6} more)" if len(errs) > 6 else ""))
    sec = [d for d in diags if d.severity == ERROR and d.code.startswith("S")]
    require(not sec, "; ".join(f"{d.code} {d.path}" for d in sec[:4]))


@check("CARD-03", "Card is served as JSON (Content-Type application/json)", SHOULD, "8.2", "card")
def c_card_ctype(ctx: Ctx):
    ct = ctx.card_http.header("content-type").lower()
    require("json" in ct, f"Content-Type is {ct or 'missing'}")


@check("CARD-04", "Card response carries Cache-Control with max-age", SHOULD, "8.6.1", "card")
def c_card_cache(ctx: Ctx):
    cc = ctx.card_http.header("cache-control")
    require(cc and "max-age" in cc.lower(), f"Cache-Control is {cc or 'missing'}")


@check("CARD-05", "Card response carries an ETag", SHOULD, "8.6.1", "card")
def c_card_etag(ctx: Ctx):
    require(ctx.card_http.header("etag"), "no ETag header")


@check("CARD-06", "Conditional GET (If-None-Match) returns 304 for an unchanged card", MAY, "8.6.2", "card")
def c_card_304(ctx: Ctx):
    etag = ctx.card_http.header("etag")
    if not etag:
        skip("no ETag to revalidate with")
    h = wire.http_request("GET", ctx.card_url, None,
                          {"If-None-Match": etag, "Accept": "application/json", "User-Agent": wire.USER_AGENT},
                          ctx.timeout)
    require(h.status == 304, f"HTTP {h.status} (a full body is re-sent on every revalidation)")


@check("CARD-07", "Every interface declares protocolVersion; at least one is 1.x", MUST, "8.3.1, 3.6", "card")
def c_card_versions(ctx: Ctx):
    ifaces = ctx.card.get("supportedInterfaces") if isinstance(ctx.card, dict) else None
    require(isinstance(ifaces, list) and ifaces, "no supportedInterfaces")
    vers = [i.get("protocolVersion") for i in ifaces if isinstance(i, dict)]
    require(all(isinstance(v, str) and v for v in vers), "an interface lacks protocolVersion")
    require(any(v.startswith("1.") or v == "1" for v in vers), f"no 1.x interface (declared: {vers})")


@check("CARD-08", "Card does not point clients at loopback/private/metadata addresses", SHOULD, "8.3 / SSRF", "card")
def c_card_ssrf(ctx: Ctx):
    from . import cardsec
    if _is_local(ctx.card_url):
        skip("card is served from a local address; private endpoints are expected")
    bad = [d for d in cardsec.lint_security(ctx.card) if d.code == "S804"]
    require(not bad, "; ".join(f"{d.path}: {clean(d.message)[:80]}" for d in bad[:3]))


@check("CARD-09", "Card prose has no hidden characters or model-directed instructions (heuristic)", SHOULD, "security", "card")
def c_card_injection(ctx: Ctx):
    from . import cardsec
    bad = [d for d in cardsec.lint_security(ctx.card) if d.code in ("S801", "S802", "S803")]
    require(not bad, "; ".join(f"{d.code} {d.path}" for d in bad[:5]))


def _is_local(url: str) -> bool:
    from .cardsec import classify_host
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    return classify_host(host) != "public-or-name"


# ======================================================== JSON-RPC ==========

@check("RPC-01", "Malformed JSON body yields JSON-RPC error -32700", MUST, "9.5", "jsonrpc")
def r_parse(ctx: Ctx):
    rr = ctx.rpc("", raw_body=b"{not json", version=wire.A2A_VERSION)
    if _is_auth_wall(rr.http):
        skip("agent requires credentials")
    require(rr.code == -32700, f"expected code -32700; got {rr.code} (HTTP {rr.http.status})")


@check("RPC-02", "A body that is not a JSON-RPC request object yields -32600", MUST, "9.5", "jsonrpc")
def r_invalid_request(ctx: Ctx):
    rr = ctx.rpc("", raw_body=b"[1,2,3]")
    if _is_auth_wall(rr.http):
        skip("agent requires credentials")
    require(rr.code == -32600, f"expected code -32600; got {rr.code} (HTTP {rr.http.status})")


@check("RPC-03", "Unknown method yields -32601 and echoes the request id", MUST, "9.5", "jsonrpc")
def r_unknown_method(ctx: Ctx):
    rr = ctx.rpc("a2aops/does-not-exist", {}, rid="probe-3")
    if _is_auth_wall(rr.http):
        skip("agent requires credentials")
    require(rr.code == -32601, f"expected code -32601; got {rr.code} (HTTP {rr.http.status})")
    require(isinstance(rr.envelope, dict) and rr.envelope.get("id") == "probe-3",
            f"response id {rr.envelope.get('id') if isinstance(rr.envelope, dict) else None!r} does not echo 'probe-3'")
    require(rr.envelope.get("jsonrpc") == "2.0", "response lacks \"jsonrpc\": \"2.0\"")


@check("RPC-04", "Pre-1.0 method names (message/send, tasks/get) are not silently accepted as 1.0", SHOULD, "5.3, 9.1", "jsonrpc")
def r_legacy_names(ctx: Ctx):
    rr = ctx.rpc("tasks/get", {"id": "a2aops-probe"})
    if _is_auth_wall(rr.http):
        skip("agent requires credentials")
    require(rr.code in (-32601, -32009, -32602), f"expected -32601 (PascalCase names only); got {rr.code if rr.error else 'a result'}")


@check("RPC-05", "SendMessage without a message yields -32602 Invalid params", MUST, "5.7, 9.5", "jsonrpc")
def r_invalid_params(ctx: Ctx):
    rr = ctx.rpc(wire.M_SEND, {})
    if _is_auth_wall(rr.http):
        skip("agent requires credentials")
    require(rr.error is not None, "request without message was accepted")
    require(rr.code == -32602, f"expected -32602; got {rr.code}")


@check("RPC-06", "Unsupported A2A-Version yields VersionNotSupportedError (-32009)", MUST, "3.6.2", "jsonrpc")
def r_version(ctx: Ctx):
    rr = ctx.rpc(wire.M_GET, {"id": "a2aops-probe"}, version="99.0")
    _expect_rpc_error(rr, "VersionNotSupportedError")


@check("RPC-07", "GetTask for an unknown id yields TaskNotFoundError (-32001)", MUST, "5.4", "jsonrpc")
def r_task_not_found(ctx: Ctx):
    _expect_rpc_error(ctx.rpc(wire.M_GET, {"id": "a2aops-no-such-task"}), "TaskNotFoundError")


@check("RPC-08", "A2A errors carry google.rpc.ErrorInfo (reason TASK_NOT_FOUND, domain a2a-protocol.org)", SHOULD, "9.5", "jsonrpc")
def r_errorinfo(ctx: Ctx):
    rr = ctx.rpc(wire.M_GET, {"id": "a2aops-no-such-task"})
    _expect_rpc_error(rr, "TaskNotFoundError")
    require(rr.reason == "TASK_NOT_FOUND", f"error.data lacks ErrorInfo reason TASK_NOT_FOUND (got {rr.reason or 'none'})")
    require(wire.error_domain(rr.error, rest=False) == wire.ERRORINFO_DOMAIN, "ErrorInfo domain is not a2a-protocol.org")


@check("RPC-09", "CancelTask for an unknown id yields TaskNotFoundError (-32001)", MUST, "5.4", "jsonrpc")
def r_cancel_unknown(ctx: Ctx):
    _expect_rpc_error(ctx.rpc(wire.M_CANCEL, {"id": "a2aops-no-such-task"}), "TaskNotFoundError")


@check("RPC-10", "Push-notification config calls fail with -32003 when pushNotifications is not declared", MUST, "3.3.4", "jsonrpc")
def r_push_gate(ctx: Ctx):
    if ctx.cap("pushNotifications"):
        skip("card declares pushNotifications")
    rr = ctx.rpc(wire.M_PUSH_CREATE, {"taskId": "a2aops-probe", "url": "https://example.invalid/hook"})
    _expect_rpc_error(rr, "PushNotificationNotSupportedError")


@check("RPC-11", "GetExtendedAgentCard fails with -32004 when extendedAgentCard is not declared", MUST, "3.3.4", "jsonrpc")
def r_ext_gate(ctx: Ctx):
    if ctx.cap("extendedAgentCard"):
        skip("card declares extendedAgentCard")
    _expect_rpc_error(ctx.rpc(wire.M_EXT_CARD, {}), "UnsupportedOperationError")


@check("RPC-12", "ListTasks returns tasks[], pageSize, totalSize and nextPageToken", MUST, "proto ListTasksResponse", "jsonrpc")
def r_list(ctx: Ctx):
    rr = ctx.rpc(wire.M_LIST, {})
    if _is_auth_wall(rr.http):
        skip("agent requires credentials")
    if rr.code in (-32004,):
        skip("ListTasks not supported by this agent (UnsupportedOperationError)")
    require(rr.error is None, f"error {rr.code}: {clean((rr.error or {}).get('message'))}")
    res = rr.result
    require(isinstance(res, dict), "no result object")
    require(isinstance(res.get("tasks", []), list), "tasks is not an array")
    for k in ("pageSize", "totalSize"):
        require(isinstance(res.get(k, 0), int), f"{k} is not an integer")


@check("RPC-13", "Credentials declared in the card are enforced (anonymous request is rejected)", MUST, "3.3.2", "jsonrpc")
def r_auth_enforced(ctx: Ctx):
    declared = ctx.card.get("securityRequirements") if isinstance(ctx.card, dict) else None
    if not declared:
        skip("card declares no securityRequirements")
    rr = ctx.rpc(wire.M_GET, {"id": "a2aops-no-such-task"}, authed=False)
    require(not rr.http.error, f"transport error: {rr.http.error}")
    require(_is_auth_wall(rr.http) or (rr.code is not None and rr.code not in (-32001,) and rr.http.status >= 400),
            f"card declares auth but an anonymous GetTask got " +
            (f"JSON-RPC {rr.code} {rr.reason or ''}" if rr.error else "a result") + f" (HTTP {rr.http.status}); "
            "declared auth is not enforced")


@check("RPC-14", "A 401 response includes a WWW-Authenticate challenge", SHOULD, "3.3.2", "jsonrpc")
def r_challenge(ctx: Ctx):
    if not (isinstance(ctx.card, dict) and ctx.card.get("securityRequirements")):
        skip("card declares no securityRequirements")
    rr = ctx.rpc(wire.M_GET, {"id": "a2aops-no-such-task"}, authed=False)
    if rr.http.status != 401:
        skip(f"anonymous request got HTTP {rr.http.status}, not 401")
    require(rr.http.header("www-authenticate"), "HTTP 401 without WWW-Authenticate")


@check("RPC-15", "Error bodies do not leak stack traces or server paths", SHOULD, "3.3.2 / security", "jsonrpc")
def r_leak(ctx: Ctx):
    rr = ctx.rpc("", raw_body=b"{not json")
    text = rr.http.text()[:4000]
    pats = [r"Traceback \(most recent call last\)", r'File "[^"]+\.py"', r"\bat [\w.$]+\([\w.]+\.java:\d+\)",
            r"node_modules[/\\]", r"/(usr|home|var|opt|app)/[\w./-]+\.(py|js|rb|go|rs)\b", r"[A-Za-z]:\\[\w\\ .-]+\.\w+"]
    hit = next((p for p in pats if re.search(p, text)), None)
    require(hit is None, "error body contains an internal path or stack frame")


# --- active JSON-RPC ----

@check("RPC-20", "SendMessage returns a Task or a Message (exactly one) with valid fields", MUST, "9.4.1, proto SendMessageResponse", "jsonrpc", active=True)
def r_send(ctx: Ctx):
    rr = ctx.rpc(wire.M_SEND, {"message": wire.sample_message(), "configuration": {"returnImmediately": False}})
    if _is_auth_wall(rr.http):
        skip("agent requires credentials")
    require(rr.error is None, f"error {rr.code}: {clean((rr.error or {}).get('message'))}")
    kind, obj = _validate_send_payload(rr.result, "SendMessage")
    ctx.sent = {"kind": kind, "obj": obj}
    return f"returned a {kind}" + (f" in state {obj['status']['state']}" if kind == "task" else "")


@check("RPC-21", "GetTask returns the task SendMessage created", MUST, "9.4.3", "jsonrpc", active=True)
def r_get_roundtrip(ctx: Ctx):
    if not ctx.sent:
        skip("RPC-20 did not run or failed")
    if ctx.sent["kind"] != "task":
        skip("SendMessage returned a Message, not a Task")
    tid = ctx.sent["obj"]["id"]
    rr = ctx.rpc(wire.M_GET, {"id": tid})
    require(rr.error is None, f"error {rr.code}: {clean((rr.error or {}).get('message'))}")
    _validate_task(rr.result, "GetTask")
    require(rr.result["id"] == tid, f"GetTask returned id {rr.result['id']!r}, expected {tid!r}")


@check("RPC-22", "Returned Task carries a contextId", SHOULD, "3.4.1", "jsonrpc", active=True)
def r_context(ctx: Ctx):
    if not ctx.sent or ctx.sent["kind"] != "task":
        skip("no Task from SendMessage")
    require(ctx.sent["obj"].get("contextId"), "task.contextId is empty")


@check("RPC-23", "CancelTask on a task already in a terminal state yields TaskNotCancelableError (-32002)", MUST, "5.4", "jsonrpc", active=True)
def r_cancel_terminal(ctx: Ctx):
    if not ctx.sent or ctx.sent["kind"] != "task":
        skip("no Task from SendMessage")
    tid = ctx.sent["obj"]["id"]
    got = ctx.rpc(wire.M_GET, {"id": tid})
    state = ((got.result or {}).get("status") or {}).get("state") if isinstance(got.result, dict) else None
    if state not in wire.TERMINAL_STATES:
        skip(f"task is {state}, not terminal; cannot test cancel-after-final")
    _expect_rpc_error(ctx.rpc(wire.M_CANCEL, {"id": tid}), "TaskNotCancelableError")


@check("RPC-24", "SubscribeToTask on a terminal task yields UnsupportedOperationError (-32004)", MUST, "9.4.6", "jsonrpc", active=True)
def r_subscribe_terminal(ctx: Ctx):
    if not ctx.cap("streaming"):
        skip("card does not declare streaming")
    if not ctx.sent or ctx.sent["kind"] != "task":
        skip("no Task from SendMessage")
    tid = ctx.sent["obj"]["id"]
    got = ctx.rpc(wire.M_GET, {"id": tid})
    state = ((got.result or {}).get("status") or {}).get("state") if isinstance(got.result, dict) else None
    if state not in wire.TERMINAL_STATES:
        skip(f"task is {state}, not terminal")
    rr = ctx.rpc(wire.M_SUBSCRIBE, {"id": tid})
    if rr.error is None and "text/event-stream" in rr.http.header("content-type"):
        fail("subscribed to a terminal task; the spec requires UnsupportedOperationError")
    _expect_rpc_error(rr, "UnsupportedOperationError")


@check("RPC-25", "Streaming is rejected with -32004 when streaming is not declared", MUST, "3.3.4", "jsonrpc", active=True)
def r_stream_gate(ctx: Ctx):
    if ctx.cap("streaming"):
        skip("card declares streaming")
    rr = ctx.rpc(wire.M_STREAM, {"message": wire.sample_message()})
    if "text/event-stream" in rr.http.header("content-type"):
        fail("agent streamed although the card does not declare streaming")
    _expect_rpc_error(rr, "UnsupportedOperationError")


@check("SSE-01", "SendStreamingMessage answers 200 text/event-stream with JSON-RPC envelopes", MUST, "9.4.2", "sse", active=True)
def s_rpc_stream(ctx: Ctx):
    if not ctx.cap("streaming"):
        skip("card does not declare streaming")
    if not ctx.jsonrpc:
        skip("no JSONRPC interface")
    url = ctx.jsonrpc["url"]
    body = {"jsonrpc": "2.0", "id": 7, "method": wire.M_STREAM, "params": {"message": wire.sample_message()}}
    if ctx.tenant(ctx.jsonrpc):
        body["params"]["tenant"] = ctx.tenant(ctx.jsonrpc)
    cap = wire.sse_collect("POST", url, json.dumps(body).encode(),
                           wire.default_headers(wire.A2A_VERSION, extra=ctx._hdrs(url)), deadline=ctx.timeout)
    _check_stream(cap, rpc=True)
    ctx.sent_stream = cap  # type: ignore[attr-defined]
    return f"{cap.raw_events} events"


def _check_stream(cap: wire.SseCapture, *, rpc: bool):
    if cap.status in (401, 403):
        skip("agent requires credentials")
    require(not cap.error or cap.events, f"transport error: {cap.error}")
    require(cap.status == 200, f"HTTP {cap.status}: {clean(cap.body_prefix[:120])}")
    require("text/event-stream" in cap.headers.get("content-type", "").lower(),
            f"Content-Type is {cap.headers.get('content-type', 'missing')}, not text/event-stream: {clean(cap.body_prefix[:80])}")
    require(cap.events, "stream carried no events")
    require(cap.bad_json == 0, f"{cap.bad_json} event(s) were not valid JSON")
    payloads = []
    for i, ev in enumerate(cap.events):
        if rpc:
            require(isinstance(ev, dict) and ev.get("jsonrpc") == "2.0" and "result" in ev,
                    f"event {i} is not a JSON-RPC envelope with a result")
            payloads.append(ev["result"])
        else:
            payloads.append(ev)
    kinds = [wire.unwrap(p)[0] for p in payloads]
    require(all(k in ("task", "message", "statusUpdate", "artifactUpdate") for k in kinds),
            f"event kinds {sorted(set(kinds))} include something that is not a StreamResponse payload")
    cap.kinds = kinds  # type: ignore[attr-defined]
    cap.payloads = payloads  # type: ignore[attr-defined]


@check("SSE-02", "Stream begins with a Task (or a single Message)", SHOULD, "11.7", "sse", active=True)
def s_first(ctx: Ctx):
    cap = getattr(ctx, "sent_stream", None)
    if cap is None or not hasattr(cap, "kinds"):
        skip("SSE-01 did not produce a parsed stream")
    require(cap.kinds[0] in ("task", "message"), f"first event is {cap.kinds[0]}")


@check("SSE-03", "Stream closes after the task reaches a terminal or interrupted state", MUST, "3.5, 11.7", "sse", active=True)
def s_closes(ctx: Ctx):
    cap = getattr(ctx, "sent_stream", None)
    if cap is None or not hasattr(cap, "kinds"):
        skip("SSE-01 did not produce a parsed stream")
    states = [wire.state_of(p) for p in cap.payloads if wire.state_of(p)]
    if cap.kinds == ["message"]:
        return "single Message response"
    require(states, "stream carried no task state")
    final = states[-1]
    require(final in wire.TERMINAL_STATES + wire.INTERRUPTED_STATES,
            f"stream ended in non-final state {final} (closed_cleanly={cap.closed_cleanly})")
    require(cap.closed_cleanly, "server kept the connection open after the final state")
    first_final = next((i for i, s in enumerate(states) if s in wire.TERMINAL_STATES), None)
    if first_final is not None:
        require(first_final == len(states) - 1, "events were sent after a terminal state")


@check("SSE-04", "Every state in the stream is a valid TaskState and timestamps are ISO 8601 UTC", MUST, "5.6.1", "sse", active=True)
def s_states(ctx: Ctx):
    cap = getattr(ctx, "sent_stream", None)
    if cap is None or not hasattr(cap, "payloads"):
        skip("no parsed stream")
    for p in cap.payloads:
        s = wire.state_of(p)
        if s is not None:
            require(s in wire.TASK_STATES and s != "TASK_STATE_UNSPECIFIED", f"invalid state {s!r}")
        kind, obj = wire.unwrap(p)
        if kind in ("task", "statusUpdate"):
            ts = (obj.get("status") or {}).get("timestamp")
            require(ts is None or _ISO_Z.match(str(ts)), f"timestamp {ts!r} is not ISO 8601 UTC with 'Z'")
        if kind == "statusUpdate":
            require(obj.get("taskId") and obj.get("contextId"), "statusUpdate lacks taskId/contextId (REQUIRED)")


# ============================================================ REST ==========

@check("REST-01", "Invalid JSON to POST /message:send yields HTTP 400", MUST, "11.6", "rest")
def h_bad_json(ctx: Ctx):
    rs = ctx.restc(wire.M_SEND, raw_body=b"{not json")
    if _is_auth_wall(rs.http):
        skip("agent requires credentials")
    require(rs.http.status == 400, f"expected HTTP 400; got {rs.http.status}")


@check("REST-02", "POST /message:send without a message yields HTTP 400", MUST, "5.7, 11.6", "rest")
def h_no_message(ctx: Ctx):
    rs = ctx.restc(wire.M_SEND, {})
    if _is_auth_wall(rs.http):
        skip("agent requires credentials")
    require(rs.http.status == 400, f"expected HTTP 400; got HTTP {rs.http.status}")


@check("REST-03", "Unsupported A2A-Version yields 400 with ErrorInfo VERSION_NOT_SUPPORTED", MUST, "3.6.2, 11.6", "rest")
def h_version(ctx: Ctx):
    _expect_rest_error(ctx.restc(wire.M_GET, task_id="a2aops-probe", version="99.0"), "VersionNotSupportedError")


@check("REST-04", "GET /tasks/{unknown} yields 404 with ErrorInfo TASK_NOT_FOUND", MUST, "5.4, 11.6", "rest")
def h_not_found(ctx: Ctx):
    _expect_rest_error(ctx.restc(wire.M_GET, task_id="a2aops-no-such-task"), "TaskNotFoundError")


@check("REST-05", "POST /tasks/{unknown}:cancel yields 404 with ErrorInfo TASK_NOT_FOUND", MUST, "5.4, 11.6", "rest")
def h_cancel_unknown(ctx: Ctx):
    _expect_rest_error(ctx.restc(wire.M_CANCEL, {}, task_id="a2aops-no-such-task"), "TaskNotFoundError")


@check("REST-06", "Push-notification config calls yield 400 PUSH_NOTIFICATION_NOT_SUPPORTED when not declared", MUST, "3.3.4", "rest")
def h_push_gate(ctx: Ctx):
    if ctx.cap("pushNotifications"):
        skip("card declares pushNotifications")
    rs = ctx.restc(wire.M_PUSH_CREATE, {"url": "https://example.invalid/hook"}, task_id="a2aops-probe")
    _expect_rest_error(rs, "PushNotificationNotSupportedError")


@check("REST-07", "GET /extendedAgentCard yields 400 UNSUPPORTED_OPERATION when not declared", MUST, "3.3.4", "rest")
def h_ext_gate(ctx: Ctx):
    if ctx.cap("extendedAgentCard"):
        skip("card declares extendedAgentCard")
    _expect_rest_error(ctx.restc(wire.M_EXT_CARD), "UnsupportedOperationError")


@check("REST-08", "GET /tasks returns tasks[] (list shape)", MUST, "proto ListTasksResponse", "rest")
def h_list(ctx: Ctx):
    rs = ctx.restc(wire.M_LIST)
    if _is_auth_wall(rs.http):
        skip("agent requires credentials")
    if rs.http.status == 400 and rs.reason == "UNSUPPORTED_OPERATION":
        skip("ListTasks not supported")
    require(rs.http.status == 200, f"HTTP {rs.http.status}")
    require(isinstance(rs.body, dict) and isinstance(rs.body.get("tasks", []), list), "body lacks tasks[]")


@check("REST-09", "Responses use Content-Type application/a2a+json", SHOULD, "11.1", "rest")
def h_ctype(ctx: Ctx):
    rs = ctx.restc(wire.M_GET, task_id="a2aops-no-such-task")
    if _is_auth_wall(rs.http):
        skip("agent requires credentials")
    ct = rs.http.header("content-type").lower()
    require("application/a2a+json" in ct, f"Content-Type is {ct or 'missing'}")


@check("REST-10", "Credentials declared in the card are enforced (anonymous request is rejected)", MUST, "3.3.2", "rest")
def h_auth_enforced(ctx: Ctx):
    declared = ctx.card.get("securityRequirements") if isinstance(ctx.card, dict) else None
    if not declared:
        skip("card declares no securityRequirements")
    rs = ctx.restc(wire.M_GET, task_id="a2aops-no-such-task", authed=False)
    require(not rs.http.error, f"transport error: {rs.http.error}")
    require(_is_auth_wall(rs.http),
            f"card declares auth but an anonymous GET /tasks/x got HTTP {rs.http.status} "
            f"({rs.reason or 'no ErrorInfo'}); declared auth is not enforced")


@check("REST-20", "POST /message:send returns {task|message} with valid fields", MUST, "11.3.1", "rest", active=True)
def h_send(ctx: Ctx):
    rs = ctx.restc(wire.M_SEND, {"message": wire.sample_message(), "configuration": {"returnImmediately": False}})
    if _is_auth_wall(rs.http):
        skip("agent requires credentials")
    require(rs.http.status == 200, f"HTTP {rs.http.status}: {clean(rs.http.text()[:120])}")
    kind, obj = _validate_send_payload(rs.body, "POST /message:send")
    ctx.sent_rest = {"kind": kind, "obj": obj}
    return f"returned a {kind}"


@check("REST-21", "GET /tasks/{id} returns the task just created", MUST, "11.3.2", "rest", active=True)
def h_get_roundtrip(ctx: Ctx):
    if not ctx.sent_rest or ctx.sent_rest["kind"] != "task":
        skip("no Task from REST-20")
    tid = ctx.sent_rest["obj"]["id"]
    rs = ctx.restc(wire.M_GET, task_id=tid)
    require(rs.http.status == 200, f"HTTP {rs.http.status}")
    _validate_task(rs.body, "GET /tasks/{id}")
    require(rs.body["id"] == tid, "id mismatch")


@check("REST-22", "POST /tasks/{id}:cancel on a terminal task yields 400 TASK_NOT_CANCELABLE", MUST, "5.4", "rest", active=True)
def h_cancel_terminal(ctx: Ctx):
    if not ctx.sent_rest or ctx.sent_rest["kind"] != "task":
        skip("no Task from REST-20")
    tid = ctx.sent_rest["obj"]["id"]
    got = ctx.restc(wire.M_GET, task_id=tid)
    state = ((got.body or {}).get("status") or {}).get("state") if isinstance(got.body, dict) else None
    if state not in wire.TERMINAL_STATES:
        skip(f"task is {state}, not terminal")
    _expect_rest_error(ctx.restc(wire.M_CANCEL, {}, task_id=tid), "TaskNotCancelableError")


@check("REST-23", "SubscribeToTask on a terminal task yields 400 UNSUPPORTED_OPERATION", MUST, "9.4.6, 11.3.2", "rest", active=True)
def h_subscribe_terminal(ctx: Ctx):
    if not ctx.cap("streaming"):
        skip("card does not declare streaming")
    if not ctx.sent_rest or ctx.sent_rest["kind"] != "task":
        skip("no Task from REST-20")
    tid = ctx.sent_rest["obj"]["id"]
    got = ctx.restc(wire.M_GET, task_id=tid)
    state = ((got.body or {}).get("status") or {}).get("state") if isinstance(got.body, dict) else None
    if state not in wire.TERMINAL_STATES:
        skip(f"task is {state}, not terminal")
    verbs = []
    for verb in ("GET", "POST"):   # proto says GET, the spec text says POST: accept either
        base = ctx.rest_url()
        rs = wire.rest_call(base, verb, f"/tasks/{urllib.parse.quote(tid, safe='')}:subscribe", {} if verb == "POST" else None,
                            timeout=ctx.timeout, headers=ctx._hdrs(base))
        verbs.append((verb, rs))
        if rs.http.status not in (404, 405):
            break
    verb, rs = verbs[-1]
    require("text/event-stream" not in rs.http.header("content-type"),
            "subscribed to a terminal task; the spec requires UnsupportedOperationError")
    _expect_rest_error(rs, "UnsupportedOperationError")
    return f"via {verb}"


@check("SSE-10", "POST /message:stream answers 200 text/event-stream with StreamResponse events", MUST, "11.7", "sse", active=True)
def s_rest_stream(ctx: Ctx):
    if not ctx.cap("streaming"):
        skip("card does not declare streaming")
    base = ctx.rest_url()
    cap = wire.sse_collect("POST", base + "/message:stream", json.dumps({"message": wire.sample_message()}).encode(),
                           wire.default_headers(wire.A2A_VERSION, rest=True, extra=ctx._hdrs(base)),
                           deadline=ctx.timeout)
    _check_stream(cap, rpc=False)
    states = [wire.state_of(p) for p in cap.payloads if wire.state_of(p)]
    if states:
        require(states[-1] in wire.TERMINAL_STATES + wire.INTERRUPTED_STATES, f"stream ended in non-final state {states[-1]}")
        require(cap.closed_cleanly, "server kept the connection open after the final state")
    return f"{cap.raw_events} events"


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def _select_interfaces(ctx: Ctx) -> None:
    ifaces = ctx.card.get("supportedInterfaces") if isinstance(ctx.card, dict) else None
    if not isinstance(ifaces, list):
        return
    for i in ifaces:
        if not isinstance(i, dict) or not isinstance(i.get("url"), str):
            continue
        ver = str(i.get("protocolVersion", ""))
        if not (ver == "1" or ver.startswith("1.")):
            continue
        if i.get("protocolBinding") == "JSONRPC" and ctx.jsonrpc is None:
            ctx.jsonrpc = i
        if i.get("protocolBinding") == "HTTP+JSON" and ctx.rest is None:
            ctx.rest = i
    if ctx.only:
        if "jsonrpc" not in ctx.only:
            ctx.jsonrpc = None
        if "rest" not in ctx.only:
            ctx.rest = None


def load_card_into(ctx: Ctx) -> None:
    paths = [ctx.card_path] if ctx.card_path else ["/.well-known/agent-card.json"]
    for p in paths:
        url = ctx.base + p
        h = wire.http_request("GET", url, None, {"Accept": "application/json", "User-Agent": wire.USER_AGENT}, ctx.timeout)
        ctx.card_http, ctx.card_url = h, url
        if h.status == 200:
            ctx.card = h.json()
            break


def run(base: str, *, active: bool = False, timeout: float = 10.0, headers: Optional[dict] = None,
        card_path: Optional[str] = None, bindings: Optional[set] = None,
        only_ids: Optional[set] = None) -> tuple[Ctx, list[Result]]:
    ctx = Ctx(base, timeout=timeout, active=active, headers=headers, card_path=card_path, bindings=bindings)
    load_card_into(ctx)
    _select_interfaces(ctx)
    results: list[Result] = []
    card_ok = isinstance(ctx.card, dict)
    for c in REGISTRY:
        if only_ids and c.id not in only_ids:
            continue
        t0 = time.monotonic()
        status, detail = PASS, ""
        if c.group in ("jsonrpc", "sse") and c.id.startswith(("RPC", "SSE-0")) and ctx.jsonrpc is None and card_ok:
            status, detail = SKIP, "no JSONRPC 1.x interface in the card"
        elif c.group == "rest" or c.id.startswith("SSE-1"):
            if ctx.rest is None and card_ok:
                status, detail = SKIP, "no HTTP+JSON 1.x interface in the card"
        if status == PASS and not card_ok and c.group != "card":
            status, detail = SKIP, "no usable AgentCard"
        if status == PASS and c.active and not active:
            status, detail = SKIP, "state-changing probe; re-run with --active"
        if status == PASS:
            try:
                out = c.fn(ctx)
                detail = out or ""
            except _Skip as e:
                status, detail = SKIP, str(e)
            except _Fail as e:
                status = FAIL if c.level == MUST else WARN if c.level == SHOULD else SKIP
                detail = str(e)
            except Exception as e:  # noqa: BLE001 - a probe bug must not kill the run
                status, detail = FAIL if c.level == MUST else WARN, f"probe error: {type(e).__name__}: {e}"
        results.append(Result(c.id, c.title, c.level, c.spec, c.group, status, detail,
                              int((time.monotonic() - t0) * 1000)))
    return ctx, results


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def summarize(results: list[Result]) -> dict:
    s = {PASS: 0, FAIL: 0, WARN: 0, SKIP: 0}
    for r in results:
        s[r.status] += 1
    return {"pass": s[PASS], "fail": s[FAIL], "warn": s[WARN], "skip": s[SKIP], "total": len(results)}


def failed(results: list[Result], strict: bool = False) -> bool:
    return any(r.status == FAIL or (strict and r.status == WARN) for r in results)


def to_text(results: list[Result], url: str, active: bool) -> str:
    icon = {PASS: "PASS", FAIL: "FAIL", WARN: "WARN", SKIP: "skip"}
    lines = [f"a2aops conformance {clean(url)}  ({'active' if active else 'passive'} mode, A2A v1.0 spec 1.0.x)"]
    group = None
    for r in results:
        if r.group != group:
            group = r.group
            lines.append(f"\n[{group}]")
        lines.append(clean(f"  {icon[r.status]}  {r.id:8} {r.level:6} §{r.spec:<22} {r.title}"))
        if r.detail and r.status != PASS or (r.detail and r.status == PASS):
            lines.append(clean(f"            -> {r.detail}"))
    s = summarize(results)
    lines.append(f"\n{s['pass']} passed, {s['fail']} failed (MUST), {s['warn']} warnings (SHOULD), {s['skip']} skipped")
    return "\n".join(lines)


def to_json(results: list[Result], url: str, active: bool) -> str:
    from . import __version__
    return json.dumps({"tool": "a2aops", "version": __version__, "command": "conformance", "url": url,
                       "mode": "active" if active else "passive", "specVersion": "1.0",
                       "summary": summarize(results), "results": [r.to_dict() for r in results]}, indent=2)


def to_junit(results: list[Result], url: str) -> str:
    s = summarize(results)
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           f'<testsuites name="a2aops conformance" tests="{s["total"]}" failures="{s["fail"] + s["warn"]}" skipped="{s["skip"]}">']
    for group in dict.fromkeys(r.group for r in results):
        rs = [r for r in results if r.group == group]
        fails = sum(r.status in (FAIL, WARN) for r in rs)
        out.append(f'  <testsuite name={quoteattr(group)} tests="{len(rs)}" failures="{fails}" '
                   f'skipped="{sum(r.status == SKIP for r in rs)}">')
        for r in rs:
            out.append(f'    <testcase classname={quoteattr("a2a." + group)} name={quoteattr(r.id + " " + r.title)} '
                       f'time="{r.elapsed_ms / 1000:.3f}">')
            body = escape(f"{r.level} spec §{r.spec}: {r.detail}")
            if r.status == FAIL:
                out.append(f'      <failure message={quoteattr(r.detail[:300])} type="{r.level}">{body}</failure>')
            elif r.status == WARN:
                out.append(f'      <failure message={quoteattr(r.detail[:300])} type="{r.level}">{body}</failure>')
            elif r.status == SKIP:
                out.append(f'      <skipped message={quoteattr(r.detail[:300])}/>')
            out.append('    </testcase>')
        out.append('  </testsuite>')
    out.append('</testsuites>')
    return "\n".join(out)


def to_diagnostics(results: list[Result]) -> list[Diagnostic]:
    """Failed checks as Diagnostics (so SARIF output reuses the existing writer)."""
    diags = []
    for r in results:
        if r.status in (FAIL, WARN):
            diags.append(Diagnostic(ERROR if r.status == FAIL else WARNING, r.id,
                                    f"{r.title} [{r.level}, spec §{r.spec}] - {r.detail}", r.group))
    return diags
