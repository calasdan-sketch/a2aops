"""A2A v1.0 wire helpers: requests, responses, errors, SSE collection.

Everything here follows ``a2a.proto`` (package ``lf.a2a.v1``) and the spec
page, section numbers in brackets:

* JSON-RPC methods are PascalCase (``SendMessage``, ``GetTask``,
  ``SubscribeToTask`` ...) [5.3, 9.4]. The pre-1.0 names (``message/send``,
  ``tasks/get``, ``tasks/resubscribe``) are kept as ``LEGACY_METHODS`` so the
  tools can still talk to 0.3 agents when asked to.
* REST paths are ``/message:send``, ``/tasks/{id}``, ``/tasks/{id}:cancel``,
  ``/tasks/{id}:subscribe`` ... relative to the interface URL [11.3]. There is
  no ``/v1`` prefix in the spec; if an agent wants one it puts it in the
  interface ``url``.
* Clients MUST send ``A2A-Version`` [3.6.2]; an empty value means 0.3.
* ``SendMessageResponse`` and ``StreamResponse`` are one-of wrappers:
  ``{"task": ...}``, ``{"message": ...}``, ``{"statusUpdate": ...}``,
  ``{"artifactUpdate": ...}``. JSON-RPC puts them in ``result`` [9.4.1].
* Errors: JSON-RPC ``error.{code,message,data[]}``; REST ``error.{code,status,
  message,details[]}`` with a ``google.rpc.ErrorInfo`` entry whose ``reason``
  is the UPPER_SNAKE error name and ``domain`` is ``a2a-protocol.org``
  [9.5, 11.6].

Only the standard library is used.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

from .net import USER_AGENT, ResponseTooLarge, read_capped

A2A_VERSION = "1.0"
ERRORINFO_TYPE = "type.googleapis.com/google.rpc.ErrorInfo"
ERRORINFO_DOMAIN = "a2a-protocol.org"

#: JSON-RPC method names, v1.0 [5.3].
M_SEND = "SendMessage"
M_STREAM = "SendStreamingMessage"
M_GET = "GetTask"
M_LIST = "ListTasks"
M_CANCEL = "CancelTask"
M_SUBSCRIBE = "SubscribeToTask"
M_PUSH_CREATE = "CreateTaskPushNotificationConfig"
M_PUSH_GET = "GetTaskPushNotificationConfig"
M_PUSH_LIST = "ListTaskPushNotificationConfigs"
M_PUSH_DELETE = "DeleteTaskPushNotificationConfig"
M_EXT_CARD = "GetExtendedAgentCard"

#: v1.0 name -> pre-1.0 (0.3) JSON-RPC name.
LEGACY_METHODS = {
    M_SEND: "message/send",
    M_STREAM: "message/stream",
    M_GET: "tasks/get",
    M_CANCEL: "tasks/cancel",
    M_SUBSCRIBE: "tasks/resubscribe",
    M_PUSH_CREATE: "tasks/pushNotificationConfig/set",
    M_PUSH_GET: "tasks/pushNotificationConfig/get",
    M_PUSH_LIST: "tasks/pushNotificationConfig/list",
    M_PUSH_DELETE: "tasks/pushNotificationConfig/delete",
    M_EXT_CARD: "agent/getAuthenticatedExtendedCard",
}

#: every v1.0 JSON-RPC method name (ListTasks has no pre-1.0 equivalent).
V1_METHODS = frozenset(LEGACY_METHODS) | {M_LIST}

#: A2A error name -> (JSON-RPC code, HTTP status, REST reason) [5.4].
ERRORS = {
    "TaskNotFoundError": (-32001, 404, "TASK_NOT_FOUND"),
    "TaskNotCancelableError": (-32002, 400, "TASK_NOT_CANCELABLE"),
    "PushNotificationNotSupportedError": (-32003, 400, "PUSH_NOTIFICATION_NOT_SUPPORTED"),
    "UnsupportedOperationError": (-32004, 400, "UNSUPPORTED_OPERATION"),
    "ContentTypeNotSupportedError": (-32005, 400, "CONTENT_TYPE_NOT_SUPPORTED"),
    "InvalidAgentResponseError": (-32006, 500, "INVALID_AGENT_RESPONSE"),
    "ExtendedAgentCardNotConfiguredError": (-32007, 400, "EXTENDED_AGENT_CARD_NOT_CONFIGURED"),
    "ExtensionSupportRequiredError": (-32008, 400, "EXTENSION_SUPPORT_REQUIRED"),
    "VersionNotSupportedError": (-32009, 400, "VERSION_NOT_SUPPORTED"),
}
CODE_TO_ERROR = {v[0]: k for k, v in ERRORS.items()}

TASK_STATES = (
    "TASK_STATE_UNSPECIFIED", "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING",
    "TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED",
    "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_REJECTED", "TASK_STATE_AUTH_REQUIRED",
)
TERMINAL_STATES = ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED",
                   "TASK_STATE_CANCELED", "TASK_STATE_REJECTED")
INTERRUPTED_STATES = ("TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED")

MAX_SSE_LINE = 1 << 20          # one SSE line
MAX_SSE_BYTES = 8 << 20         # a whole collected stream


def jsonrpc_method(name: str, legacy: bool = False) -> str:
    """The JSON-RPC method string for a v1.0 method name."""
    return LEGACY_METHODS.get(name, name) if legacy else name


def default_headers(version: Optional[str] = A2A_VERSION, *, rest: bool = False,
                    extra: Optional[dict] = None) -> dict:
    h = {"User-Agent": USER_AGENT,
         "Accept": "application/a2a+json, application/json" if rest else "application/json",
         "Content-Type": "application/a2a+json" if rest else "application/json"}
    if version:
        h["A2A-Version"] = version
    h.update(extra or {})
    return h


@dataclass
class Http:
    """One HTTP exchange, never raising for 4xx/5xx."""
    status: int = 0
    headers: dict = field(default_factory=dict)   # lower-cased names
    body: bytes = b""
    error: str = ""                               # transport failure text
    elapsed_ms: int = 0

    @property
    def ok_transport(self) -> bool:
        return not self.error and self.status > 0

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8-sig"))
        except (ValueError, UnicodeDecodeError):
            return None

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # pragma: no cover - trivial
        return None


def http_request(method: str, url: str, body: Optional[bytes] = None,
                 headers: Optional[dict] = None, timeout: float = 10.0,
                 follow_redirects: bool = True) -> Http:
    """Perform one request. Transport problems are returned in ``Http.error``."""
    started = time.monotonic()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    opener = urllib.request.build_opener() if follow_redirects else \
        urllib.request.build_opener(_NoRedirect)
    out = Http()
    try:
        with opener.open(req, timeout=timeout) as resp:
            out.status = resp.status
            out.headers = {k.lower(): v for k, v in resp.headers.items()}
            out.body = read_capped(resp)
    except urllib.error.HTTPError as e:
        out.status = e.code
        out.headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            out.body = read_capped(e)
        except (ResponseTooLarge, OSError, http.client.HTTPException) as ee:
            out.error = f"error body unreadable: {ee}"
    except ResponseTooLarge as e:
        out.error = str(e)
    except urllib.error.URLError as e:
        out.error = f"{e.reason}"
    except (TimeoutError, OSError, ValueError, http.client.HTTPException) as e:
        out.error = f"{type(e).__name__}: {e}"
    out.elapsed_ms = int((time.monotonic() - started) * 1000)
    return out


# --------------------------------------------------------------------------
# JSON-RPC
# --------------------------------------------------------------------------

@dataclass
class RpcResult:
    http: Http
    envelope: Any = None          # parsed JSON body (any type)
    result: Any = None
    error: Optional[dict] = None

    @property
    def code(self) -> Optional[int]:
        c = (self.error or {}).get("code")
        return c if isinstance(c, int) and not isinstance(c, bool) else None

    @property
    def reason(self) -> str:
        return error_reason(self.error, rest=False)


def jsonrpc_call(url: str, method: str, params: Optional[dict] = None, *,
                 version: Optional[str] = A2A_VERSION, legacy: bool = False,
                 rid: Any = 1, timeout: float = 10.0, headers: Optional[dict] = None,
                 raw_body: Optional[bytes] = None) -> RpcResult:
    """POST one JSON-RPC request. ``raw_body`` replaces the encoded request."""
    if raw_body is None:
        payload = {"jsonrpc": "2.0", "id": rid, "method": jsonrpc_method(method, legacy)}
        if params is not None:
            payload["params"] = params
        raw_body = json.dumps(payload).encode()
    h = default_headers(version, extra=headers)
    resp = http_request("POST", url, raw_body, h, timeout)
    env = resp.json() if resp.body else None
    rr = RpcResult(resp, env)
    if isinstance(env, dict):
        if isinstance(env.get("error"), dict):
            rr.error = env["error"]
        elif "result" in env:
            rr.result = env["result"]
    return rr


def error_reason(err: Any, *, rest: bool) -> str:
    """The ``ErrorInfo.reason`` inside an error object, or ''."""
    if not isinstance(err, dict):
        return ""
    details = err.get("details" if rest else "data")
    if isinstance(details, list):
        for d in details:
            if isinstance(d, dict) and d.get("@type") == ERRORINFO_TYPE:
                r = d.get("reason")
                return r if isinstance(r, str) else ""
    return ""


def error_domain(err: Any, *, rest: bool) -> str:
    if not isinstance(err, dict):
        return ""
    details = err.get("details" if rest else "data")
    if isinstance(details, list):
        for d in details:
            if isinstance(d, dict) and d.get("@type") == ERRORINFO_TYPE:
                r = d.get("domain")
                return r if isinstance(r, str) else ""
    return ""


# --------------------------------------------------------------------------
# REST
# --------------------------------------------------------------------------

@dataclass
class RestResult:
    http: Http
    body: Any = None
    error: Optional[dict] = None

    @property
    def reason(self) -> str:
        return error_reason(self.error, rest=True)


def join_url(base: str, path: str) -> str:
    return base.rstrip("/") + path


def rest_call(base: str, method: str, path: str, body: Any = None, *,
              version: Optional[str] = A2A_VERSION, timeout: float = 10.0,
              headers: Optional[dict] = None, raw_body: Optional[bytes] = None,
              query: Optional[dict] = None) -> RestResult:
    url = join_url(base, path)
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = raw_body
    if data is None and body is not None:
        data = json.dumps(body).encode()
    resp = http_request(method, url, data, default_headers(version, rest=True, extra=headers), timeout)
    parsed = resp.json() if resp.body else None
    rr = RestResult(resp, parsed)
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
        rr.error = parsed["error"]
    return rr


def rest_path(op: str, task_id: str = "", config_id: str = "") -> tuple[str, str]:
    """(HTTP verb, path) for a v1.0 operation name [11.3]."""
    t = urllib.parse.quote(task_id, safe="")
    c = urllib.parse.quote(config_id, safe="")
    table = {
        M_SEND: ("POST", "/message:send"),
        M_STREAM: ("POST", "/message:stream"),
        M_GET: ("GET", f"/tasks/{t}"),
        M_LIST: ("GET", "/tasks"),
        M_CANCEL: ("POST", f"/tasks/{t}:cancel"),
        M_SUBSCRIBE: ("GET", f"/tasks/{t}:subscribe"),
        M_PUSH_CREATE: ("POST", f"/tasks/{t}/pushNotificationConfigs"),
        M_PUSH_GET: ("GET", f"/tasks/{t}/pushNotificationConfigs/{c}"),
        M_PUSH_LIST: ("GET", f"/tasks/{t}/pushNotificationConfigs"),
        M_PUSH_DELETE: ("DELETE", f"/tasks/{t}/pushNotificationConfigs/{c}"),
        M_EXT_CARD: ("GET", "/extendedAgentCard"),
    }
    return table[op]


# --------------------------------------------------------------------------
# Payload helpers
# --------------------------------------------------------------------------

def sample_message(text: str = "a2aops conformance probe", message_id: Optional[str] = None) -> dict:
    return {"messageId": message_id or f"a2aops-{int(time.time() * 1000)}",
            "role": "ROLE_USER", "parts": [{"text": text}]}


def unwrap(payload: Any) -> tuple[str, Any]:
    """Classify a SendMessageResponse / StreamResponse payload.

    Returns ``(kind, object)`` with kind in ``task``, ``message``,
    ``statusUpdate``, ``artifactUpdate`` or ``unknown``. A bare task-shaped
    object (``id`` + ``status``) from a pre-1.0 agent is kind ``task``; a bare
    ``taskId`` + ``status`` object is ``statusUpdate`` (legacy flat event).
    """
    if not isinstance(payload, dict):
        return "unknown", payload
    for k in ("task", "message", "statusUpdate", "artifactUpdate"):
        if isinstance(payload.get(k), dict):
            return k, payload[k]
    if "taskId" in payload and isinstance(payload.get("status"), dict):
        return "statusUpdate", payload
    if "id" in payload and isinstance(payload.get("status"), dict):
        return "task", payload
    if "taskId" in payload and isinstance(payload.get("artifact"), dict):
        return "artifactUpdate", payload
    if payload.get("kind") == "message" or ("messageId" in payload and "parts" in payload):
        return "message", payload
    return "unknown", payload


def unwrap_rpc(result: Any) -> tuple[str, Any]:
    return unwrap(result)


def state_of(payload: Any) -> Optional[str]:
    """The task state carried by a task or status-update payload, if any."""
    kind, obj = unwrap(payload)
    if kind in ("task", "statusUpdate") and isinstance(obj, dict):
        st = obj.get("status")
        if isinstance(st, dict) and isinstance(st.get("state"), str):
            return st["state"]
    if isinstance(payload, dict) and isinstance(payload.get("state"), str):
        return payload["state"]    # tolerate flat observation shapes
    return None


def task_id_of(payload: Any) -> Optional[str]:
    kind, obj = unwrap(payload)
    if not isinstance(obj, dict):
        return None
    v = obj.get("id") if kind == "task" else obj.get("taskId")
    return v if isinstance(v, str) else None


# --------------------------------------------------------------------------
# SSE collection (for probes)
# --------------------------------------------------------------------------

@dataclass
class SseCapture:
    status: int = 0
    headers: dict = field(default_factory=dict)
    events: list = field(default_factory=list)   # parsed JSON payloads (data fields)
    raw_events: int = 0
    bad_json: int = 0
    closed_cleanly: bool = False                 # server closed before the deadline
    error: str = ""
    body_prefix: str = ""                        # first bytes when not an event stream
    elapsed_ms: int = 0


def sse_collect(method: str, url: str, body: Optional[bytes], headers: dict, *,
                max_events: int = 50, deadline: float = 10.0) -> SseCapture:
    """Open an SSE request and gather ``data:`` payloads until close/limits."""
    cap = SseCapture()
    started = time.monotonic()
    headers = dict(headers)
    headers["Accept"] = "text/event-stream"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=min(deadline, 30.0))
    except urllib.error.HTTPError as e:
        cap.status = e.code
        cap.headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            cap.body_prefix = e.read(4096).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            pass
        cap.elapsed_ms = int((time.monotonic() - started) * 1000)
        return cap
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as e:
        cap.error = f"{getattr(e, 'reason', e)}"
        cap.elapsed_ms = int((time.monotonic() - started) * 1000)
        return cap
    with resp:
        cap.status = resp.status
        cap.headers = {k.lower(): v for k, v in resp.headers.items()}
        if "text/event-stream" not in cap.headers.get("content-type", "").lower():
            try:
                cap.body_prefix = resp.read(4096).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            cap.elapsed_ms = int((time.monotonic() - started) * 1000)
            return cap
        data_lines: list[str] = []
        total = 0
        try:
            while True:
                if time.monotonic() - started > deadline:
                    break
                raw = resp.readline(MAX_SSE_LINE + 1)
                if not raw:
                    cap.closed_cleanly = True
                    break
                total += len(raw)
                if len(raw) > MAX_SSE_LINE or total > MAX_SSE_BYTES:
                    cap.error = "stream exceeded the size cap"
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    if data_lines:
                        cap.raw_events += 1
                        try:
                            cap.events.append(json.loads("\n".join(data_lines)))
                        except ValueError:
                            cap.bad_json += 1
                        data_lines = []
                        if cap.raw_events >= max_events:
                            break
                elif line.startswith("data:"):
                    v = line[5:]
                    data_lines.append(v[1:] if v.startswith(" ") else v)
        except (OSError, http.client.HTTPException, TimeoutError) as e:
            cap.error = f"{type(e).__name__}: {e}"
        if data_lines:   # trailing event without blank line
            cap.raw_events += 1
            try:
                cap.events.append(json.loads("\n".join(data_lines)))
            except ValueError:
                cap.bad_json += 1
    cap.elapsed_ms = int((time.monotonic() - started) * 1000)
    return cap


def iter_stream_states(events: list) -> Iterator[str]:
    """States carried by captured stream events, in order (JSON-RPC aware)."""
    for ev in events:
        payload = ev.get("result") if isinstance(ev, dict) and "result" in ev else ev
        s = state_of(payload)
        if s is not None:
            yield s
