"""Local multi-agent playground.

Spins up mock A2A agents on localhost and runs scripted conversations between
them, producing a timestamped JSONL wire log.

Honesty note (panel decision D7): mock agents are **wire-correct scripted
fixtures**, not simulations of real agent intelligence. Every wire behavior
below traces to an A2A v1.0 clause: AgentCard serving (with ``Cache-Control``
and ``ETag``), JSON-RPC ``SendMessage`` / ``SendStreamingMessage`` /
``GetTask`` / ``ListTasks`` / ``CancelTask`` / ``SubscribeToTask`` and the REST
routes ``/message:send``, ``/message:stream``, ``/tasks/{id}``,
``/tasks/{id}:cancel``, ``/tasks/{id}:subscribe`` (streams close on terminal or
interrupted states; subscribing to a final task is an error, spec 9.4.6), with
spec-shaped errors (``ErrorInfo`` reason/domain). The pre-1.0 names
(``message/send``, ``tasks/get``, ``tasks/resubscribe``, ``/v1/...``) are still
served so old client code can be tested. Use this to test
*your client code* against the protocol surface — not to predict what a
real agent will say.
"""

from __future__ import annotations

import copy
import http.server
import json
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import wire
from .spec import load_spec


JSONRPC = "JSONRPC"
# Wire values the fixture emits are derived from the pinned spec snapshot,
# so a snapshot update flows through here too.
_TERMINAL_STATES = frozenset("TASK_STATE_" + s for s in load_spec()["terminal_states"])
_INTERRUPTED_STATES = frozenset(("TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"))


# --------------------------------------------------------------------------
# Mock agent
# --------------------------------------------------------------------------

class MockAgent:
    """A wire-correct, scripted A2A agent fixture served over local HTTP."""

    def __init__(self, name: str, skills: Optional[list[dict]] = None,
                 description: str = "", port: int = 0,
                 streaming: bool = True, legacy: bool = True) -> None:
        # legacy=False makes the fixture a strict v1.0 agent (pre-1.0 method
        # names and /v1/ routes answer "Method not found" / 404); it is the
        # reference agent of the conformance benchmark.
        self.legacy = legacy
        self.name = name
        self.description = description or f"Mock agent '{name}' (a2aops playground fixture)"
        self.skills = skills or [{"id": "echo", "name": "Echo",
                                  "description": "Echoes the input back as an artifact.",
                                  "tags": ["test", "echo"]}]
        self.port = port
        self.streaming = streaming
        self._tasks: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._counter = 0
        self._server: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle ------------------------------------------------------
    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def card(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "version": "0.1.0-fixture",
            "supportedInterfaces": [
                {"url": self.base_url + "/", "protocolBinding": JSONRPC, "protocolVersion": "1.0"},
                {"url": self.base_url, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
            ],
            "capabilities": {"streaming": self.streaming,
                             "pushNotifications": False,
                             "extendedAgentCard": False},
            "defaultInputModes": ["text/plain", "application/json"],
            "defaultOutputModes": ["application/json"],
            "skills": self.skills,
            "provider": {"organization": "a2aops playground",
                         "url": "https://example.invalid"},
        }

    def start(self) -> "MockAgent":
        agent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "a2aops-fixture/1.0"

            def log_message(self, *args):  # keep test output clean
                pass

            # -- helpers ---------------------------------------------------
            def _send(self, status: int, obj: dict, ctype: str = "application/json"):
                body = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _rest_error(self, name: str, message: str, **meta):
                code, http_status, reason = wire.ERRORS[name]
                self._send(http_status, {"error": {
                    "code": http_status,
                    "status": "NOT_FOUND" if http_status == 404 else "FAILED_PRECONDITION",
                    "message": message,
                    "details": [{"@type": wire.ERRORINFO_TYPE, "reason": reason,
                                 "domain": wire.ERRORINFO_DOMAIN, "metadata": meta}]}},
                           "application/a2a+json")

            def _rpc_error(self, rid, code: int, message: str, reason: str = ""):
                err = {"code": code, "message": message}
                if reason:
                    err["data"] = [{"@type": wire.ERRORINFO_TYPE, "reason": reason,
                                    "domain": wire.ERRORINFO_DOMAIN, "metadata": {}}]
                self._send(200, {"jsonrpc": "2.0", "id": rid, "error": err})

            def _rpc_a2a_error(self, rid, name: str, message: str):
                code, _http, reason = wire.ERRORS[name]
                self._rpc_error(rid, code, message, reason)

            def _version_ok(self) -> bool:
                v = self.headers.get("A2A-Version")
                return v is None or v.strip() in ("", "1.0", "0.3")

            # -- REST (v1.0) + card ---------------------------------------
            def do_GET(self):
                path = self.path.split("?", 1)[0]
                if path == "/.well-known/agent-card.json":
                    body = json.dumps(agent.card).encode()
                    if self.headers.get("If-None-Match") == agent.card_etag:
                        self.send_response(304)
                        self.send_header("ETag", agent.card_etag)
                        self.end_headers()
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "public, max-age=60")
                    self.send_header("ETag", agent.card_etag)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif path != "/" and not self._version_ok():
                    self._rest_error("VersionNotSupportedError", "A2A version not supported")
                elif "/pushNotificationConfigs" in path:
                    self._rest_error("PushNotificationNotSupportedError",
                                     "push notifications are not supported")
                elif path == "/extendedAgentCard":
                    self._rest_error("UnsupportedOperationError",
                                     "the fixture has no extended agent card")
                elif path == "/tasks":
                    self._send(200, {"tasks": [agent._view_v1(t) for t in agent._all_tasks()],
                                     "nextPageToken": "", "pageSize": 50,
                                     "totalSize": len(agent._all_tasks())},
                               "application/a2a+json")
                elif path.startswith("/tasks/") and path.endswith(":subscribe"):
                    tid = urllib.parse.unquote(path[len("/tasks/"):-len(":subscribe")])
                    agent._subscribe_v1(self, {"rpc": False}, tid)
                elif path.startswith("/tasks/"):
                    tid = urllib.parse.unquote(path[len("/tasks/"):])
                    agent._maybe_advance(tid)
                    task = agent._get_task(tid)
                    if task is None:
                        self._rest_error("TaskNotFoundError", "task not found", taskId=tid)
                    else:
                        self._send(200, agent._view_v1(task), "application/a2a+json")
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length) if length else b""
                path = self.path.split("?", 1)[0]
                # REST resubscribe: v1.0 POST /tasks/{id}:subscribe, legacy /v1/...
                if path.startswith(("/v1/tasks/", "/tasks/")) and path.endswith(":subscribe"):
                    legacy = path.startswith("/v1/")
                    if legacy and not agent.legacy:
                        self._send(404, {"error": "not found"})
                        return
                    start = len("/v1/tasks/") if legacy else len("/tasks/")
                    tid = urllib.parse.unquote(path[start:-len(":subscribe")])
                    if legacy:
                        agent._resubscribe_for(self, {"id": tid})
                    else:
                        agent._subscribe_v1(self, {"rpc": False}, tid)
                    return
                if "/pushNotificationConfigs" in path and path.startswith("/tasks/"):
                    if not self._version_ok():
                        self._rest_error("VersionNotSupportedError", "A2A version not supported")
                    else:
                        self._rest_error("PushNotificationNotSupportedError",
                                         "push notifications are not supported")
                    return
                if path in ("/message:send", "/message:stream") or (
                        path.startswith("/tasks/") and path.endswith(":cancel")):
                    self._rest_v1_post(path, raw)
                    return
                try:
                    req = json.loads((raw or b"{}").decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    self._send(400, {"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32700, "message": "Parse error"}})
                    return
                if not isinstance(req, dict):
                    self._send(400, {"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32600, "message": "Invalid Request"}})
                    return
                method = req.get("method", "")
                params = req.get("params") or {}
                rid = req.get("id")
                if not isinstance(params, dict):
                    self._rpc_error(rid, -32602, "Invalid params", "INVALID_PARAMS")
                    return
                # ---- v1.0 method names (spec 5.3) ----
                if method in wire.V1_METHODS:
                    if not self._version_ok():
                        self._rpc_a2a_error(rid, "VersionNotSupportedError",
                                            "A2A version not supported")
                        return
                    ctx = {"rpc": True, "rid": rid}
                    if method == wire.M_SEND:
                        if not isinstance(params.get("message"), dict):
                            self._rpc_error(rid, -32602, "Invalid params", "INVALID_PARAMS")
                            return
                        self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                            "task": agent._view_v1(agent._handle_send_raw(params))}})
                    elif method == wire.M_STREAM:
                        if not isinstance(params.get("message"), dict):
                            self._rpc_error(rid, -32602, "Invalid params", "INVALID_PARAMS")
                            return
                        tid = agent._handle_send_raw(params)["id"]
                        agent._stream_v1(self, ctx, tid)
                    elif method == wire.M_GET:
                        tid = str(params.get("id", ""))
                        agent._maybe_advance(tid)
                        task = agent._get_task(tid)
                        if task is None:
                            self._rpc_a2a_error(rid, "TaskNotFoundError", "task not found")
                        else:
                            self._send(200, {"jsonrpc": "2.0", "id": rid,
                                             "result": agent._view_v1(task)})
                    elif method == wire.M_CANCEL:
                        tid = str(params.get("id", ""))
                        task = agent._get_task(tid)
                        if task is None:
                            self._rpc_a2a_error(rid, "TaskNotFoundError", "task not found")
                        elif task["state"] in _TERMINAL_STATES:
                            self._rpc_a2a_error(rid, "TaskNotCancelableError", "task is already final")
                        else:
                            agent._cancel(tid)
                            self._send(200, {"jsonrpc": "2.0", "id": rid,
                                             "result": agent._view_v1(agent._get_task(tid) or {})})
                    elif method == wire.M_SUBSCRIBE:
                        agent._subscribe_v1(self, ctx, str(params.get("id", "")))
                    elif method == wire.M_LIST:
                        tasks = agent._all_tasks()
                        self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                            "tasks": [agent._view_v1(t) for t in tasks], "nextPageToken": "",
                            "pageSize": 50, "totalSize": len(tasks)}})
                    elif method == wire.M_EXT_CARD:
                        self._rpc_a2a_error(rid, "UnsupportedOperationError", "no extended card")
                    else:   # push-notification configuration is not supported by the fixture
                        self._rpc_a2a_error(rid, "PushNotificationNotSupportedError",
                                            "push notifications are not supported")
                    return
                # ---- legacy (pre-1.0) names, kept for old clients ----
                if not agent.legacy:
                    self._rpc_error(rid, -32601, "Method not found")
                elif method == "message/send":
                    result = agent._handle_send(params)
                    self._send(200, {"jsonrpc": "2.0", "id": rid, "result": result})
                elif method == "message/stream":
                    agent._stream_for(self, params)
                    return
                elif method == "tasks/get":
                    agent._maybe_advance(str(params.get("id", "")))
                    task = agent._get_task(str(params.get("id", "")))
                    if task is None:
                        self._send(200, {"jsonrpc": "2.0", "id": rid,
                                         "error": {"code": -32001, "message": "task not found"}})
                    else:
                        self._send(200, {"jsonrpc": "2.0", "id": rid,
                                         "result": agent._task_view(task)})
                elif method == "tasks/resubscribe":
                    agent._resubscribe_for(self, params)
                    return
                elif method == "tasks/cancel":
                    task = agent._cancel(str(params.get("id", "")))
                    self._send(200, {"jsonrpc": "2.0", "id": rid, "result": task})
                else:
                    self._rpc_error(rid, -32601, "Method not found")

            def _rest_v1_post(self, path: str, raw: bytes):
                try:
                    body = json.loads((raw or b"{}").decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    self._send(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT",
                                               "message": "invalid JSON"}}, "application/a2a+json")
                    return
                if not self._version_ok():
                    self._rest_error("VersionNotSupportedError", "A2A version not supported")
                    return
                if path.endswith(":cancel"):
                    tid = urllib.parse.unquote(path[len("/tasks/"):-len(":cancel")])
                    task = agent._get_task(tid)
                    if task is None:
                        self._rest_error("TaskNotFoundError", "task not found", taskId=tid)
                    elif task["state"] in _TERMINAL_STATES:
                        self._rest_error("TaskNotCancelableError", "task is already final", taskId=tid)
                    else:
                        agent._cancel(tid)
                        self._send(200, agent._view_v1(agent._get_task(tid) or {}), "application/a2a+json")
                    return
                if not isinstance(body, dict) or not isinstance(body.get("message"), dict):
                    self._send(400, {"error": {"code": 400, "status": "INVALID_ARGUMENT",
                                               "message": "message is required",
                                               "details": [{"@type": wire.ERRORINFO_TYPE,
                                                            "reason": "INVALID_REQUEST",
                                                            "domain": wire.ERRORINFO_DOMAIN}]}},
                               "application/a2a+json")
                    return
                task = agent._handle_send_raw(body)
                if path == "/message:send":
                    self._send(200, {"task": agent._view_v1(task)}, "application/a2a+json")
                else:
                    agent._stream_v1(self, {"rpc": False}, task["id"])

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    # -- task mechanics ---------------------------------------------------
    def _next_id(self, prefix: str) -> str:
        # Task ids are unique per agent: two agents in one scenario must not
        # mint the same "task-0001", or wire logs would merge their histories
        # when inspected.
        with self._lock:
            self._counter += 1
            slug = "".join(c if c.isalnum() else "-" for c in self.name.lower())
            return f"{prefix}-{slug}-{self._counter:04d}"

    def _get_task(self, task_id: str) -> Optional[dict]:
        with self._lock:
            t = self._tasks.get(task_id)
            return copy.deepcopy(t) if t else None

    def _task_view(self, task: dict) -> dict:
        return {"id": task["id"], "contextId": task["contextId"],
                "status": {"state": task["state"], "message": task.get("message")},
                "artifacts": task.get("artifacts", []),
                "history": task.get("history", [])}

    def _record(self, task: dict, state: str, message: Optional[str] = None) -> None:
        with self._lock:
            t = self._tasks[task["id"]]
            t["state"] = state
            t["message"] = message
            t["history"].append({"state": state, "ts": time.time()})

    def _handle_send(self, params: dict) -> dict:
        """Legacy (pre-1.0) view of :meth:`_handle_send_raw`."""
        return self._task_view(self._handle_send_raw(params))

    def _handle_send_raw(self, params: dict) -> dict:
        """Scripted task machine. Keywords in the text select the path:
        'fail' -> FAILED, 'need input' -> INPUT_REQUIRED, 'slow' -> stays
        WORKING (for poll demos); anything else -> COMPLETED with an artifact.
        """
        message = params.get("message") or {}
        parts = message.get("parts") or []
        text = " ".join(p.get("text", "") for p in parts if isinstance(p, dict))
        task_id = self._next_id("task")
        context_id = str(message.get("contextId") or self._next_id("ctx"))
        low = text.lower()

        with self._lock:
            self._tasks[task_id] = {
                "id": task_id, "contextId": context_id,
                "state": "TASK_STATE_SUBMITTED", "message": None,
                "artifacts": [], "history": [{"state": "TASK_STATE_SUBMITTED", "ts": time.time()}],
                "mode": ("fail" if "fail" in low else
                         "input" if "need input" in low else
                         "slow" if "slow" in low else "ok"),
                "text": text,
                "user_message": {
                    "messageId": str(message.get("messageId") or self._next_id("msg")),
                    "contextId": context_id, "taskId": task_id,
                    "role": "ROLE_USER", "parts": [{"text": text}]},
            }
        task = self._get_task(task_id)
        assert task is not None
        mode = task["mode"]

        if mode == "fail":
            self._record(self._tasks[task_id], "TASK_STATE_WORKING", "starting work")
            self._record(self._tasks[task_id], "TASK_STATE_FAILED", "scripted failure (keyword 'fail')")
        elif mode == "input":
            self._record(self._tasks[task_id], "TASK_STATE_WORKING", "starting work")
            self._record(self._tasks[task_id], "TASK_STATE_INPUT_REQUIRED",
                         "scripted pause: tell me which color (keyword 'need input')")
        elif mode == "slow":
            self._record(self._tasks[task_id], "TASK_STATE_WORKING", "working slowly (keyword 'slow')")
            # stays WORKING until polled a few times, then completes
            with self._lock:
                self._tasks[task_id]["polls_left"] = 3
        else:
            self._record(self._tasks[task_id], "TASK_STATE_WORKING", "working")
            artifact = {"artifactId": self._next_id("artifact"),
                        "parts": [{"text": f"[{self.name}] processed: {text}"}]}
            with self._lock:
                t = self._tasks[task_id]
                t["artifacts"].append(artifact)
                t["state"] = "TASK_STATE_COMPLETED"
                t["message"] = "done"
                t["history"].append({"state": "TASK_STATE_COMPLETED", "ts": time.time()})
        return self._get_task(task_id) or {}

    def _cancel(self, task_id: str) -> dict:
        with self._lock:
            t = self._tasks.get(task_id)
            if t and t["state"] not in _TERMINAL_STATES:
                t["state"] = "TASK_STATE_CANCELED"
                t["message"] = "canceled by client"
                t["history"].append({"state": "TASK_STATE_CANCELED", "ts": time.time()})
            return self._task_view(copy.deepcopy(t)) if t else {"error": "task not found"}

    def _maybe_advance(self, task_id: str) -> None:
        """Advance scripted 'slow' tasks one step per tasks/get poll."""
        with self._lock:
            t = self._tasks.get(task_id)
            if not t or t.get("mode") != "slow":
                return
            left = t.get("polls_left", 0) - 1
            t["polls_left"] = left
            if left <= 0 and t["state"] == "TASK_STATE_WORKING":
                t["state"] = "TASK_STATE_COMPLETED"
                t["message"] = "done"
                t["artifacts"].append({"artifactId": f"artifact-{self._counter:04d}",
                                      "parts": [{"text": f"[{self.name}] slow task finished"}]})
                t["history"].append({"state": "TASK_STATE_COMPLETED", "ts": time.time()})

    # -- v1.0 views ----------------------------------------------------------
    @property
    def card_etag(self) -> str:
        import hashlib
        return '"' + hashlib.sha256(json.dumps(self.card, sort_keys=True).encode()).hexdigest()[:16] + '"'

    def _all_tasks(self) -> list[dict]:
        with self._lock:
            return [copy.deepcopy(t) for t in self._tasks.values()]

    @staticmethod
    def _iso(ts: Optional[float] = None) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts or time.time())) + ".000Z"

    def _status_v1(self, task: dict, state: Optional[str] = None, with_message: bool = True) -> dict:
        status = {"state": state or task["state"], "timestamp": self._iso()}
        text = task.get("message")
        if with_message and text:
            status["message"] = {"messageId": f"{task['id']}-status", "contextId": task["contextId"],
                                 "taskId": task["id"], "role": "ROLE_AGENT", "parts": [{"text": str(text)}]}
        return status

    def _view_v1(self, task: dict, state: Optional[str] = None, artifacts: bool = True) -> dict:
        """A v1.0 ``Task``: ``status.message`` and ``history`` hold real Messages."""
        if not task:
            return {}
        view = {"id": task["id"], "contextId": task["contextId"],
                "status": self._status_v1(task, state)}
        if artifacts and task.get("artifacts"):
            view["artifacts"] = task["artifacts"]
        if task.get("user_message"):
            view["history"] = [task["user_message"]]
        return view

    def _emit_v1(self, handler, ctx: dict, eid: str, kind: str, body: dict) -> None:
        payload = {kind: body}
        if ctx.get("rpc"):
            payload = {"jsonrpc": "2.0", "id": ctx.get("rid"), "result": payload}
        handler.wfile.write(f"id: {eid}\ndata: {json.dumps(payload)}\n\n".encode())
        handler.wfile.flush()

    def _stream_v1(self, handler, ctx: dict, task_id: str) -> None:
        """v1.0 stream: a Task snapshot, status/artifact updates, then close."""
        self._sse_headers(handler)
        t = self._get_task(task_id) or {}
        states = [h["state"] for h in t.get("history", [])] or ["TASK_STATE_SUBMITTED"]
        n = 0

        def eid() -> str:
            nonlocal n
            n += 1
            return f"{task_id}-{n}"

        self._emit_v1(handler, ctx, eid(), "task", self._view_v1(t, states[0], artifacts=False))
        final = states[-1] in _TERMINAL_STATES or states[-1] in _INTERRUPTED_STATES
        for st in (states[1:-1] if final else states[1:]):
            time.sleep(0.02)
            self._emit_v1(handler, ctx, eid(), "statusUpdate",
                          {"taskId": task_id, "contextId": t.get("contextId"),
                           "status": self._status_v1(t, st, with_message=False)})
        if t.get("mode") == "slow" and not final:
            for _ in range(3):
                time.sleep(0.15)
                self._emit_v1(handler, ctx, eid(), "statusUpdate",
                              {"taskId": task_id, "contextId": t.get("contextId"),
                               "status": self._status_v1(t, "TASK_STATE_WORKING", with_message=False)})
            with self._lock:
                tt = self._tasks[task_id]
                tt["state"] = "TASK_STATE_COMPLETED"
                tt["message"] = "done"
                tt["artifacts"].append({"artifactId": self._next_id("artifact"),
                                        "parts": [{"text": f"[{self.name}] slow task finished"}]})
                tt["history"].append({"state": "TASK_STATE_COMPLETED", "ts": time.time()})
            t = self._get_task(task_id) or {}
            final = True
        if not final:
            return
        for art in t.get("artifacts", []):
            self._emit_v1(handler, ctx, eid(), "artifactUpdate",
                          {"taskId": task_id, "contextId": t.get("contextId"), "artifact": art,
                           "lastChunk": True})
        if len(states) > 1 or t.get("state") != states[0]:
            self._emit_v1(handler, ctx, eid(), "statusUpdate",
                          {"taskId": task_id, "contextId": t.get("contextId"),
                           "status": self._status_v1(t)})

    def _subscribe_v1(self, handler, ctx: dict, task_id: str) -> None:
        """SubscribeToTask: error for unknown/final tasks (spec 9.4.6), else stream."""
        t = self._get_task(task_id)
        if t is None:
            self._sub_error(handler, ctx, "TaskNotFoundError", "task not found")
            return
        if t["state"] in _TERMINAL_STATES:
            self._sub_error(handler, ctx, "UnsupportedOperationError",
                            "task is in a terminal state; use GetTask")
            return
        self._sse_headers(handler)
        self._emit_v1(handler, ctx, f"{task_id}-sub-0", "task", self._view_v1(t))
        if t.get("mode") == "slow":
            for i in range(2):
                time.sleep(0.1)
                self._emit_v1(handler, ctx, f"{task_id}-sub-{i + 1}", "statusUpdate",
                              {"taskId": task_id, "contextId": t["contextId"],
                               "status": self._status_v1(t, "TASK_STATE_WORKING", with_message=False)})
            with self._lock:
                tt = self._tasks[task_id]
                tt["state"] = "TASK_STATE_COMPLETED"
                tt["message"] = "done"
                tt["history"].append({"state": "TASK_STATE_COMPLETED", "ts": time.time()})
            self._emit_v1(handler, ctx, f"{task_id}-sub-9", "statusUpdate",
                          {"taskId": task_id, "contextId": t["contextId"],
                           "status": self._status_v1(self._get_task(task_id) or t)})

    def _sub_error(self, handler, ctx: dict, name: str, message: str) -> None:
        code, http_status, reason = wire.ERRORS[name]
        info = {"@type": wire.ERRORINFO_TYPE, "reason": reason,
                "domain": wire.ERRORINFO_DOMAIN, "metadata": {}}
        if ctx.get("rpc"):
            body = {"jsonrpc": "2.0", "id": ctx.get("rid"),
                    "error": {"code": code, "message": message, "data": [info]}}
            status = 200
        else:
            body = {"error": {"code": http_status, "message": message, "details": [info]}}
            status = http_status
        raw = json.dumps(body).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    # -- SSE ---------------------------------------------------------------
    def _sse_headers(self, handler: http.server.BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Cache-Control", "no-cache")
        handler.send_header("X-Accel-Buffering", "no")
        handler.end_headers()

    def _sse_write(self, handler, event_id: str, name: str, payload: dict, final: bool = False) -> None:
        line = (f"id: {event_id}\nevent: {name}\n"
                f"data: {json.dumps(payload)}\n\n")
        handler.wfile.write(line.encode())
        handler.wfile.flush()

    def _emit_status(self, handler, task: dict, eid: str, final: bool) -> None:
        self._sse_write(handler, eid, "TaskStatusUpdateEvent", {
            "taskId": task["id"], "contextId": task["contextId"],
            "status": {"state": task["state"], "message": task.get("message")},
            "final": final,
        })

    def _stream_for(self, handler: http.server.BaseHTTPRequestHandler, params: dict) -> None:
        """Serve message/stream: create the task, then stream its transitions.

        Replays the task's recorded history so clients observe real state
        transitions, then closes the stream once a terminal or interrupted
        state is reached (spec requirement).
        """
        task_view = self._handle_send(params)
        task_id = task_view["id"]
        self._sse_headers(handler)
        n = 0

        def emit(state: str, message: Optional[str] = None, final: bool = False):
            nonlocal n
            n += 1
            t = self._get_task(task_id) or {}
            self._emit_status(handler, {"id": task_id,
                                        "contextId": t.get("contextId"),
                                        "state": state, "message": message},
                              f"{task_id}-{n}", final)

        task = self._get_task(task_id) or {}
        mode = task.get("mode")
        for h in task.get("history", []):
            emit(h["state"])
            time.sleep(0.03)

        if mode == "slow":
            # live task: heartbeat WORKING, then complete
            for _ in range(3):
                time.sleep(0.15)
                emit("TASK_STATE_WORKING")
            with self._lock:
                t = self._tasks[task_id]
                t["state"] = "TASK_STATE_COMPLETED"
                t["message"] = "done"
                t["artifacts"].append({"artifactId": self._next_id("artifact"),
                                      "parts": [{"text": f"[{self.name}] slow task finished"}]})
                t["history"].append({"state": "TASK_STATE_COMPLETED", "ts": time.time()})

        final_state = (self._get_task(task_id) or {}).get("state", "TASK_STATE_UNSPECIFIED")
        emit(final_state, final=True)
        # stream closes here: terminal/interrupted state reached (spec requirement)

    def _resubscribe_for(self, handler: http.server.BaseHTTPRequestHandler, params: dict) -> None:
        task_id = str(params.get("id", ""))
        task = self._get_task(task_id)
        self._sse_headers(handler)
        if task is None:
            self._sse_write(handler, f"{task_id}-err", "TaskStatusUpdateEvent",
                            {"taskId": task_id,
                             "status": {"state": "TASK_STATE_UNSPECIFIED",
                                        "message": "task not found"},
                             "final": True})
            return
        # Resume from the current position; terminal tasks get one final event.
        terminal = task["state"] in _TERMINAL_STATES
        self._emit_status(handler, task, f"{task_id}-resub", final=terminal)
        # stream closes; a live task would keep it open, the fixture is scripted


# --------------------------------------------------------------------------
# Scenario runner
# --------------------------------------------------------------------------

@dataclass
class ScenarioStep:
    frm: str
    to: str
    text: str


@dataclass
class Scenario:
    agents: list[dict] = field(default_factory=list)   # {"name":..., "skills"?...}
    script: list[ScenarioStep] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Scenario":
        steps = [ScenarioStep(s["from"], s["to"], s["text"]) for s in data.get("script", [])]
        return cls(agents=data.get("agents", []), script=steps)

    @classmethod
    def from_json(cls, path: str) -> "Scenario":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


def _rpc(url: str, method: str, params: dict, timeout: float = 15.0) -> dict:
    payload = {"jsonrpc": "2.0", "id": f"a2aops-{int(time.time() * 1000)}",
               "method": method, "params": params}
    headers = {"Content-Type": "application/json", "User-Agent": "a2aops/1.0"}
    if method in wire.V1_METHODS:           # v1.0 method names carry the version header
        headers["A2A-Version"] = wire.A2A_VERSION
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8-sig"))


@dataclass
class RunReport:
    agents: list[str]
    steps: int
    tasks: list[dict]
    log_path: str
    elapsed_s: float


def run_scenario(scenario: Scenario, log_path: str,
                 on_log: Optional[Callable[[dict], None]] = None) -> RunReport:
    """Start the mock agents, run the script, write the JSONL wire log."""
    started = time.time()
    agents: dict[str, MockAgent] = {}
    logf = open(log_path, "w", encoding="utf-8")

    def log(entry: dict) -> None:
        entry = {"ts": time.time(), **entry}
        logf.write(json.dumps(entry) + "\n")
        logf.flush()
        if on_log:
            on_log(entry)

    tasks: list[dict] = []
    try:
        for spec in scenario.agents:
            agent = MockAgent(name=spec["name"], skills=spec.get("skills"),
                              description=spec.get("description", "")).start()
            # give the socket a moment
            time.sleep(0.05)
            agents[spec["name"]] = agent
            log({"kind": "agent_started", "agent": spec["name"],
                 "base_url": agent.base_url, "fixture": True,
                 "note": "wire-correct scripted fixture, not a real agent"})

        for step in scenario.script:
            if step.to not in agents:
                log({"kind": "error", "message": f"unknown agent '{step.to}'"})
                continue
            target = agents[step.to]
            log({"kind": "message_send", "from": step.frm, "to": step.to,
                 "url": target.base_url + "/", "text": step.text})
            try:
                resp = _rpc(target.base_url + "/", wire.M_SEND, {
                    "message": {"messageId": f"msg-{int(time.time()*1000)}",
                                "role": "ROLE_USER",
                                "parts": [{"text": step.text}]}})
            except Exception as e:
                log({"kind": "error", "from": step.frm, "to": step.to,
                     "message": f"SendMessage failed: {e}"})
                continue
            result = wire.unwrap(resp.get("result", {}))[1]
            if not isinstance(result, dict):
                result = {}
            log({"kind": "task_created", "from": step.frm, "to": step.to,
                 "task": result})
            tasks.append({"from": step.frm, "to": step.to, "task": result})

            # follow the task to a terminal state via tasks/get (poll)
            task_id = result.get("id")
            if task_id:
                for _ in range(50):
                    time.sleep(0.1)
                    try:
                        got = _rpc(target.base_url + "/", wire.M_GET, {"id": task_id})
                    except Exception as e:
                        log({"kind": "error", "message": f"GetTask failed: {e}"})
                        break
                    t = got.get("result", {})
                    if not isinstance(t, dict):
                        t = {}
                    state = (t.get("status") or {}).get("state", "")
                    log({"kind": "task_polled", "task_id": task_id, "state": state})
                    if state in _TERMINAL_STATES:
                        log({"kind": "task_terminal", "task_id": task_id,
                             "state": state, "artifacts": t.get("artifacts", [])})
                        break
    finally:
        for agent in agents.values():
            agent.stop()
        logf.close()

    return RunReport(agents=list(agents), steps=len(scenario.script),
                     tasks=tasks, log_path=log_path,
                     elapsed_s=time.time() - started)


def demo_scenario() -> Scenario:
    """Built-in two-agent demo: a planner delegates to a worker."""
    return Scenario(
        agents=[
            {"name": "planner",
             "description": "Fixture planner: breaks a request into one subtask.",
             "skills": [{"id": "plan", "name": "Plan work",
                         "description": "Turns a request into subtasks.",
                         "tags": ["planning", "delegation"]}]},
            {"name": "worker",
             "description": "Fixture worker: executes subtasks.",
             "skills": [{"id": "execute", "name": "Execute subtask",
                         "description": "Executes a single subtask.",
                         "tags": ["execution"]}]},
        ],
        script=[
            ScenarioStep("you", "planner", "summarize this quarter's snow-clearing costs"),
            ScenarioStep("planner", "worker", "add up the invoices for Q3"),
            ScenarioStep("you", "worker", "fail this on purpose"),
        ],
    )
