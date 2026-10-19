"""Local multi-agent playground.

Spins up mock A2A agents on localhost and runs scripted conversations between
them, producing a timestamped JSONL wire log.

Honesty note (panel decision D7): mock agents are **wire-correct scripted
fixtures**, not simulations of real agent intelligence. Every wire behavior
below traces to an A2A v1.0 clause: AgentCard serving, ``message/send``,
``message/stream`` (SSE, closed on terminal states), ``tasks/get``,
``tasks/resubscribe`` (duplicate-tolerant), and ``tasks/cancel``. Use this to
test *your client code* against the protocol surface — not to predict what a
real agent will say.
"""

from __future__ import annotations

import copy
import http.server
import json
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from .spec import load_spec


JSONRPC = "JSONRPC"
# Wire values the fixture emits are derived from the pinned spec snapshot,
# so a snapshot update flows through here too.
_TERMINAL_STATES = frozenset("TASK_STATE_" + s for s in load_spec()["terminal_states"])


# --------------------------------------------------------------------------
# Mock agent
# --------------------------------------------------------------------------

class MockAgent:
    """A wire-correct, scripted A2A agent fixture served over local HTTP."""

    def __init__(self, name: str, skills: Optional[list[dict]] = None,
                 description: str = "", port: int = 0,
                 streaming: bool = True) -> None:
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
            "supportedInterfaces": [{
                "url": self.base_url + "/",
                "protocolBinding": JSONRPC,
                "protocolVersion": "1.0",
            }],
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

            def do_GET(self):
                if self.path == "/.well-known/agent-card.json":
                    body = json.dumps(agent.card).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path.startswith("/tasks/"):
                    task_id = self.path[len("/tasks/"):]
                    task = agent._get_task(task_id)
                    if task is None:
                        self._send(404, {"error": "task not found"})
                    else:
                        self._send(200, agent._task_view(task))
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    req = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    self._send(400, {"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32700, "message": "Parse error"}})
                    return
                method = req.get("method", "")
                params = req.get("params") or {}
                rid = req.get("id")
                if method == "message/send":
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
                    self._send(200, {"jsonrpc": "2.0", "id": rid,
                                     "error": {"code": -32601, "message": f"unknown method {method}"}})

            def _send(self, status: int, obj: dict):
                body = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

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
        with self._lock:
            self._counter += 1
            return f"{prefix}-{self._counter:04d}"

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
        return self._task_view(self._get_task(task_id) or {})

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
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "a2aops/1.0"})
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
                resp = _rpc(target.base_url + "/", "message/send", {
                    "message": {"messageId": f"msg-{int(time.time()*1000)}",
                                "role": "user",
                                "parts": [{"text": step.text}]}})
            except Exception as e:
                log({"kind": "error", "from": step.frm, "to": step.to,
                     "message": f"message/send failed: {e}"})
                continue
            result = resp.get("result", {})
            log({"kind": "task_created", "from": step.frm, "to": step.to,
                 "task": result})
            tasks.append({"from": step.frm, "to": step.to, "task": result})

            # follow the task to a terminal state via tasks/get (poll)
            task_id = result.get("id")
            if task_id:
                for _ in range(50):
                    time.sleep(0.1)
                    try:
                        got = _rpc(target.base_url + "/", "tasks/get", {"id": task_id})
                    except Exception as e:
                        log({"kind": "error", "message": f"tasks/get failed: {e}"})
                        break
                    t = got.get("result", {})
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
