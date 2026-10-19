"""Task lifecycle inspector.

Two modes:

1. **Offline**: feed it observed (task_id, state) events — from a JSONL wire
   log, the playground, or your own client — and get a report. It flags exactly
   what the spec guarantees:
   - transitions *out of* a terminal state (the one hard rule),
   - TASK_STATE_UNSPECIFIED / unknown state strings (protocol violations),
   - INPUT_REQUIRED with no guidance message (clients cannot proceed),
   - the removed v0.x "unknown" state.
   It does NOT enforce a normative transition table, because the spec does not
   publish one (panel decision D5). Everything else is reported as an observed
   transition graph.

2. **Live poll**: repeatedly GET a task's state and feed observations into the
   inspector. The fetch function is injected so polling is testable without a
   network.
"""

from __future__ import annotations

import json
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .card import ERROR, WARNING, Diagnostic
from .states import is_terminal, normalize_state, state_class


@dataclass
class Observation:
    task_id: str
    state: str          # raw wire string
    ts: float = 0.0
    message: Optional[str] = None   # status message, if any


@dataclass
class Transition:
    task_id: str
    from_state: str      # canonical names
    to_state: str
    count: int = 1


class TaskInspector:
    """Accumulates task-state observations and reports violations."""

    def __init__(self) -> None:
        self._last: dict[str, str] = {}          # task_id -> canonical state
        self._transitions: Counter[tuple[str, str, str]] = Counter()
        self._diags: list[Diagnostic] = []
        self._seen_tasks: set[str] = set()

    def observe(self, obs: Observation) -> None:
        norm = normalize_state(obs.state)
        self._seen_tasks.add(obs.task_id)

        if norm.name == "UNKNOWN":
            self._diags.append(Diagnostic(
                WARNING, "T401",
                f"task {obs.task_id}: state 'unknown' was removed in v1.0 (normalize at the client edge)",
                f"tasks.{obs.task_id}"))
        elif not norm.known:
            self._diags.append(Diagnostic(
                ERROR, "T402",
                f"task {obs.task_id}: unknown state string {obs.state!r} (protocol violation)",
                f"tasks.{obs.task_id}"))
        elif norm.name == "UNSPECIFIED":
            self._diags.append(Diagnostic(
                ERROR, "T403",
                f"task {obs.task_id}: TASK_STATE_UNSPECIFIED is invalid on the wire",
                f"tasks.{obs.task_id}"))

        prev = self._last.get(obs.task_id)
        if prev is not None and norm.known and norm.name != "UNKNOWN":
            self._transitions[(obs.task_id, prev, norm.name)] += 1
            if is_terminal(prev) and norm.name != prev:
                self._diags.append(Diagnostic(
                    ERROR, "T404",
                    f"task {obs.task_id}: transition out of terminal state {prev} -> {norm.name}; "
                    "terminal tasks are immutable and must reject further messages",
                    f"tasks.{obs.task_id}"))

        if norm.name == "INPUT_REQUIRED" and not (obs.message or "").strip():
            self._diags.append(Diagnostic(
                WARNING, "T405",
                f"task {obs.task_id}: INPUT_REQUIRED with no status message — the client cannot know what to provide",
                f"tasks.{obs.task_id}"))

        if norm.known and norm.name != "UNKNOWN":
            self._last[obs.task_id] = norm.name

    def transitions(self) -> list[Transition]:
        return [Transition(tid, a, b, c) for (tid, a, b), c in sorted(self._transitions.items())]

    def current_states(self) -> dict[str, str]:
        return dict(self._last)

    def summary(self) -> dict[str, Any]:
        by_class: Counter[str] = Counter()
        for s in self._last.values():
            by_class[state_class(s)] += 1
        return {
            "tasks_observed": len(self._seen_tasks),
            "current_by_class": dict(by_class),
            "transitions_observed": sum(self._transitions.values()),
            "violations": sum(1 for d in self._diags if d.severity == ERROR),
            "warnings": sum(1 for d in self._diags if d.severity == WARNING),
        }

    def report(self) -> list[Diagnostic]:
        return list(self._diags)

    def add_diagnostic(self, diag: Diagnostic) -> None:
        """Append an externally-observed diagnostic (e.g. a poll failure)."""
        self._diags.append(diag)

    def format(self) -> str:
        lines = [f"tasks observed: {len(self._seen_tasks)}"]
        for t in self.transitions():
            lines.append(f"  {t.task_id}: {t.from_state} -> {t.to_state} x{t.count}")
        diags = self.report()
        if diags:
            lines.append("findings:")
            lines.extend(f"  {d}" for d in diags)
        else:
            lines.append("no violations found.")
        return "\n".join(lines)


def observations_from_jsonl(path: str) -> list[Observation]:
    """Load observations from a JSONL file.

    Two shapes are accepted:
    - direct: ``{"task_id":..., "state":..., "message"?}`` per line;
    - playground wire logs: ``task_polled`` / ``task_terminal`` entries carry
      ``task_id`` + ``state``; ``task_created`` entries carry the full task
      object (state extracted from ``task.status.state``). Other playground
      entries (``agent_started``, ``message_send``, ``error``, ...) are not
      task observations and are skipped.
    """
    obs: list[Observation] = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{n}: invalid JSON: {e}") from e
            obs_row = _observation_row(row, path, n)
            if obs_row is None:
                continue  # non-task playground entry
            obs.append(obs_row)
    return obs


def _observation_row(row: Any, path: str, n: int) -> Optional[Observation]:
    if not isinstance(row, dict):
        raise ValueError(f"{path}:{n}: each line must be a JSON object")
    if "task_id" in row and "state" in row:
        # Direct shape, or a playground task_polled / task_terminal entry.
        return Observation(task_id=str(row["task_id"]), state=str(row["state"]),
                           ts=float(row.get("ts", 0.0)),
                           message=row.get("message"))
    kind = row.get("kind")
    if kind == "task_created":
        task = row.get("task") or {}
        task_id = task.get("id")
        state = (task.get("status") or {}).get("state")
        if not task_id or not state:
            raise ValueError(f"{path}:{n}: task_created entry has no task id/state")
        return Observation(task_id=str(task_id), state=str(state),
                           ts=float(row.get("ts", 0.0)))
    if kind is not None:
        return None  # agent_started, message_send, error, ...: skip
    raise ValueError(f"{path}:{n}: each line needs 'task_id' and 'state'")


def rest_get_task(base_url: str, task_id: str, timeout: float = 10.0) -> dict:
    """REST poll: GET {base}/tasks/{task_id}."""
    url = f"{base_url.rstrip()}/tasks/{task_id}"
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "a2aops/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8-sig"))


def jsonrpc_get_task(base_url: str, task_id: str, timeout: float = 10.0) -> dict:
    """JSON-RPC poll: tasks/get against the interface URL."""
    payload = {"jsonrpc": "2.0", "id": f"a2aops-{int(time.time())}",
               "method": "tasks/get", "params": {"id": task_id}}
    req = urllib.request.Request(base_url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "a2aops/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8-sig"))
    if isinstance(body, dict) and "result" in body:
        return body["result"]
    return body


def _extract_state(task: dict) -> tuple[str, Optional[str]]:
    """Pull (state, message) out of a task object in either binding shape."""
    if not isinstance(task, dict):
        return "UNSPECIFIED", None
    status = task.get("status")
    if isinstance(status, dict):
        state = status.get("state", "UNSPECIFIED")
        msg = status.get("message")
        if isinstance(msg, dict):
            # message parts -> text summary
            parts = msg.get("parts") or []
            texts = [p.get("text") for p in parts if isinstance(p, dict) and p.get("text")]
            msg = " ".join(texts) if texts else None
        return str(state), (str(msg) if msg else None)
    return str(task.get("state", "UNSPECIFIED")), None


def poll_task(base_url: str, task_id: str,
              fetch: Optional[Callable[[str, str], dict]] = None,
              interval: float = 2.0, timeout: float = 300.0,
              inspector: Optional[TaskInspector] = None,
              on_observation: Optional[Callable[[Observation], None]] = None,
              sleep: Callable[[float], None] = time.sleep,
              clock: Callable[[], float] = time.monotonic) -> TaskInspector:
    """Poll a task until it reaches a terminal state or the timeout elapses.

    ``fetch(base_url, task_id)`` returns the task object; defaults to the REST
    binding. Returns the populated inspector.
    """
    insp = inspector or TaskInspector()
    fetch = fetch or (lambda b, t: rest_get_task(b, t))
    deadline = clock() + timeout
    while True:
        try:
            task = fetch(base_url, task_id)
        except Exception as e:
            insp.add_diagnostic(Diagnostic(ERROR, "T410",
                                           f"task {task_id}: poll failed: {e}", f"tasks.{task_id}"))
            break
        state, message = _extract_state(task)
        obs = Observation(task_id=task_id, state=state, ts=time.time(), message=message)
        insp.observe(obs)
        if on_observation:
            on_observation(obs)
        if is_terminal(normalize_state(state).name):
            break
        if clock() >= deadline:
            insp.add_diagnostic(Diagnostic(
                WARNING, "T411",
                f"task {task_id}: still not terminal after {timeout:.0f}s of polling",
                f"tasks.{task_id}"))
            break
        sleep(interval)
    return insp
