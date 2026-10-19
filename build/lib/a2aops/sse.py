"""SSE client with spec-correct resubscription.

The documented failure mode: SSE connections drop (proxies, mobile, timeouts)
and clients never resubscribe. This module implements the A2A resubscribe path
(JSON-RPC ``tasks/resubscribe`` or REST ``POST /v1/tasks/{id}:subscribe``),
with exponential-backoff reconnect, event-id deduping (the spec allows
duplicate events after resubscribe), and clean close on terminal states.

It does not "repair" streams or hide server bugs — every reconnect and every
duplicate is surfaced to the caller.
"""

from __future__ import annotations

import json
import random
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterator, Optional

from .states import is_terminal, normalize_state


@dataclass
class SSEEvent:
    id: Optional[str] = None
    event: Optional[str] = None
    data: str = ""
    retry: Optional[int] = None
    comment: Optional[str] = None


def parse_sse_stream(lines: Iterator[str]) -> Iterator[SSEEvent]:
    """Parse an SSE byte/char stream into events.

    Handles LF, CRLF, and lone-CR line endings; multi-line ``data:`` fields are
    joined with ``\\n``; comment lines (``: ...``) are yielded as comment
    events so callers can observe keep-alives.
    """
    buf_id: Optional[str] = None
    buf_event: Optional[str] = None
    buf_data: list[str] = []
    buf_retry: Optional[int] = None

    def dispatch() -> Optional[SSEEvent]:
        nonlocal buf_id, buf_event, buf_data, buf_retry
        # Per the SSE spec, a dispatch with an empty data buffer is ignored.
        if not any(buf_data) and buf_event is None and buf_id is None:
            buf_id, buf_event, buf_data, buf_retry = None, None, [], None
            return None
        ev = SSEEvent(id=buf_id, event=buf_event, data="\n".join(buf_data), retry=buf_retry)
        buf_id, buf_event, buf_data, buf_retry = None, None, [], None
        return ev

    pending = ""
    for chunk in lines:
        pending += chunk
        while True:
            # find the next line boundary (any of \r\n, \n, \r)
            idx_rn = pending.find("\r\n")
            idx_n = pending.find("\n")
            idx_r = pending.find("\r")
            candidates = [i for i in (idx_rn, idx_n, idx_r) if i != -1]
            if not candidates:
                break
            idx = min(candidates)
            if idx == idx_rn:
                line, pending = pending[:idx], pending[idx + 2:]
            elif idx == idx_n:
                line, pending = pending[:idx], pending[idx + 1:]
            else:
                line, pending = pending[:idx], pending[idx + 1:]

            if line == "":
                ev = dispatch()
                if ev is not None:
                    yield ev
                continue
            if line.startswith(":"):
                ev = dispatch()
                if ev is not None:
                    yield ev
                yield SSEEvent(comment=line[1:].strip())
                continue
            if ":" in line:
                fname, _, fvalue = line.partition(":")
                fvalue = fvalue[1:] if fvalue.startswith(" ") else fvalue
            else:
                fname, fvalue = line, ""
            if fname == "data":
                buf_data.append(fvalue)
            elif fname == "event":
                buf_event = fvalue
            elif fname == "id":
                buf_id = fvalue
            elif fname == "retry":
                try:
                    buf_retry = int(fvalue)
                except ValueError:
                    pass
            # unknown fields are ignored per the SSE spec

    if pending.strip():
        # trailing data without a terminator: treat lone field lines leniently
        for line in pending.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            if line.startswith("data:"):
                buf_data.append(line[5:].lstrip(" "))
    ev = dispatch()
    if ev is not None:
        yield ev


def _line_iter(resp) -> Iterator[str]:
    while True:
        raw = resp.readline()
        if not raw:
            break
        yield raw.decode("utf-8", errors="replace")


def open_sse(url: str, headers: Optional[dict] = None,
             data: Optional[bytes] = None,
             timeout: float = 60.0):
    """Open an SSE HTTP request and return the response object."""
    req = urllib.request.Request(url, data=data, headers={
        "Accept": "text/event-stream",
        "Cache-Control": "no-cache",
        "User-Agent": "a2aops/1.0",
        **(headers or {}),
    })
    return urllib.request.urlopen(req, timeout=timeout)


def build_resubscribe_request(base_url: str, task_id: str,
                              binding: str = "rest",
                              history_length: int = 0) -> tuple[str, Optional[bytes], dict]:
    """Build the HTTP request for the A2A resubscribe path.

    Returns (url, body, headers). ``binding`` is "rest"
    (``POST /v1/tasks/{id}:subscribe``) or "jsonrpc" (``tasks/resubscribe``).
    """
    base = base_url.rstrip("/")
    if binding == "rest":
        url = f"{base}/v1/tasks/{task_id}:subscribe"
        body = json.dumps({"id": task_id, "historyLength": history_length}).encode()
        return url, body, {"Content-Type": "application/json"}
    if binding == "jsonrpc":
        payload = {"jsonrpc": "2.0", "id": f"a2aops-{int(time.time())}",
                   "method": "tasks/resubscribe",
                   "params": {"id": task_id, "historyLength": history_length}}
        return base, json.dumps(payload).encode(), {"Content-Type": "application/json"}
    raise ValueError(f"unknown binding '{binding}' (expected 'rest' or 'jsonrpc')")


@dataclass
class StreamStats:
    events: int = 0
    duplicates: int = 0
    reconnects: int = 0
    comments: int = 0
    closed_on_terminal: bool = False
    notes: list[str] = field(default_factory=list)


def stream_with_resubscribe(
    base_url: str,
    task_id: str,
    binding: str = "rest",
    on_event: Optional[Callable[[SSEEvent], None]] = None,
    max_events: int = 0,
    max_reconnects: int = 10,
    backoff_base: float = 1.0,
    backoff_max: float = 30.0,
    history_length: int = 0,
    opener: Optional[Callable] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> StreamStats:
    """Stream task events, resubscribing with backoff on disconnect.

    - Dedupes events by SSE ``id`` (the spec allows duplicates on resubscribe).
    - Stops cleanly when an event carries a terminal task state.
    - ``opener`` is injectable for tests; defaults to :func:`open_sse`.
    - Exceptions raised by ``on_event`` propagate to the caller; they are
      never misreported as stream failures.
    Returns StreamStats describing what happened (reconnects/duplicates are
    surfaced, never hidden).
    """
    stats = StreamStats()
    seen_ids: set[str] = set()
    reconnects = 0
    opener = opener or open_sse

    def task_state_of(ev: SSEEvent) -> Optional[str]:
        if not ev.data:
            return None
        try:
            payload = json.loads(ev.data)
        except (json.JSONDecodeError, ValueError):
            return None
        # TaskStatusUpdateEvent: {"taskId":..., "status": {"state": ...}, "final": bool}
        status = payload.get("status") if isinstance(payload, dict) else None
        state = status.get("state") if isinstance(status, dict) else None
        if state is None and isinstance(payload, dict):
            state = payload.get("state")  # tolerate flat shapes
        return state if isinstance(state, str) else None

    while True:
        url, body, headers = build_resubscribe_request(base_url, task_id, binding, history_length)
        try:
            resp = opener(url, headers=headers, data=body, timeout=60.0)
        except Exception as e:
            reconnects += 1
            stats.reconnects = reconnects
            if reconnects > max_reconnects:
                stats.notes.append(f"gave up after {max_reconnects} reconnect attempts: {e}")
                return stats
            delay = min(backoff_max, backoff_base * (2 ** (reconnects - 1))) * (0.8 + 0.4 * random.random())
            stats.notes.append(f"connect failed ({e}); retry {reconnects} in {delay:.1f}s")
            sleep(delay)
            continue

        stream_broken = False
        callback_failed = False
        try:
            with resp:
                for ev in parse_sse_stream(_line_iter(resp)):
                    if ev.comment is not None:
                        stats.comments += 1
                        continue
                    if ev.id is not None:
                        if ev.id in seen_ids:
                            stats.duplicates += 1
                            stats.notes.append(f"duplicate event id {ev.id} skipped (resubscribe overlap)")
                            continue
                        seen_ids.add(ev.id)
                    stats.events += 1
                    if on_event:
                        try:
                            on_event(ev)
                        except Exception:
                            callback_failed = True
                            raise
                    if max_events and stats.events >= max_events:
                        return stats
                    state = task_state_of(ev)
                    if state is not None:
                        norm = normalize_state(state)
                        if norm.name == "UNSPECIFIED" and not norm.known:
                            stats.notes.append(f"protocol violation: task reported unknown state {state!r}")
                        if is_terminal(norm.name):
                            stats.closed_on_terminal = True
                            stats.notes.append(f"stream closed: task reached terminal state {norm.name}")
                            return stats
        except Exception as e:
            if callback_failed:
                raise  # caller's bug: never misreport it as a stream failure
            stream_broken = True
            stats.notes.append(f"stream broke mid-read ({e}); resubscribing")

        if not stream_broken:
            # Server closed the stream without a terminal state: resubscribe once
            # the task may still be active; the loop below handles backoff.
            stats.notes.append("server closed stream without terminal state; resubscribing")
        reconnects += 1
        stats.reconnects = reconnects
        if reconnects > max_reconnects:
            stats.notes.append(f"gave up after {max_reconnects} reconnects")
            return stats
        delay = min(backoff_max, backoff_base * (2 ** (reconnects - 1))) * (0.8 + 0.4 * random.random())
        stats.notes.append(f"reconnect {reconnects} in {delay:.1f}s")
        sleep(delay)
