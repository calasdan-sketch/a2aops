"""Tests for SSE parsing and the resubscribe client."""

import io
import unittest

from a2aops.sse import (SSEEvent, build_resubscribe_request, parse_sse_stream,
                        stream_with_resubscribe)


def sse_text(s):
    return iter(s.splitlines(keepends=True))


class TestParse(unittest.TestCase):
    def test_basic_event(self):
        events = list(parse_sse_stream(sse_text("id: 1\nevent: ping\ndata: hello\n\n")))
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual((ev.id, ev.event, ev.data), ("1", "ping", "hello"))

    def test_crlf_and_lone_cr(self):
        events = list(parse_sse_stream(iter(["id: 2\r\ndata: a\r\n\r\n",
                                             "data: b\r\r"])))
        self.assertEqual(events[0].data, "a")
        self.assertEqual(events[1].data, "b")

    def test_multiline_data_joined(self):
        events = list(parse_sse_stream(sse_text("data: line1\ndata: line2\n\n")))
        self.assertEqual(events[0].data, "line1\nline2")

    def test_comments_observed(self):
        events = list(parse_sse_stream(sse_text(": keep-alive\n\ndata: x\n\n")))
        comments = [e for e in events if e.comment is not None]
        self.assertEqual(len(comments), 1)
        self.assertEqual(comments[0].comment, "keep-alive")

    def test_data_without_space(self):
        events = list(parse_sse_stream(sse_text("data:nospace\n\n")))
        self.assertEqual(events[0].data, "nospace")

    def test_retry_field(self):
        events = list(parse_sse_stream(sse_text("retry: 3000\ndata: x\n\n")))
        self.assertEqual(events[0].retry, 3000)

    def test_multiple_events(self):
        events = list(parse_sse_stream(sse_text("data: 1\n\ndata: 2\n\n")))
        self.assertEqual([e.data for e in events], ["1", "2"])

    def test_unknown_fields_ignored(self):
        events = list(parse_sse_stream(sse_text("mystery: 1\ndata: ok\n\n")))
        self.assertEqual(events[0].data, "ok")


class FakeResp:
    """Minimal SSE response double: yields chunks, then optionally raises."""

    def __init__(self, chunks, fail_after=None, exc=None):
        self._chunks = list(chunks)
        self._fail_after = fail_after
        self._exc = exc or ConnectionError("boom")
        self._n = 0

    def readline(self):
        if self._fail_after is not None and self._n >= self._fail_after:
            raise self._exc
        if self._n >= len(self._chunks):
            return b""
        line = self._chunks[self._n]
        self._n += 1
        return line

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def ev_text(eid, state):
    import json
    payload = json.dumps({"taskId": "t1",
                          "status": {"state": state},
                          "final": state in ("TASK_STATE_COMPLETED",)})
    return f"id: {eid}\nevent: TaskStatusUpdateEvent\ndata: {payload}\n\n".encode()


class TestResubscribe(unittest.TestCase):
    def test_build_requests(self):
        url, body, headers = build_resubscribe_request("https://x.example", "t9", "rest")
        self.assertEqual(url, "https://x.example/v1/tasks/t9:subscribe")
        self.assertIn(b"t9", body)

        url, body, headers = build_resubscribe_request("https://x.example/rpc", "t9", "jsonrpc")
        import json
        payload = json.loads(body)
        self.assertEqual(payload["method"], "tasks/resubscribe")
        self.assertEqual(headers["Content-Type"], "application/json")

        with self.assertRaises(ValueError):
            build_resubscribe_request("https://x.example", "t9", "smoke")

    def test_terminal_state_closes_stream(self):
        chunks = [ev_text("1", "TASK_STATE_WORKING"), ev_text("2", "TASK_STATE_COMPLETED")]
        opener = lambda *a, **k: FakeResp(chunks)
        seen = []
        stats = stream_with_resubscribe("https://x.example", "t1", opener=opener,
                                        on_event=seen.append, sleep=lambda s: None)
        self.assertTrue(stats.closed_on_terminal)
        self.assertEqual(stats.events, 2)
        self.assertEqual(stats.reconnects, 0)

    def test_broken_stream_resubscribes_and_dedupes(self):
        first = [ev_text("1", "TASK_STATE_WORKING"), ev_text("2", "TASK_STATE_WORKING")]
        # reconnect replays event 2 (duplicate) then delivers the terminal event
        second = [ev_text("2", "TASK_STATE_WORKING"), ev_text("3", "TASK_STATE_COMPLETED")]
        calls = {"n": 0}

        def opener(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                return FakeResp(first, fail_after=2)
            return FakeResp(second)

        seen = []
        stats = stream_with_resubscribe("https://x.example", "t1", opener=opener,
                                        on_event=seen.append, sleep=lambda s: None,
                                        max_reconnects=3)
        self.assertEqual(stats.reconnects, 1)
        self.assertEqual(stats.duplicates, 1)  # duplicate id "2" skipped, surfaced in stats
        self.assertTrue(stats.closed_on_terminal)
        self.assertEqual(len(seen), 3)  # ids 1, 2, 3

    def test_gives_up_after_max_reconnects(self):
        opener = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("down"))
        stats = stream_with_resubscribe("https://x.example", "t1", opener=opener,
                                        sleep=lambda s: None, max_reconnects=2)
        self.assertEqual(stats.reconnects, 3)  # attempts: 1 initial + 2 retries counted... see below
        self.assertTrue(any("gave up" in n for n in stats.notes))

    def test_unknown_state_noted(self):
        chunks = [ev_text("1", "TASK_STATE_MELTED"), ev_text("2", "TASK_STATE_COMPLETED")]
        opener = lambda *a, **k: FakeResp(chunks)
        stats = stream_with_resubscribe("https://x.example", "t1", opener=opener,
                                        sleep=lambda s: None)
        self.assertTrue(any("unknown state" in n for n in stats.notes))

    def test_callback_exception_propagates_not_masked(self):
        chunks = [ev_text("1", "TASK_STATE_WORKING"), ev_text("2", "TASK_STATE_COMPLETED")]

        def bad_callback(ev):
            raise RuntimeError("caller bug")

        opener = lambda *a, **k: FakeResp(chunks)
        with self.assertRaises(RuntimeError):
            stream_with_resubscribe("https://x.example", "t1", opener=opener,
                                    on_event=bad_callback, sleep=lambda s: None,
                                    max_reconnects=0)


if __name__ == "__main__":
    unittest.main()


class TestParseEdgeCases(unittest.TestCase):
    def test_empty_data_line_still_dispatches(self):
        # Per the SSE spec, a `data:` line with an empty value dispatches
        # an event with data == ""; only a dispatch with *no* data lines
        # at all is ignored.
        events = list(parse_sse_stream(sse_text("data:\n\n")))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].data, "")

    def test_bare_blank_line_dispatches_nothing(self):
        self.assertEqual(list(parse_sse_stream(sse_text("\n\n"))), [])

    def test_bom_at_stream_start_is_stripped(self):
        from a2aops.sse import _line_iter

        class FakeResp:
            def __init__(self, chunks):
                self._chunks = list(chunks)

            def readline(self):
                return self._chunks.pop(0) if self._chunks else b""

        events = list(
            parse_sse_stream(_line_iter(FakeResp([b"\xef\xbb\xbfdata: hi\n", b"\n"])))
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].data, "hi")
