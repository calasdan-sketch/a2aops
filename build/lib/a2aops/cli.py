"""a2aops command-line interface.

Subcommands:
  card check <base>        fetch + validate + lint an AgentCard
  card fetch <base>        print the raw AgentCard JSON
  compat <base|file>       v0.x -> v1.0 migration report
  auth <base>              read-only auth-surface consistency check
  task poll <base> <id>    poll a task to a terminal state, report violations
  task inspect <events>    inspect a JSONL event log for lifecycle violations
  stream <base> <id>       SSE stream with resubscribe + dedupe
  play demo | run <file>   local multi-agent playground

Exit codes: 0 = clean, 1 = findings reported, 2 = usage/operational failure.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import authcheck as auth_mod
from . import compat as compat_mod
from . import sse as sse_mod
from . import tasks as tasks_mod
from .card import (CardFetchError, check_card, fetch_card, format_diagnostics,
                   has_errors)
from .playground import demo_scenario, run_scenario, Scenario
from .spec import spec_version


def _read_card_source(source: str):
    """A card source is a base URL, or a path to a JSON file, or '-' for stdin."""
    if source == "-":
        return json.load(sys.stdin), None
    try:
        with open(source, encoding="utf-8") as f:
            return json.load(f), None
    except (OSError, ValueError):
        pass
    card, info = fetch_card(source)
    return card, info


def cmd_card_check(args) -> int:
    try:
        card, info = fetch_card(args.base, timeout=args.timeout)
    except CardFetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"fetched {info.resolved_url} (HTTP {info.status}, {info.elapsed_ms}ms)")
    if info.legacy_fallback:
        print("note: v1.0 path 404'd; fell back to legacy /.well-known/agent.json")
    diags = check_card(card)
    print(format_diagnostics(diags))
    return 1 if has_errors(diags) else 0


def cmd_card_fetch(args) -> int:
    try:
        card, info = fetch_card(args.base, timeout=args.timeout)
    except CardFetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(card, indent=2))
    return 0


def cmd_compat(args) -> int:
    try:
        card, info = _read_card_source(args.source)
    except CardFetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as e:
        print(f"error: cannot read card source: {e}", file=sys.stderr)
        return 2
    print(f"a2aops {__version__} — spec snapshot v{spec_version()}")
    print(f"detected card version: {compat_mod.detect_card_version(card)}")
    items = compat_mod.compat_report(card, info)
    print(compat_mod.format_report(items))
    return 1 if compat_mod.needs_migration(items) else 0


def cmd_auth(args) -> int:
    try:
        card, info = fetch_card(args.base, timeout=args.timeout)
    except CardFetchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    diags = auth_mod.check_auth_surface(card, timeout=args.timeout,
                                        check_remote=not args.offline)
    print(format_diagnostics(diags) if diags
          else "OK: auth surface is consistent (no credentials were requested).")
    return 1 if has_errors(diags) else 0


def cmd_task_poll(args) -> int:
    binding = tasks_mod.rest_get_task if args.binding == "rest" else tasks_mod.jsonrpc_get_task

    def on_obs(obs):
        print(f"{obs.task_id}: {obs.state}" + (f" — {obs.message}" if obs.message else ""))

    insp = tasks_mod.poll_task(args.base, args.task_id, fetch=binding,
                               interval=args.interval, timeout=args.timeout,
                               on_observation=on_obs)
    print("---")
    print(insp.format())
    return 1 if any(d.severity == "error" for d in insp.report()) else 0


def cmd_task_inspect(args) -> int:
    try:
        observations = tasks_mod.observations_from_jsonl(args.events)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    insp = tasks_mod.TaskInspector()
    for obs in observations:
        insp.observe(obs)
    print(insp.format())
    print("---")
    print(json.dumps(insp.summary(), indent=2))
    return 1 if any(d.severity == "error" for d in insp.report()) else 0


def cmd_stream(args) -> int:
    received: list[str] = []

    def on_event(ev):
        line = f"[{ev.id or '-'}] {ev.event or 'message'}: {ev.data[:200]}"
        print(line)
        received.append(line)

    stats = sse_mod.stream_with_resubscribe(
        args.base, args.task_id, binding=args.binding,
        on_event=on_event, max_events=args.max_events,
        max_reconnects=args.max_reconnects)
    print("---")
    print(f"events={stats.events} duplicates_skipped={stats.duplicates} "
          f"reconnects={stats.reconnects} closed_on_terminal={stats.closed_on_terminal}")
    for note in stats.notes:
        print(f"note: {note}")
    return 0


def cmd_play_demo(args) -> int:
    scenario = demo_scenario()
    report = run_scenario(scenario, args.log)
    print(f"agents: {', '.join(report.agents)}")
    print(f"steps: {report.steps}  elapsed: {report.elapsed_s:.1f}s  log: {report.log_path}")
    for t in report.tasks:
        task = t["task"]
        state = (task.get("status") or {}).get("state")
        print(f"  {t['from']} -> {t['to']}: {task.get('id')} ended {state}")
    return 0


def cmd_play_run(args) -> int:
    try:
        scenario = Scenario.from_json(args.scenario)
    except (OSError, ValueError) as e:
        print(f"error: cannot load scenario: {e}", file=sys.stderr)
        return 2
    report = run_scenario(scenario, args.log)
    print(f"agents: {', '.join(report.agents)}  steps: {report.steps}  log: {report.log_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="a2aops",
                                description="Operational toolkit for the A2A protocol "
                                            f"(spec snapshot v{spec_version()}). Zero dependencies.")
    p.add_argument("--version", action="version", version=f"a2aops {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("card", help="fetch / validate / lint AgentCards")
    csub = c.add_subparsers(dest="card_cmd", required=True)
    cc = csub.add_parser("check", help="fetch, validate, and lint a card")
    cc.add_argument("base", help="agent base URL, e.g. https://agent.example.com")
    cc.add_argument("--timeout", type=float, default=10.0)
    cc.set_defaults(func=cmd_card_check)
    cf = csub.add_parser("fetch", help="print the raw AgentCard JSON")
    cf.add_argument("base")
    cf.add_argument("--timeout", type=float, default=10.0)
    cf.set_defaults(func=cmd_card_fetch)

    cp = sub.add_parser("compat", help="v0.x -> v1.0 migration report")
    cp.add_argument("source", help="base URL, JSON file, or '-' for stdin")
    cp.set_defaults(func=cmd_compat)

    au = sub.add_parser("auth", help="read-only auth-surface consistency check")
    au.add_argument("base")
    au.add_argument("--timeout", type=float, default=10.0)
    au.add_argument("--offline", action="store_true",
                    help="skip fetching remote OIDC discovery documents")
    au.set_defaults(func=cmd_auth)

    t = sub.add_parser("task", help="task lifecycle tools")
    tsub = t.add_subparsers(dest="task_cmd", required=True)
    tp = tsub.add_parser("poll", help="poll a task to a terminal state")
    tp.add_argument("base")
    tp.add_argument("task_id")
    tp.add_argument("--binding", choices=["rest", "jsonrpc"], default="rest")
    tp.add_argument("--interval", type=float, default=2.0)
    tp.add_argument("--timeout", type=float, default=300.0)
    tp.set_defaults(func=cmd_task_poll)
    ti = tsub.add_parser("inspect", help="inspect a JSONL event log")
    ti.add_argument("events", help="JSONL file with {task_id, state, message?} per line")
    ti.set_defaults(func=cmd_task_inspect)

    st = sub.add_parser("stream", help="SSE stream with resubscribe + dedupe")
    st.add_argument("base")
    st.add_argument("task_id")
    st.add_argument("--binding", choices=["rest", "jsonrpc"], default="rest")
    st.add_argument("--max-events", type=int, default=0,
                    help="stop after N events (0 = unlimited)")
    st.add_argument("--max-reconnects", type=int, default=10)
    st.set_defaults(func=cmd_stream)

    pl = sub.add_parser("play", help="local multi-agent playground")
    plsub = pl.add_subparsers(dest="play_cmd", required=True)
    pd = plsub.add_parser("demo", help="run the built-in two-agent demo")
    pd.add_argument("--log", default="a2aops-session.jsonl")
    pd.set_defaults(func=cmd_play_demo)
    pr = plsub.add_parser("run", help="run a scenario JSON file")
    pr.add_argument("scenario")
    pr.add_argument("--log", default="a2aops-session.jsonl")
    pr.set_defaults(func=cmd_play_run)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
