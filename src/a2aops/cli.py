"""a2aops command-line interface.

Subcommands:
  card check <src>         validate + lint an AgentCard (URL, file, or -)
  card fetch <base>        print the raw AgentCard JSON
  card diff <old> <new>    breaking-change report between two cards
  compat <src>             v0.x -> v1.0 migration report
  auth <src>               read-only auth-surface consistency check
  task poll <base> <id>    poll a task to a terminal state, report violations
  task inspect <events>    inspect a JSONL event log for lifecycle violations
  stream <base> <id>       SSE stream with resubscribe + dedupe
  play demo | run <file>   local multi-agent playground

Exit codes: 0 = clean, 1 = findings reported, 2 = usage/operational failure.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse

from . import __author__, __version__
from . import authcheck as auth_mod
from . import compat as compat_mod
from . import sse as sse_mod
from . import tasks as tasks_mod
from . import report as report_mod
from . import suppress
from .card import (CardFetchError, check_card, fetch_card, format_diagnostics,
                   read_card_source)
from .diff import diff_cards
from .net import clean, loads_strict
from .playground import demo_scenario, run_scenario, Scenario
from .spec import spec_version


def _load(args, source: str):
    """Load a card from a URL, file, or '-'. Returns (card, info, label, text).

    The file is read exactly once; ``text`` is that same content (used for
    SARIF line lookup). ``label`` is a valid URI reference for SARIF.
    """
    src = read_card_source(source, timeout=getattr(args, "timeout", 10.0),
                           card_path=getattr(args, "card_path", None))
    if src.kind == "url":
        return src.card, src.info, src.info.resolved_url, None
    if src.kind == "stdin":
        return src.card, None, "stdin", src.text
    return src.card, None, report_mod.path_to_uri(source), src.text


def _emit(args, diags, *, command: str, label: str, text=None,
          banner=(), ok_text="OK: no issues found.") -> int:
    fmt = getattr(args, "format", "text")
    strict = getattr(args, "strict", False)
    try:
        ignore = suppress.parse_ignore(getattr(args, "ignore", None))
        wb = getattr(args, "write_baseline", None)
        base_path = getattr(args, "baseline", None)
        if wb and base_path:
            raise suppress.SuppressError("use either --baseline or --write-baseline, not both")
        baseline = suppress.load_baseline(base_path) if base_path else None
        if wb:
            total = suppress.write_baseline(wb, suppress.apply(diags, ignore, None)[0])
            print(f"wrote {total} finding(s) to {wb}; future runs with --baseline {wb} fail only on new ones",
                  file=sys.stderr)
            return 0
        diags, hidden = suppress.apply(diags, ignore, baseline)
    except suppress.SuppressError as e:
        return _err(e)
    if fmt == "json":
        print(report_mod.to_json(diags, command=command, source=label, strict=strict,
                                 extra={"suppressed": hidden}))
    elif fmt == "sarif":
        print(report_mod.to_sarif(diags, command=command, artifact_uri=label, source_text=text))
    elif fmt == "junit":
        print(report_mod.to_junit(diags, command=command, source=label, strict=strict))
    else:
        for line in banner:
            print(clean(line))
        print(format_diagnostics(diags) if diags else ok_text)
        if hidden:
            print(f"({hidden} finding(s) hidden by --ignore/--baseline)")
    return 1 if report_mod.failed(diags, strict) else 0


def _pos_float(text: str) -> float:
    """argparse type: a finite number greater than zero (rejects 0, -5, nan, inf)."""
    try:
        v = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not (0 < v < 1e9):
        raise argparse.ArgumentTypeError(f"{text!r} must be a number greater than 0 (seconds)")
    return v


def _nonneg_int(text: str) -> int:
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if v < 0:
        raise argparse.ArgumentTypeError(f"{text!r} must be 0 or more")
    return v


def _err(e) -> int:
    print(f"error: {clean(e)}", file=sys.stderr)
    return 2


def cmd_card_check(args) -> int:
    try:
        card, info, label, text = _load(args, args.base)
    except CardFetchError as e:
        return _err(e)
    banner = []
    if info is not None:
        banner.append(f"fetched {info.resolved_url} (HTTP {info.status}, {info.elapsed_ms}ms)")
        if info.legacy_fallback:
            banner.append("note: v1.0 path 404'd; fell back to legacy /.well-known/agent.json")
    else:
        banner.append(f"read {'stdin' if args.base == '-' else args.base}")
    from . import cardsec
    from .card import INFO, WARNING, Diagnostic
    local = False
    if info is not None:
        host = urllib.parse.urlparse(info.resolved_url).hostname or ""
        local = cardsec.classify_host(host.lower()) != "public-or-name"
    diags = check_card(card, local_origin=local)
    if info is not None:
        diags += cardsec.lint_origin(card, info.resolved_url)
        if info.content_type and "json" not in info.content_type.lower():
            diags.append(Diagnostic(WARNING, "W215", f"card served as '{info.content_type}', expected application/json", ""))
        if not info.cache_control:
            diags.append(Diagnostic(INFO, "I215", "no Cache-Control header on the card (spec 8.6.1 SHOULD): "
                                    "clients and registries cannot cache it safely", ""))
        if not info.etag:
            diags.append(Diagnostic(INFO, "I216", "no ETag header on the card (spec 8.6.1 SHOULD): "
                                    "clients cannot revalidate cheaply", ""))
    return _emit(args, diags, command="card-check", label=label,
                 text=text, banner=banner)


def cmd_card_diff(args) -> int:
    if args.old == "-" and args.new == "-":
        print("error: only one of OLD/NEW can be '-' (stdin)", file=sys.stderr)
        return 2
    try:
        old, _, _, _ = _load(args, args.old)
        new, _, new_label, new_text = _load(args, args.new)
    except CardFetchError as e:
        return _err(e)
    diags = diff_cards(old, new)
    banner = [f"diff {'stdin' if args.old == '-' else args.old} -> {'stdin' if args.new == '-' else args.new}"]
    if args.semver or args.enforce_semver:
        from . import diff as diff_mod
        want = diff_mod.recommend_bump(old, new, diags)
        got = diff_mod.actual_bump(old.get("version") if isinstance(old, dict) else None,
                                   new.get("version") if isinstance(new, dict) else None)
        banner.append(f"recommended version bump: {want} (version moved: {got})")
        if args.enforce_semver:
            diags = diags + diff_mod.check_bump(old, new, diags)
    return _emit(args, diags, command="card-diff", label=new_label, text=new_text,
                 banner=banner,
                 ok_text="OK: no breaking or notable changes detected.")


def cmd_card_verify(args) -> int:
    from . import cardsig, jws
    try:
        card, info, label, text = _load(args, args.base)
    except CardFetchError as e:
        return _err(e)
    keys: list[dict] = []
    for src in args.jwks or []:
        try:
            if src.startswith(("http://", "https://")):
                doc = cardsig._fetch_jwks(src, args.timeout)
            else:
                with open(src, "rb") as f:
                    doc = loads_strict(f.read(1 << 20).decode("utf-8-sig"))
            keys += jws.load_jwks(doc)
        except (OSError, ValueError, jws.JwsError) as e:
            return _err(f"cannot load keys from {src}: {e}")
        except Exception as e:  # noqa: BLE001 - UnsafeURL and friends
            return _err(f"cannot load keys from {src}: {e}")
    host = urllib.parse.urlparse(info.resolved_url).hostname if info is not None else None
    diags = cardsig.verify_card(card, keys, card_host=host, trust_jku=args.trust_jku,
                                timeout=args.timeout)
    if not keys and not args.trust_jku:
        from .card import Diagnostic
        diags.append(Diagnostic(
            "warning", "G905", "no trusted keys supplied (use --jwks FILE|URL); nothing can verify", ""))
    return _emit(args, diags, command="card-verify", label=label, text=text,
                 banner=[f"verify signatures of {'stdin' if args.base == '-' else args.base}"],
                 ok_text="OK")


def _parse_headers(items) -> dict:
    out: dict = {}
    for item in items or []:
        name, sep, value = item.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not name or not all(c.isalnum() or c in "-_" for c in name) \
                or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(f"bad --header {name or item!r}: expected 'Name: value' without control characters")
        out[name] = value
    return out


def cmd_conformance(args) -> int:
    from . import conformance as conf
    try:
        headers = _parse_headers(args.header)
    except ValueError as e:
        return _err(e)
    bindings = set(args.binding) if args.binding else None
    known = {c.id for c in conf.REGISTRY}
    chosen: dict[str, set] = {}
    for flag in ("only", "skip"):
        ids = {i.strip().upper() for v in (getattr(args, flag) or []) for i in v.split(",") if i.strip()}
        unknown = sorted(ids - known)
        if unknown:   # a typo must not turn into a green run that checked nothing
            return _err(f"--{flag}: unknown check id(s) {', '.join(unknown)}; "
                        f"known ids look like {sorted(known)[0]} ... {sorted(known)[-1]}")
        chosen[flag] = ids
    if chosen["only"] and chosen["only"] <= chosen["skip"]:
        return _err("--only and --skip together leave no checks to run")
    ctx, results = conf.run(args.url, active=args.active, timeout=args.timeout, headers=headers,
                            card_path=args.card_path, bindings=bindings,
                            allow_private_endpoints=args.allow_private_endpoints,
                            only_ids=chosen["only"] or None, skip_ids=chosen["skip"] or None)
    if ctx.card_http is not None and ctx.card_http.error:
        return _err(f"cannot reach {ctx.card_url}: {ctx.card_http.error}")
    for b in sorted(bindings or ()):
        if isinstance(ctx.card, dict) and getattr(ctx, "jsonrpc" if b == "jsonrpc" else "rest", None) is None:
            why = (f" (not probed, points into a private network: {', '.join(ctx.refused[:2])}; "
                   "pass --allow-private-endpoints if you trust this card)") if ctx.refused else ""
            return _err(f"--binding {b}: the card offers no usable {b} v1.x interface, so nothing would be tested{why}")
    if results and all(r.status == conf.SKIP for r in results):
        return _err("every check was skipped, so nothing was verified (use --active, or check --binding/--only)")
    fmt = args.format
    if fmt == "json":
        print(conf.to_json(results, args.url, args.active))
    elif fmt == "junit":
        print(conf.to_junit(results, args.url))
    elif fmt == "sarif":
        print(report_mod.to_sarif(conf.to_diagnostics(results), command="conformance",
                                  artifact_uri=ctx.card_url or args.url, source_text=None))
    else:
        print(conf.to_text(results, args.url, args.active))
    return 1 if conf.failed(results, args.strict) else 0


def cmd_explain(args) -> int:
    from . import explain as explain_mod
    if not args.code:
        for code in sorted(explain_mod.CODES):
            print(f"{code}  {explain_mod.CODES[code][0]}")
        return 0
    text = explain_mod.explain(args.code)
    for line in text.splitlines():
        print(clean(line))
    return 0 if args.code.strip().upper() in explain_mod.CODES else 2


def cmd_card_fetch(args) -> int:
    try:
        card, info = fetch_card(args.base, timeout=args.timeout, card_path=args.card_path)
    except CardFetchError as e:
        return _err(e)
    print(json.dumps(card, indent=2))
    return 0


def cmd_compat(args) -> int:
    try:
        card, info, label, _ = _load(args, args.source)
    except CardFetchError as e:
        return _err(e)
    version = compat_mod.detect_card_version(card)
    items = compat_mod.compat_report(card, info)
    needs = compat_mod.needs_migration(items)
    if args.format == "json":
        print(json.dumps({"tool": "a2aops", "version": __version__, "command": "compat",
                          "source": label, "spec_version": spec_version(),
                          "detected_card_version": version, "ok": not needs,
                          "items": [i.to_dict() for i in items]}, indent=2))
    else:
        print(f"a2aops {__version__} — spec snapshot v{spec_version()}")
        print(f"detected card version: {version}")
        print(compat_mod.format_report(items))
    return 1 if needs else 0


def cmd_auth(args) -> int:
    try:
        card, info, label, text = _load(args, args.base)
    except CardFetchError as e:
        return _err(e)
    diags = auth_mod.check_auth_surface(card, timeout=args.timeout,
                                        check_remote=not args.offline,
                                        allow_private=args.allow_private)
    return _emit(args, diags, command="auth", label=label, text=text,
                 ok_text="OK: auth surface is consistent (no credentials were requested).")


def cmd_task_poll(args) -> int:
    if args.binding == "rest":
        binding = tasks_mod.rest_get_task
    else:
        legacy = getattr(args, "legacy", False)
        binding = lambda b, t: tasks_mod.jsonrpc_get_task(b, t, legacy=legacy)  # noqa: E731

    def on_obs(obs):
        print(clean(f"{obs.task_id}: {obs.state}" + (f" — {obs.message}" if obs.message else "")))

    insp = tasks_mod.poll_task(args.base, args.task_id, fetch=binding,
                               interval=args.interval, timeout=args.timeout,
                               on_observation=on_obs)
    print("---")
    print(insp.format())
    return 1 if any(d.severity == "error" for d in insp.report()) else 0


def cmd_task_inspect(args) -> int:
    try:
        observations = tasks_mod.observations_from_jsonl(args.events)
    except FileNotFoundError:
        return _err(f"file not found: {args.events}")
    except (OSError, ValueError) as e:
        return _err(e)
    insp = tasks_mod.TaskInspector()
    for obs in observations:
        insp.observe(obs)
    print(insp.format())  # every line already passes through clean()
    print("---")
    print(json.dumps(insp.summary(), indent=2))  # JSON-escaped (ASCII)
    return 1 if any(d.severity == "error" for d in insp.report()) else 0


def cmd_stream(args) -> int:
    def on_event(ev):
        print(clean(f"[{ev.id or '-'}] {ev.event or 'message'}: {ev.data[:200]}"))

    stats = sse_mod.stream_with_resubscribe(
        args.base, args.task_id, binding=args.binding,
        on_event=on_event, max_events=args.max_events,
        max_reconnects=args.max_reconnects, legacy=getattr(args, "legacy", False))
    print("---")
    print(f"events={stats.events} duplicates_skipped={stats.duplicates} "
          f"reconnects={stats.reconnects} closed_on_terminal={stats.closed_on_terminal}")
    for note in stats.notes:
        print(clean(f"note: {note}"))
    return 1 if stats.gave_up else 0   # a stream that never reached a verdict must not look green


def cmd_play_demo(args) -> int:
    scenario = demo_scenario()
    try:
        report = run_scenario(scenario, args.log)
    except OSError as e:
        return _err(f"cannot write the session log {args.log}: {e}")
    print(f"agents: {', '.join(report.agents)}")
    print(f"steps: {report.steps}  elapsed: {report.elapsed_s:.1f}s  log: {report.log_path}")
    for t in report.tasks:
        task = t["task"]
        state = (task.get("status") or {}).get("state")
        print(clean(f"  {t['from']} -> {t['to']}: {task.get('id')} ended {state}"))
    return 0


def cmd_play_run(args) -> int:
    try:
        scenario = Scenario.from_json(args.scenario)
    except (OSError, ValueError) as e:
        return _err(f"cannot load scenario: {e}")
    try:
        report = run_scenario(scenario, args.log)
    except OSError as e:
        return _err(f"cannot write the session log {args.log}: {e}")
    print(f"agents: {', '.join(report.agents)}  steps: {report.steps}  log: {report.log_path}")
    return 0


_OUTPUT_HELP = ("write the report to FILE (UTF-8, no BOM, LF line ends) instead of stdout; "
                "the exit code is unchanged, and nothing is written when the run itself fails (exit 2)")


def _write_report(path: str, text: str) -> None:
    """Write ``text`` to ``path`` as UTF-8 without BOM, via a temp file so a crash cannot leave half a report."""
    data = text.replace("\r\n", "\n").encode("utf-8", "backslashreplace")
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        except OSError:
            with open(path, "wb") as f:      # rename refused (Windows, some shares): write in place
                f.write(data)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="a2aops",
                                description="Operational toolkit for the A2A protocol "
                                            f"(spec snapshot v{spec_version()}). Zero dependencies.",
                                epilog=f"a2aops {__version__} by {__author__}. MIT licence.")
    p.add_argument("--version", action="version", version=f"a2aops {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("card", help="fetch / validate / lint AgentCards")
    csub = c.add_subparsers(dest="card_cmd", required=True)
    src_help = "agent base URL, a card JSON file, or '-' for stdin"

    def fetch_opts(sp):
        sp.add_argument("--timeout", type=_pos_float, default=10.0)
        sp.add_argument("--card-path", default=None, metavar="PATH",
                        help="fetch the card from this path instead of /.well-known discovery")

    def filter_opts(sp):
        sp.add_argument("--ignore", action="append", metavar="CODE",
                        help="hide a code or prefix, e.g. W203 or S8 (repeatable, comma-separated); hidden count is reported")
        sp.add_argument("--baseline", metavar="FILE", help="hide findings recorded in FILE; fail only on new ones")
        sp.add_argument("--write-baseline", metavar="FILE",
                        help="record the current findings in FILE and exit 0")

    def out_opts(sp, sarif=True):
        sp.add_argument("--format", choices=["text", "json", "sarif", "junit"] if sarif else ["text", "json"],
                        default="text", help="output format (sarif = GitHub code scanning, junit = CI test report)")
        if sarif:
            sp.add_argument("--strict", action="store_true", help="warnings also fail (exit 1)")
        sp.add_argument("--output", metavar="FILE", help=_OUTPUT_HELP)

    cc = csub.add_parser("check", help="validate and lint a card (URL, file, or stdin)")
    cc.add_argument("base", metavar="source", help=src_help)
    fetch_opts(cc)
    out_opts(cc)
    filter_opts(cc)
    cc.set_defaults(func=cmd_card_check)
    cf = csub.add_parser("fetch", help="print the raw AgentCard JSON")
    cf.add_argument("base")
    fetch_opts(cf)
    cf.set_defaults(func=cmd_card_fetch)
    cv = csub.add_parser("verify", help="verify the card's JWS signatures against keys you trust")
    cv.add_argument("base", metavar="source", help=src_help)
    cv.add_argument("--jwks", action="append", metavar="FILE|URL",
                    help="trusted public key(s): a JWK Set or single JWK (repeatable)")
    cv.add_argument("--trust-jku", action="store_true",
                    help="also fetch the signature's jku, only if it is on the card's own host (SSRF-guarded)")
    fetch_opts(cv)
    out_opts(cv)
    filter_opts(cv)
    cv.set_defaults(func=cmd_card_verify)
    cd = csub.add_parser("diff", help="report breaking changes between two cards")
    cd.add_argument("old", help="the card clients use today (" + src_help + ")")
    cd.add_argument("new", help="the proposed card")
    fetch_opts(cd)
    out_opts(cd)
    filter_opts(cd)
    cd.add_argument("--semver", action="store_true",
                    help="print the version bump these changes deserve (major/minor/patch/none)")
    cd.add_argument("--enforce-semver", action="store_true",
                    help="fail (D610) when the new card's version moved less than the recommended bump")
    cd.set_defaults(func=cmd_card_diff)

    ex = sub.add_parser("explain", help="what a diagnostic code means and how to fix it")
    ex.add_argument("code", nargs="?", help="e.g. E341 (omit to list every code)")
    ex.set_defaults(func=cmd_explain)

    cp = sub.add_parser("compat", help="v0.x -> v1.0 migration report")
    cp.add_argument("source", help=src_help)
    fetch_opts(cp)
    out_opts(cp, sarif=False)
    cp.set_defaults(func=cmd_compat)

    au = sub.add_parser("auth", help="read-only auth-surface consistency check")
    au.add_argument("base", metavar="source", help=src_help)
    fetch_opts(au)
    out_opts(au)
    filter_opts(au)
    au.add_argument("--offline", action="store_true",
                    help="skip fetching remote OIDC discovery documents")
    au.add_argument("--allow-private", action="store_true",
                    help="let card-supplied URLs reach loopback/private addresses "
                         "(local dev only; disables the SSRF guard)")
    au.set_defaults(func=cmd_auth)

    t = sub.add_parser("task", help="task lifecycle tools")
    tsub = t.add_subparsers(dest="task_cmd", required=True)
    tp = tsub.add_parser("poll", help="poll a task to a terminal state")
    tp.add_argument("base")
    tp.add_argument("task_id")
    tp.add_argument("--binding", choices=["rest", "jsonrpc"], default="rest")
    tp.add_argument("--interval", type=_pos_float, default=2.0)
    tp.add_argument("--timeout", type=_pos_float, default=300.0)
    tp.add_argument("--legacy", action="store_true",
                    help="speak the pre-1.0 (0.3) JSON-RPC dialect (tasks/get)")
    tp.set_defaults(func=cmd_task_poll)
    ti = tsub.add_parser("inspect", help="inspect a JSONL event log")
    ti.add_argument(
        "events",
        help="JSONL file with {task_id, state, message?} per line, "
        "or a playground wire log (a2aops play demo --log ...)",
    )
    ti.set_defaults(func=cmd_task_inspect)

    st = sub.add_parser("stream", help="SSE stream with resubscribe + dedupe")
    st.add_argument("base")
    st.add_argument("task_id")
    st.add_argument("--binding", choices=["rest", "jsonrpc"], default="rest")
    st.add_argument("--max-events", type=_nonneg_int, default=0,
                    help="stop after N events (0 = unlimited)")
    st.add_argument("--max-reconnects", type=_nonneg_int, default=10)
    st.add_argument("--legacy", action="store_true",
                    help="speak the pre-1.0 (0.3) wire dialect: tasks/resubscribe, /v1/ REST path")
    st.set_defaults(func=cmd_stream)

    cf2 = sub.add_parser("conformance", help="live A2A v1.0 protocol checks against an agent URL")
    cf2.add_argument("url", help="agent base URL (its card is read from /.well-known/agent-card.json)")
    cf2.add_argument("--active", action="store_true",
                     help="also run probes that create a task (sends one harmless text message)")
    cf2.add_argument("--format", choices=["text", "json", "junit", "sarif"], default="text")
    cf2.add_argument("--output", metavar="FILE", help=_OUTPUT_HELP)
    cf2.add_argument("--strict", action="store_true", help="SHOULD-level failures (warnings) also fail")
    cf2.add_argument("--header", action="append", metavar="'Name: value'",
                     help="extra request header, e.g. Authorization (sent only to the card's own host; never printed)")
    cf2.add_argument("--binding", action="append", choices=["jsonrpc", "rest"],
                     help="test only this binding (repeatable; default: all offered)")
    cf2.add_argument("--only", action="append", metavar="ID", help="run only this check id (repeatable; unknown ids are an error)")
    cf2.add_argument("--skip", action="append", metavar="ID", help="do not run this check id (repeatable; unknown ids are an error)")
    cf2.add_argument("--allow-private-endpoints", action="store_true",
                     help="also probe card interfaces that point at loopback/private/metadata addresses "
                          "(refused by default when the card itself comes from a public host)")
    cf2.add_argument("--timeout", type=_pos_float, default=10.0)
    cf2.add_argument("--card-path", default=None, metavar="PATH")
    cf2.set_defaults(func=cmd_conformance)

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
    # Findings echo card text. A console or pipe that cannot encode a character
    # (cp1252 on Windows, ASCII in a minimal container) must degrade to an
    # escape, never to a traceback that hides the verdict.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass  # not a TextIOWrapper (tests, embedding): leave it alone
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        out_path = getattr(args, "output", None)
        if not out_path:
            return args.func(args)
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = args.func(args)
        if rc in (0, 1) and buf.getvalue():
            try:
                _write_report(out_path, buf.getvalue())
            except OSError as e:
                return _err(f"cannot write {out_path}: {e.strerror or e}")
            print(f"wrote report to {out_path}", file=sys.stderr)
        else:                        # failed run or nothing to report (e.g. --write-baseline): print as usual
            sys.stdout.write(buf.getvalue())
        return rc
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 2
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")   # silence the interpreter's flush-at-exit error
        except OSError:
            pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
