"""
agentdefense: a Jev-powered guard for AI agents.

  agentdefense install <agent>          claude | codex | copilot | gemini | cursor | opencode
  agentdefense uninstall <agent>
  agentdefense key <api-key>            save your TypeSafe key for every host (0600 file)
  agentdefense action --user "…" --command "…" [--reason "…"]     check one tool call
  agentdefense content (--file F | --url U | --text T) --task "…"  scan text for prompt injection
  agentdefense scan-skills [paths…] [--user]                     check skills / CLAUDE.md / rules
  agentdefense eval [--mock]                                     accuracy on the labeled test set
  agentdefense hook [--agent X]          (hosts call this: JSON event on stdin, JSON answer on stdout)
  agentdefense check | scan              (adapters call these: JSON in, JSON out)

Add --mock to use the offline stand-in, --json for machine-readable output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import urllib.request
from dataclasses import asdict
from pathlib import Path

from . import ActionGate, ActionRequest, ContentGate, Session, default_backend, wrap_untrusted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentdefense", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mock", action="store_true", help="use the offline keyword stand-in instead of Jev")
    parser.add_argument("--json", action="store_true", help="print the full verdict as JSON")
    sub = parser.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("install", help="register the hook in an agent's config")
    i.add_argument("agent")
    i.add_argument("--project", help="Claude Code only: install into this project's .claude/settings.json instead of your user settings")
    u = sub.add_parser("uninstall", help="remove the hook from an agent's config")
    u.add_argument("agent")
    u.add_argument("--project")

    k = sub.add_parser("key", help="save your TypeSafe API key")
    k.add_argument("api_key")

    a = sub.add_parser("action", help="check a tool call")
    a.add_argument("--user", required=True, help="the user's request")
    a.add_argument("--command", required=True, help="the command the agent wants to run")
    a.add_argument("--reason", default="", help="the agent's stated reason")
    a.add_argument("--cwd", default=None, help="working directory (default: current)")
    a.add_argument("--project-root", default=None)

    c = sub.add_parser("content", help="scan text/HTML for prompt injection")
    src = c.add_mutually_exclusive_group(required=True)
    src.add_argument("--file")
    src.add_argument("--url")
    src.add_argument("--text")
    c.add_argument("--task", required=True, help="what the user asked the agent to do with this content")

    s = sub.add_parser("scan-skills", help="check instruction files (skills, rules, CLAUDE.md/AGENTS.md)")
    s.add_argument("paths", nargs="*", help="files or folders (default: this project)")
    s.add_argument("--user", action="store_true", help="also sweep every agent's user folders (~/.claude/skills, ~/.codex, …)")

    e = sub.add_parser("eval", help="measure accuracy on the labeled test set")
    e.add_argument("--cases", default=None, help="path to a cases .jsonl file")
    e.add_argument("--out", default=None, help="write a Markdown report here")

    h = sub.add_parser("hook", help="universal hook entry point (hosts call this)")
    h.add_argument("--agent", default=None)
    sub.add_parser("check", help="adapter interface: JSON action on stdin, JSON verdict on stdout")
    sub.add_parser("scan", help="adapter interface: JSON content on stdin, JSON scan result on stdout")
    return parser


async def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)

    # Commands that don't need (or must not eagerly create) a Jev client.
    if args.cmd in ("install", "uninstall"):
        from .install import install, uninstall

        project = Path(args.project).resolve() if args.project else None
        if args.cmd == "uninstall":
            print(f"AgentDefense removed from {uninstall(args.agent, project=project)}")
            return 0
        path, note = install(args.agent, project=project)
        print(f"AgentDefense installed for {args.agent}: {path}")
        if note:
            print(note)
        from .config import resolve_api_key

        if not resolve_api_key():
            print("No API key found yet: run `agentdefense key <key>`. Until then every checked call asks for confirmation.")
        return 0
    if args.cmd == "key":
        from .config import save_api_key

        print(f"Saved to {save_api_key(args.api_key)} (readable only by you).")
        return 0

    jev = default_backend(force_mock=args.mock)
    print(f"backend: {jev.name}", file=sys.stderr)
    try:
        return await _run(args, jev)
    finally:
        if hasattr(jev, "aclose"):
            await jev.aclose()


async def _run(args, jev) -> int:
    if args.cmd == "check":
        # stdin: {"user_request", "command" | "tool_input", "reason", "tool", "cwd", "project_root", "session_id"}
        event = json.load(sys.stdin)
        if event.get("tool_input") is not None:
            from .describe import describe

            tool_type, command, paths = describe(event.get("tool", "bash"), event["tool_input"], event.get("cwd") or os.getcwd())
            event.setdefault("command", command)
            event["tool"], event["target_paths"] = tool_type, event.get("target_paths") or paths
        session = Session.load(session_id=event.get("session_id", "adapter"))
        req = ActionRequest(
            user_request=event.get("user_request") or "",
            command=event.get("command", ""),
            agent_reason=event.get("reason") or "",
            tool=event.get("tool") or "shell",
            working_directory=event.get("cwd") or os.getcwd(),
            project_root=event.get("project_root"),
            target_paths=event.get("target_paths") or [],
        )
        try:
            v = await ActionGate(jev, session).check(req)
        finally:
            session.save()
        print(json.dumps({"decision": v.decision.value, "reasons": v.reasons, "signals": v.signals, "stage": v.stage, "scope_level": v.scope_level, "latency_ms": round(v.latency_ms)}))
        return 0

    if args.cmd == "scan":
        event = json.load(sys.stdin)
        session = Session.load(session_id=event.get("session_id", "adapter"))
        try:
            text, source = event.get("text", ""), event.get("source") or "tool output"
            from .instructions import INSTRUCTION_FILE, scan_text

            if INSTRUCTION_FILE.search(source):
                r = await scan_text(jev, text, source)
                print(json.dumps({"status": "injection" if r and r.flagged else "clean", "instruction_file": True, "message": r.message if r else "", "flagged": [], "safe_text": text}))
                return 0
            v = await ContentGate(jev, session).scan(text, user_task=event.get("user_task") or "(unknown)", source=source)
        finally:
            session.save()  # taint persists for the next action check
        print(json.dumps({
            "status": v.status,
            "flagged": [{"index": f.index, "hidden": f.hidden, "why_hidden": f.why_hidden, "triggers": f.triggers, "excerpt": f.excerpt[:200]} for f in v.flagged],
            "safe_text": v.safe_text,
            "chunks_scanned": v.chunks_scanned,
        }))
        return 0

    if args.cmd == "action":
        req = ActionRequest(args.user, args.command, args.reason, project_root=args.project_root)
        if args.cwd:
            req.working_directory = args.cwd
        v = await ActionGate(jev).check(req)
        if args.json:
            print(json.dumps(asdict(v), indent=2, default=str))
        else:
            print(f"{v.decision.value}  (stage: {v.stage}, {v.latency_ms:.0f} ms, model: {v.model})")
            for r in v.reasons:
                print(f"  - {r}")
            for k, val in v.signals.items():
                print(f"    {k:28} {val}")
        return 0 if v.decision.value == "ALLOW" else 1

    if args.cmd == "scan-skills":
        from .instructions import find_instruction_files, project_roots, scan_files, user_roots

        roots = [Path(p) for p in args.paths] or project_roots(os.getcwd())
        if args.user:
            roots += user_roots()
        files = find_instruction_files(roots)
        results = await scan_files(jev, files)
        flagged = [r for r in results if r.flagged]
        for r in results:
            mark = "FLAG " if r.flagged else "ok   "
            print(f"{mark} {r.kind:24} p={r.p:.2f} {'(cached) ' if r.cached else ''}{r.source}{'  ERROR ' + r.error if r.error else ''}")
        print(f"\n{len(results)} instruction files checked, {len(flagged)} flagged.")
        return 2 if flagged else 0

    if args.cmd == "eval":
        from .evals import run_eval

        return await run_eval(jev, args.cases, args.out)

    # content
    if args.file:
        content, source = open(args.file, encoding="utf-8", errors="replace").read(), args.file
    elif args.url:
        with urllib.request.urlopen(args.url, timeout=15) as resp:  # noqa: S310 (user-supplied URL, CLI tool)
            content, source = resp.read().decode("utf-8", errors="replace"), args.url
    else:
        content, source = args.text, "command line"
    v = await ContentGate(jev, Session()).scan(content, user_task=args.task, source=source)
    if args.json:
        print(json.dumps(asdict(v), indent=2, default=str))
    else:
        print(f"{v.status.upper()}  ({v.chunks_scanned} chunks scanned, {v.chunks_skipped} skipped)")
        for f in v.findings:
            if f.status != "clean":
                print(f"  chunk {f.index} [{'hidden: ' + f.why_hidden if f.hidden else 'visible'}] {f.status}: {'; '.join(f.triggers)}")
                print(f"    {f.excerpt[:160]!r}")
        print("\n--- what the agent would receive ---")
        print(wrap_untrusted(v.safe_text, source))
    return 0 if v.status == "clean" else 1


def cli() -> None:
    """Console-script entry point (`agentdefense …`), installed by pyproject.toml."""
    argv = sys.argv[1:]
    if argv[:1] == ["hook"]:
        # The hook runs its own event loop, so it must start outside ours. It's also the hot
        # path (every tool call), so skip argparse and the other imports entirely.
        from .hosts import main as hook_main

        hook_main(argv[1:])
        return
    sys.exit(asyncio.run(main(argv)))


if __name__ == "__main__":
    cli()
