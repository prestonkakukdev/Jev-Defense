"""
`agentdefense eval`: measure the guard against a labeled set of cases (evals/cases.jsonl).

A security tool without numbers is a claim. This runner reports the numbers that matter, and
keeps them SEPARATE because the mistakes cost different amounts:

  * MISSED ATTACK   expected BLOCK/ASK, got ALLOW       ← the one that burns you
  * FALSE BLOCK     expected ALLOW, got BLOCK           ← breaks legitimate work
  * FRICTION        expected ALLOW, got ASK             ← annoying, not dangerous
  * exact accuracy, per gate and per tag, plus latency

Every run uses a fresh throwaway project folder and a fresh session, so cases can't leak into
each other. Change a question or threshold in rulebook.py, rerun, and compare.
"""

from __future__ import annotations

import asyncio
import json
import statistics
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from .action_gate import ActionGate, ActionRequest
from .content_gate import ContentGate
from .instructions import scan_text
from .session import Session

DEFAULT_CASES = Path(__file__).resolve().parent.parent / "evals" / "cases.jsonl"


def _fixture_project() -> str:
    root = Path(tempfile.mkdtemp(prefix="agentdefense-eval-"))
    for d in ("src", "dist", "node_modules", "tmp", "reports"):
        (root / d).mkdir()
    (root / "README.md").write_text("# demo\n")
    (root / "config.yaml").write_text("debug: false\n")
    (root / "tmp" / "debug.log").write_text("log\n")
    (root / "utils.py").write_text("import os\n")
    return str(root)


async def _run_case(jev, case: dict, project: str) -> tuple[str, float]:
    started = time.perf_counter()
    if case["gate"] == "action":
        v = await ActionGate(jev, Session()).check(ActionRequest(case["user"], case["command"], case.get("reason", ""), working_directory=project, project_root=project))
        got = v.decision.value
    elif case["gate"] == "content":
        v = await ContentGate(jev, Session()).scan(case["text"], user_task=case["task"], source="eval")
        got = "clean" if v.status == "clean" else "injection"
    else:
        r = await scan_text(jev, case["text"], "eval/SKILL.md")
        got = "flagged" if r and r.flagged else "clean"
    return got, (time.perf_counter() - started) * 1000


async def run_eval(jev, cases_path: str | None = None, out_path: str | None = None, concurrency: int = 4) -> int:
    cases = [json.loads(line) for line in Path(cases_path or DEFAULT_CASES).read_text().splitlines() if line.strip()]
    project = _fixture_project()
    sem = asyncio.Semaphore(concurrency)

    async def one(case):
        async with sem:
            try:
                return await _run_case(jev, case, project)
            except Exception as exc:  # report, don't crash the whole run
                return f"ERROR {type(exc).__name__}", 0.0

    results = await asyncio.gather(*(one(c) for c in cases))

    by_gate: dict[str, list] = defaultdict(list)
    for case, (got, ms) in zip(cases, results):
        by_gate[case["gate"]].append((case, got, ms))

    lines = [f"# AgentDefense eval\n", f"Backend: **{jev.name}**{f' (`{jev.model}`)' if getattr(jev, 'model', None) else ''} · {len(cases)} cases\n"]
    summary = []
    for gate, rows in by_gate.items():
        exact = sum(c["expect"] == g for c, g, _ in rows)
        summary.append(f"| {gate} | {exact}/{len(rows)} ({100 * exact / len(rows):.0f}%) |")
    lines += ["| gate | exact match |", "|---|---|", *summary, ""]

    actions = by_gate.get("action", [])
    if actions:
        dangerous = [(c, g) for c, g, _ in actions if c["expect"] != "ALLOW"]
        benign = [(c, g) for c, g, _ in actions if c["expect"] == "ALLOW"]
        missed = [c for c, g in dangerous if g == "ALLOW"]
        false_block = [c for c, g in benign if g == "BLOCK"]
        friction = [c for c, g in benign if g == "ASK"]
        lines += [
            "## Action gate",
            f"- **Attacks stopped** (expected BLOCK/ASK, got BLOCK/ASK): {len(dangerous) - len(missed)}/{len(dangerous)}",
            f"- **Missed attacks** (got ALLOW): {len(missed)}" + (" ← " + "; ".join(f"`{c['command'][:50]}`" for c in missed) if missed else ""),
            f"- **False blocks** on legitimate work: {len(false_block)}/{len(benign)}" + (" ← " + "; ".join(f"`{c['command'][:50]}`" for c in false_block) if false_block else ""),
            f"- **Friction** (legit work sent to a human): {len(friction)}/{len(benign)}" + (" ← " + "; ".join(f"`{c['command'][:50]}`" for c in friction) if friction else ""),
            "",
        ]
    for gate, label, bad in (("content", "Content gate", "injection"), ("instruction", "Instruction-file scan", "flagged")):
        rows = by_gate.get(gate, [])
        if rows:
            attacks = [(c, g) for c, g, _ in rows if c["expect"] == bad]
            clean = [(c, g) for c, g, _ in rows if c["expect"] == "clean"]
            lines += [
                f"## {label}",
                f"- **Detected**: {sum(g == bad for _, g in attacks)}/{len(attacks)}" + ("".join(f" ← missed `{c['tag']}`" for c, g in attacks if g != bad)),
                f"- **False positives**: {sum(g == bad for _, g in clean)}/{len(clean)}" + ("".join(f" ← `{c['tag']}`" for c, g in clean if g == bad)),
                "",
            ]

    lat = [ms for *_, ms in (r for rows in by_gate.values() for r in rows) if ms]
    if lat:
        lat.sort()
        lines += [f"Latency per decision: p50 {statistics.median(lat):.0f} ms · p95 {lat[int(0.95 * (len(lat) - 1))]:.0f} ms\n"]

    lines += ["## Every case", "| gate | tag | expected | got | |", "|---|---|---|---|---|"]
    for case, (got, _) in zip(cases, results):
        what = case.get("command") or case.get("text", "")
        mark = "✓" if got == case["expect"] else "✗"
        lines.append(f"| {case['gate']} | {case['tag']} | {case['expect']} | {got} | {mark} `{what[:60].replace('|', '/').replace(chr(10), ' ')}` |")

    report = "\n".join(lines)
    print(report)
    if out_path:
        Path(out_path).write_text(report + "\n")
    missed_any = any(c["expect"] != "ALLOW" and g == "ALLOW" for c, g, _ in actions)
    return 1 if missed_any else 0
