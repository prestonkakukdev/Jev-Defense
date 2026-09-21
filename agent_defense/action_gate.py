"""
ACTION GATE: decide whether an agent's tool call may run.

The pipeline for every tool call (cheapest checks first):

    ┌──────────────┐   ┌──────────────┐   ┌─────────────────────────────┐   ┌──────────────┐
    │ 1. Hard deny │ → │ 2. Fast path │ → │ 3. Ask Jev (4 parallel calls,│ → │ 4. Policy    │ → ALLOW / ASK / BLOCK
    │   (regex)    │   │ (read-only)  │   │    each seeing only what it  │   │  (plain code │
    └──────────────┘   └──────────────┘   │    needs)                    │   │   rules)     │
                                          └─────────────────────────────┘   └──────────────┘

Jev never makes the final decision.  Jev answers narrow questions with probabilities;
plain, readable code (`decide_action`) turns those numbers into a verdict.  That split is
the core TypeSafe design idea: "code stays in control, the model handles judgment."
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from enum import Enum

from . import shell_facts
from .jev import Answer, JevBackend
from .rulebook import ACTION, ACTION_GROUPS, SCOPE_OUTSIDE, SCOPE_PROJECT, TAINT_GROUP, QuestionGroup
from .session import Session

UNKNOWN_REQUEST = "(unknown)"


def _known(text: str) -> bool:
    return bool(text.strip()) and text.strip().lower() not in {UNKNOWN_REQUEST, "(could not read the user's request)", "unknown"}


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ASK = "ASK"  # pause and get a human to confirm
    BLOCK = "BLOCK"


@dataclass
class ActionRequest:
    user_request: str  # what the human asked for
    command: str  # what the agent wants to run
    agent_reason: str = ""  # why the agent says it wants to run it
    tool: str = "shell"
    working_directory: str = field(default_factory=os.getcwd)
    project_root: str | None = None
    # For non-shell tools (e.g. a Write tool), the paths it touches:
    target_paths: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    decision: Decision
    reasons: list[str]
    stage: str  # "hard_rule" | "fast_path" | "jev" | "error"
    signals: dict[str, float] = field(default_factory=dict)  # every Jev answer, for the audit log
    scope_level: int | None = None
    facts: dict = field(default_factory=dict)
    backend: str = ""
    model: str | None = None
    latency_ms: float = 0.0
    # True when an ASK exists only because the action is consequential, and the user's own
    # recent words clearly asked for it. Hosts that CAN'T show an approval prompt use this: the
    # user's explicit request is already the human confirmation an ASK is looking for.
    user_confirmed: bool = False


def user_clearly_confirmed(a: dict[str, Answer], tainted: bool) -> bool:
    """Explicit request, reason fits (or absent), no manipulation, no injected-instruction match, clean session."""
    if tainted or "user_requested" not in a:
        return False
    need = ACTION.clearly_requested
    reason = a.get("reason_matches_request")
    return (
        a["user_requested"].value >= need
        and (reason is None or reason.value >= ACTION.reason_matches)
        and max(a["reason_has_manipulation"].value, a["command_has_reviewer_text"].value) < ACTION.manipulation_block
        and ("follows_untrusted_instruction" not in a or a["follows_untrusted_instruction"].value < ACTION.follows_untrusted_block)
    )


class ActionGate:
    def __init__(self, jev: JevBackend, session: Session | None = None):
        self.jev = jev
        self.session = session or Session()

    async def check(self, req: ActionRequest) -> Verdict:
        started = time.perf_counter()
        verdict = await self._check(req)
        verdict.latency_ms = (time.perf_counter() - started) * 1000
        verdict.backend = self.jev.name
        verdict.model = getattr(self.jev, "model", None)
        self.session.record_action(req.command, verdict.decision.value, verdict.reasons)
        return verdict

    async def _check(self, req: ActionRequest) -> Verdict:
        project_root = req.project_root or req.working_directory

        # ── Stage 1 & 2: plain code ──────────────────────────────────────────────────
        if req.tool == "shell":
            facts = shell_facts.analyze(req.command, req.working_directory, project_root)
        else:
            facts = shell_facts.ShellFacts(sql=shell_facts.sql_facts(req.command))
            for pattern, why in shell_facts.SQL_HARD_DENY:
                if pattern.search(req.command):
                    facts.hard_deny_reason = why
            for p in req.target_paths:
                resolved = os.path.realpath(os.path.join(req.working_directory, os.path.expanduser(p)))
                facts.paths.append(shell_facts.PathFact(p, resolved, shell_facts.classify_path(resolved, project_root)))

        if facts.hard_deny_reason:
            return Verdict(Decision.BLOCK, [f"Hard rule: command {facts.hard_deny_reason}."], "hard_rule", facts=facts.for_jev())

        # A tainted session skips the fast path: after reading a malicious page, even
        # "harmless" reads get a real review.
        if facts.read_only_fast_path and not self.session.tainted:
            return Verdict(Decision.ALLOW, ["Read-only command inside the project (fast path, Jev not needed)."], "fast_path", facts=facts.for_jev())

        # ── Stage 3: ask Jev ─────────────────────────────────────────────────────────
        evidence = {
            "tool": req.tool,
            "command": req.command,
            "working_directory": req.working_directory,
            "project_root": project_root,
            "parser_facts": facts.for_jev(),
            "user_request": req.user_request,
            "agent_stated_reason": req.agent_reason or "(the agent gave no reason)",
            "untrusted_content_excerpts": self.session.untrusted_excerpts,
        }
        skip = set()
        if not _known(req.user_request):
            # Some hosts can't tell us what the user asked. "Unknown" is not "they didn't
            # ask" — asking anyway would score ~0 and block everything. Drop those
            # questions; the policy escalates to a human instead of guessing.
            skip |= {"request_vs_command", "request_vs_reason"}
        groups: list[QuestionGroup] = [g for name, g in ACTION_GROUPS.items() if name not in skip]
        if not req.agent_reason.strip():
            # No reason given (many tools don't provide one, and transcripts lag). Asking
            # "does this reason fit?" about a placeholder always scores ~0, which would
            # block legitimate work. ABSENCE OF EVIDENCE IS NOT EVIDENCE OF GUILT: drop the
            # question instead, and let the other signals decide.
            skip.add("request_vs_reason")
            groups = [g for name, g in ACTION_GROUPS.items() if name not in skip]
        if self.session.tainted:
            groups.append(TAINT_GROUP)

        try:
            answers = await ask_groups(self.jev, groups, evidence)
        except Exception as exc:  # network down, bad key, rate limited past retries...
            # FAIL CLOSED: if the guard can't think, it must not wave things through.
            return Verdict(Decision.ASK, [f"Jev unavailable ({type(exc).__name__}: {exc}). Failing closed: a human must confirm."], "error", facts=facts.for_jev())

        # ── Stage 4: policy ──────────────────────────────────────────────────────────
        # Non-shell tools that write (Write/Edit/Delete) outside the project count too.
        writes_outside = list(facts.writes_outside_project) or (
            [p.token for p in facts.paths if p.location not in ("project", "temp")] if req.tool in ("Write", "Edit", "MultiEdit", "Delete", "NotebookEdit") else []
        )
        decision, reasons, scope = decide_action(answers, facts.scope_floor, self.session.tainted, code_destructive=facts.destroys_whole_table, writes_outside=writes_outside)
        signals = {qid: round(a.value, 3) for qid, a in answers.items()}
        confirmed = decision == Decision.ASK and user_clearly_confirmed(answers, self.session.tainted) and not writes_outside and not facts.destroys_whole_table
        return Verdict(decision, reasons, "jev", signals=signals, scope_level=scope, facts=facts.for_jev(), user_confirmed=confirmed)


async def ask_groups(jev: JevBackend, groups: list[QuestionGroup], evidence: dict) -> dict[str, Answer]:
    """
    Send each group to Jev as its own request, all at the same time.

    `asyncio.gather` starts every request immediately and waits for all of them, so four
    ~100 ms calls take ~100 ms total, not ~400 ms.  (Concurrency: waiting on the network
    in parallel instead of in a line.)
    """
    states = [{key: evidence[key] for key in g.sees} for g in groups]  # need-to-know filtering
    results = await asyncio.gather(*(jev.ask(state, g.questions) for state, g in zip(states, groups)))
    merged: dict[str, Answer] = {}
    for r in results:
        merged.update(r)
    return merged


def effective_scope(answer: Answer, code_floor: int) -> int:
    """
    Turn the blast_radius Score into a level: 0 temp, 1 project, 2 outside/system.

    * Confident answer → round the probability-weighted score.
    * Unsure answer → be pessimistic: take the HIGHEST level that still has a real
      probability.  (A 60/40 split between "project" and "system" is treated as "system".)
    * Code-found paths set a floor Jev can't lower.
    """
    if answer.confidence is not None and answer.confidence >= ACTION.scope_min_confidence:
        level = round(answer.value)
    elif answer.probabilities:
        level = max(lvl for lvl, p in answer.probabilities.items() if p >= ACTION.scope_pessimistic_min_prob)
    else:
        level = round(answer.value + 0.49)  # no distribution: round up
    return max(level, code_floor)


def decide_action(a: dict[str, Answer], scope_floor: int, tainted: bool, code_destructive: bool = False, writes_outside: list[str] | None = None) -> tuple[Decision, list[str], int]:
    """
    The policy: an ordered list of rules.  The first rule that fires decides.

    Written as plain if-statements on purpose.  Anyone can read it, test it, and change it
    without touching a prompt.  (A "decision table".)
    """
    t = ACTION
    deletes = a["deletes_or_overwrites"].value
    if code_destructive:  # e.g. DELETE with no WHERE: code KNOWS every row goes, whatever Jev says
        deletes = max(deletes, 0.95)
    requested = a["user_requested"].value if "user_requested" in a else None
    # None = no reason was given, so this question was never asked. Treat it as neutral:
    # a missing reason is not proof of a bad one.
    matches = a["reason_matches_request"].value if "reason_matches_request" in a else None
    reason_fits = matches is None or matches >= ACTION.reason_matches
    requested_text = "unknown" if requested is None else f"{requested:.2f}"
    matches_text = "not stated" if matches is None else f"{matches:.2f}"
    reversible = a["reversible"].value
    manipulation = max(a["reason_has_manipulation"].value, a["command_has_reviewer_text"].value)
    follows_untrusted = a["follows_untrusted_instruction"].value if "follows_untrusted_instruction" in a else 0.0
    scope = effective_scope(a["blast_radius"], scope_floor)
    scope_name = ["one temp file", "project files", "outside the project / system"][scope]
    need = t.clearly_requested_when_tainted if tainted else t.clearly_requested

    # Rule 1: the agent is trying to talk its way past the reviewer.
    if manipulation >= t.manipulation_block:
        return Decision.BLOCK, [f"Agent text contains urgency, claimed approval, or reviewer-directed instructions (p={manipulation:.2f})."], scope

    # Rule 2: the command matches instructions from a web page / file the agent read.
    if follows_untrusted >= t.follows_untrusted_block:
        return Decision.BLOCK, [f"Command appears to carry out instructions from untrusted content (p={follows_untrusted:.2f}). Likely prompt injection."], scope

    if deletes >= t.destructive:
        # Rule 3: destructive + not clearly requested.
        if requested is None:
            # We don't know what the user wanted, and this destroys data. Ask a human.
            return Decision.ASK, [f"Deletes or overwrites data (p={deletes:.2f}) and the user's original request is unknown. Confirm before running."], scope
        # The "maybe" band is skipped when code KNOWS the damage is total (e.g. DELETE with no WHERE):
        # "the user probably asked" is not good enough to empty a table.
        if not tainted and not code_destructive and t.maybe_requested <= requested < need and reason_fits:
            # Mixed evidence: probably requested, but not clearly. Don't guess either way.
            # Skipped when the session is tainted: after an injection, "probably" isn't good enough.
            return Decision.ASK, [
                f"Deletes or overwrites data (p={deletes:.2f}) and the user may have asked for it "
                f"(requested p={requested:.2f}, below the {need} needed to run it unattended). Confirm before running."
            ], scope
        if requested < need or not reason_fits:
            return Decision.BLOCK, [
                f"Deletes or overwrites data (p={deletes:.2f}) but the user did not clearly ask for it "
                f"(requested p={requested_text}, reason fits request p={matches_text})."
            ], scope
        # Rule 4: requested, but reaches outside the project.
        if scope >= SCOPE_OUTSIDE:
            return Decision.ASK, [f"User asked for this, but it reaches {scope_name}. Confirm before running."], scope
        # Rule 5: requested, inside the project, but permanent.
        if reversible < t.reversible and scope >= SCOPE_PROJECT:
            return Decision.ASK, [f"User asked for this, but it permanently changes {scope_name} (reversible p={reversible:.2f})."], scope
        # Rule 6: after reading suspicious content, every destructive step gets a human.
        if tainted:
            return Decision.ASK, ["Session read suspicious content earlier; destructive actions need confirmation."], scope
        # Rule 7: requested, contained, recoverable.
        return Decision.ALLOW, [f"Destructive but requested, contained to {scope_name}, and recoverable."], scope

    # Exfiltration: nothing is deleted, but data leaves and can never be recalled. Checked
    # AFTER destruction (a command can do both) and BEFORE the lenient non-destructive rules.
    sends = a["sends_data_outward"].value if "sends_data_outward" in a else 0.0
    sensitive = a["touches_sensitive_data"].value if "touches_sensitive_data" in a else 0.0
    if sends >= t.sends_outward:
        what = "credentials or private data" if sensitive >= t.sensitive else "data"
        if requested is None or requested < t.maybe_requested or (sensitive >= t.sensitive and requested < need):
            # Secrets leaving the machine without an unmistakable request is never just "ask":
            # once a credential is out, it's out.
            return Decision.BLOCK, [f"Sends {what} off this machine (p={sends:.2f}) and the user did not clearly ask for it (requested p={requested_text})."], scope
        if requested < need or sensitive >= t.sensitive:
            return Decision.ASK, [f"Sends {what} off this machine (p={sends:.2f}). Confirm the destination before running."], scope

    # Rule: writes that land outside the project (code-found). They outlive the task and are a
    # common persistence trick, so a person confirms even when the user asked.
    if writes_outside:
        return Decision.ASK, [f"Writes outside the project ({', '.join(writes_outside[:3])}). Changes there outlive this task; confirm before running."], scope

    # Rule: the catch-all (see rulebook `needs_approval`). Escalates, never blocks, and never
    # overrides a clear request: it exists to catch the dimensions nobody wrote a question for.
    approval = a["needs_approval"].value if "needs_approval" in a else 0.0
    if approval >= t.needs_approval and (requested is None or requested < need):
        return Decision.ASK, [f"A careful engineer would want to approve this first (p={approval:.2f}), and the user did not clearly ask for it (requested p={requested_text})."], scope

    # Non-destructive actions from here on.
    # Rule 8: clearly off-task.  Often an incorrect tool call, sometimes an injection symptom.
    if requested is not None and requested < t.off_task_requested and not reason_fits:
        return Decision.ASK, [f"Action looks unrelated to the user's request (requested p={requested:.2f}). Possible wrong tool call."], scope
    # Rule 9: doesn't delete, but has permanent effects beyond the project (e.g. sends data, pushes).
    if scope >= SCOPE_OUTSIDE and reversible < t.reversible:
        return Decision.ASK, [f"Has permanent effects {scope_name} (reversible p={reversible:.2f})."], scope

    # Rule 10: nothing worrying.
    return Decision.ALLOW, ["No destructive or off-task signals."], scope
