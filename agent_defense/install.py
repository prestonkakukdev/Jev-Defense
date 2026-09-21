"""
`agentdefense install <agent>`: register the hook in an agent's own config file.

Rules every installer follows:
  * IDEMPOTENT: running it twice gives the same file. Old AgentDefense entries are removed before
    new ones are added, and nobody else's hooks are touched.
  * ABSOLUTE PATHS: the hook command uses this exact Python interpreter. Editors launched from the
    Dock don't load your shell's PATH, so a bare `agentdefense` might not be found there.
  * BACKUP: the previous file is kept next to it as `<name>.agentdefense.bak`.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

# Every command we write contains one of these, which is how we recognise (and replace) our own
# entries, including ones from the older hooks/claude_code_guard.py setup.
MARKS = ("agent_defense", "claude_code_guard")
AGENTS = ("claude", "codex", "copilot", "gemini", "cursor", "opencode")

# Tool matchers for Claude-shaped hosts. PreToolUse covers everything that changes the world;
# PostToolUse covers everything that brings outside text in (Bash output is filtered in code).
PRE_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*"
POST_MATCHER = "WebFetch|WebSearch|Read|Bash|Skill|mcp__.*"


def hook_command(agent: str | None = None) -> str:
    cmd = f'"{sys.executable}" -m agent_defense hook'
    return f"{cmd} --agent {agent}" if agent else cmd


def _read(path: Path) -> dict:
    if not path.is_file():
        return {}
    text = path.read_text().strip()
    return json.loads(text) if text else {}


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        shutil.copy2(path, path.with_name(path.name + ".agentdefense.bak"))
    path.write_text(json.dumps(data, indent=2) + "\n")


def _not_ours(entries: list | None) -> list:
    return [e for e in (entries or []) if not any(m in json.dumps(e) for m in MARKS)]


def install(agent: str, home: Path | None = None, project: Path | None = None) -> tuple[Path, str]:
    """Returns (file written, note for the user)."""
    home = home or Path.home()
    note = ""

    if agent in ("claude", "codex"):
        if agent == "claude":
            path = (project / ".claude" / "settings.json") if project else home / ".claude" / "settings.json"
        else:
            path = home / ".codex" / "hooks.json"
        cfg = _read(path)
        hooks = cfg.setdefault("hooks", {})
        cmd = hook_command("codex" if agent == "codex" else None)
        entry = lambda matcher=None: {**({"matcher": matcher} if matcher else {}), "hooks": [{"type": "command", "command": cmd, "timeout": 30}]}  # noqa: E731
        plan = {"PreToolUse": entry(PRE_MATCHER), "PostToolUse": entry(POST_MATCHER), "UserPromptSubmit": entry(), "SessionStart": entry()}
        if agent == "claude":
            plan["InstructionsLoaded"] = entry()
        for event, e in plan.items():
            hooks[event] = _not_ours(hooks.get(event)) + [e]
        if agent == "codex":
            note = "Run /hooks inside Codex to trust the new hooks. Codex can't show approval prompts, so ASK verdicts are refused (AGENT_DEFENSE_ASK_FALLBACK=warn to change)."

    elif agent == "copilot":
        path = home / ".copilot" / "hooks" / "agentdefense.json"
        cmd = hook_command("copilot")
        cfg = {"version": 1, "hooks": {ev: [{"type": "command", "bash": cmd, "timeoutSec": 30}] for ev in ("PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart")}}

    elif agent == "gemini":
        path = home / ".gemini" / "settings.json"
        cfg = _read(path)
        hooks = cfg.setdefault("hooks", {})
        e = {"hooks": [{"name": "agentdefense", "type": "command", "command": hook_command(), "timeout": 30_000}]}
        for event in ("BeforeTool", "AfterTool", "BeforeAgent", "SessionStart"):
            hooks[event] = _not_ours(hooks.get(event)) + [e]
        note = "Gemini CLI can't show approval prompts, so ASK verdicts are refused (AGENT_DEFENSE_ASK_FALLBACK=warn to change)."

    elif agent == "cursor":
        path = home / ".cursor" / "hooks.json"
        cfg = _read(path)
        cfg.setdefault("version", 1)
        hooks = cfg.setdefault("hooks", {})

        def add(event: str, **extra) -> None:
            hooks[event] = _not_ours(hooks.get(event)) + [{"command": hook_command(), "timeout": 30, **extra}]

        add("beforeShellExecution")
        add("beforeMCPExecution")
        add("preToolUse", matcher="Write|Delete")
        add("postToolUse")
        add("beforeSubmitPrompt")
        add("sessionStart")

    elif agent == "opencode":
        path = home / ".config" / "opencode" / "plugins" / "agentdefense.js"
        path.parent.mkdir(parents=True, exist_ok=True)
        plugin = Path(__file__).resolve().parent / "plugins" / "opencode.js"
        # Copy (not symlink) so a moved checkout can't silently break the guard; rerun install after upgrading.
        text = plugin.read_text().replace('process.env.AGENTDEFENSE_CMD || "agentdefense"', f"process.env.AGENTDEFENSE_CMD || {json.dumps(sys.executable + ' -m agent_defense')}")
        path.write_text(text)
        note = (
            'For real approval prompts, set "permission": {"bash": "ask", "edit": "ask"} in opencode.json. '
            "AgentDefense then auto-approves safe calls and only prompts you for risky ones."
        )
        return path, note

    else:
        raise ValueError(f"unknown agent {agent!r}; choose one of: {', '.join(AGENTS)}")

    _write(path, cfg)
    return path, note


def uninstall(agent: str, home: Path | None = None, project: Path | None = None) -> Path | None:
    home = home or Path.home()
    if agent == "opencode":
        path = home / ".config" / "opencode" / "plugins" / "agentdefense.js"
        path.unlink(missing_ok=True)
        return path
    if agent == "copilot":
        path = home / ".copilot" / "hooks" / "agentdefense.json"
        path.unlink(missing_ok=True)
        return path
    path = {
        "claude": (project / ".claude" / "settings.json") if project else home / ".claude" / "settings.json",
        "codex": home / ".codex" / "hooks.json",
        "gemini": home / ".gemini" / "settings.json",
        "cursor": home / ".cursor" / "hooks.json",
    }[agent]
    cfg = _read(path)
    for event in list(cfg.get("hooks", {})):
        cfg["hooks"][event] = _not_ours(cfg["hooks"][event])
        if not cfg["hooks"][event]:
            del cfg["hooks"][event]
    _write(path, cfg)
    return path
