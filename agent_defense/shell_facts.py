"""
Plain-code checks that run BEFORE Jev is asked anything.

Rule of thumb from the Jev docs: "Use code when you can."  Code is free, instant, and
never fooled by clever wording.  But code is also brittle: a regex for `rm -rf` misses
`find . -delete`, and no simple parser understands the Python inside `python -c "..."`.

So this module does three narrow jobs and leaves the judgment calls to Jev:

  1. HARD DENY:  a short blocklist of commands so catastrophic we never need a model's opinion.
  2. FAST PATH:  a short allowlist of read-only commands that skip Jev entirely (saves cost/latency).
  3. PATH FACTS: find the file paths it can and label where they point (temp / project / home /
     system).  Jev struggles with multi-step reasoning like "does ../../etc resolve outside the
     project?", so code resolves the paths and hands Jev the plain-English answer.
"""

from __future__ import annotations

import os
import re
import shlex
import tempfile
from dataclasses import dataclass, field

# ── 1. Hard deny ─────────────────────────────────────────────────────────────────────
# Keep this list SHORT and OBVIOUS.  Every pattern here is a "no model needed" case.
# Anything subtler goes to Jev, because pattern lists are easy to dodge.
_ROOTISH = r"(?:/|/\*|~|~/|~/\*|\$HOME|\$HOME/|\$HOME/\*|\"\$HOME\")"
HARD_DENY: list[tuple[re.Pattern[str], str]] = [
    (re.compile(rf"\brm\s+(?:-\S+\s+)*{_ROOTISH}(?:\s|$|;|&|\|)"), "deletes the whole filesystem or home folder"),
    (re.compile(r"\bmkfs(?:\.\w+)?\b"), "formats a disk"),
    (re.compile(r"\bdd\b[^|;&]*\bof=/dev/(?:sd|disk|nvme|hd)"), "writes raw bytes over a disk"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "fork bomb (crashes the machine)"),
    (re.compile(r"\bchmod\s+(?:-\S+\s+)*777\s+/(?:\s|$)"), "makes the whole filesystem world-writable"),
    (re.compile(r">\s*/dev/(?:sd|disk|nvme)"), "overwrites a disk device"),
]

# ── SQL (agents increasingly drive databases through MCP tools) ─────────────────────
# Whether a DELETE has a WHERE clause is a fact, not a judgment, so code decides it. Code
# can RAISE risk above what Jev says, never lower it.
SQL_HARD_DENY: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bdrop\s+(?:database|schema)\b", re.I), "drops an entire database or schema"),
]
_SQL_WRITE = re.compile(r"\b(delete\s+from|update)\s+([\w.\"`\[\]]+)(.*?)(?:;|$)", re.I | re.S)
_SQL_WHOLE_TABLE = re.compile(r"\b(truncate(?:\s+table)?|drop\s+table(?:\s+if\s+exists)?)\s+([\w.\"`\[\]]+)", re.I)


def sql_facts(text: str) -> list[dict]:
    """Statements that rewrite or remove rows, and whether they hit EVERY row."""
    found = []
    for verb, table, rest in _SQL_WRITE.findall(text or ""):
        found.append({"statement": verb.split()[0].upper(), "table": table, "affects_every_row": not re.search(r"\bwhere\b", rest, re.I)})
    for verb, table in _SQL_WHOLE_TABLE.findall(text or ""):
        found.append({"statement": verb.split()[0].upper(), "table": table, "affects_every_row": True})
    return found


# ── 2. Fast path ─────────────────────────────────────────────────────────────────────
# Allowlists are HARD to get right: `git diff --output=x` writes a file, `find` has
# `-delete`, `sed` has `-i`.  So this list is tiny and conservative on purpose.
READ_ONLY_PROGRAMS = {"ls", "pwd", "cat", "head", "tail", "wc", "grep", "rg", "which", "file", "stat", "tree"}
READ_ONLY_GIT = {"status", "diff", "log", "show", "branch"}
# Any of these means pipes, redirects, chaining, subshells, or variable expansion. Too clever for the fast path.
SHELL_METACHARS = re.compile(r"[;&|<>`$(){}\n\\]")

SYSTEM_DIRS = ("/etc", "/usr", "/bin", "/sbin", "/System", "/Library", "/var", "/opt", "/dev", "/boot", "/private/etc")


@dataclass
class PathFact:
    token: str  # as written in the command
    resolved: str  # absolute, symlinks followed
    location: str  # "temp" | "project" | "home_outside_project" | "system" | "outside_project"


@dataclass
class ShellFacts:
    hard_deny_reason: str | None = None
    read_only_fast_path: bool = False
    paths: list[PathFact] = field(default_factory=list)
    sql: list[dict] = field(default_factory=list)
    uses_shell_variables: bool = False
    chains_or_pipes: bool = False
    writes_outside_project: list[str] = field(default_factory=list)  # redirect/tee targets beyond the project
    parse_error: bool = False

    @property
    def destroys_whole_table(self) -> bool:
        return any(q["affects_every_row"] for q in self.sql)

    @property
    def scope_floor(self) -> int:
        """
        The LOWEST blast radius the command can have, based on paths code could actually see.
        If code saw a path in /etc, the scope is at least "system", no matter what Jev says.
        (Code facts can raise the scope, never lower it.)
        """
        locations = {p.location for p in self.paths}
        if locations & {"system", "home_outside_project", "outside_project"}:
            return 2
        if "project" in locations:
            return 1
        return 0

    def for_jev(self) -> dict:
        """A compact, plain-English summary suitable for Jev's state."""
        return {
            "paths": [{"as_written": p.token, "resolves_to": p.resolved, "location": p.location} for p in self.paths],
            "uses_shell_variables": self.uses_shell_variables,
            "chains_or_pipes_commands": self.chains_or_pipes,
            **({"sql_statements": self.sql} if self.sql else {}),
            **({"writes_files_outside_project": self.writes_outside_project} if self.writes_outside_project else {}),
            "note": "Found by a simple parser. Paths built inside code (python -c, node -e, variables) are not listed.",
        }


def classify_path(resolved: str, project_root: str) -> str:
    project_root = os.path.realpath(project_root)
    temp_roots = {os.path.realpath(tempfile.gettempdir()), "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"}
    home = os.path.realpath(os.path.expanduser("~"))

    def inside(child: str, parent: str) -> bool:
        return child == parent or child.startswith(parent.rstrip("/") + "/")

    # Project first: if the project itself lives in a temp folder, its files are still project files.
    if inside(resolved, project_root):
        return "project"
    if any(inside(resolved, t) for t in temp_roots):
        return "temp"
    if resolved == "/" or any(inside(resolved, d) for d in SYSTEM_DIRS):
        return "system"
    if inside(resolved, home):
        return "home_outside_project"
    return "outside_project"


def _looks_like_path(token: str, cwd: str) -> bool:
    if token.startswith("-") or "://" in token:  # flags and URLs aren't local paths
        return False
    if token.startswith(("/", "~", "./", "../")) or token in {".", ".."}:
        return True
    if "/" in token and not token.startswith(("'", '"')):
        return True
    return os.path.exists(os.path.join(cwd, token))


def analyze(command: str, working_directory: str, project_root: str | None = None) -> ShellFacts:
    project_root = project_root or working_directory
    facts = ShellFacts()

    for pattern, why in HARD_DENY + SQL_HARD_DENY:
        if pattern.search(command):
            facts.hard_deny_reason = why
            break
    facts.sql = sql_facts(command)

    facts.uses_shell_variables = "$" in command
    facts.chains_or_pipes = bool(re.search(r"[;&|]", command))

    try:
        tokens = shlex.split(command, comments=True)
    except ValueError:  # unbalanced quotes etc.
        facts.parse_error = True
        tokens = command.split()

    for tok in tokens:
        if _looks_like_path(tok, working_directory):
            expanded = os.path.expanduser(os.path.expandvars(tok))
            resolved = os.path.realpath(os.path.join(working_directory, expanded))
            facts.paths.append(PathFact(tok, resolved, classify_path(resolved, project_root)))

    # Where does output get WRITTEN? `>> ~/.zshrc` looks harmless (append, reversible) but it
    # changes config that outlives the project: a classic way to plant persistence. The target is
    # plain text in the command, so code finds it instead of asking a model.
    for target in re.findall(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*([^\s;&|]+)", command):
        target = target.strip("'\"")
        if target.startswith("&") or target in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            continue
        resolved = os.path.realpath(os.path.join(working_directory, os.path.expanduser(os.path.expandvars(target))))
        if classify_path(resolved, project_root) not in ("project", "temp"):
            facts.writes_outside_project.append(target)

    facts.read_only_fast_path = _is_fast_path(command, tokens, facts)
    return facts


def _is_fast_path(command: str, tokens: list[str], facts: ShellFacts) -> bool:
    if facts.hard_deny_reason or facts.parse_error or not tokens or SHELL_METACHARS.search(command):
        return False
    program = os.path.basename(tokens[0])
    if program == "git":
        if len(tokens) < 2 or tokens[1] not in READ_ONLY_GIT:
            return False
        if any(t.startswith("--output") for t in tokens) or (tokens[1] == "branch" and len(tokens) > 2):
            return False
    elif program not in READ_ONLY_PROGRAMS:
        return False
    # Reading is harmless, but reading ~/.ssh/id_rsa is not. Stay inside project/temp.
    return all(p.location in {"project", "temp"} for p in facts.paths)
