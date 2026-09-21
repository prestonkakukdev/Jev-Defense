"""
Session memory that links the gates: what the user said, and what looked hostile.

Two jobs:

1. PROMPT MEMORY.  Every host's "user submitted a prompt" hook (UserPromptSubmit, BeforeAgent,
   beforeSubmitPrompt) records the user's words here the instant they hit enter.  This replaced
   reading the transcript file, which the host writes asynchronously and which lagged behind the
   conversation, the root cause of most false blocks we hit.  (Idea from jev-guard.)
   Nothing from a tool result is ever stored as the user speaking.

2. TAINT TRACKING.  Borrowed from information-flow security: once untrusted data has flowed
   into a program, treat everything downstream with suspicion.  When the content gate flags a
   passage, the session is marked `tainted`, and from then on the action gate
     * skips its read-only fast path,
     * demands stronger evidence that the user really asked for destructive actions,
     * asks Jev an extra question: "does this command carry out an instruction from that passage?"
   So even if an injection slips past the content gate, the action gate is already on alert.
   That's DEFENSE IN DEPTH: layers that fail differently.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import config

MAX_EXCERPTS = 5
MAX_EXCERPT_CHARS = 500
MAX_PROMPTS = 6
MAX_PROMPT_CHARS = 2000


def session_path(session_id: str) -> Path:
    """
    Session ids come from the host, i.e. from outside. Using one raw as a filename would let
    an id like "../../.ssh/authorized_keys" write anywhere. Hashing it makes every id a safe,
    fixed-length filename.
    """
    digest = hashlib.sha1(str(session_id).encode()).hexdigest()[:16]
    return Path(os.environ.get("AGENT_DEFENSE_STATE_DIR", config.HOME_DIR / "sessions")) / f"{digest}.json"


@dataclass
class Session:
    session_id: str = "local"
    tainted: bool = False
    untrusted_excerpts: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)  # the user's own words, oldest first
    swept: bool = False  # instruction files scanned for this session already?
    pending_notes: list[str] = field(default_factory=list)  # findings not yet shown to the agent
    events: list[dict] = field(default_factory=list)  # audit log

    # ── prompts ──────────────────────────────────────────────────────────────────────
    def record_prompt(self, text: str) -> None:
        text = (text or "").strip()
        if text and (not self.prompts or self.prompts[-1] != text):
            self.prompts = (self.prompts + [text[:MAX_PROMPT_CHARS]])[-MAX_PROMPTS:]

    def user_request(self, n: int = 3) -> str:
        """The last few prompts, newest last. "Yes, do it" only means something next to what it approves."""
        return "\n---\n".join(self.prompts[-n:])

    # ── taint ────────────────────────────────────────────────────────────────────────
    def record_content(self, source: str, status: str, flagged_excerpts: list[str]) -> None:
        self.events.append({"t": time.time(), "type": "content", "source": source, "status": status})
        if status != "clean":
            self.tainted = True
            for ex in flagged_excerpts:
                self.untrusted_excerpts.append(ex[:MAX_EXCERPT_CHARS])
            # Keep the newest few: bounded memory, and Jev accuracy drops with bloated state.
            self.untrusted_excerpts = self.untrusted_excerpts[-MAX_EXCERPTS:]
        self.events = self.events[-200:]

    def record_action(self, command: str, decision: str, reasons: list[str]) -> None:
        self.events.append({"t": time.time(), "type": "action", "command": command[:300], "decision": decision, "reasons": reasons})
        self.events = self.events[-200:]

    # ── persistence ──────────────────────────────────────────────────────────────────
    # Hooks run as separate processes, so memory has to live on disk between them.
    def save(self, path: Path | None = None) -> None:
        path = path or session_path(self.session_id)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Write-then-rename: a crash mid-write can't leave a half-written (corrupt) file,
        # because the rename is atomic. The reader sees the old version or the new one.
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2))
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: Path | None = None, session_id: str = "local") -> "Session":
        path = path or session_path(session_id)
        if path.is_file():
            try:
                data = json.loads(path.read_text())
                known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
                return cls(**known)
            except (json.JSONDecodeError, TypeError):
                # A corrupted memory file could hide a past taint, so assume the worst.
                return cls(session_id=session_id, tainted=True)
        return cls(session_id=session_id)
