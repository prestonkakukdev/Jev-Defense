"""
Turn a tool call into the sentence Jev reads.

This lives in the library, not in one host's adapter, because Jev reads it LITERALLY and
small wording differences change the answer. Two bugs came from getting this wrong:

  * "creates it, or replaces ALL contents if it exists" made every NEW file score 0.97 on
    "does this delete or overwrite data?"
  * "change part of a file" scored 0.82, because replacing text sounds like losing text.

The fix in both cases was the same: CHECK THE FACT IN CODE, then state it plainly.
Every host adapter should call this so they all behave identically.
"""

from __future__ import annotations

import json
import os

MAX_SNIPPET = 400

# Each agent names the same tools differently. Normalize once, here, so every host asks Jev the
# same question about the same action.
SHELL_TOOLS = {"bash", "shell", "run_shell_command", "exec_command", "local_shell", "terminal"}
WRITE_TOOLS = {"write", "write_file", "create_file"}
EDIT_TOOLS = {"edit", "multiedit", "patch", "notebookedit", "replace", "apply_patch", "str_replace", "str_replace_based_edit_tool"}
DELETE_TOOLS = {"delete", "delete_file", "remove_file"}


def describe(tool: str, args: dict, cwd: str = "") -> tuple[str, str, list[str]]:
    """Return (gate tool type, action text for Jev, target paths)."""
    tool_lower = tool.lower()
    if not isinstance(args, dict):
        args = {"input": args}

    if tool_lower in SHELL_TOOLS:
        cmd = args.get("command") or args.get("cmd") or ""
        return "shell", " ".join(cmd) if isinstance(cmd, list) else str(cmd), []

    path = args.get("file_path") or args.get("filePath") or args.get("path") or args.get("notebook_path") or ""

    if tool_lower in DELETE_TOOLS:
        return "Delete", f"Delete the file {path}", [path] if path else []

    if tool_lower in WRITE_TOOLS:
        exists = bool(path) and os.path.exists(os.path.join(cwd, os.path.expanduser(path)))
        what = (
            f"Replace the entire contents of the existing file {path}"
            if exists
            else f"Create a new file {path}. No file exists at that path, so nothing is deleted or overwritten"
        )
        return "Write", what, [path] if path else []

    if tool_lower in EDIT_TOOLS:
        old = str(args.get("old_string") or args.get("oldString") or args.get("old_str") or "")[:MAX_SNIPPET]
        new = str(args.get("new_string") or args.get("newString") or args.get("new_str") or "")[:MAX_SNIPPET]
        if not old and (args.get("input") or args.get("patch")):  # Codex apply_patch: a unified diff
            return tool, f"Apply this patch:\n{str(args.get('input') or args.get('patch'))[:1500]}", [path] if path else []
        if old and new.startswith(old):
            # Purely additive: the old text survives verbatim inside the new text.
            added = new[len(old) :]
            return tool, (
                f"In the existing file {path}, ADD new text. Nothing is deleted or replaced: the existing "
                f"text stays exactly as it is and this text is added to it:\n---ADDED---\n{added}\n---END---"
            ), [path] if path else []
        if old:
            return tool, (
                f"In the existing file {path}, replace this exact text:\n---OLD---\n{old}\n---NEW---\n{new}\n---END---\n"
                f"The rest of the file is untouched."
            ), [path] if path else []
        return tool, f"Change the file {path}", [path] if path else []

    return tool, f"Call tool {tool} with arguments {json.dumps(args)[:1500]}", [path] if path else []
