# Security

Jev Defense is a guardrail, not a sandbox. Please report bypasses: they are the most useful contribution this project can get.

**Found a bypass?** Open a private security advisory on GitHub (Security → Report a vulnerability) with:
- the host (Claude Code, Codex, …) and version,
- the exact tool call or content that got through,
- what AgentDefense returned (`agentdefense action … --json` or the hook output).

Please don't file bypasses as public issues until a fix ships. Once fixed, the case is added to `evals/` so it can never silently regress.

## What is sent where

Tool calls (name, arguments, working directory), the user's recent prompts, and tool output are sent to TypeSafe's API (`api.typesafe.ai`) for scoring. Nothing else leaves your machine. Session memory and the scan cache live in `~/.agent_defense/` with owner-only permissions.
