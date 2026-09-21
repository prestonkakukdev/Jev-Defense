# Changelog

## 0.2.0
- **Every major agent**: one universal hook speaks Claude Code, Codex, Copilot CLI, Gemini CLI, and Cursor; OpenCode plugin with real approval prompts via `permission.ask`. `agentdefense install|uninstall <agent>`.
- **Prompt capture at submit time** (`UserPromptSubmit` and equivalents) instead of reading lagging transcripts.
- **Instruction-file scanning** for skills, rules, `CLAUDE.md`/`AGENTS.md`, cached by content hash; `agentdefense scan-skills`.
- **New questions**: exfiltration (`sends_data_outward`, `touches_sensitive_data`), catch-all `needs_approval`, content `discussion`/`canary` categories.
- **Database awareness**: code detects SQL that hits every row; `DROP DATABASE` is a hard rule.
- **Writes outside the project** (`>> ~/.zshrc`) found in code and escalated.
- **Eval harness** (`agentdefense eval`) with a dev set and a held-out set, run on live Jev.
- Key file for GUI hosts (`agentdefense key`), total time budget per decision, hashed session filenames, atomic session writes.
- Fixed: short injections skipped by a minimum-length filter; transcript reader dropping the first line of small files.
- Credits: multi-host design informed by jev-guard (MIT).

## 0.1.0
- Action gate with isolated question groups, content gate with hidden-text extraction and passage removal, taint tracking, Claude Code hook, OpenCode plugin, demo and playground.
