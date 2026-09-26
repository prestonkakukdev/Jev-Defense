# Changelog

## 0.2.1
- **Less rigid on hosts without approval prompts** (OpenCode without prompt config, Codex, Gemini CLI). An ASK used to become a refusal even when you had explicitly asked, e.g. "delete the src folder". Now a clear, explicit request counts as the confirmation (`smart` fallback). Vague requests, tainted sessions, whole-table SQL, and writes outside the project are still refused.
- Verified end to end on live Jev: explicitly requested deletes and every requested file edit or write run; unrequested destructive edits, exfiltration, and "yes do it" without a named target are still stopped.

## 0.2.0
- **Every major agent**: one universal hook speaks Claude Code, Codex, Copilot CLI, Gemini CLI, and Cursor; OpenCode plugin with real approval prompts via `permission.ask`. `jevdefense install|uninstall <agent>`.
- **Prompt capture at submit time** (`UserPromptSubmit` and equivalents) instead of reading lagging transcripts.
- **Instruction-file scanning** for skills, rules, `CLAUDE.md`/`AGENTS.md`, cached by content hash; `jevdefense scan-skills`.
- **New questions**: exfiltration (`sends_data_outward`, `touches_sensitive_data`), catch-all `needs_approval`, content `discussion`/`canary` categories.
- **Database awareness**: code detects SQL that hits every row; `DROP DATABASE` is a hard rule.
- **Writes outside the project** (`>> ~/.zshrc`) found in code and escalated.
- **Eval harness** (`jevdefense eval`) with a dev set and a held-out set, run on live Jev.
- Key file for GUI hosts (`jevdefense key`), total time budget per decision, hashed session filenames, atomic session writes.
- Fixed: short injections skipped by a minimum-length filter; transcript reader dropping the first line of small files.
- Credits: multi-host design informed by jev-guard (MIT).

## 0.1.0
- Action gate with isolated question groups, content gate with hidden-text extraction and passage removal, taint tracking, Claude Code hook, OpenCode plugin, demo and playground.
