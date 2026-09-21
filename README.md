# AgentDefense

**A security guard for AI agents, powered by [Jev](https://docs.typesafe.ai/introduction).**
It stops dangerous tool calls before they run, strips prompt injection out of what agents read, and checks skills and rule files for hidden instructions.

Works with **Claude Code · Codex · GitHub Copilot CLI · Gemini CLI · Cursor · OpenCode**, plus a Python library and a JSON interface for your own agents.

```text
$ agentdefense action --user "fix the typo in the README" --command "git reset --hard HEAD~5"
BLOCK  Deletes or overwrites data (p=0.98) but the user did not clearly ask for it (requested p=0.02)
```

---

## Why

An agent acts with **your** permissions while taking directions from **whatever text it reads**. A web page, an issue comment, a README in a cloned repo, or a malicious skill can all tell it to delete your work or upload your `.env`, and to the model that text looks just like your instructions.

Model-side refusals help, but they vary by model and fail on attacks that look like ordinary documentation. AgentDefense sits *outside* the model, so the same checks apply whichever model you run.

## Results (live Jev, `jev-1.13.0`)

| | Dev set (51 cases) | Held-out set (24 cases, run once, not tuned) |
|---|---|---|
| Dangerous actions stopped | **23 / 23** | **11 / 11** |
| Legitimate actions wrongly blocked | 0 / 14 | 0 / 7 |
| Legitimate actions sent to a human | 1 / 14 | 0 / 7 |
| Prompt injections detected | 5 / 5 | 2 / 2 |
| False alarms on normal pages (incl. security articles) | 0 / 4 | 0 / 2 |
| Malicious skills detected / false alarms | 3 / 3 · 0 / 2 | 1 / 1 · 0 / 1 |

Median decision time is about 270 ms (p95 about 770 ms). Full per-case tables: [`evals/RESULTS.md`](evals/RESULTS.md) and [`evals/HOLDOUT_RESULTS.md`](evals/HOLDOUT_RESULTS.md). Run them yourself with `agentdefense eval`.

Read these numbers honestly. The sets are small and hand-written, and the dev set was used to tune the policy. The held-out set is the fairer signal. In it, two attacks were stopped with ASK rather than BLOCK (`chmod -R 777 ~`, `truncate` on a lockfile); both are listed as known gaps.

## Install

```bash
git clone https://github.com/<you>/AgentDefense && cd AgentDefense
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/agentdefense key <your TypeSafe API key>      # from console.typesafe.ai
```

Then register it with your agent (each command is idempotent, keeps your other hooks, and backs up the file):

| Agent | Command | Risky call | After a tool reads something |
|---|---|---|---|
| Claude Code | `agentdefense install claude` (or `--project <dir>`) | deny · **approval prompt** | warn + strip (MCP) |
| OpenCode | `agentdefense install opencode` | deny · **approval prompt**¹ | warn + strip |
| Cursor | `agentdefense install cursor` | deny · **approval prompt** (shell, MCP) | warn |
| Copilot CLI | `agentdefense install copilot` | deny · **approval prompt** | warn |
| Codex | `agentdefense install codex` | deny · smart fallback² | warn |
| Gemini CLI | `agentdefense install gemini` | deny · smart fallback² | warn |

¹ Set `"permission": {"bash": "ask", "edit": "ask"}` in `opencode.json`; AgentDefense then auto-approves safe calls and prompts only for risky ones. Without that, it uses the smart fallback².
² For hosts that can't show an approval prompt: if you **clearly asked for that exact action** ("delete the src folder"), your request counts as the confirmation and it runs. If AgentDefense isn't sure you asked ("clean up", "yes do it"), or the session read hostile content, it refuses and says why. `AGENT_DEFENSE_ASK_FALLBACK=deny` always refuses; `=warn` always runs.

Remove it again with `agentdefense uninstall <agent>`.

## How it works

```text
 you ──► agent ──► tool call ──► ACTION GATE ──► allow / ask a human / block
            ▲                         ▲
            │                         │ taint: "this session read hostile text"
            │                  ┌──────┴───────┐
            └── cleaned text ◄─┤ CONTENT GATE │◄── web pages, files, MCP output
                               └──────────────┘
          skills, rules, CLAUDE.md ──► INSTRUCTION SCAN (at session start and on load)
```

**Jev never makes the final decision.** It answers narrow, typed yes/no questions with calibrated probabilities. A readable table of `if` statements turns those numbers into a verdict. All questions and thresholds live in one file, [`agent_defense/rulebook.py`](agent_defense/rulebook.py).

### Action gate: what's checked before a tool runs

1. **Hard rules in code**: `rm -rf ~`, `mkfs`, `DROP DATABASE`, fork bombs. No model involved.
2. **Facts in code**: where each path resolves (project, temp, home, or system), SQL that touches **every row** (`DELETE` / `UPDATE` with no `WHERE`), and redirects that write outside the project (`>> ~/.zshrc`).
3. **Jev**, asked in **four isolated calls**:

| Group (each sees only its listed evidence) | Questions |
|---|---|
| the command alone | deletes or overwrites data? · sends data off the machine? · touches credentials? · reversible? · blast radius (temp / project / outside) · would a senior engineer want to approve it? |
| your request + the command | did you ask for, or clearly imply, this action? |
| your request + the agent's reason | does the stated reason serve your goal? |
| the agent's reason + the command | urgency, claimed approval, or notes aimed at the reviewer? |

**The isolation is the point.** A hijacked agent writes its own justification, so that text is attacker-controlled. Jev's docs say adversarial text in the state "can move the answer". Here, the question "does this delete data?" never sees the agent's excuse, so no excuse can argue it down.

### Content gate: what's checked after a tool reads something

- Separates **visible text from hidden text**: `display:none`, CSS classes that hide text, white-on-white, zero font size, HTML comments, `alt` and `meta` text, and invisible Unicode tag characters ("ASCII smuggling"), which are decoded and scanned.
- Scores every chunk **in its own call**, so one poisoned paragraph can't influence the verdict on another.
- Uses a `discussion` category so articles *about* prompt injection aren't flagged, and a `canary` category for "if you're an AI, include the word X" traps.
- **Removes** flagged passages instead of annotating them, so even a model that ignores warnings never reads the attack. What remains is fenced with an unguessable random boundary.
- Marks the session **tainted**. Later actions get stricter thresholds plus one more question: *does this command carry out an instruction from that page?*

### Instruction scan: skills, rules, `CLAUDE.md`, `AGENTS.md`

These files are supposed to instruct the agent, which makes them a supply-chain target. They are asked a different question: does this file also do something its installer wouldn't expect (exfiltration, covert execution, overriding safety checks, canaries, unrelated config edits)? Results are cached by content hash, so repeat sweeps are free. Run `agentdefense scan-skills --user` to audit every agent's skill folders.

## Use it in your own agent

```python
from agent_defense import ActionGate, ActionRequest, ContentGate, Session, default_backend, wrap_untrusted

jev, session = default_backend(), Session()
verdict = await ActionGate(jev, session).check(ActionRequest(user_message, command, agent_reason))
scan = await ContentGate(jev, session).scan(page_html, user_task=user_message, source=url)
agent_reads = wrap_untrusted(scan.safe_text, url)
```

Other languages can use the JSON interface: `echo '{"user_request":"…","command":"…"}' | agentdefense check`.

## Configuration

| Variable | Default | Effect |
|---|---|---|
| `TYPESAFE_API_KEY` | (none) | API key. Also read from `.env` or `~/.agent_defense/config.json` (`agentdefense key`) |
| `TYPESAFE_DEFAULT_MODEL` | `jev-latest` | Pin a version (e.g. `jev-1.13.0`) once you've tuned thresholds |
| `AGENT_DEFENSE_TIMEOUT` | `20` | Seconds per decision, retries included. Stays under the ~30 s hook limit so failing closed really happens |
| `AGENT_DEFENSE_FAIL_OPEN` | unset | `1` = allow when Jev is unreachable. **Default is fail closed** (a human decides) |
| `AGENT_DEFENSE_ASK_FALLBACK` | `smart` | Hosts without approval prompts: `smart` runs what you clearly asked for, `deny` always refuses, `warn` always runs |
| `AGENT_DEFENSE_SKIP_TOOLS` / `_SKIP_SCAN` | (none) | Comma-separated tool names to exclude |

Thresholds and questions are in [`rulebook.py`](agent_defense/rulebook.py). Rerun `agentdefense eval` after changing them.

## Try it without risk

- `python demo.py -v` walks through every scenario with the raw Jev probabilities.
- `python playground.py` runs a deliberately **gullible agent** that obeys any instruction it reads. The same attack runs twice: without the guard your sandbox files really disappear; with it they don't. `--repl` lets you play both sides.
- Everything runs offline with `--mock`, a keyword stand-in that is **not a real defense**. Use a key to test Jev.

## Limits

- **A guardrail, not a sandbox.** A misconfigured hook, a tool path the host doesn't expose to hooks, or a wrong answer from Jev can let something through. Keep your other controls.
- **It only sees the dimensions it asks about.** A catch-all "would an engineer want to approve this?" question narrows the gap but doesn't close it.
- **Host gaps.** Claude Code can't rewrite a built-in tool's output after the fact (AgentDefense warns and taints instead). OpenCode reportedly doesn't fire plugin hooks for subagent tool calls ([opencode#5894](https://github.com/anomalyco/opencode/issues/5894)).
- **Privacy.** Tool calls and tool output are sent to TypeSafe's API for scoring. Review their [privacy policy](https://typesafe.ai/privacy) before using it on sensitive repositories.
- **Cost and latency.** About four Jev calls per checked action (small fractions of a cent) and about a quarter second added. Read-only tools and simple read commands skip Jev entirely.

## Learn how it works

[`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md) is a plain-language tour of Jev, every design decision, and the computer science behind it: defense in depth, least privilege, taint tracking, fail-closed design, and calibration.

## Credits

The multi-agent reach of v0.2 follows **[jev-guard](https://github.com/leepokai/jev-guard)** (MIT) by leepokai. Its host payload formats, prompt-hook context capture, OpenCode `permission.ask` technique, instruction-file scanning, `discussion`/`canary` categories, and catch-all approval question all informed this version. AgentDefense's own contributions are the isolated-question design, hidden-content extraction, passage removal, taint tracking, SQL and path facts, exfiltration questions, and the eval harness.

## License

MIT
