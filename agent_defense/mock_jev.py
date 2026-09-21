"""
MockJev: a keyword-matching STAND-IN for Jev so the demo and tests run with no API key.

⚠  This is NOT Jev and NOT a real defense.  It's regexes, the exact kind of brittle
pattern matching that Jev is meant to replace.  It exists so you can see the pipeline
work end-to-end, and so the tests are deterministic.  Put a TYPESAFE_API_KEY in `.env`
and the demo switches to the real model automatically.

It answers the same question ids with the same answer shapes as LiveJev, which is what
lets the gates swap one for the other.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from .jev import Answer
from .rulebook import Question

YES, NO, UNSURE = 0.95, 0.05, 0.5


def _has(pattern: str, text: str) -> bool:
    return bool(re.search(pattern, text or "", re.IGNORECASE))


DESTRUCTIVE = (
    r"\brm\s|-delete\b|git\s+clean|git\s+reset\s+--hard|rmtree|os\.remove|os\.unlink|unlink\(|\bshred\b"
    r"|\btruncate\b|drop\s+table|push\s+(?:-f\b|--force)|(?<![>&\d])>(?!>)\s*[\w./~]"
)
REGENERABLE = r"node_modules|\bdist\b|\bbuild\b|__pycache__|\.cache|\btarget\b|\.pytest_cache"


def _words(text: str) -> set[str]:
    stop = {"the", "and", "this", "that", "with", "from", "into", "please", "can", "you", "for", "my", "our"}
    return {w for w in re.findall(r"[a-z]{4,}", (text or "").lower()) if w not in stop}


class MockJev:
    name = "MockJev (offline keyword stand-in, NOT the real model)"
    model = None

    async def ask(self, state: Mapping[str, Any], questions: Mapping[str, Question]) -> dict[str, Answer]:
        return {qid: self._answer(qid, state) for qid in questions}

    def _answer(self, qid: str, s: Mapping[str, Any]) -> Answer:
        cmd = s.get("command", "")
        destructive = _has(DESTRUCTIVE, cmd)

        if qid == "deletes_or_overwrites":
            return Answer("noul", YES if destructive else NO)

        if qid == "blast_radius":
            locations = {p["location"] for p in s.get("parser_facts", {}).get("paths", [])}
            if locations & {"system", "home_outside_project", "outside_project"} or _has(r"expanduser|~/|\$HOME|--force\s+origin|\|\s*(?:ba)?sh\b", cmd):
                level = 2
            elif "project" in locations or destructive:
                level = 1
            else:
                level = 0
            probs = {i: (0.8 if i == level else 0.1) for i in range(3)}
            return Answer("score", float(level), 0.75, probs)

        if qid == "reversible":
            if not destructive and not _has(r"\|\s*(?:ba)?sh\b|curl .*-X\s*POST", cmd):
                return Answer("noul", YES)
            return Answer("noul", 0.85 if _has(REGENERABLE, cmd) else 0.1)

        if qid == "sends_data_outward":
            return Answer("noul", 0.9 if _has(r"curl\b.*(-X\s*POST|--data|-d\s|-F\s|-T\s)|\bscp\b|\brsync\b.*:|\bnc\b\s|git\s+push|wget\b.*--post", cmd) else NO)

        if qid == "touches_sensitive_data":
            return Answer("noul", 0.9 if _has(r"\.env\b|id_rsa|id_ed25519|credentials|\bsecrets?\b|\btokens?\b|api[_ ]?key|\.ssh|printenv|\.aws|\.npmrc", cmd) else NO)

        if qid == "needs_approval":
            risky = destructive or _has(r"deploy|--prod|production|release|publish|kubectl\s+(delete|apply)|terraform\s+(apply|destroy)|stripe|payment|sudo|git\s+push", cmd)
            return Answer("noul", 0.85 if risky else 0.1)

        if qid == "user_requested":
            req = s.get("user_request", "")
            asked_to_delete = _has(r"delet|remov|clean|clear|wipe|reset|get rid|purge", req)
            if destructive:
                return Answer("noul", 0.9 if asked_to_delete else 0.08)
            return Answer("noul", 0.75 if _words(req) & _words(cmd) or _has(r"\btest", req) and _has(r"test", cmd) else 0.15)

        if qid == "reason_matches_request":
            return Answer("noul", 0.8 if _words(s.get("user_request")) & _words(s.get("agent_stated_reason")) else 0.25)

        if qid == "reason_has_manipulation":
            return Answer("noul", YES if _has(r"urgent|immediately|asap|already approved|pre-?approved|authori[sz]ed|reviewer|safety check|mark (?:this )?as safe|ignore (?:previous|prior)", s.get("agent_stated_reason")) else NO)

        if qid == "command_has_reviewer_text":
            return Answer("noul", 0.9 if _has(r"(#|echo).*(reviewer|approved|safe\b|authori[sz]ed|\bAI\b|assistant)", cmd) else 0.03)

        if qid == "follows_untrusted_instruction":
            excerpts = " ".join(s.get("untrusted_content_excerpts", []))
            urls = set(re.findall(r"https?://[^\s'\"|)]+", cmd))
            hit = any(u in excerpts for u in urls) or len(_words(cmd) & _words(excerpts)) >= 3
            return Answer("noul", 0.9 if hit else 0.1)

        # ── content gate questions ──
        text = s.get("chunk_text", "")
        if qid == "addresses_ai_agent":
            return Answer("noul", YES if _has(r"\b(AI|assistant|agent|language model|LLM|chatbot|GPT|Claude)s?\b", text) else NO)
        if qid == "tries_to_override":
            return Answer("noul", YES if _has(r"ignore (?:all )?(?:previous|prior|above|earlier)|disregard|new instructions|forget (?:your|all)|override", text) else NO)
        if qid == "requests_unrelated_action":
            return Answer("noul", 0.9 if _has(r"\b(?:run|execute|curl|wget|download and run|send|email|upload|post)\b.{0,60}(?:https?://|\bcommand|\bscript|\bto\b)", text) else 0.1)
        if qid == "requests_secret_exfiltration":
            secret = r"api[_ ]?keys?|passwords?|tokens?|secrets?|credentials?|\.ssh|id_rsa|\.env\b|conversation history|chat history|system prompt"
            verb = r"send|post|upload|reveal|share|include|print|output|forward"
            return Answer("noul", YES if _has(rf"(?:{verb}).{{0,60}}(?:{secret})|(?:{secret}).{{0,60}}(?:{verb})", text) and not _has(r"never share|do not share|don't share", text) else NO)
        if qid == "claims_authority":
            return Answer("noul", 0.9 if _has(r"system (?:message|notice|prompt)|from the (?:developer|administrator|admin|user)|security team|IMPORTANT MESSAGE", text) else 0.05)

        if qid == "content_kind":
            if _has(r"prompt injection|jailbreak|attackers? (?:can|may|often)|for example[,:]? an? (?:attacker|page)|this (?:attack|technique)", text) and not _has(r"^\s*(?:AI|assistant|agent)s?\b.{0,20}:", text):
                return _choice("discussion", ("injection", "canary", "discussion", "benign"))
            if _has(r"if you are an? (?:AI|LLM|language model)|include the (?:word|phrase)|admit (?:that )?you are", text):
                return _choice("canary", ("injection", "canary", "discussion", "benign"))
            if self._answer("tries_to_override", s).value > 0.5 or self._answer("requests_unrelated_action", s).value > 0.5 and self._answer("addresses_ai_agent", s).value > 0.5:
                return _choice("injection", ("injection", "canary", "discussion", "benign"))
            return _choice("benign", ("injection", "canary", "discussion", "benign"))

        # ── instruction-file questions ──
        body = s.get("content", "")
        exfil = _has(r"(?:send|post|upload|curl).{0,80}(?:\.env|secret|token|credential|api[_ ]?key|history)", body)
        covert = _has(r"curl[^|\n]*\|\s*(?:ba)?sh|base64\s+-d|do not (?:mention|tell)|without telling", body)
        override = _has(r"ignore (?:all |any )?(?:permission|safety|other instructions|previous)|bypass|disable (?:the )?(?:hooks?|guard)", body)
        if qid == "unexpected_behavior":
            return Answer("noul", 0.95 if (exfil or covert or override) else 0.1)
        if qid == "behavior_kind":
            kind = "exfiltration" if exfil else "covert_execution" if covert else "instruction_override" if override else "clean"
            return _choice(kind, ("exfiltration", "covert_execution", "instruction_override", "canary", "unrelated_side_effects", "clean"))

        return Answer("noul", UNSURE)  # unknown question: a coin flip, not a fake certainty


def _choice(winner: str, options: tuple[str, ...]) -> Answer:
    rest = (1 - 0.9) / (len(options) - 1)
    probs = {o: (0.9 if o == winner else rest) for o in options}
    return Answer("choice", 0.9, 0.85, probs, winner)
