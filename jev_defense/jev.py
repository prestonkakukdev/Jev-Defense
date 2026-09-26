"""
Talking to Jev.

The rest of the system never imports the TypeSafe SDK directly.  It talks to a tiny
interface, `JevBackend`, with one method: `ask(state, questions) -> answers`.

Two classes implement that interface:
  * LiveJev  — the real model, through TypeSafe's async Python SDK.
  * MockJev  — a keyword-matching stand-in (mock_jev.py) so the demo and tests run offline.

This is the "program to an interface, not an implementation" principle (also called
dependency injection).  The gates don't care which one they get, so swapping the fake for
the real thing needs no change to the gate code.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from . import config
from .rulebook import Question


@dataclass(frozen=True)
class Answer:
    """Our own small answer type, so the gates don't depend on SDK classes."""

    kind: str  # "noul", "score", or "choice"
    value: float  # noul: P(yes).  score: probability-weighted level.  choice: P(chosen option).
    confidence: float | None = None  # score and choice only (Noul answers don't carry one)
    probabilities: dict | None = None  # score: level -> p.  choice: option -> p.
    choice: str | None = None  # choice only: the winning option


class JevBackend(Protocol):
    name: str
    model: str | None  # versioned model id that answered most recently (for audit logs)

    async def ask(self, state: Mapping[str, Any], questions: Mapping[str, Question]) -> dict[str, Answer]: ...


class LiveJev:
    """The real Jev, via `typesafe_sdk.AsyncTypeSafeClient`."""

    name = "Jev (live)"

    def __init__(self, model: str = "jev-latest", api_key: str | None = None, timeout: float | None = None, transport: Any = None):
        # The SDK client is created lazily on first use, inside the running event loop.
        # (Async HTTP clients are tied to the event loop that created them.)
        self._model_alias = model
        self._api_key = api_key
        self._budget = timeout or config.TIMEOUT_S
        self._transport = transport  # tests inject a fake HTTP transport here
        self._client = None
        self.model: str | None = None

    async def ask(self, state: Mapping[str, Any], questions: Mapping[str, Question]) -> dict[str, Answer]:
        from typesafe_sdk import AsyncTypeSafeClient, Choice, Noul, NoulCriteria, Score

        if self._client is None:
            self._client = AsyncTypeSafeClient(api_key=self._api_key, model=self._model_alias, timeout=self._budget, transport=self._transport)

        sdk_questions = {}
        for qid, q in questions.items():
            if q.kind == "noul":
                criteria = NoulCriteria(true=q.criteria["true"], false=q.criteria["false"]) if q.criteria else None
                sdk_questions[qid] = Noul(instructions=q.instructions, criteria=criteria)
            elif q.kind == "choice":
                sdk_questions[qid] = Choice(instructions=q.instructions, criteria=q.criteria)
            else:
                sdk_questions[qid] = Score(instructions=q.instructions, criteria=q.criteria)

        # ONE network call; Jev evaluates every question in it in parallel, each in isolation.
        # wait_for caps the whole thing, SDK retries included (see config.TIMEOUT_S for why).
        response = await asyncio.wait_for(self._client.system_one(dict(state), sdk_questions), timeout=self._budget)
        self.model = response.model  # e.g. "jev-1.13.0"; aliases move, so log the real id

        answers: dict[str, Answer] = {}
        for qid, q in questions.items():
            if q.kind == "noul":
                answers[qid] = Answer("noul", response.nouls[qid].noul)
            elif q.kind == "choice":
                c = response.choices[qid]
                probs = {str(k): v for k, v in c.probabilities.items()}
                answers[qid] = Answer("choice", probs.get(c.choice, 0.0), c.confidence, probs, c.choice)
            else:
                s = response.scores[qid]
                answers[qid] = Answer("score", s.score, s.confidence, {int(k): v for k, v in s.probabilities.items()})
        return answers

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


def load_dotenv(path: str | Path | None = None) -> None:
    """Kept for backwards compatibility: puts the resolved key into the environment."""
    key = config.resolve_api_key()
    if key:
        os.environ.setdefault("TYPESAFE_API_KEY", key)


def default_backend(force_mock: bool = False) -> JevBackend:
    """Live Jev if an API key is available anywhere config.py looks, otherwise the offline mock."""
    key = None if force_mock else config.resolve_api_key()
    if key:
        return LiveJev(model=os.environ.get("TYPESAFE_DEFAULT_MODEL", "jev-latest"), api_key=key)
    from .mock_jev import MockJev

    return MockJev()
