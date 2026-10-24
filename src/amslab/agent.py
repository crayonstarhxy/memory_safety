from __future__ import annotations

import re
from dataclasses import dataclass

from .models import MemoryRecord
from .store import MemoryStore
from .tools import MockToolGateway, ToolEvent


@dataclass(slots=True)
class AgentResponse:
    text: str
    recalled: list[MemoryRecord]
    tool_events: list[ToolEvent]


class DeterministicAgent:
    """Small deterministic stand-in that makes memory influence observable."""

    _call_pattern = re.compile(r"\[CALL:(?P<tool>[a-z_]+)(?P<args>[^\]]*)\]", re.IGNORECASE)

    def __init__(self, store: MemoryStore, tools: MockToolGateway, namespace: str) -> None:
        self.store = store
        self.tools = tools
        self.namespace = namespace

    def respond(self, prompt: str) -> AgentResponse:
        recalled = self.store.query(self.namespace, prompt)
        before = len(self.tools.events)
        for record in recalled:
            for match in self._call_pattern.finditer(record.candidate.content):
                arguments = self._parse_args(match.group("args"))
                self.tools.invoke(match.group("tool").lower(), arguments)
        sources = ", ".join(record.record_id[:8] for record in recalled) or "none"
        return AgentResponse(
            text=f"Recalled memory objects: {sources}",
            recalled=recalled,
            tool_events=self.tools.events[before:],
        )

    @staticmethod
    def _parse_args(raw: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for token in raw.strip().split():
            if "=" in token:
                key, value = token.split("=", 1)
                result[key] = value
        return result

