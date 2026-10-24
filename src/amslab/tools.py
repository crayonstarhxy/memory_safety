from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ToolEvent:
    tool: str
    arguments: dict[str, str]
    executed: bool
    reason: str


class MockToolGateway:
    """Records sensitive attempts but never performs external side effects."""

    def __init__(self) -> None:
        self.events: list[ToolEvent] = []

    def invoke(self, tool: str, arguments: dict[str, str], *, approval: str | None = None) -> ToolEvent:
        if tool == "read_note":
            event = ToolEvent(tool, arguments, True, "safe_local_mock")
        else:
            event = ToolEvent(tool, arguments, False, "sensitive_mock_requires_out_of_band_approval")
        self.events.append(event)
        return event

