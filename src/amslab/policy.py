from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable

from .models import (
    DecisionAction,
    MemoryCandidate,
    MemoryRecord,
    PolicyDecision,
    TrustLevel,
)


class PermissivePolicy:
    """Deliberately vulnerable baseline used to validate the tests."""

    def evaluate(
        self, candidate: MemoryCandidate, active_records: Iterable[MemoryRecord]
    ) -> PolicyDecision:
        return PolicyDecision(DecisionAction.ACCEPT, 0, ["baseline_accepts_all"])


class HardenedPolicy:
    _behavior_patterns = tuple(
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"ignore\s+(all\s+)?previous",
            r"from\s+now\s+on",
            r"always\s+(use|trust|send|execute)",
            r"system\s+prompt",
            r"\[call:[^\]]+\]",
            r"忽略.{0,8}(之前|以上|原有)",
            r"从现在开始",
            r"始终.{0,8}(使用|信任|发送|执行)",
        )
    )

    def evaluate(
        self, candidate: MemoryCandidate, active_records: Iterable[MemoryRecord]
    ) -> PolicyDecision:
        score = 0
        reasons: list[str] = []
        normalized = unicodedata.normalize("NFKC", candidate.content)

        if candidate.trust is TrustLevel.UNTRUSTED_EXTERNAL:
            score += 25
            reasons.append("untrusted_external_source")

        if any(pattern.search(normalized) for pattern in self._behavior_patterns):
            score += 50
            reasons.append("behavior_shaping_instruction")

        if any(unicodedata.category(char) == "Cf" for char in candidate.content):
            score += 30
            reasons.append("unicode_format_control")

        key = candidate.metadata.get("key")
        if key and any(
            record.candidate.metadata.get("key") == key
            and record.candidate.content != candidate.content
            for record in active_records
        ):
            score += 40
            reasons.append("conflicts_with_active_memory")

        if candidate.metadata.get("privileged_behavior"):
            score += 30
            reasons.append("targets_privileged_behavior")

        if candidate.trust is TrustLevel.USER_CONFIRMED:
            score = max(0, score - 40)
            reasons.append("explicit_user_confirmation")

        if score >= 80:
            action = DecisionAction.REJECT
        elif score >= 40:
            action = DecisionAction.QUARANTINE
        else:
            action = DecisionAction.ACCEPT
        return PolicyDecision(action, score, reasons or ["no_risk_signal"])

