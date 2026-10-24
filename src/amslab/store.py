from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from .models import (
    DecisionAction,
    MemoryCandidate,
    MemoryRecord,
    MemoryStatus,
)


class MemoryStore:
    def __init__(self, policy, *, strict_namespace: bool, enforce_ttl: bool) -> None:
        self._policy = policy
        self._strict_namespace = strict_namespace
        self._enforce_ttl = enforce_ttl
        self._records: list[MemoryRecord] = []

    @property
    def records(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._records)

    def write(self, candidate: MemoryCandidate) -> MemoryRecord:
        active = [r for r in self._records if r.status is MemoryStatus.ACTIVE]
        decision = self._policy.evaluate(candidate, active)
        status = {
            DecisionAction.ACCEPT: MemoryStatus.ACTIVE,
            DecisionAction.QUARANTINE: MemoryStatus.QUARANTINED,
            DecisionAction.REJECT: MemoryStatus.REJECTED,
        }[decision.action]
        record = MemoryRecord(
            record_id=uuid.uuid4().hex,
            candidate=candidate,
            status=status,
            risk_score=decision.risk_score,
            decision_reasons=decision.reasons,
        )
        self._records.append(record)
        return record

    def query(self, namespace: str, text: str, *, limit: int = 5) -> list[MemoryRecord]:
        now = datetime.now(timezone.utc)
        query_tokens = self._tokens(text)
        scored: list[tuple[int, int, MemoryRecord]] = []

        for position, record in enumerate(self._records):
            if record.status is not MemoryStatus.ACTIVE:
                continue
            if self._strict_namespace and record.candidate.namespace != namespace:
                continue
            if (
                self._enforce_ttl
                and record.candidate.expires_at
                and record.candidate.expires_at <= now
            ):
                record.status = MemoryStatus.EXPIRED
                continue
            overlap = len(query_tokens & self._tokens(record.candidate.content))
            # Recency breaks ties, approximating common retrieval behavior.
            scored.append((overlap, position, record))

        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [record for _, _, record in scored[:limit]]

    def delete(self, record_id: str) -> bool:
        for record in self._records:
            if record.record_id == record_id:
                record.status = MemoryStatus.DELETED
                return True
        return False

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return set(re.findall(r"[\w.-]+", text.casefold()))

