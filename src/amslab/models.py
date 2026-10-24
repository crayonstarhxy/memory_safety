from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class TrustLevel(StrEnum):
    SYSTEM = "system"
    USER_CONFIRMED = "user_confirmed"
    USER = "user"
    TOOL = "tool"
    UNTRUSTED_EXTERNAL = "untrusted_external"


class MemoryStatus(StrEnum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    EXPIRED = "expired"
    DELETED = "deleted"


class DecisionAction(StrEnum):
    ACCEPT = "accept"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class Profile(StrEnum):
    VULNERABLE = "vulnerable"
    HARDENED = "hardened"


@dataclass(slots=True)
class MemoryCandidate:
    namespace: str
    content: str
    source: str
    trust: TrustLevel
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None


@dataclass(slots=True)
class PolicyDecision:
    action: DecisionAction
    risk_score: int
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MemoryRecord:
    record_id: str
    candidate: MemoryCandidate
    status: MemoryStatus
    risk_score: int
    decision_reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        result["candidate"]["trust"] = self.candidate.trust.value
        result["candidate"]["created_at"] = self.candidate.created_at.isoformat()
        expires_at = self.candidate.expires_at
        result["candidate"]["expires_at"] = expires_at.isoformat() if expires_at else None
        return result


@dataclass(frozen=True, slots=True)
class CaseDefinition:
    case_id: str
    title: str
    theory: str
    framework_refs: tuple[str, ...]


@dataclass(slots=True)
class CaseResult:
    case_id: str
    profile: Profile
    attack_succeeded: bool
    metrics: dict[str, bool | int | float | str]
    evidence: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "profile": self.profile.value,
            "attack_succeeded": self.attack_succeeded,
            "metrics": self.metrics,
            "evidence": self.evidence,
        }

