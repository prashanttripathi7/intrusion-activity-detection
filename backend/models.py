from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class LogEvent:
    timestamp: str
    source: str
    raw: str
    parsed: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AlertEvent:
    timestamp: str
    rule_id: str
    category: str
    severity: str
    source: str
    message: str
    ip_address: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    title: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChain:
    chain_id: str
    title: str
    severity: str
    source_ip: str | None
    steps: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
