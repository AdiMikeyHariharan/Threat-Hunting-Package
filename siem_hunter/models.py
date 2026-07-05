"""Core data structures passed between pipeline stages.

Kept as plain dataclasses so they serialise cleanly into the JSON logs and the
detection output without any framework coupling.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """A single normalised log event.

    ``raw`` keeps the original line for evidence; ``fields`` holds the parsed,
    queryable key/values that rules match against.
    """

    timestamp: datetime
    source: str                      # e.g. "auth.log"
    raw: str
    fields: dict[str, Any] = field(default_factory=dict)

    @property
    def event_id(self) -> str:
        """Stable short id derived from the raw line — used for correlation."""
        return hashlib.sha1(self.raw.encode("utf-8")).hexdigest()[:12]

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "fields": self.fields,
        }


@dataclass
class Detection:
    """A rule (or anomaly) firing against one or more events."""

    rule_id: str
    title: str
    severity: str                    # low | medium | high | critical
    detector: str                    # "rule" | "threshold" | "anomaly"
    event_ids: list[str]
    entity: str | None = None        # the src_ip / user the finding is about
    timestamp: datetime | None = None
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "detector": self.detector,
            "entity": self.entity,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_ids": self.event_ids,
            "mitre": self.mitre_techniques,
            "context": self.context,
        }
