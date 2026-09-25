from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    """
    Immutable record of an important security-system event.

    Audit events describe what happened; they do not execute
    security actions.
    """

    audit_id: str
    timestamp: datetime
    event_type: str
    actor: str
    incident_id: str
    action: str
    status: str
    reason: str = ""
    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    @classmethod
    def create(
        cls,
        audit_id: str,
        event_type: str,
        actor: str,
        incident_id: str,
        action: str,
        status: str,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> "AuditEvent":
        """
        Create an audit event using the current UTC timestamp.
        """

        return cls(
            audit_id=audit_id,
            timestamp=datetime.now(
                timezone.utc
            ),
            event_type=event_type,
            actor=actor,
            incident_id=incident_id,
            action=action,
            status=status,
            reason=reason,
            metadata=(
                dict(metadata)
                if metadata is not None
                else {}
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the audit event to a JSON-serializable dictionary.
        """

        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "actor": self.actor,
            "incident_id": self.incident_id,
            "action": self.action,
            "status": self.status,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }
