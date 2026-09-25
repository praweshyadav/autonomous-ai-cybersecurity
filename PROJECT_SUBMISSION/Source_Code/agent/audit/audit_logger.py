from __future__ import annotations

from typing import Any

from agent.audit.audit_event import AuditEvent


class AuditLogger:
    """
    Records audit events in memory and optionally persists them
    through an injected repository.

    The logger remains usable without a repository, which keeps
    unit tests and local development lightweight.
    """

    def __init__(self, repository=None):
        self._events: list[AuditEvent] = []
        self._repository = repository

    def record(self, event: AuditEvent) -> AuditEvent:
        """
        Record an already-created AuditEvent.

        The event is always stored in memory.

        If a repository is configured, the same event is also
        persisted to the repository.
        """
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent")

        self._events.append(event)

        if self._repository is not None:
            self._repository.save(event)

        return event

    def log(
        self,
        audit_id: str,
        event_type: str,
        actor: str,
        incident_id: str,
        action: str,
        status: str,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Create and record an AuditEvent.
        """
        event = AuditEvent.create(
            audit_id=audit_id,
            event_type=event_type,
            actor=actor,
            incident_id=incident_id,
            action=action,
            status=status,
            reason=reason,
            metadata=metadata,
        )

        return self.record(event)

    def get_all(self) -> list[AuditEvent]:
        """
        Return all events recorded by this logger.
        """
        return list(self._events)

    def get_for_incident(self, incident_id: str) -> list[AuditEvent]:
        """
        Return in-memory events belonging to an incident.
        """
        if not isinstance(incident_id, str):
            raise TypeError("incident_id must be a string")

        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")

        return [
            event
            for event in self._events
            if event.incident_id == incident_id
        ]

    def count(self) -> int:
        """
        Return the number of events currently held in memory.
        """
        return len(self._events)

    @property
    def repository(self):
        """
        Return the configured persistence repository, if any.
        """
        return self._repository
