from __future__ import annotations

import json
from typing import Any

import psycopg

from agent.audit.audit_event import AuditEvent


class AuditRepository:
    """
    PostgreSQL repository for append-only AuditEvent storage.

    Audit events can be inserted and retrieved, but they cannot be
    updated or deleted through this repository.
    """

    def __init__(
        self,
        database_url: str,
    ) -> None:
        if not isinstance(
            database_url,
            str,
        ):
            raise TypeError(
                "database_url must be a string."
            )

        if not database_url.strip():
            raise ValueError(
                "database_url cannot be empty."
            )

        self.database_url = database_url

    def _connect(self) -> psycopg.Connection:
        """
        Create a PostgreSQL connection.
        """

        return psycopg.connect(
            self.database_url
        )

    def create_table(self) -> None:
        """
        Create the audit_events table if it does not exist.
        """

        query = """
            CREATE TABLE IF NOT EXISTS audit_events (
                audit_id TEXT PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)

    @staticmethod
    def _event_to_values(
        event: AuditEvent,
    ) -> tuple[Any, ...]:
        """
        Convert an AuditEvent into PostgreSQL-ready values.
        """

        if not isinstance(
            event,
            AuditEvent,
        ):
            raise TypeError(
                "event must be an AuditEvent."
            )

        return (
            event.audit_id,
            event.timestamp,
            event.event_type,
            event.actor,
            event.incident_id,
            event.action,
            event.status,
            event.reason,
            json.dumps(event.metadata),
        )

    def save(
        self,
        event: AuditEvent,
    ) -> None:
        """
        Append one audit event.

        Existing audit IDs are rejected rather than updated.
        This preserves append-only semantics.
        """

        values = self._event_to_values(
            event
        )

        query = """
            INSERT INTO audit_events (
                audit_id,
                timestamp,
                event_type,
                actor,
                incident_id,
                action,
                status,
                reason,
                metadata
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s::jsonb
            )
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    values,
                )

    def save_batch(
        self,
        events: list[AuditEvent],
    ) -> None:
        """
        Append multiple audit events in one transaction.

        Existing audit IDs are rejected.
        """

        if not isinstance(
            events,
            list,
        ):
            raise TypeError(
                "events must be a list."
            )

        for event in events:
            if not isinstance(
                event,
                AuditEvent,
            ):
                raise TypeError(
                    "all items in events must be AuditEvent objects."
                )

        if not events:
            return

        query = """
            INSERT INTO audit_events (
                audit_id,
                timestamp,
                event_type,
                actor,
                incident_id,
                action,
                status,
                reason,
                metadata
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s::jsonb
            )
        """

        values = [
            self._event_to_values(event)
            for event in events
        ]

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.executemany(
                    query,
                    values,
                )

    @staticmethod
    def _row_to_event(
        row: tuple[Any, ...],
    ) -> AuditEvent:
        """
        Convert a PostgreSQL row into an AuditEvent.
        """

        (
            audit_id,
            timestamp,
            event_type,
            actor,
            incident_id,
            action,
            status,
            reason,
            metadata,
        ) = row

        if isinstance(
            metadata,
            str,
        ):
            metadata = json.loads(metadata)

        return AuditEvent(
            audit_id=str(audit_id),
            timestamp=timestamp,
            event_type=event_type,
            actor=actor,
            incident_id=incident_id,
            action=action,
            status=status,
            reason=reason,
            metadata=metadata or {},
        )

    def get_by_id(
        self,
        audit_id: str,
    ) -> AuditEvent | None:
        """
        Retrieve one audit event by ID.
        """

        if not isinstance(
            audit_id,
            str,
        ):
            raise TypeError(
                "audit_id must be a string."
            )

        if not audit_id.strip():
            raise ValueError(
                "audit_id cannot be empty."
            )

        query = """
            SELECT
                audit_id,
                timestamp,
                event_type,
                actor,
                incident_id,
                action,
                status,
                reason,
                metadata
            FROM audit_events
            WHERE audit_id = %s
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    (audit_id,),
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_event(row)

    def get_for_incident(
        self,
        incident_id: str,
    ) -> list[AuditEvent]:
        """
        Retrieve all audit events for an incident
        in chronological order.
        """

        if not isinstance(
            incident_id,
            str,
        ):
            raise TypeError(
                "incident_id must be a string."
            )

        if not incident_id.strip():
            raise ValueError(
                "incident_id cannot be empty."
            )

        query = """
            SELECT
                audit_id,
                timestamp,
                event_type,
                actor,
                incident_id,
                action,
                status,
                reason,
                metadata
            FROM audit_events
            WHERE incident_id = %s
            ORDER BY timestamp ASC, audit_id ASC
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    (incident_id,),
                )

                rows = cursor.fetchall()

        return [
            self._row_to_event(row)
            for row in rows
        ]

    def list_recent(
        self,
        limit: int = 50,
    ) -> list[AuditEvent]:
        """
        Retrieve the most recent audit events.
        """

        if not isinstance(
            limit,
            int,
        ) or limit <= 0:
            raise ValueError(
                "limit must be a positive integer."
            )

        query = """
            SELECT
                audit_id,
                timestamp,
                event_type,
                actor,
                incident_id,
                action,
                status,
                reason,
                metadata
            FROM audit_events
            ORDER BY timestamp DESC, audit_id DESC
            LIMIT %s
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    (limit,),
                )

                rows = cursor.fetchall()

        return [
            self._row_to_event(row)
            for row in rows
        ]

    def count(self) -> int:
        """
        Return the total number of audit events.
        """

        query = """
            SELECT COUNT(*)
            FROM audit_events
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)

                row = cursor.fetchone()

        return int(row[0])
