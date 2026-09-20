from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import psycopg

from correlation.schema import SecurityEvent


class EventRepository:
    """
    PostgreSQL repository for SecurityEvent persistence.

    Responsibilities:
    - Store SecurityEvent objects in security_events.
    - Retrieve events by event_id.
    - Link events to incidents through incident_events.
    - Retrieve all events belonging to an incident.
    - Delete events safely.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        dbname: str = "cybersecurity",
        user: str = "cybersecurity",
        password: str = "cybersecurity_dev_password",
    ) -> None:
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.password = password

    def _connect(self) -> psycopg.Connection:
        """Create a new PostgreSQL connection."""
        return psycopg.connect(
            host=self.host,
            port=self.port,
            dbname=self.dbname,
            user=self.user,
            password=self.password,
        )

    @staticmethod
    def _event_to_values(event: SecurityEvent) -> tuple[Any, ...]:
        """Convert a SecurityEvent into PostgreSQL-ready values."""
        return (
            event.event_id,
            event.timestamp,
            event.src_ip,
            event.dst_ip,
            event.src_port,
            event.dst_port,
            event.protocol,
            event.protocol_name,
            int(event.binary_prediction),
            event.attack_family,
            float(event.confidence),
            event.source_file,
            event.true_label,
            event.true_attack_family,
            event.event_type,
            event.windows_event_id,
            event.username,
            event.domain,
            event.process_name,
            event.firewall_action,
            event.raw_log,
            json.dumps(event.metadata),
        )

    @staticmethod
    def _row_to_event(row: tuple[Any, ...]) -> SecurityEvent:
        """Convert a PostgreSQL row into a SecurityEvent."""

        (
            event_id,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            protocol_name,
            binary_prediction,
            attack_family,
            confidence,
            source_file,
            true_label,
            true_attack_family,
            event_type,
            windows_event_id,
            username,
            domain,
            process_name,
            firewall_action,
            raw_log,
            metadata,
        ) = row

        if isinstance(metadata, str):
            metadata = json.loads(metadata)

        return SecurityEvent(
            event_id=str(event_id),
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            protocol_name=protocol_name,
            binary_prediction=int(binary_prediction),
            attack_family=attack_family,
            confidence=float(confidence),
            source_file=source_file,
            true_label=true_label,
            true_attack_family=true_attack_family,
            event_type=event_type,
            windows_event_id=windows_event_id,
            username=username,
            domain=domain,
            process_name=process_name,
            firewall_action=firewall_action,
            raw_log=raw_log,
            metadata=metadata or {},
        )

    def save(self, event: SecurityEvent) -> None:
        """Insert or update a single SecurityEvent."""

        query = """
            INSERT INTO security_events (
                event_id,
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                protocol_name,
                binary_prediction,
                attack_family,
                confidence,
                source_file,
                true_label,
                true_attack_family,
                event_type,
                windows_event_id,
                username,
                domain,
                process_name,
                firewall_action,
                raw_log,
                metadata
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (event_id)
            DO UPDATE SET
                timestamp = EXCLUDED.timestamp,
                src_ip = EXCLUDED.src_ip,
                dst_ip = EXCLUDED.dst_ip,
                src_port = EXCLUDED.src_port,
                dst_port = EXCLUDED.dst_port,
                protocol = EXCLUDED.protocol,
                protocol_name = EXCLUDED.protocol_name,
                binary_prediction = EXCLUDED.binary_prediction,
                attack_family = EXCLUDED.attack_family,
                confidence = EXCLUDED.confidence,
                source_file = EXCLUDED.source_file,
                true_label = EXCLUDED.true_label,
                true_attack_family = EXCLUDED.true_attack_family,
                event_type = EXCLUDED.event_type,
                windows_event_id = EXCLUDED.windows_event_id,
                username = EXCLUDED.username,
                domain = EXCLUDED.domain,
                process_name = EXCLUDED.process_name,
                firewall_action = EXCLUDED.firewall_action,
                raw_log = EXCLUDED.raw_log,
                metadata = EXCLUDED.metadata
        """

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, self._event_to_values(event))

    def save_batch(self, events: list[SecurityEvent]) -> None:
        """Insert or update multiple SecurityEvents in one transaction."""

        if not events:
            return

        query = """
            INSERT INTO security_events (
                event_id,
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                protocol_name,
                binary_prediction,
                attack_family,
                confidence,
                source_file,
                true_label,
                true_attack_family,
                event_type,
                windows_event_id,
                username,
                domain,
                process_name,
                firewall_action,
                raw_log,
                metadata
            )
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT (event_id)
            DO UPDATE SET
                timestamp = EXCLUDED.timestamp,
                src_ip = EXCLUDED.src_ip,
                dst_ip = EXCLUDED.dst_ip,
                src_port = EXCLUDED.src_port,
                dst_port = EXCLUDED.dst_port,
                protocol = EXCLUDED.protocol,
                protocol_name = EXCLUDED.protocol_name,
                binary_prediction = EXCLUDED.binary_prediction,
                attack_family = EXCLUDED.attack_family,
                confidence = EXCLUDED.confidence,
                source_file = EXCLUDED.source_file,
                true_label = EXCLUDED.true_label,
                true_attack_family = EXCLUDED.true_attack_family,
                event_type = EXCLUDED.event_type,
                windows_event_id = EXCLUDED.windows_event_id,
                username = EXCLUDED.username,
                domain = EXCLUDED.domain,
                process_name = EXCLUDED.process_name,
                firewall_action = EXCLUDED.firewall_action,
                raw_log = EXCLUDED.raw_log,
                metadata = EXCLUDED.metadata
        """

        values = [self._event_to_values(event) for event in events]

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.executemany(query, values)

    def get_by_id(self, event_id: str) -> SecurityEvent | None:
        """Retrieve a SecurityEvent by its event ID."""

        query = """
            SELECT
                event_id,
                timestamp,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                protocol_name,
                binary_prediction,
                attack_family,
                confidence,
                source_file,
                true_label,
                true_attack_family,
                event_type,
                windows_event_id,
                username,
                domain,
                process_name,
                firewall_action,
                raw_log,
                metadata
            FROM security_events
            WHERE event_id = %s
        """

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (event_id,))
                row = cur.fetchone()

        if row is None:
            return None

        return self._row_to_event(row)

    def link_to_incident(
        self,
        incident_id: str,
        event_id: str,
    ) -> None:
        """
        Create an incident-event relationship.

        Both the incident and event must already exist.
        """

        query = """
            INSERT INTO incident_events (
                incident_id,
                event_id
            )
            VALUES (%s, %s)
            ON CONFLICT (incident_id, event_id)
            DO NOTHING
        """

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (incident_id, event_id))

    def link_events_to_incident(
        self,
        incident_id: str,
        event_ids: list[str],
    ) -> None:
        """Link multiple events to an incident."""

        if not event_ids:
            return

        query = """
            INSERT INTO incident_events (
                incident_id,
                event_id
            )
            VALUES (%s, %s)
            ON CONFLICT (incident_id, event_id)
            DO NOTHING
        """

        values = [
            (incident_id, event_id)
            for event_id in event_ids
        ]

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.executemany(query, values)

    def get_incident_events(
        self,
        incident_id: str,
    ) -> list[SecurityEvent]:
        """Retrieve all events associated with an incident."""

        query = """
            SELECT
                se.event_id,
                se.timestamp,
                se.src_ip,
                se.dst_ip,
                se.src_port,
                se.dst_port,
                se.protocol,
                se.protocol_name,
                se.binary_prediction,
                se.attack_family,
                se.confidence,
                se.source_file,
                se.true_label,
                se.true_attack_family,
                se.event_type,
                se.windows_event_id,
                se.username,
                se.domain,
                se.process_name,
                se.firewall_action,
                se.raw_log,
                se.metadata
            FROM security_events AS se
            INNER JOIN incident_events AS ie
                ON se.event_id = ie.event_id
            WHERE ie.incident_id = %s
            ORDER BY se.timestamp ASC
        """

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (incident_id,))
                rows = cur.fetchall()

        return [self._row_to_event(row) for row in rows]

    def count(self) -> int:
        """Return the total number of persisted security events."""

        query = "SELECT COUNT(*) FROM security_events"

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()

        return int(row[0])

    def delete(self, event_id: str) -> bool:
        """
        Delete an event.

        Associated incident_events rows are automatically removed
        by the database foreign-key cascade.
        """

        query = """
            DELETE FROM security_events
            WHERE event_id = %s
        """

        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (event_id,))
                return cur.rowcount > 0