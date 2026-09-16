from __future__ import annotations

import json
import uuid
from typing import Any

import psycopg

from correlation.schema import Incident


class IncidentRepository:
    """
    PostgreSQL repository for persistent Incident storage.
    """

    def __init__(
        self,
        database_url: str,
    ) -> None:
        if not isinstance(database_url, str):
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

    @staticmethod
    def _incident_to_row(
        incident: Incident,
    ) -> dict[str, Any]:
        """
        Convert an Incident object into database-ready values.
        """

        if not isinstance(
            incident,
            Incident,
        ):
            raise TypeError(
                "incident must be an Incident."
            )

        if incident.start_time is None:
            raise ValueError(
                "incident.start_time cannot be None."
            )

        if incident.end_time is None:
            raise ValueError(
                "incident.end_time cannot be None."
            )

        return {
            "incident_id": str(
                incident.incident_id
            ),
            "start_time": incident.start_time,
            "end_time": incident.end_time,
            "severity": incident.severity,
            "primary_family": (
                incident.primary_attack_family
                or "Unknown"
            ),
            "confidence": float(
                incident.confidence
            ),
            "event_count": len(
                incident.events
            ),
            "source_ips": json.dumps(
                sorted(incident.src_ips)
            ),
            "destination_ips": json.dumps(
                sorted(incident.dst_ips)
            ),
            "destination_ports": json.dumps(
                sorted(incident.dst_ports)
            ),
            "protocols": json.dumps(
                sorted(incident.protocols)
            ),
            "family_distribution": json.dumps(
                incident.family_distribution
            ),
        }

    @staticmethod
    def _row_to_incident(
        row: tuple[Any, ...],
    ) -> Incident:
        """
        Convert a PostgreSQL row into an Incident object.

        Event objects are not reconstructed here because the
        current incidents table stores incident-level data only.
        """

        (
            incident_id,
            start_time,
            end_time,
            severity,
            primary_family,
            confidence,
            event_count,
            source_ips,
            destination_ips,
            destination_ports,
            protocols,
            family_distribution,
        ) = row

        if isinstance(
            source_ips,
            str,
        ):
            source_ips = json.loads(
                source_ips
            )

        if isinstance(
            destination_ips,
            str,
        ):
            destination_ips = json.loads(
                destination_ips
            )

        if isinstance(
            destination_ports,
            str,
        ):
            destination_ports = json.loads(
                destination_ports
            )

        if isinstance(
            protocols,
            str,
        ):
            protocols = json.loads(
                protocols
            )

        if isinstance(
            family_distribution,
            str,
        ):
            family_distribution = json.loads(
                family_distribution
            )

        return Incident(
            incident_id=str(
                incident_id
            ),
            start_time=start_time,
            end_time=end_time,
            severity=severity,
            primary_attack_family=(
                primary_family
            ),
            family_distribution=dict(
                family_distribution
            ),
            confidence=float(
                confidence
            ),
            src_ips=list(
                source_ips
            ),
            dst_ips=list(
                destination_ips
            ),
            dst_ports=list(
                destination_ports
            ),
            protocols=list(
                protocols
            ),
        )

    def save(
        self,
        incident: Incident,
    ) -> None:
        """
        Insert an incident.

        If the same incident_id already exists,
        update the existing record.
        """

        row = self._incident_to_row(
            incident
        )

        query = """
            INSERT INTO incidents (
                incident_id,
                start_time,
                end_time,
                severity,
                primary_family,
                confidence,
                event_count,
                source_ips,
                destination_ips,
                destination_ports,
                protocols,
                family_distribution
            )
            VALUES (
                %(incident_id)s,
                %(start_time)s,
                %(end_time)s,
                %(severity)s,
                %(primary_family)s,
                %(confidence)s,
                %(event_count)s,
                %(source_ips)s::jsonb,
                %(destination_ips)s::jsonb,
                %(destination_ports)s::jsonb,
                %(protocols)s::jsonb,
                %(family_distribution)s::jsonb
            )
            ON CONFLICT (incident_id)
            DO UPDATE SET
                start_time = EXCLUDED.start_time,
                end_time = EXCLUDED.end_time,
                severity = EXCLUDED.severity,
                primary_family = EXCLUDED.primary_family,
                confidence = EXCLUDED.confidence,
                event_count = EXCLUDED.event_count,
                source_ips = EXCLUDED.source_ips,
                destination_ips = EXCLUDED.destination_ips,
                destination_ports = EXCLUDED.destination_ports,
                protocols = EXCLUDED.protocols,
                family_distribution = EXCLUDED.family_distribution
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    row,
                )

    def save_batch(
        self,
        incidents: list[Incident],
    ) -> None:
        """
        Persist multiple incidents in one transaction.
        """

        if not isinstance(
            incidents,
            list,
        ):
            raise TypeError(
                "incidents must be a list."
            )

        for incident in incidents:
            if not isinstance(
                incident,
                Incident,
            ):
                raise TypeError(
                    "all items in incidents must be Incident objects."
                )

        if not incidents:
            return

        query = """
            INSERT INTO incidents (
                incident_id,
                start_time,
                end_time,
                severity,
                primary_family,
                confidence,
                event_count,
                source_ips,
                destination_ips,
                destination_ports,
                protocols,
                family_distribution
            )
            VALUES (
                %(incident_id)s,
                %(start_time)s,
                %(end_time)s,
                %(severity)s,
                %(primary_family)s,
                %(confidence)s,
                %(event_count)s,
                %(source_ips)s::jsonb,
                %(destination_ips)s::jsonb,
                %(destination_ports)s::jsonb,
                %(protocols)s::jsonb,
                %(family_distribution)s::jsonb
            )
            ON CONFLICT (incident_id)
            DO UPDATE SET
                start_time = EXCLUDED.start_time,
                end_time = EXCLUDED.end_time,
                severity = EXCLUDED.severity,
                primary_family = EXCLUDED.primary_family,
                confidence = EXCLUDED.confidence,
                event_count = EXCLUDED.event_count,
                source_ips = EXCLUDED.source_ips,
                destination_ips = EXCLUDED.destination_ips,
                destination_ports = EXCLUDED.destination_ports,
                protocols = EXCLUDED.protocols,
                family_distribution = EXCLUDED.family_distribution
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                for incident in incidents:
                    cursor.execute(
                        query,
                        self._incident_to_row(
                            incident
                        ),
                    )

    def get_by_id(
        self,
        incident_id: uuid.UUID | str,
    ) -> Incident | None:
        """
        Retrieve an incident by incident_id.
        """

        if not isinstance(
            incident_id,
            (uuid.UUID, str),
        ):
            raise TypeError(
                "incident_id must be a UUID or string."
            )

        incident_id = str(
            incident_id
        )

        query = """
            SELECT
                incident_id,
                start_time,
                end_time,
                severity,
                primary_family,
                confidence,
                event_count,
                source_ips,
                destination_ips,
                destination_ports,
                protocols,
                family_distribution
            FROM incidents
            WHERE incident_id = %s
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    (incident_id,),
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_incident(
            row
        )

    def list_recent(
        self,
        limit: int = 50,
    ) -> list[Incident]:
        """
        Retrieve the most recently created incidents.
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
                incident_id,
                start_time,
                end_time,
                severity,
                primary_family,
                confidence,
                event_count,
                source_ips,
                destination_ips,
                destination_ports,
                protocols,
                family_distribution
            FROM incidents
            ORDER BY created_at DESC
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
            self._row_to_incident(row)
            for row in rows
        ]

    def count(self) -> int:
        """
        Return the total number of persisted incidents.
        """

        query = """
            SELECT COUNT(*)
            FROM incidents
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query
                )

                row = cursor.fetchone()

        return int(
            row[0]
        )

    def delete(
        self,
        incident_id: uuid.UUID | str,
    ) -> bool:
        """
        Delete an incident.

        Returns True if an incident was deleted.
        """

        if not isinstance(
            incident_id,
            (uuid.UUID, str),
        ):
            raise TypeError(
                "incident_id must be a UUID or string."
            )

        incident_id = str(
            incident_id
        )

        query = """
            DELETE FROM incidents
            WHERE incident_id = %s
        """

        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
                    (incident_id,),
                )

                return cursor.rowcount > 0