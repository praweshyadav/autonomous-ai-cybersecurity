import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from correlation.schema import Incident, SecurityEvent
from persistence.event_repository import EventRepository
from persistence.incident_persistence_service import (
    IncidentPersistenceService,
)
from persistence.incident_repository import IncidentRepository


DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://cybersecurity:cybersecurity_dev_password@localhost:5432/cybersecurity",
)


def make_event(
    event_id: str | None = None,
    timestamp: datetime | None = None,
    attack_family: str = "Brute Force",
) -> SecurityEvent:
    """Create a realistic SecurityEvent for integration testing."""

    return SecurityEvent(
        event_id=event_id or str(uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.10",
        src_port=49152,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family=attack_family,
        confidence=0.95,
        source_file="integration_test.log",
        true_label="SSH-Bruteforce",
        true_attack_family="Brute Force",
        event_type="network_flow",
        metadata={
            "test": True,
            "stage": "incident_persistence",
        },
    )


def make_incident(
    incident_id: str,
    events: list[SecurityEvent],
) -> Incident:
    """Build an Incident using the current Incident schema."""

    return Incident(
        incident_id=incident_id,
        events=events,
        start_time=min(event.timestamp for event in events),
        end_time=max(event.timestamp for event in events),
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=sorted(
            {
                event.attack_family
                for event in events
            }
        ),
        family_distribution={
            family: sum(
                1
                for event in events
                if event.attack_family == family
            )
            for family in sorted(
                {
                    event.attack_family
                    for event in events
                }
            )
        },
        confidence=max(
            event.confidence
            for event in events
        ),
        src_ips=sorted(
            {
                event.src_ip
                for event in events
                if event.src_ip is not None
            }
        ),
        dst_ips=sorted(
            {
                event.dst_ip
                for event in events
                if event.dst_ip is not None
            }
        ),
        dst_ports=sorted(
            {
                event.dst_port
                for event in events
                if event.dst_port is not None
            }
        ),
        protocols=sorted(
            {
                event.protocol
                for event in events
                if event.protocol is not None
            }
        ),
    )


def cleanup(
    incident_repository: IncidentRepository,
    event_repository: EventRepository,
    incident_id: str,
    event_ids: list[str],
) -> None:
    """Clean integration-test data from PostgreSQL."""

    with incident_repository._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM incidents
                WHERE incident_id = %s
                """,
                (incident_id,),
            )

    for event_id in event_ids:
        event_repository.delete(event_id)


def test_save_incident_with_events():
    """Incident and all evidence should be persisted together."""

    service = IncidentPersistenceService(
        database_url=DATABASE_URL
    )

    incident_repository = service.incident_repository
    event_repository = service.event_repository

    base_time = datetime.now(timezone.utc)

    events = [
        make_event(
            timestamp=base_time,
        ),
        make_event(
            timestamp=base_time + timedelta(seconds=5),
        ),
        make_event(
            timestamp=base_time + timedelta(seconds=10),
            attack_family="DoS",
        ),
    ]

    incident_id = str(uuid4())

    incident = make_incident(
        incident_id=incident_id,
        events=events,
    )

    try:
        service.save_incident_with_events(incident)

        saved_incident = incident_repository.get_by_id(
            incident_id
        )

        assert saved_incident is not None
        assert saved_incident.incident_id == incident_id
        assert saved_incident.severity == "high"
        assert saved_incident.primary_attack_family == "Brute Force"
        assert len(saved_incident.events) == 0

        for event in events:
            saved_event = event_repository.get_by_id(
                event.event_id
            )

            assert saved_event is not None
            assert saved_event.event_id == event.event_id

        incident_events = (
            event_repository.get_incident_events(
                incident_id
            )
        )

        assert len(incident_events) == 3

        saved_event_ids = {
            event.event_id
            for event in incident_events
        }

        expected_event_ids = {
            event.event_id
            for event in events
        }

        assert saved_event_ids == expected_event_ids

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident_id,
            [event.event_id for event in events],
        )


def test_save_incident_with_single_event():
    """A single-event incident should persist correctly."""

    service = IncidentPersistenceService(
        database_url=DATABASE_URL
    )

    incident_repository = service.incident_repository
    event_repository = service.event_repository

    event = make_event()
    incident_id = str(uuid4())

    incident = make_incident(
        incident_id=incident_id,
        events=[event],
    )

    try:
        service.save_incident_with_events(incident)

        saved_incident = incident_repository.get_by_id(
            incident_id
        )

        assert saved_incident is not None
        assert len(saved_incident.events) == 0

        saved_events = (
            event_repository.get_incident_events(
                incident_id
            )
        )

        assert len(saved_events) == 1
        assert saved_events[0].event_id == event.event_id

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident_id,
            [event.event_id],
        )


def test_save_incident_updates_existing_incident_and_events():
    """Saving the same incident again should update its evidence."""

    service = IncidentPersistenceService(
        database_url=DATABASE_URL
    )

    incident_repository = service.incident_repository
    event_repository = service.event_repository

    first_event = make_event()
    second_event = make_event(
        attack_family="DoS",
    )

    incident_id = str(uuid4())

    first_incident = make_incident(
        incident_id=incident_id,
        events=[first_event],
    )

    updated_incident = make_incident(
        incident_id=incident_id,
        events=[
            first_event,
            second_event,
        ],
    )

    try:
        service.save_incident_with_events(
            first_incident
        )

        service.save_incident_with_events(
            updated_incident
        )

        saved_incident = incident_repository.get_by_id(
            incident_id
        )

        assert saved_incident is not None
        assert saved_incident.incident_id == incident_id
        assert len(saved_incident.events) == 0

        saved_events = (
            event_repository.get_incident_events(
                incident_id
            )
        )

        assert len(saved_events) == 2

        saved_event_ids = {
            event.event_id
            for event in saved_events
        }

        assert saved_event_ids == {
            first_event.event_id,
            second_event.event_id,
        }

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident_id,
            [
                first_event.event_id,
                second_event.event_id,
            ],
        )


def test_empty_incident_is_rejected():
    """An incident without evidence must not be persisted."""

    service = IncidentPersistenceService(
        database_url=DATABASE_URL
    )

    incident_repository = service.incident_repository
    event_repository = service.event_repository

    incident_id = str(uuid4())

    incident = Incident(
        incident_id=incident_id,
        events=[],
        severity="low",
        primary_attack_family="Benign",
    )

    try:
        try:
            service.save_incident_with_events(
                incident
            )
            assert False, (
                "Expected ValueError for empty incident."
            )
        except ValueError as exc:
            assert (
                str(exc)
                == "incident must contain at least one SecurityEvent."
            )

        assert (
            incident_repository.get_by_id(
                incident_id
            )
            is None
        )

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident_id,
            [],
        )


def test_duplicate_event_ids_are_rejected():
    """Duplicate event IDs inside one incident must be rejected."""

    service = IncidentPersistenceService(
        database_url=DATABASE_URL
    )

    incident_repository = service.incident_repository
    event_repository = service.event_repository

    event = make_event()
    incident_id = str(uuid4())

    incident = make_incident(
        incident_id=incident_id,
        events=[
            event,
            event,
        ],
    )

    try:
        try:
            service.save_incident_with_events(
                incident
            )
            assert False, (
                "Expected ValueError for duplicate event IDs."
            )
        except ValueError as exc:
            assert (
                str(exc)
                == "incident contains duplicate event_id values."
            )

        assert event_repository.get_by_id(
            event.event_id
        ) is None

        assert incident_repository.get_by_id(
            incident_id
        ) is None

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident_id,
            [event.event_id],
        )


def test_transaction_rolls_back_on_invalid_incident():
    """
    If incident validation fails after event preparation,
    no partial database state should remain.

    This test uses an invalid primary family value to trigger
    PostgreSQL NOT NULL validation on primary_family.
    """

    service = IncidentPersistenceService(
        database_url=DATABASE_URL
    )

    incident_repository = service.incident_repository
    event_repository = service.event_repository

    event = make_event()
    incident_id = str(uuid4())

    incident = make_incident(
        incident_id=incident_id,
        events=[event],
    )

    incident.primary_attack_family = None

    try:
        try:
            service.save_incident_with_events(
                incident
            )
            assert False, (
                "Expected database error for invalid incident."
            )
        except Exception:
            pass

        assert event_repository.get_by_id(
            event.event_id
        ) is None

        assert incident_repository.get_by_id(
            incident_id
        ) is None

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident_id,
            [event.event_id],
        )




