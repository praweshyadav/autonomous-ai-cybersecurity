from datetime import datetime, timezone
from uuid import uuid4

import pytest

from correlation.schema import Incident, SecurityEvent
from persistence.event_repository import EventRepository
from persistence.incident_persistence_adapter import (
    IncidentPersistenceAdapter,
)
from persistence.incident_repository import IncidentRepository
from persistence.incident_persistence_service import (
    IncidentPersistenceService,
)


DATABASE_URL = (
    "postgresql://cybersecurity:"
    "cybersecurity_dev_password@localhost:5432/"
    "cybersecurity"
)


def make_event(
    event_id=None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id or str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=12345,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.95,
        event_type="network_flow",
    )


def make_incident(
    events,
) -> Incident:
    incident = Incident(
        incident_id=str(uuid4()),
        events=list(events),
        start_time=events[0].timestamp,
        end_time=events[-1].timestamp,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": len(events)},
        confidence=0.95,
        src_ips=["192.168.1.10"],
        dst_ips=["10.0.0.5"],
        dst_ports=[22],
        protocols=[6],
    )

    return incident


def cleanup(
    incident_repository,
    event_repository,
    incident_id,
):
    saved_events = event_repository.get_incident_events(
        incident_id
    )

    for event in saved_events:
        event_repository.delete(event.event_id)

    incident_repository.delete(
        incident_id
    )


def test_adapter_initializes():
    service = IncidentPersistenceService(
        DATABASE_URL
    )

    adapter = IncidentPersistenceAdapter(
        persistence_service=service
    )

    assert adapter.persistence_service is service


def test_adapter_persists_incident():
    incident_repository = IncidentRepository(
        DATABASE_URL
    )

    event_repository = EventRepository()

    service = IncidentPersistenceService(
        DATABASE_URL
    )

    adapter = IncidentPersistenceAdapter(
        persistence_service=service
    )

    event = make_event()

    incident = make_incident(
        [event]
    )

    try:
        adapter.process(
            incident
        )

        saved_incident = incident_repository.get_by_id(
            incident.incident_id
        )

        saved_events = event_repository.get_incident_events(
            incident.incident_id
        )

        assert saved_incident is not None
        assert len(saved_events) == 1
        assert saved_events[0].event_id == event.event_id

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident.incident_id,
        )


def test_adapter_rejects_invalid_incident():
    adapter = IncidentPersistenceAdapter(
        persistence_service=IncidentPersistenceService(
            DATABASE_URL
        )
    )

    with pytest.raises(TypeError):
        adapter.process(
            "not-an-incident"
        )


def test_adapter_process_batch():
    incident_repository = IncidentRepository(
        DATABASE_URL
    )

    event_repository = EventRepository()

    service = IncidentPersistenceService(
        DATABASE_URL
    )

    adapter = IncidentPersistenceAdapter(
        persistence_service=service
    )

    event1 = make_event()
    event2 = make_event()

    incident1 = make_incident(
        [event1]
    )

    incident2 = make_incident(
        [event2]
    )

    try:
        results = adapter.process_batch(
            [
                incident1,
                incident2,
            ]
        )

        assert results == [
            None,
            None,
        ]

        saved_events_1 = (
            event_repository.get_incident_events(
                incident1.incident_id
            )
        )

        saved_events_2 = (
            event_repository.get_incident_events(
                incident2.incident_id
            )
        )

        assert len(saved_events_1) == 1
        assert len(saved_events_2) == 1

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident1.incident_id,
        )

        cleanup(
            incident_repository,
            event_repository,
            incident2.incident_id,
        )


def test_adapter_rejects_invalid_batch():
    adapter = IncidentPersistenceAdapter(
        persistence_service=IncidentPersistenceService(
            DATABASE_URL
        )
    )

    with pytest.raises(TypeError):
        adapter.process_batch(
            "not-a-list"
        )


def test_adapter_rejects_invalid_batch_item():
    adapter = IncidentPersistenceAdapter(
        persistence_service=IncidentPersistenceService(
            DATABASE_URL
        )
    )

    with pytest.raises(TypeError):
        adapter.process_batch(
            [
                "not-an-incident"
            ]
        )
