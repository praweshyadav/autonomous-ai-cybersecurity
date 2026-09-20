from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from correlation.correlation_adapter import CorrelationAdapter
from correlation.correlator import IncidentCorrelator
from correlation.schema import SecurityEvent
from ingestion.incident_processor import IncidentProcessor
from persistence.event_repository import EventRepository
from persistence.incident_persistence_adapter import (
    IncidentPersistenceAdapter,
)
from persistence.incident_persistence_service import (
    IncidentPersistenceService,
)
from persistence.incident_repository import IncidentRepository


DATABASE_URL = (
    "postgresql://cybersecurity:"
    "cybersecurity_dev_password@localhost:5432/"
    "cybersecurity"
)


def make_event(
    event_id=None,
    timestamp=None,
):
    return SecurityEvent(
        event_id=event_id or str(uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
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


def create_processor():
    correlation_adapter = CorrelationAdapter(
        IncidentCorrelator(
            time_window_seconds=60,
            correlation_threshold=4,
        )
    )

    persistence_service = IncidentPersistenceService(
        DATABASE_URL
    )

    persistence_adapter = IncidentPersistenceAdapter(
        persistence_service=persistence_service
    )

    processor = IncidentProcessor(
        correlation_adapter=correlation_adapter,
        persistence_adapter=persistence_adapter,
    )

    return processor


def cleanup(
    incident_repository,
    event_repository,
    incident_id,
):
    saved_events = event_repository.get_incident_events(
        incident_id
    )

    for event in saved_events:
        event_repository.delete(
            event.event_id
        )

    incident_repository.delete(
        incident_id
    )


def test_incident_processor_initializes():
    processor = create_processor()

    assert isinstance(
        processor.correlation_adapter,
        CorrelationAdapter,
    )

    assert isinstance(
        processor.persistence_adapter,
        IncidentPersistenceAdapter,
    )


def test_incident_processor_rejects_invalid_input():
    processor = create_processor()

    with pytest.raises(TypeError):
        processor.process(
            "not-a-list"
        )


def test_incident_processor_rejects_invalid_event():
    processor = create_processor()

    with pytest.raises(TypeError):
        processor.process(
            [
                "not-a-security-event"
            ]
        )


def test_incident_processor_handles_empty_input():
    processor = create_processor()

    incidents = processor.process([])

    assert incidents == []


def test_incident_processor_correlates_and_persists():
    incident_repository = IncidentRepository(
        DATABASE_URL
    )

    event_repository = EventRepository()

    processor = create_processor()

    base_time = datetime(
        2026,
        9,
        16,
        3,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            timestamp=base_time + timedelta(
                seconds=index
            ),
        )
        for index in range(5)
    ]

    incidents = processor.process(
        events
    )

    assert len(incidents) == 1

    incident = incidents[0]

    assert len(incident.events) == 5
    assert incident.primary_attack_family == "Brute Force"
    assert incident.severity == "high"

    saved_incident = incident_repository.get_by_id(
        incident.incident_id
    )

    saved_events = event_repository.get_incident_events(
        incident.incident_id
    )

    try:
        assert saved_incident is not None
        assert len(saved_events) == 5

        assert {
            event.event_id for event in saved_events
        } == {
            event.event_id for event in events
        }

    finally:
        cleanup(
            incident_repository,
            event_repository,
            incident.incident_id,
        )


def test_incident_processor_clears_correlation_buffer():
    processor = create_processor()

    events = [
        make_event(
            )
        for index in range(3)
    ]

    processor.process(
        events
    )

    assert processor.correlation_adapter.get_events() == []

