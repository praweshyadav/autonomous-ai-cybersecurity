from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest

from correlation.correlator import IncidentCorrelator
from correlation.incident_manager import IncidentManager
from correlation.incident_window import IncidentWindow
from correlation.schema import SecurityEvent


def make_event(
    timestamp,
    src_ip="192.168.1.10",
    dst_ip="10.0.0.5",
    attack_family="Brute Force",
    confidence=0.95,
):
    return SecurityEvent(
        event_id=str(uuid4()),
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=22,
        protocol=6,
        binary_prediction=1,
        attack_family=attack_family,
        confidence=confidence,
    )


def create_manager(window_seconds=60):
    window = IncidentWindow(
        window_seconds=window_seconds
    )

    correlator = IncidentCorrelator(
        time_window_seconds=window_seconds,
        correlation_threshold=4,
    )

    persistence_adapter = Mock()

    manager = IncidentManager(
        window=window,
        correlator=correlator,
        persistence_adapter=persistence_adapter,
    )

    return manager, persistence_adapter


def test_incident_manager_initializes():
    manager, persistence_adapter = create_manager()

    assert manager.buffered_event_count == 0
    assert manager.next_incident_number == 1
    assert manager.window is not None
    assert manager.correlator is not None
    assert manager.persistence_adapter is persistence_adapter


def test_incident_manager_rejects_invalid_event():
    manager, _ = create_manager()

    with pytest.raises(TypeError):
        manager.process_event("not-an-event")


def test_incident_manager_buffers_events_inside_window():
    manager, persistence_adapter = create_manager()

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    event_1 = make_event(base_time)
    event_2 = make_event(
        base_time + timedelta(seconds=30)
    )

    result_1 = manager.process_event(event_1)
    result_2 = manager.process_event(event_2)

    assert result_1 == []
    assert result_2 == []

    assert manager.buffered_event_count == 2
    persistence_adapter.process_batch.assert_not_called()


def test_incident_manager_flushes_when_event_exceeds_window():
    manager, persistence_adapter = create_manager()

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    event_1 = make_event(base_time)
    event_2 = make_event(
        base_time + timedelta(seconds=10)
    )
    event_3 = make_event(
        base_time + timedelta(seconds=61)
    )

    assert manager.process_event(event_1) == []
    assert manager.process_event(event_2) == []

    emitted_incidents = manager.process_event(event_3)

    assert len(emitted_incidents) == 1

    incident = emitted_incidents[0]

    assert incident.incident_id == "INC-000001"
    assert len(incident.events) == 2
    assert manager.buffered_event_count == 1
    assert manager.next_incident_number == 2

    persistence_adapter.process_batch.assert_called_once()

    persisted_incidents = (
        persistence_adapter.process_batch.call_args.args[0]
    )

    assert len(persisted_incidents) == 1
    assert persisted_incidents[0] is incident


def test_incident_manager_flush_persists_active_window():
    manager, persistence_adapter = create_manager()

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            base_time + timedelta(seconds=index)
        )
        for index in range(3)
    ]

    for event in events:
        assert manager.process_event(event) == []

    assert manager.buffered_event_count == 3

    incidents = manager.flush()

    assert len(incidents) == 1
    assert len(incidents[0].events) == 3
    assert incidents[0].incident_id == "INC-000001"

    assert manager.buffered_event_count == 0
    assert manager.next_incident_number == 2

    persistence_adapter.process_batch.assert_called_once()


def test_incident_manager_flush_empty_window():
    manager, persistence_adapter = create_manager()

    incidents = manager.flush()

    assert incidents == []
    assert manager.buffered_event_count == 0
    persistence_adapter.process_batch.assert_not_called()


def test_incident_manager_reset_discards_buffered_events():
    manager, persistence_adapter = create_manager()

    timestamp = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    manager.process_event(
        make_event(timestamp)
    )

    assert manager.buffered_event_count == 1

    manager.reset()

    assert manager.buffered_event_count == 0
    assert manager.window.is_empty()
    persistence_adapter.process_batch.assert_not_called()


def test_incident_manager_assigns_unique_ids_across_flushes():
    manager, persistence_adapter = create_manager()

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    first_event = make_event(base_time)

    second_event = make_event(
        base_time + timedelta(seconds=61),
        src_ip="192.168.1.20",
        dst_ip="10.0.0.10",
    )

    third_event = make_event(
        base_time + timedelta(seconds=122),
        src_ip="192.168.1.30",
        dst_ip="10.0.0.20",
    )

    manager.process_event(first_event)

    first_incidents = manager.process_event(
        second_event
    )

    second_incidents = manager.process_event(
        third_event
    )

    assert len(first_incidents) == 1
    assert len(second_incidents) == 1

    assert (
        first_incidents[0].incident_id
        == "INC-000001"
    )

    assert (
        second_incidents[0].incident_id
        == "INC-000002"
    )

    assert manager.next_incident_number == 3
    assert persistence_adapter.process_batch.call_count == 2


def test_incident_manager_flush_ignores_benign_only_window():
    manager, persistence_adapter = create_manager()

    timestamp = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    benign_event = make_event(
        timestamp,
        attack_family="Benign",
        confidence=0.99,
    )

    manager.process_event(benign_event)

    incidents = manager.flush()

    assert incidents == []
    assert manager.buffered_event_count == 0
    persistence_adapter.process_batch.assert_not_called()

def test_incident_manager_is_callable():
    manager, _ = create_manager()

    timestamp = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    event = make_event(timestamp)

    result = manager(event)

    assert result == []
    assert manager.buffered_event_count == 1


def test_incident_manager_process_batch():
    manager, persistence_adapter = create_manager()

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            base_time + timedelta(seconds=index)
        )
        for index in range(3)
    ]

    results = manager.process_batch(events)

    assert len(results) == 3
    assert results == [[], [], []]

    assert manager.buffered_event_count == 3
    persistence_adapter.process_batch.assert_not_called()


def test_incident_manager_process_batch_flushes_when_window_changes():
    manager, persistence_adapter = create_manager()

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(base_time),
        make_event(
            base_time + timedelta(seconds=10)
        ),
        make_event(
            base_time + timedelta(seconds=61)
        ),
    ]

    results = manager.process_batch(events)

    assert len(results) == 3

    assert results[0] == []
    assert results[1] == []
    assert len(results[2]) == 1

    assert results[2][0].incident_id == "INC-000001"

    assert manager.buffered_event_count == 1
    assert manager.next_incident_number == 2

    persistence_adapter.process_batch.assert_called_once()
