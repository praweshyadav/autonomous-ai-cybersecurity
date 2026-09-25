from datetime import datetime, timezone

import pytest

from correlation.correlator import IncidentCorrelator
from correlation.correlation_adapter import CorrelationAdapter
from correlation.schema import SecurityEvent


def create_event(
    event_id: str,
    src_ip: str,
    dst_ip: str,
    attack_family: str = "Brute Force",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(
            2026,
            3,
            10,
            10,
            15,
            30,
            tzinfo=timezone.utc,
        ),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family=attack_family,
        confidence=0.95,
        event_type="network_flow",
    )


def test_correlation_adapter_starts_empty():
    adapter = CorrelationAdapter()

    assert adapter.get_events() == []


def test_correlation_adapter_requires_valid_event():
    adapter = CorrelationAdapter()

    with pytest.raises(TypeError):
        adapter.process("not-a-security-event")


def test_correlation_adapter_stores_event():
    adapter = CorrelationAdapter()

    event = create_event(
        "EVENT-001",
        "192.168.1.10",
        "10.0.0.20",
    )

    adapter.process(event)

    events = adapter.get_events()

    assert len(events) == 1
    assert events[0] is event


def test_correlation_adapter_process_batch():
    adapter = CorrelationAdapter()

    events = [
        create_event(
            "EVENT-001",
            "192.168.1.10",
            "10.0.0.20",
        ),
        create_event(
            "EVENT-002",
            "192.168.1.10",
            "10.0.0.20",
        ),
    ]

    results = adapter.process_batch(events)

    assert results == [None, None]
    assert adapter.get_events() == events


def test_correlation_adapter_rejects_invalid_batch():
    adapter = CorrelationAdapter()

    with pytest.raises(TypeError):
        adapter.process_batch(
            "not-a-list"
        )


def test_correlation_adapter_rejects_invalid_batch_event():
    adapter = CorrelationAdapter()

    with pytest.raises(TypeError):
        adapter.process_batch(
            [
                create_event(
                    "EVENT-001",
                    "192.168.1.10",
                    "10.0.0.20",
                ),
                "not-a-security-event",
            ]
        )


def test_correlation_adapter_correlates_events():
    correlator = IncidentCorrelator(
        time_window_seconds=60,
        correlation_threshold=4,
    )

    adapter = CorrelationAdapter(
        correlator=correlator
    )

    events = [
        create_event(
            "EVENT-001",
            "192.168.1.10",
            "10.0.0.20",
        ),
        create_event(
            "EVENT-002",
            "192.168.1.10",
            "10.0.0.20",
        ),
    ]

    adapter.process_batch(events)

    incidents = adapter.correlate()

    assert len(incidents) == 1

    incident = incidents[0]

    assert len(incident.events) == 2
    assert incident.primary_attack_family == "Brute Force"


def test_correlation_adapter_clear():
    adapter = CorrelationAdapter()

    event = create_event(
        "EVENT-001",
        "192.168.1.10",
        "10.0.0.20",
    )

    adapter.process(event)

    assert len(adapter.get_events()) == 1

    adapter.clear()

    assert adapter.get_events() == []
    assert adapter.correlate() == []