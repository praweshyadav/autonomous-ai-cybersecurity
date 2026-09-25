from datetime import datetime

import pytest

from correlation.schema import SecurityEvent
from ingestion.queue.event_deserializer import (
    SecurityEventDeserializer,
)


def create_event_data(
    event_id: str = "event-001",
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-09-16T03:00:00",
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.5",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": 6,
        "protocol_name": "TCP",
        "binary_prediction": 1,
        "attack_family": "Brute Force",
        "confidence": 0.95,
        "source_file": "test.log",
        "event_type": "network_flow",
        "username": "test-user",
        "metadata": {
            "source": "test"
        },
    }


def test_deserializer_initializes():
    deserializer = SecurityEventDeserializer()

    assert isinstance(
        deserializer,
        SecurityEventDeserializer,
    )


def test_deserialize_requires_dictionary():
    deserializer = SecurityEventDeserializer()

    with pytest.raises(TypeError):
        deserializer.deserialize(None)


def test_deserialize_requires_event_id():
    deserializer = SecurityEventDeserializer()

    event_data = {
        "timestamp": "2026-09-16T03:00:00"
    }

    with pytest.raises(ValueError):
        deserializer.deserialize(event_data)


def test_deserialize_requires_timestamp():
    deserializer = SecurityEventDeserializer()

    event_data = {
        "event_id": "event-001"
    }

    with pytest.raises(ValueError):
        deserializer.deserialize(event_data)


def test_deserialize_rejects_invalid_timestamp():
    deserializer = SecurityEventDeserializer()

    event_data = {
        "event_id": "event-001",
        "timestamp": "invalid-timestamp",
    }

    with pytest.raises(ValueError):
        deserializer.deserialize(event_data)


def test_deserialize_creates_security_event():
    deserializer = SecurityEventDeserializer()

    event_data = create_event_data()

    event = deserializer.deserialize(event_data)

    assert isinstance(event, SecurityEvent)


def test_deserialize_preserves_event_fields():
    deserializer = SecurityEventDeserializer()

    event_data = create_event_data(
        "redis-event-001"
    )

    event = deserializer.deserialize(event_data)

    assert event.event_id == "redis-event-001"
    assert event.timestamp == datetime(
        2026,
        9,
        16,
        3,
        0,
        0,
    )

    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "10.0.0.5"
    assert event.src_port == 12345
    assert event.dst_port == 443

    assert event.protocol == 6
    assert event.protocol_name == "TCP"

    assert event.binary_prediction == 1
    assert event.attack_family == "Brute Force"
    assert event.confidence == 0.95

    assert event.source_file == "test.log"
    assert event.event_type == "network_flow"

    assert event.username == "test-user"

    assert event.metadata == {
        "source": "test"
    }


def test_deserialize_uses_defaults_for_optional_fields():
    deserializer = SecurityEventDeserializer()

    event_data = {
        "event_id": "minimal-event",
        "timestamp": "2026-09-16T03:00:00",
    }

    event = deserializer.deserialize(event_data)

    assert event.event_id == "minimal-event"
    assert event.attack_family == "Benign"
    assert event.binary_prediction == 0
    assert event.confidence == 0.0
    assert event.src_ip is None
    assert event.dst_ip is None
    assert event.metadata == {}


def test_deserialize_batch_requires_list():
    deserializer = SecurityEventDeserializer()

    with pytest.raises(TypeError):
        deserializer.deserialize_batch(None)


def test_deserialize_batch():
    deserializer = SecurityEventDeserializer()

    events_data = [
        create_event_data("event-001"),
        create_event_data("event-002"),
        create_event_data("event-003"),
    ]

    events = deserializer.deserialize_batch(
        events_data
    )

    assert len(events) == 3

    assert all(
        isinstance(event, SecurityEvent)
        for event in events
    )

    assert [
        event.event_id
        for event in events
    ] == [
        "event-001",
        "event-002",
        "event-003",
    ]