from datetime import datetime, timezone

import pytest

from correlation.schema import SecurityEvent
from ingestion.event_router import EventRouter


@pytest.fixture
def event():
    return SecurityEvent(
        event_id="TEST-001",
        timestamp=datetime(
            2026,
            3,
            10,
            10,
            15,
            30,
            tzinfo=timezone.utc,
        ),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.20",
        src_port=54321,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.95,
    )


def test_router_starts_empty():
    router = EventRouter()

    assert router.handler_names() == []


def test_register_handler(event):
    router = EventRouter()

    received = []

    def handler(security_event):
        received.append(security_event)
        return "processed"

    router.register("detection", handler)

    assert router.handler_names() == ["detection"]
    assert router.has_handler("detection")

    result = router.route(event)

    assert received == [event]
    assert result == {"detection": "processed"}


def test_multiple_handlers_receive_same_event(event):
    router = EventRouter()

    received = []

    def detection_handler(security_event):
        received.append(("detection", security_event.event_id))
        return "detected"

    def storage_handler(security_event):
        received.append(("storage", security_event.event_id))
        return "stored"

    router.register("detection", detection_handler)
    router.register("storage", storage_handler)

    result = router.route(event)

    assert result == {
        "detection": "detected",
        "storage": "stored",
    }

    assert received == [
        ("detection", "TEST-001"),
        ("storage", "TEST-001"),
    ]


def test_route_batch(event):
    router = EventRouter()

    received_ids = []

    def handler(security_event):
        received_ids.append(security_event.event_id)
        return security_event.event_id

    router.register("collector_test", handler)

    event2 = SecurityEvent(
        event_id="TEST-002",
        timestamp=event.timestamp,
        attack_family="DoS",
        confidence=0.90,
    )

    results = router.route_batch([event, event2])

    assert results == [
        {"collector_test": "TEST-001"},
        {"collector_test": "TEST-002"},
    ]

    assert received_ids == [
        "TEST-001",
        "TEST-002",
    ]


def test_unregister_handler(event):
    router = EventRouter()

    def handler(security_event):
        return "processed"

    router.register("detection", handler)

    assert router.has_handler("detection")

    router.unregister("detection")

    assert not router.has_handler("detection")
    assert router.handler_names() == []


def test_clear_handlers():
    router = EventRouter()

    router.register("detection", lambda event: "detected")
    router.register("storage", lambda event: "stored")

    assert len(router.handler_names()) == 2

    router.clear()

    assert router.handler_names() == []


def test_duplicate_handler_registration_is_rejected():
    router = EventRouter()

    handler = lambda event: "processed"

    router.register("detection", handler)

    with pytest.raises(
        ValueError,
        match="Handler already registered",
    ):
        router.register("detection", handler)


def test_invalid_handler_name_is_rejected():
    router = EventRouter()

    with pytest.raises(TypeError):
        router.register(None, lambda event: None)

    with pytest.raises(ValueError):
        router.register("", lambda event: None)

    with pytest.raises(ValueError):
        router.register("   ", lambda event: None)


def test_invalid_handler_is_rejected():
    router = EventRouter()

    with pytest.raises(TypeError):
        router.register("detection", "not-a-function")


def test_invalid_event_is_rejected():
    router = EventRouter()

    router.register(
        "detection",
        lambda event: "processed",
    )

    with pytest.raises(TypeError):
        router.route("not-an-event")


def test_invalid_batch_is_rejected():
    router = EventRouter()

    with pytest.raises(TypeError):
        router.route_batch("not-a-list")

    with pytest.raises(TypeError):
        router.route_batch(
            [
                "not-a-security-event",
            ]
        )


def test_unregister_unknown_handler_is_rejected():
    router = EventRouter()

    with pytest.raises(
        KeyError,
        match="Handler not registered",
    ):
        router.unregister("missing")


def test_has_handler_requires_string():
    router = EventRouter()

    with pytest.raises(TypeError):
        router.has_handler(None)
def test_route_batch_uses_batch_handler_when_available(event):
    router = EventRouter()

    class BatchHandler:
        def __init__(self):
            self.batch_called = False
            self.single_called = False

        def __call__(self, security_event):
            self.single_called = True
            return "single"

        def process_batch(self, events):
            self.batch_called = True
            return [
                f"batch-{security_event.event_id}"
                for security_event in events
            ]

    handler = BatchHandler()

    router.register(
        "detection",
        handler,
    )

    event2 = SecurityEvent(
        event_id="TEST-002",
        timestamp=event.timestamp,
        attack_family="DoS",
        confidence=0.90,
    )

    results = router.route_batch(
        [event, event2]
    )

    assert results == [
        {"detection": "batch-TEST-001"},
        {"detection": "batch-TEST-002"},
    ]

    assert handler.batch_called is True
    assert handler.single_called is False
