from datetime import datetime

import pytest

from correlation.schema import SecurityEvent
from ingestion.queue.redis_stream import RedisEventQueue


class FakeEvent:
    def __init__(self, event_id: str = "event-1"):
        self.event_id = event_id

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": datetime.now().isoformat(),
        }


def test_queue_requires_valid_redis_url():
    with pytest.raises(RuntimeError):
        RedisEventQueue(redis_url="")


def test_queue_requires_valid_stream_name():
    with pytest.raises(ValueError):
        RedisEventQueue(stream_name="")


def test_queue_initializes():
    queue = RedisEventQueue()

    assert queue.redis_url == "redis://127.0.0.1:6379/0"
    assert queue.stream_name == "security_events"


def test_publish_requires_event():
    queue = RedisEventQueue()

    with pytest.raises(ValueError):
        queue.publish(None)


def test_publish_requires_to_dict():
    queue = RedisEventQueue()

    with pytest.raises(TypeError):
        queue.publish(object())


def test_publish_requires_dictionary():
    class InvalidEvent:
        def to_dict(self):
            return "invalid"

    queue = RedisEventQueue()

    with pytest.raises(TypeError):
        queue.publish(InvalidEvent())


def test_publish_batch_requires_list():
    queue = RedisEventQueue()

    with pytest.raises(TypeError):
        queue.publish_batch(None)


def test_publish_batch_empty_list():
    queue = RedisEventQueue()

    result = queue.publish_batch([])

    assert result == []


def test_queue_can_accept_security_event_after_serialization_requirement():
    event = SecurityEvent(
        event_id="test-event",
        timestamp=datetime.now(),
    )

    assert isinstance(event, SecurityEvent)


def test_security_event_to_dict_serializes_timestamp():
    timestamp = datetime(2026, 9, 16, 2, 30, 0)

    event = SecurityEvent(
        event_id="test-event",
        timestamp=timestamp,
    )

    result = event.to_dict()

    assert result["event_id"] == "test-event"
    assert result["timestamp"] == "2026-09-16T02:30:00"


def test_security_event_to_dict_preserves_event_fields():
    event = SecurityEvent(
        event_id="event-123",
        timestamp=datetime.now(),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=12345,
        dst_port=443,
        protocol_name="TCP",
        attack_family="Brute Force",
        confidence=0.95,
    )

    result = event.to_dict()

    assert result["event_id"] == "event-123"
    assert result["src_ip"] == "192.168.1.10"
    assert result["dst_ip"] == "10.0.0.5"
    assert result["src_port"] == 12345
    assert result["dst_port"] == 443
    assert result["protocol_name"] == "TCP"
    assert result["attack_family"] == "Brute Force"
    assert result["confidence"] == 0.95


def test_redis_connection():
    queue = RedisEventQueue()

    assert queue.ping() is True


def test_publish_real_security_event():
    queue = RedisEventQueue(
        stream_name="test_security_events"
    )

    queue.clear()

    event = SecurityEvent(
        event_id="redis-test-001",
        timestamp=datetime(2026, 9, 16, 2, 30, 0),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=12345,
        dst_port=443,
        protocol_name="TCP",
        event_type="network_flow",
        attack_family="Brute Force",
        confidence=0.95,
    )

    message_id = queue.publish(event)

    assert message_id
    assert queue.length() == 1

    queue.clear()


def test_publish_batch_real_security_events():
    queue = RedisEventQueue(
        stream_name="test_security_events_batch"
    )

    queue.clear()

    events = [
        SecurityEvent(
            event_id="redis-batch-001",
            timestamp=datetime(2026, 9, 16, 2, 30, 0),
        ),
        SecurityEvent(
            event_id="redis-batch-002",
            timestamp=datetime(2026, 9, 16, 2, 31, 0),
        ),
        SecurityEvent(
            event_id="redis-batch-003",
            timestamp=datetime(2026, 9, 16, 2, 32, 0),
        ),
    ]

    message_ids = queue.publish_batch(events)

    assert len(message_ids) == 3
    assert all(message_ids)
    assert queue.length() == 3

    queue.clear()


def test_read_returns_published_event():
    queue = RedisEventQueue(
        stream_name="test_security_events_read"
    )

    queue.clear()

    event = SecurityEvent(
        event_id="redis-read-001",
        timestamp=datetime(2026, 9, 16, 3, 0, 0),
        src_ip="192.168.1.20",
        dst_ip="10.0.0.10",
        dst_port=22,
        protocol_name="TCP",
        event_type="network_flow",
    )

    published_id = queue.publish(event)

    messages = queue.read(
        last_id="0-0",
        count=10,
    )

    assert len(messages) == 1

    message_id, event_data = messages[0]

    assert message_id == published_id
    assert event_data["event_id"] == "redis-read-001"
    assert event_data["src_ip"] == "192.168.1.20"
    assert event_data["dst_ip"] == "10.0.0.10"
    assert event_data["dst_port"] == 22

    queue.clear()


def test_read_returns_multiple_events_in_order():
    queue = RedisEventQueue(
        stream_name="test_security_events_order"
    )

    queue.clear()

    events = [
        SecurityEvent(
            event_id="order-001",
            timestamp=datetime(2026, 9, 16, 3, 0, 0),
        ),
        SecurityEvent(
            event_id="order-002",
            timestamp=datetime(2026, 9, 16, 3, 1, 0),
        ),
        SecurityEvent(
            event_id="order-003",
            timestamp=datetime(2026, 9, 16, 3, 2, 0),
        ),
    ]

    queue.publish_batch(events)

    messages = queue.read(
        last_id="0-0",
        count=10,
    )

    assert len(messages) == 3

    event_ids = [
        event_data["event_id"]
        for _, event_data in messages
    ]

    assert event_ids == [
        "order-001",
        "order-002",
        "order-003",
    ]

    queue.clear()


def test_read_requires_valid_last_id():
    queue = RedisEventQueue()

    with pytest.raises(ValueError):
        queue.read(last_id="")


def test_read_requires_positive_count():
    queue = RedisEventQueue()

    with pytest.raises(ValueError):
        queue.read(count=0)


def test_read_new_requires_valid_last_id():
    queue = RedisEventQueue()

    with pytest.raises(ValueError):
        queue.read_new(last_id="")


def test_read_new_requires_positive_count():
    queue = RedisEventQueue()

    with pytest.raises(ValueError):
        queue.read_new(count=0)


def test_read_new_requires_non_negative_block_time():
    queue = RedisEventQueue()

    with pytest.raises(ValueError):
        queue.read_new(block_ms=-1)






