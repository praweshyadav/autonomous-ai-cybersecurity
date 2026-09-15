from datetime import datetime

import pytest

from correlation.schema import SecurityEvent
from ingestion.queue.redis_consumer import RedisStreamConsumer
from ingestion.queue.redis_stream import RedisEventQueue


def create_event(event_id: str) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 9, 16, 3, 0, 0),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        dst_port=443,
        protocol_name="TCP",
        event_type="network_flow",
        attack_family="Brute Force",
        confidence=0.95,
    )


def test_consumer_requires_redis_queue():
    with pytest.raises(TypeError):
        RedisStreamConsumer(None)


def test_consumer_initializes():
    queue = RedisEventQueue(
        stream_name="test_consumer_init"
    )

    consumer = RedisStreamConsumer(queue)

    assert consumer.queue is queue
    assert consumer.last_id == "0-0"

    queue.clear()


def test_consumer_rejects_invalid_count():
    queue = RedisEventQueue(
        stream_name="test_consumer_validation"
    )

    consumer = RedisStreamConsumer(queue)

    with pytest.raises(ValueError):
        consumer.read_batch(count=0)

    queue.clear()


def test_consumer_reads_single_event():
    queue = RedisEventQueue(
        stream_name="test_consumer_single"
    )

    queue.clear()

    queue.publish(
        create_event("consumer-001")
    )

    consumer = RedisStreamConsumer(queue)

    messages = consumer.read_batch(count=10)

    assert len(messages) == 1

    message_id, event_data = messages[0]

    assert message_id
    assert event_data["event_id"] == "consumer-001"

    assert consumer.last_id == message_id

    queue.clear()


def test_consumer_reads_multiple_events_in_order():
    queue = RedisEventQueue(
        stream_name="test_consumer_order"
    )

    queue.clear()

    events = [
        create_event("consumer-001"),
        create_event("consumer-002"),
        create_event("consumer-003"),
    ]

    queue.publish_batch(events)

    consumer = RedisStreamConsumer(queue)

    messages = consumer.read_batch(count=10)

    assert len(messages) == 3

    event_ids = [
        event_data["event_id"]
        for _, event_data in messages
    ]

    assert event_ids == [
        "consumer-001",
        "consumer-002",
        "consumer-003",
    ]

    assert consumer.last_id == messages[-1][0]

    queue.clear()


def test_consumer_does_not_read_same_events_twice():
    queue = RedisEventQueue(
        stream_name="test_consumer_no_duplicates"
    )

    queue.clear()

    queue.publish(
        create_event("consumer-001")
    )

    consumer = RedisStreamConsumer(queue)

    first_batch = consumer.read_batch(count=10)

    assert len(first_batch) == 1

    second_batch = consumer.read_batch(count=10)

    assert second_batch == []

    queue.clear()


def test_consumer_reads_only_events_after_last_id():
    queue = RedisEventQueue(
        stream_name="test_consumer_incremental"
    )

    queue.clear()

    queue.publish(
        create_event("consumer-001")
    )

    consumer = RedisStreamConsumer(queue)

    first_batch = consumer.read_batch(count=10)

    assert len(first_batch) == 1
    assert first_batch[0][1]["event_id"] == "consumer-001"

    queue.publish(
        create_event("consumer-002")
    )

    second_batch = consumer.read_batch(count=10)

    assert len(second_batch) == 1
    assert second_batch[0][1]["event_id"] == "consumer-002"

    queue.clear()


def test_consumer_reset():
    queue = RedisEventQueue(
        stream_name="test_consumer_reset"
    )

    queue.clear()

    queue.publish(
        create_event("consumer-001")
    )

    consumer = RedisStreamConsumer(queue)

    first_batch = consumer.read_batch()

    assert len(first_batch) == 1
    assert consumer.last_id != "0-0"

    consumer.reset()

    assert consumer.last_id == "0-0"

    queue.clear()