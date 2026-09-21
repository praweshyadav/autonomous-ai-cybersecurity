from datetime import datetime

import pytest

from correlation.schema import SecurityEvent
from ingestion.event_router import EventRouter
from ingestion.queue.redis_consumer import RedisStreamConsumer
from ingestion.queue.redis_processor import RedisStreamProcessor
from ingestion.queue.redis_stream import RedisEventQueue


def create_event(event_id: str) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(
            2026,
            9,
            16,
            3,
            0,
            0,
        ),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        dst_port=443,
        protocol_name="TCP",
        event_type="network_flow",
        attack_family="Brute Force",
        confidence=0.95,
    )


def create_processor(
    stream_name: str,
):
    queue = RedisEventQueue(
        stream_name=stream_name
    )

    queue.clear()

    consumer = RedisStreamConsumer(queue)

    router = EventRouter()

    processor = RedisStreamProcessor(
        consumer=consumer,
        event_router=router,
    )

    return queue, consumer, router, processor


def test_processor_requires_consumer():
    router = EventRouter()

    with pytest.raises(TypeError):
        RedisStreamProcessor(
            consumer=None,
            event_router=router,
        )


def test_processor_requires_event_router():
    queue = RedisEventQueue(
        stream_name="test_processor_router_validation"
    )

    consumer = RedisStreamConsumer(queue)

    with pytest.raises(TypeError):
        RedisStreamProcessor(
            consumer=consumer,
            event_router=None,
        )

    queue.clear()


def test_processor_initializes():
    (
        queue,
        consumer,
        router,
        processor,
    ) = create_processor(
        "test_processor_init"
    )

    assert processor.consumer is consumer
    assert processor.event_router is router
    assert processor.deserializer is not None
    assert processor.last_processed_message_id is None

    queue.clear()


def test_processor_returns_empty_when_no_events():
    (
        queue,
        _,
        _,
        processor,
    ) = create_processor(
        "test_processor_empty"
    )

    result = processor.process_batch()

    assert result == []
    assert processor.last_processed_message_id is None

    queue.clear()


def test_processor_deserializes_and_routes_event():
    (
        queue,
        consumer,
        router,
        processor,
    ) = create_processor(
        "test_processor_single"
    )

    received_events = []

    def handler(event):
        received_events.append(event)

    router.register(
        "test_handler",
        handler,
    )

    queue.publish(
        create_event("processor-001")
    )

    result = processor.process_batch()

    assert len(result) == 1

    event = result[0]

    assert isinstance(
        event,
        SecurityEvent,
    )

    assert event.event_id == "processor-001"

    assert len(received_events) == 1

    assert received_events[0] is event

    assert processor.last_processed_message_id is not None
    assert consumer.last_id == "0-0"

    consumer.acknowledge(
        processor.last_processed_message_id
    )

    assert consumer.last_id == processor.last_processed_message_id

    queue.clear()


def test_processor_handles_multiple_events():
    (
        queue,
        consumer,
        router,
        processor,
    ) = create_processor(
        "test_processor_multiple"
    )

    received_events = []

    def handler(event):
        received_events.append(event)

    router.register(
        "test_handler",
        handler,
    )

    events = [
        create_event("processor-001"),
        create_event("processor-002"),
        create_event("processor-003"),
    ]

    queue.publish_batch(events)

    result = processor.process_batch(
        count=10
    )

    assert len(result) == 3

    assert [
        event.event_id
        for event in result
    ] == [
        "processor-001",
        "processor-002",
        "processor-003",
    ]

    assert len(received_events) == 3

    assert processor.last_processed_message_id is not None
    assert consumer.last_id == "0-0"

    consumer.acknowledge(
        processor.last_processed_message_id
    )

    assert consumer.last_id == processor.last_processed_message_id

    queue.clear()


def test_processor_advances_position_only_after_explicit_acknowledgement():
    (
        queue,
        consumer,
        _,
        processor,
    ) = create_processor(
        "test_processor_position"
    )

    queue.publish(
        create_event("processor-001")
    )

    first_result = processor.process_batch()

    assert len(first_result) == 1

    processed_message_id = (
        processor.last_processed_message_id
    )

    assert processed_message_id is not None

    # Processor successfully processed the event,
    # but consumer position is not advanced yet.
    assert consumer.last_id == "0-0"

    consumer.acknowledge(
        processed_message_id
    )

    assert consumer.last_id == processed_message_id

    second_result = processor.process_batch()

    assert second_result == []

    assert consumer.last_id == processed_message_id

    queue.clear()


def test_processor_preserves_detection_fields():
    (
        queue,
        _,
        router,
        processor,
    ) = create_processor(
        "test_processor_fields"
    )

    received_events = []

    def handler(event):
        received_events.append(event)

    router.register(
        "test_handler",
        handler,
    )

    event = create_event(
        "processor-fields-001"
    )

    queue.publish(event)

    result = processor.process_batch()

    processed_event = result[0]

    assert processed_event.binary_prediction == 0
    assert processed_event.attack_family == "Brute Force"
    assert processed_event.confidence == 0.95

    assert received_events[0] is processed_event

    queue.clear()
