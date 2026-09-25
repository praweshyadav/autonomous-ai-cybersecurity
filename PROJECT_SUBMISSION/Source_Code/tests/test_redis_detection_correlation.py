from datetime import datetime, timedelta
from pathlib import Path

from correlation.correlation_adapter import CorrelationAdapter
from correlation.correlator import IncidentCorrelator
from correlation.schema import SecurityEvent
from detection.handler import DetectionHandler
from detection.model_loader import DetectionModelLoader
from ingestion.detection_adapter import DetectionAdapter
from ingestion.event_router import EventRouter
from ingestion.queue.redis_consumer import RedisStreamConsumer
from ingestion.queue.redis_processor import RedisStreamProcessor
from ingestion.queue.redis_stream import RedisEventQueue


PROJECT_ROOT = Path(__file__).resolve().parents[1]

BINARY_MODEL_PATH = (
    PROJECT_ROOT
    / "detection"
    / "models"
    / "xgboost_binary_detector.joblib"
)

FAMILY_MODEL_PATH = (
    PROJECT_ROOT
    / "detection"
    / "models"
    / "xgboost_attack_family_classifier.joblib"
)


def create_detection_handler() -> DetectionHandler:
    """
    Load the real trained detection models and attach
    them to the DetectionHandler.
    """

    loader = DetectionModelLoader()

    binary_bundle = loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    family_bundle = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    handler = DetectionHandler()

    handler.attach_models(
        binary_bundle,
        family_bundle,
    )

    return handler


def create_feature_metadata() -> dict:
    """
    Create a valid CICFlowMeter feature dictionary using
    the exact feature names required by the trained model.

    Values are deliberately simple finite numeric values.
    """

    loader = DetectionModelLoader()

    family_bundle = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    return {
        feature_name: 1.0
        for feature_name in family_bundle.feature_columns
    }


def create_event(
    event_id: str,
    timestamp: datetime,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.5",
) -> SecurityEvent:
    """
    Create a SecurityEvent containing the exact 78
    CICFlowMeter features expected by the family model.
    """

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=12345,
        dst_port=80,
        protocol=6,
        protocol_name="TCP",
        event_type="network_flow",
        metadata=create_feature_metadata(),
    )


def create_pipeline(
    stream_name: str,
):
    """
    Build the complete Redis detection-correlation pipeline.

    Redis
        ↓
    Consumer
        ↓
    Deserializer
        ↓
    EventRouter
        ↓
    Detection
        ↓
    Correlation
    """

    queue = RedisEventQueue(
        stream_name=stream_name
    )

    queue.clear()

    consumer = RedisStreamConsumer(
        queue
    )

    detection_handler = create_detection_handler()

    detection_adapter = DetectionAdapter(
        detection_handler
    )

    correlation_adapter = CorrelationAdapter(
        IncidentCorrelator(
            time_window_seconds=60,
            correlation_threshold=4,
        )
    )

    router = EventRouter()

    # Detection must run before correlation because
    # correlation needs the detection result.
    router.register(
        "detection",
        detection_adapter,
    )

    router.register(
        "correlation",
        correlation_adapter,
    )

    processor = RedisStreamProcessor(
        consumer=consumer,
        event_router=router,
    )

    return (
        queue,
        consumer,
        detection_adapter,
        correlation_adapter,
        router,
        processor,
    )


def test_redis_pipeline_initializes():
    (
        queue,
        consumer,
        detection_adapter,
        correlation_adapter,
        router,
        processor,
    ) = create_pipeline(
        "test_redis_detection_correlation_init"
    )

    assert processor.consumer is consumer
    assert processor.event_router is router

    assert "detection" in router.handler_names()
    assert "correlation" in router.handler_names()

    assert detection_adapter.detection_handler is not None

    assert correlation_adapter.get_events() == []

    queue.clear()


def test_redis_event_reaches_real_detection():
    (
        queue,
        _,
        _,
        correlation_adapter,
        _,
        processor,
    ) = create_pipeline(
        "test_redis_real_detection"
    )

    event = create_event(
        event_id="redis-detection-001",
        timestamp=datetime(
            2026,
            9,
            16,
            3,
            0,
            0,
        ),
    )

    queue.publish(event)

    processed_events = processor.process_batch(
        count=10
    )

    assert len(processed_events) == 1

    processed_event = processed_events[0]

    assert isinstance(
        processed_event,
        SecurityEvent,
    )

    assert processed_event.event_id == (
        "redis-detection-001"
    )

    assert processed_event.binary_prediction in {
        0,
        1,
    }

    assert isinstance(
        processed_event.attack_family,
        str,
    )

    assert 0.0 <= processed_event.confidence <= 1.0

    correlation_events = (
        correlation_adapter.get_events()
    )

    assert len(correlation_events) == 1

    assert correlation_events[0] is processed_event

    queue.clear()


def test_redis_pipeline_processes_multiple_events():
    (
        queue,
        _,
        _,
        correlation_adapter,
        _,
        processor,
    ) = create_pipeline(
        "test_redis_multiple_pipeline"
    )

    base_time = datetime(
        2026,
        9,
        16,
        3,
        0,
        0,
    )

    events = [
        create_event(
            event_id=f"redis-pipeline-{index:03d}",
            timestamp=base_time + timedelta(
                seconds=index
            ),
        )
        for index in range(3)
    ]

    queue.publish_batch(events)

    processed_events = processor.process_batch(
        count=10
    )

    assert len(processed_events) == 3

    assert [
        event.event_id
        for event in processed_events
    ] == [
        "redis-pipeline-000",
        "redis-pipeline-001",
        "redis-pipeline-002",
    ]

    assert len(
        correlation_adapter.get_events()
    ) == 3

    for event in processed_events:
        assert event.binary_prediction in {
            0,
            1,
        }

        assert isinstance(
            event.attack_family,
            str,
        )

        assert 0.0 <= event.confidence <= 1.0

    queue.clear()


def test_redis_pipeline_reaches_correlation():
    (
        queue,
        _,
        _,
        correlation_adapter,
        _,
        processor,
    ) = create_pipeline(
        "test_redis_correlation_pipeline"
    )

    base_time = datetime(
        2026,
        9,
        16,
        3,
        0,
        0,
    )

    events = [
        create_event(
            event_id=f"redis-correlation-{index:03d}",
            timestamp=base_time + timedelta(
                seconds=index
            ),
            src_ip="192.168.1.50",
            dst_ip="10.0.0.20",
        )
        for index in range(5)
    ]

    queue.publish_batch(events)

    processed_events = processor.process_batch(
        count=10
    )

    assert len(processed_events) == 5

    correlation_events = (
        correlation_adapter.get_events()
    )

    assert len(correlation_events) == 5

    for processed_event, correlated_event in zip(
        processed_events,
        correlation_events,
    ):
        assert correlated_event is processed_event

    incidents = correlation_adapter.correlate()

    assert isinstance(
        incidents,
        list,
    )

    for incident in incidents:
        assert len(incident.events) >= 1

    queue.clear()
