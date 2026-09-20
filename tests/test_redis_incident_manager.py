from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pandas as pd

from correlation.correlator import IncidentCorrelator
from correlation.event_builder import build_security_event
from correlation.incident_manager import IncidentManager
from correlation.incident_window import IncidentWindow
from correlation.schema import Incident, SecurityEvent
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

DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "splits"
    / "train.csv"
)


def create_detection_handler() -> DetectionHandler:
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


def load_attack_row():
    dataframe = pd.read_csv(
        DATA_PATH,
        nrows=200_000,
    )

    attack_rows = dataframe[
        dataframe["BinaryLabel"] == 1
    ]

    assert not attack_rows.empty

    return attack_rows.iloc[0]


def create_event(
    event_id: str,
    timestamp: datetime,
    attack_row,
    src_ip: str = "192.168.1.50",
    dst_ip: str = "10.0.0.20",
) -> SecurityEvent:
    event = build_security_event(
        row=attack_row,
        event_id=event_id,
        attack_family="Unknown",
        confidence=0.0,
        binary_prediction=0,
        true_label=attack_row["Label"],
    )

    event.timestamp = timestamp
    event.src_ip = src_ip
    event.dst_ip = dst_ip

    return event


def create_pipeline(
    stream_name: str,
):
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

    persistence_adapter = Mock()

    window = IncidentWindow(
        window_seconds=60
    )

    correlator = IncidentCorrelator(
        time_window_seconds=60,
        correlation_threshold=4,
    )

    incident_manager = IncidentManager(
        window=window,
        correlator=correlator,
        persistence_adapter=persistence_adapter,
    )

    router = EventRouter()

    # Detection MUST run before IncidentManager.
    router.register(
        "detection",
        detection_adapter,
    )

    router.register(
        "incident_manager",
        incident_manager,
    )

    processor = RedisStreamProcessor(
        consumer=consumer,
        event_router=router,
    )

    return (
        queue,
        processor,
        incident_manager,
        persistence_adapter,
    )


def test_redis_events_reach_incident_manager():
    (
        queue,
        processor,
        incident_manager,
        persistence_adapter,
    ) = create_pipeline(
        "test_redis_incident_manager_reach"
    )

    attack_row = load_attack_row()

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
        create_event(
            event_id=f"incident-manager-{index:03d}",
            timestamp=base_time + timedelta(
                seconds=index
            ),
            attack_row=attack_row,
        )
        for index in range(5)
    ]

    queue.publish_batch(events)

    processed_events = processor.process_batch(
        count=10
    )

    assert len(processed_events) == 5

    assert incident_manager.buffered_event_count == 5

    for event in processed_events:
        assert event.binary_prediction == 1
        assert event.attack_family != "Benign"
        assert isinstance(
            event.attack_family,
            str,
        )
        assert 0.0 <= event.confidence <= 1.0

    persistence_adapter.process_batch.assert_not_called()

    queue.clear()


def test_redis_batches_share_same_incident_window():
    (
        queue,
        processor,
        incident_manager,
        persistence_adapter,
    ) = create_pipeline(
        "test_redis_incident_window_across_batches"
    )

    attack_row = load_attack_row()

    base_time = datetime(
        2026,
        9,
        16,
        3,
        0,
        0,
        tzinfo=timezone.utc,
    )

    first_batch = [
        create_event(
            event_id=f"batch-one-{index:03d}",
            timestamp=base_time + timedelta(
                seconds=index
            ),
            attack_row=attack_row,
        )
        for index in range(3)
    ]

    second_batch = [
        create_event(
            event_id=f"batch-two-{index:03d}",
            timestamp=base_time + timedelta(
                seconds=3 + index
            ),
            attack_row=attack_row,
        )
        for index in range(2)
    ]

    queue.publish_batch(first_batch)

    processed_first = processor.process_batch(
        count=10
    )

    assert len(processed_first) == 3
    assert incident_manager.buffered_event_count == 3

    queue.publish_batch(second_batch)

    processed_second = processor.process_batch(
        count=10
    )

    assert len(processed_second) == 2

    # The second Redis batch must continue the existing
    # IncidentWindow rather than creating a new one.
    assert incident_manager.buffered_event_count == 5

    persistence_adapter.process_batch.assert_not_called()

    queue.clear()


def test_redis_event_outside_window_flushes_previous_incident():
    (
        queue,
        processor,
        incident_manager,
        persistence_adapter,
    ) = create_pipeline(
        "test_redis_incident_window_flush"
    )

    attack_row = load_attack_row()

    base_time = datetime(
        2026,
        9,
        16,
        3,
        0,
        0,
        tzinfo=timezone.utc,
    )

    first_batch = [
        create_event(
            event_id="flush-event-001",
            timestamp=base_time,
            attack_row=attack_row,
        ),
        create_event(
            event_id="flush-event-002",
            timestamp=base_time + timedelta(
                seconds=10
            ),
            attack_row=attack_row,
        ),
    ]

    queue.publish_batch(first_batch)

    processed_first = processor.process_batch(
        count=10
    )

    assert len(processed_first) == 2
    assert incident_manager.buffered_event_count == 2

    second_batch = [
        create_event(
            event_id="flush-event-003",
            timestamp=base_time + timedelta(
                seconds=61
            ),
            attack_row=attack_row,
        )
    ]

    queue.publish_batch(second_batch)

    processed_second = processor.process_batch(
        count=10
    )

    assert len(processed_second) == 1

    # The third event causes the first window to flush and then
    # becomes the first event of the next active window.
    assert incident_manager.buffered_event_count == 1

    persistence_adapter.process_batch.assert_called_once()

    persisted_incidents = (
        persistence_adapter.process_batch.call_args[0][0]
    )

    assert isinstance(
        persisted_incidents,
        list,
    )

    assert len(persisted_incidents) >= 1

    for incident in persisted_incidents:
        assert isinstance(
            incident,
            Incident,
        )
        assert len(incident.events) >= 1

    queue.clear()
