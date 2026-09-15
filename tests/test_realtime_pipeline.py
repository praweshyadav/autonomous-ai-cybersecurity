from datetime import datetime, timezone
from pathlib import Path
import threading
import time

import joblib
import pytest

from correlation.correlation_adapter import CorrelationAdapter
from correlation.correlator import IncidentCorrelator
from correlation.schema import SecurityEvent
from detection.handler import DetectionHandler
from detection.model_loader import (
    AttackFamilyModelBundle,
    BinaryModelBundle,
)
from ingestion.detection_adapter import DetectionAdapter
from ingestion.event_router import EventRouter
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.source_ingestor import SourceIngestor
from ingestion.stream_processor import StreamProcessor


BINARY_MODEL_PATH = (
    "detection/models/xgboost_binary_detector.joblib"
)

FAMILY_MODEL_PATH = (
    "detection/models/xgboost_attack_family_classifier.joblib"
)


@pytest.fixture
def detection_adapter():
    binary_package = joblib.load(
        BINARY_MODEL_PATH
    )

    family_package = joblib.load(
        FAMILY_MODEL_PATH
    )

    binary_bundle = BinaryModelBundle(
        model=binary_package["model"],
        feature_names=binary_package["feature_names"],
    )

    family_bundle = AttackFamilyModelBundle(
        model=family_package["model"],
        label_encoder=family_package["label_encoder"],
        feature_columns=family_package["feature_columns"],
    )

    handler = DetectionHandler()

    handler.attach_models(
        binary_model=binary_bundle,
        family_model=family_bundle,
    )

    return DetectionAdapter(handler)


def test_realtime_stream_reaches_detection_and_correlation(
    tmp_path: Path,
    detection_adapter,
):
    log_file = tmp_path / "security.log"

    log_file.write_text(
        "",
        encoding="utf-8",
    )

    source_ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    router = EventRouter()

    correlation_adapter = CorrelationAdapter(
        correlator=IncidentCorrelator(
            time_window_seconds=60,
            correlation_threshold=4,
        )
    )

    router.register(
        "detection",
        detection_adapter,
    )

    router.register(
        "correlation",
        correlation_adapter,
    )

    processor = StreamProcessor(
        source_ingestor=source_ingestor,
        event_router=router,
    )

    received = []

    stream = processor.process_stream(
        poll_interval=0.01,
        start_at_end=True,
        year=2026,
    )

    def consume_stream():
        received.append(next(stream))

    thread = threading.Thread(
        target=consume_stream,
        daemon=True,
    )

    thread.start()

    time.sleep(0.05)

    with log_file.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            "Mar 10 10:15:30 server sshd[1234]: "
            "Failed password for admin from "
            "192.168.1.10 port 54321 ssh2\n"
        )
        file.flush()

    thread.join(timeout=2)

    stream.close()

    assert len(received) == 1

    event = received[0]

    assert isinstance(
        event,
        SecurityEvent,
    )

    assert event.username == "admin"
    assert event.src_ip == "192.168.1.10"
    assert event.src_port == 54321
    assert event.dst_port == 22
    assert event.protocol == 6
    assert event.event_type == "authentication_failure"

    assert event.attack_family == "Unknown"
    assert event.confidence == 0.0

    buffered_events = (
        correlation_adapter.get_events()
    )

    assert len(buffered_events) == 1
    assert buffered_events[0] is event


def test_realtime_stream_preserves_event_order(
    tmp_path: Path,
):
    log_file = tmp_path / "security.log"

    log_file.write_text(
        "",
        encoding="utf-8",
    )

    source_ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    router = EventRouter()

    received_by_router = []

    def test_handler(event):
        received_by_router.append(event)

    router.register(
        "test_handler",
        test_handler,
    )

    processor = StreamProcessor(
        source_ingestor=source_ingestor,
        event_router=router,
    )

    stream = processor.process_stream(
        poll_interval=0.01,
        start_at_end=True,
        year=2026,
    )

    received = []

    def consume_stream():
        for _ in range(2):
            received.append(next(stream))

    thread = threading.Thread(
        target=consume_stream,
        daemon=True,
    )

    thread.start()

    time.sleep(0.05)

    with log_file.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            "Mar 10 10:15:30 server sshd[1234]: "
            "Failed password for admin from "
            "192.168.1.10 port 54321 ssh2\n"
        )

        file.write(
            "Mar 10 10:15:31 server sshd[1235]: "
            "Failed password for root from "
            "192.168.1.20 port 54322 ssh2\n"
        )

        file.flush()

    thread.join(timeout=2)

    stream.close()

    assert len(received) == 2
    assert len(received_by_router) == 2

    assert received[0].username == "admin"
    assert received[1].username == "root"

    assert (
        received[0].event_id
        == received_by_router[0].event_id
    )

    assert (
        received[1].event_id
        == received_by_router[1].event_id
    )