from datetime import datetime, timezone

import joblib
import pytest

from correlation.schema import SecurityEvent
from ingestion.detection_adapter import DetectionAdapter
from detection.handler import DetectionHandler
from detection.model_loader import (
    AttackFamilyModelBundle,
    BinaryModelBundle,
)
from ingestion.event_router import EventRouter
from ingestion.stream_processor import StreamProcessor


BINARY_MODEL_PATH = (
    "detection/models/xgboost_binary_detector.joblib"
)

FAMILY_MODEL_PATH = (
    "detection/models/xgboost_attack_family_classifier.joblib"
)


@pytest.fixture
def real_detection_adapter():
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


@pytest.fixture
def network_event(real_detection_adapter):
    family_model = (
        real_detection_adapter
        .detection_handler
        ._family_model
    )

    metadata = {
        feature: 0.0
        for feature in family_model.feature_columns
    }

    return SecurityEvent(
        event_id="STREAM-NET-001",
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
        event_type="network_flow",
        metadata=metadata,
    )


def test_stream_detection_integration(
    network_event,
    real_detection_adapter,
):
    router = EventRouter()

    router.register(
        "detection",
        real_detection_adapter,
    )

    processor = StreamProcessor.__new__(
        StreamProcessor
    )

    processor.source_ingestor = None
    processor.event_router = router

    processed = processor.process_batch(
        [network_event]
    )

    assert len(processed) == 1

    event = processed[0]

    assert event.event_id == "STREAM-NET-001"
    assert event.binary_prediction == 0
    assert event.attack_family == "Benign"
    assert 0.0 <= event.confidence <= 1.0


def test_detection_result_is_written_back_to_event(
    network_event,
    real_detection_adapter,
):
    router = EventRouter()

    router.register(
        "detection",
        real_detection_adapter,
    )

    result = router.route(
        network_event
    )

    assert "detection" in result

    assert network_event.binary_prediction == 0
    assert network_event.attack_family == "Benign"
    assert 0.0 <= network_event.confidence <= 1.0


def test_linux_auth_event_passes_through_without_cic_detection(
    real_detection_adapter,
):
    linux_event = SecurityEvent(
        event_id="STREAM-LINUX-001",
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
        src_port=54321,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        event_type="authentication_failure",
        username="admin",
    )

    router = EventRouter()

    router.register(
        "detection",
        real_detection_adapter,
    )

    result = router.route(
        linux_event
    )

    detection_result = result["detection"]

    assert detection_result.supported is False
    assert detection_result.attack_family == "Unknown"
    assert detection_result.confidence == 0.0

    assert linux_event.attack_family == "Unknown"
    assert linux_event.confidence == 0.0