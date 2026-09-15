from datetime import datetime, timedelta, timezone

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


@pytest.fixture
def feature_columns(detection_adapter):
    return (
        detection_adapter
        .detection_handler
        ._family_model
        .feature_columns
    )


def make_event(
    event_id: str,
    timestamp: datetime,
    feature_columns,
) -> SecurityEvent:

    metadata = {
        feature: 0.0
        for feature in feature_columns
    }

    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.20",
        src_port=54321,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        event_type="network_flow",
        metadata=metadata,
    )


def create_router(detection_adapter):
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

    return router, correlation_adapter


def test_detection_runs_before_correlation(
    detection_adapter,
    feature_columns,
):
    timestamp = datetime(
        2026,
        3,
        10,
        10,
        15,
        30,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            "STREAM-001",
            timestamp,
            feature_columns,
        ),
        make_event(
            "STREAM-002",
            timestamp + timedelta(seconds=1),
            feature_columns,
        ),
    ]

    router, correlation_adapter = create_router(
        detection_adapter
    )

    router.route_batch(events)

    for event in events:
        assert event.attack_family == "Benign"
        assert event.binary_prediction == 0
        assert 0.0 <= event.confidence <= 1.0

    buffered_events = (
        correlation_adapter.get_events()
    )

    assert len(buffered_events) == 2

    for event in buffered_events:
        assert event.attack_family == "Benign"


def test_detection_and_correlation_are_both_called(
    detection_adapter,
    feature_columns,
):
    timestamp = datetime(
        2026,
        3,
        10,
        10,
        15,
        30,
        tzinfo=timezone.utc,
    )

    event = make_event(
        "STREAM-INTEGRATION-001",
        timestamp,
        feature_columns,
    )

    router, correlation_adapter = create_router(
        detection_adapter
    )

    result = router.route(event)

    assert "detection" in result
    assert "correlation" in result

    assert event.binary_prediction == 0
    assert event.attack_family == "Benign"

    assert len(
        correlation_adapter.get_events()
    ) == 1


def test_correlation_produces_incident_after_detection(
    detection_adapter,
):
    timestamp = datetime(
        2026,
        3,
        10,
        10,
        15,
        30,
        tzinfo=timezone.utc,
    )

    events = [
        SecurityEvent(
            event_id="INCIDENT-001",
            timestamp=timestamp,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.20",
            src_port=54321,
            dst_port=22,
            protocol=6,
            protocol_name="TCP",
            event_type="network_flow",
            binary_prediction=1,
            attack_family="Brute Force",
            confidence=0.95,
        ),
        SecurityEvent(
            event_id="INCIDENT-002",
            timestamp=timestamp + timedelta(seconds=1),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.20",
            src_port=54322,
            dst_port=22,
            protocol=6,
            protocol_name="TCP",
            event_type="network_flow",
            binary_prediction=1,
            attack_family="Brute Force",
            confidence=0.95,
        ),
    ]

    router, correlation_adapter = create_router(
        detection_adapter
    )

    # Correlation is tested with already-detected attack events.
    correlation_adapter.process_batch(events)

    incidents = correlation_adapter.correlate()

    assert len(incidents) == 1

    incident = incidents[0]

    assert len(incident.events) == 2
    assert incident.primary_attack_family == "Brute Force"
    assert incident.family_distribution == {
        "Brute Force": 2
    }