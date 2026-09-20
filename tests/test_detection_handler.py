from datetime import datetime, timezone

import joblib
import pytest

from correlation.schema import SecurityEvent
from detection.handler import DetectionHandler, DetectionResult
from detection.model_loader import (
    AttackFamilyModelBundle,
    BinaryModelBundle,
)


BINARY_MODEL_PATH = (
    "detection/models/xgboost_binary_detector.joblib"
)

FAMILY_MODEL_PATH = (
    "detection/models/xgboost_attack_family_classifier.joblib"
)


@pytest.fixture
def network_event():
    return SecurityEvent(
        event_id="NET-001",
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
    )


@pytest.fixture
def linux_event():
    return SecurityEvent(
        event_id="LINUX-001",
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


@pytest.fixture
def real_model_bundles():
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

    return binary_bundle, family_bundle


@pytest.fixture
def network_event_with_features(real_model_bundles):
    _, family_bundle = real_model_bundles

    metadata = {
        feature: 0.0
        for feature in family_bundle.feature_columns
    }

    return SecurityEvent(
        event_id="NET-FEATURED-001",
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


def test_handler_starts_without_models():
    handler = DetectionHandler()

    assert handler._binary_model is None
    assert handler._family_model is None
    assert handler._feature_adapter is None


def test_network_event_is_supported(network_event):
    handler = DetectionHandler()

    assert handler.is_supported(network_event) is True


def test_linux_event_is_not_supported(linux_event):
    handler = DetectionHandler()

    assert handler.is_supported(linux_event) is False


def test_missing_event_type_is_not_supported():
    handler = DetectionHandler()

    event = SecurityEvent(
        event_id="TEST-001",
        timestamp=datetime.now(timezone.utc),
    )

    assert handler.is_supported(event) is False


def test_invalid_event_type_is_rejected():
    handler = DetectionHandler()

    with pytest.raises(TypeError):
        handler.is_supported("not-an-event")


def test_unsupported_event_returns_explicit_result(linux_event):
    handler = DetectionHandler()

    result = handler.detect(linux_event)

    assert isinstance(result, DetectionResult)
    assert result.event_id == "LINUX-001"
    assert result.detected is False
    assert result.attack_family == "Unknown"
    assert result.confidence == 0.0
    assert result.detector_type == "cic_ids_xgboost"
    assert result.supported is False
    assert "outside" in result.reason


def test_attach_models_requires_binary_model():
    handler = DetectionHandler()

    with pytest.raises(ValueError):
        handler.attach_models(
            binary_model=None,
            family_model=object(),
        )


def test_attach_models_requires_family_model():
    handler = DetectionHandler()

    with pytest.raises(ValueError):
        handler.attach_models(
            binary_model=object(),
            family_model=None,
        )


def test_attach_models_requires_binary_bundle():
    handler = DetectionHandler()

    with pytest.raises(TypeError):
        handler.attach_models(
            binary_model=object(),
            family_model=object(),
        )


def test_attach_models_stores_real_bundles(
    real_model_bundles,
):
    handler = DetectionHandler()

    binary_model, family_model = real_model_bundles

    handler.attach_models(
        binary_model=binary_model,
        family_model=family_model,
    )

    assert handler._binary_model is binary_model
    assert handler._family_model is family_model
    assert handler._feature_adapter is not None


def test_supported_event_requires_binary_model(network_event):
    handler = DetectionHandler()

    with pytest.raises(
        RuntimeError,
        match="Binary detection model is not attached",
    ):
        handler.detect(network_event)


def test_supported_event_requires_features(
    network_event,
    real_model_bundles,
):
    handler = DetectionHandler()

    binary_model, family_model = real_model_bundles

    handler.attach_models(
        binary_model=binary_model,
        family_model=family_model,
    )

    with pytest.raises(
        ValueError,
        match="no CIC-IDS features",
    ):
        handler.detect(network_event)


def test_network_event_with_features_runs_detection(
    network_event_with_features,
    real_model_bundles,
):
    handler = DetectionHandler()

    binary_model, family_model = real_model_bundles

    handler.attach_models(
        binary_model=binary_model,
        family_model=family_model,
    )

    result = handler.detect(
        network_event_with_features
    )

    assert isinstance(result, DetectionResult)
    assert result.event_id == "NET-FEATURED-001"
    assert result.supported is True
    assert result.detected is False
    assert result.attack_family == "Benign"
    assert 0.0 <= result.confidence <= 1.0
    assert result.detector_type == "cic_ids_xgboost"


def test_invalid_event_is_rejected():
    handler = DetectionHandler()

    with pytest.raises(TypeError):
        handler.detect("not-an-event")


def test_invalid_batch_is_rejected():
    handler = DetectionHandler()

    with pytest.raises(TypeError):
        handler.detect_batch("not-a-list")


def test_batch_rejects_invalid_event():
    handler = DetectionHandler()

    with pytest.raises(TypeError):
        handler.detect_batch(
            ["not-a-security-event"]
        )


def test_batch_handles_unsupported_events(linux_event):
    handler = DetectionHandler()

    results = handler.detect_batch(
        [linux_event]
    )

    assert len(results) == 1
    assert isinstance(
        results[0],
        DetectionResult,
    )
    assert results[0].supported is False

def test_batch_results_match_individual_detection(
    network_event_with_features,
    real_model_bundles,
):
    handler = DetectionHandler()

    binary_model, family_model = real_model_bundles

    handler.attach_models(
        binary_model=binary_model,
        family_model=family_model,
    )

    events = [
        network_event_with_features,
        SecurityEvent(
            event_id="NET-FEATURED-002",
            timestamp=network_event_with_features.timestamp,
            event_type="network_flow",
            metadata=dict(
                network_event_with_features.metadata
            ),
        ),
        SecurityEvent(
            event_id="NET-FEATURED-003",
            timestamp=network_event_with_features.timestamp,
            event_type="network_flow",
            metadata=dict(
                network_event_with_features.metadata
            ),
        ),
    ]

    individual_results = [
        handler.detect(event)
        for event in events
    ]

    batch_results = handler.detect_batch(events)

    assert len(batch_results) == 3

    for individual, batch in zip(
        individual_results,
        batch_results,
    ):
        assert batch.event_id == individual.event_id
        assert batch.detected == individual.detected
        assert batch.attack_family == individual.attack_family
        assert batch.confidence == individual.confidence
        assert batch.detector_type == individual.detector_type
        assert batch.supported == individual.supported

def test_batch_results_match_individual_detection(
    network_event_with_features,
    real_model_bundles,
):
    handler = DetectionHandler()

    binary_model, family_model = real_model_bundles

    handler.attach_models(
        binary_model=binary_model,
        family_model=family_model,
    )

    events = [
        network_event_with_features,
        SecurityEvent(
            event_id="NET-FEATURED-002",
            timestamp=network_event_with_features.timestamp,
            event_type="network_flow",
            metadata=dict(
                network_event_with_features.metadata
            ),
        ),
        SecurityEvent(
            event_id="NET-FEATURED-003",
            timestamp=network_event_with_features.timestamp,
            event_type="network_flow",
            metadata=dict(
                network_event_with_features.metadata
            ),
        ),
    ]

    individual_results = [
        handler.detect(event)
        for event in events
    ]

    batch_results = handler.detect_batch(events)

    assert len(batch_results) == 3

    for individual, batch in zip(
        individual_results,
        batch_results,
    ):
        assert batch.event_id == individual.event_id
        assert batch.detected == individual.detected
        assert batch.attack_family == individual.attack_family
        assert batch.confidence == individual.confidence
        assert batch.detector_type == individual.detector_type
        assert batch.supported == individual.supported