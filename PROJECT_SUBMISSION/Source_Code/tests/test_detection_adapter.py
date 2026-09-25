import pytest

from correlation.schema import SecurityEvent
from detection.handler import DetectionHandler, DetectionResult
from ingestion.detection_adapter import DetectionAdapter


class FakeDetectionHandler(DetectionHandler):
    """
    Lightweight fake handler used to test the adapter
    without loading real ML models.
    """

    def detect(self, event):
        return DetectionResult(
            event_id=event.event_id,
            detected=True,
            attack_family="DoS",
            confidence=0.91,
            detector_type="test_detector",
            supported=True,
            reason="Test detection result.",
        )

    def detect_batch(self, events):
        return [
            DetectionResult(
                event_id=event.event_id,
                detected=True,
                attack_family="DoS",
                confidence=0.91,
                detector_type="test_detector",
                supported=True,
                reason="Test batch detection result.",
            )
            for event in events
        ]


def make_event(event_id="TEST-001"):
    return SecurityEvent(
        event_id=event_id,
        timestamp="2026-09-15T10:00:00",
        event_type="network_flow",
        metadata={
            "feature_1": 1.0,
        },
    )


def test_adapter_requires_detection_handler():
    with pytest.raises(TypeError):
        DetectionAdapter(None)


def test_process_requires_security_event():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    with pytest.raises(TypeError):
        adapter.process("invalid")


def test_process_returns_detection_result():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    event = make_event()

    result = adapter.process(event)

    assert isinstance(
        result,
        DetectionResult,
    )

    assert result.event_id == event.event_id
    assert result.detected is True
    assert result.attack_family == "DoS"
    assert result.confidence == 0.91


def test_process_applies_detection_to_event():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    event = make_event()

    adapter.process(event)

    assert event.binary_prediction == 1
    assert event.attack_family == "DoS"
    assert event.confidence == 0.91


def test_process_batch_requires_list():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    with pytest.raises(TypeError):
        adapter.process_batch("invalid")


def test_process_batch_rejects_invalid_event():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    with pytest.raises(TypeError):
        adapter.process_batch(
            [
                make_event(),
                "invalid",
            ]
        )


def test_process_batch_returns_results():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    events = [
        make_event("TEST-001"),
        make_event("TEST-002"),
        make_event("TEST-003"),
    ]

    results = adapter.process_batch(events)

    assert len(results) == 3

    assert [
        result.event_id
        for result in results
    ] == [
        "TEST-001",
        "TEST-002",
        "TEST-003",
    ]


def test_process_batch_applies_results_to_events():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    events = [
        make_event("TEST-001"),
        make_event("TEST-002"),
    ]

    adapter.process_batch(events)

    for event in events:
        assert event.binary_prediction == 1
        assert event.attack_family == "DoS"
        assert event.confidence == 0.91


def test_empty_batch_returns_empty_results():
    adapter = DetectionAdapter(
        FakeDetectionHandler()
    )

    results = adapter.process_batch([])

    assert results == []