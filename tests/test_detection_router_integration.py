from correlation.schema import SecurityEvent
from detection.handler import DetectionHandler, DetectionResult
from ingestion.detection_adapter import DetectionAdapter
from ingestion.event_router import EventRouter


class FakeDetectionHandler(DetectionHandler):
    """
    Lightweight detection handler used to verify
    DetectionAdapter + EventRouter integration.

    It inherits from DetectionHandler so that the adapter's
    production type validation remains intact.
    """

    def detect(self, event):
        return DetectionResult(
            event_id=event.event_id,
            detected=True,
            attack_family="Brute Force",
            confidence=0.95,
            detector_type="test_detector",
            supported=True,
            reason="Test detection.",
        )

    def detect_batch(self, events):
        return [
            DetectionResult(
                event_id=event.event_id,
                detected=True,
                attack_family="Brute Force",
                confidence=0.95,
                detector_type="test_detector",
                supported=True,
                reason="Test batch detection.",
            )
            for event in events
        ]


def make_event(event_id):
    return SecurityEvent(
        event_id=event_id,
        timestamp="2026-09-15T10:00:00",
        event_type="network_flow",
        metadata={
            "feature_1": 1.0,
        },
    )


def test_detection_adapter_works_through_router():
    detection_handler = FakeDetectionHandler()

    adapter = DetectionAdapter(
        detection_handler
    )

    router = EventRouter()

    router.register(
        "detection",
        adapter,
    )

    event = make_event("ROUTER-001")

    results = router.route(event)

    assert "detection" in results

    result = results["detection"]

    assert isinstance(
        result,
        DetectionResult,
    )

    assert result.event_id == "ROUTER-001"
    assert result.detected is True
    assert result.attack_family == "Brute Force"
    assert result.confidence == 0.95

    assert event.binary_prediction == 1
    assert event.attack_family == "Brute Force"
    assert event.confidence == 0.95


def test_detection_adapter_batch_works_through_router():
    detection_handler = FakeDetectionHandler()

    adapter = DetectionAdapter(
        detection_handler
    )

    router = EventRouter()

    router.register(
        "detection",
        adapter,
    )

    events = [
        make_event("ROUTER-001"),
        make_event("ROUTER-002"),
        make_event("ROUTER-003"),
    ]

    results = router.route_batch(
        events
    )

    assert len(results) == 3

    assert [
        result["detection"].event_id
        for result in results
    ] == [
        "ROUTER-001",
        "ROUTER-002",
        "ROUTER-003",
    ]

    for event in events:
        assert event.binary_prediction == 1
        assert event.attack_family == "Brute Force"
        assert event.confidence == 0.95