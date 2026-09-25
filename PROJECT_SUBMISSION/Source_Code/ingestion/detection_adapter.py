from detection.handler import DetectionHandler, DetectionResult
from correlation.schema import SecurityEvent


class DetectionAdapter:
    """
    Connects the ingestion/event-routing layer with the
    CIC-IDS detection handler.

    The adapter is intentionally thin:

        SecurityEvent
             ↓
        DetectionHandler
             ↓
        DetectionResult

    It does not perform parsing, normalization, correlation,
    or model inference itself.
    """

    def __init__(
        self,
        detection_handler: DetectionHandler,
    ) -> None:
        if not isinstance(
            detection_handler,
            DetectionHandler,
        ):
            raise TypeError(
                "detection_handler must be a DetectionHandler."
            )

        self.detection_handler = detection_handler

    def __call__(
        self,
        event: SecurityEvent,
    ) -> DetectionResult:
        """
        Allow the adapter to be registered directly as an
        EventRouter handler.
        """
        return self.process(event)

    def process(
        self,
        event: SecurityEvent,
    ) -> DetectionResult:
        """
        Process one SecurityEvent through the detection layer.
        """
        if not isinstance(
            event,
            SecurityEvent,
        ):
            raise TypeError(
                "event must be a SecurityEvent."
            )

        result = self.detection_handler.detect(
            event
        )

        self._apply_result(
            event,
            result,
        )

        return result

    def process_batch(
        self,
        events: list[SecurityEvent],
    ) -> list[DetectionResult]:
        """
        Process multiple SecurityEvents using the
        DetectionHandler batch interface.
        """
        if not isinstance(events, list):
            raise TypeError(
                "events must be a list."
            )

        for event in events:
            if not isinstance(
                event,
                SecurityEvent,
            ):
                raise TypeError(
                    "all items in events must be "
                    "SecurityEvent objects."
                )

        results = self.detection_handler.detect_batch(
            events
        )

        if len(results) != len(events):
            raise RuntimeError(
                "Detection handler returned a different "
                "number of results than input events."
            )

        for event, result in zip(
            events,
            results,
        ):
            self._apply_result(
                event,
                result,
            )

        return results

    @staticmethod
    def _apply_result(
        event: SecurityEvent,
        result: DetectionResult,
    ) -> None:
        """
        Apply detection output back to the SecurityEvent.

        This keeps the event enriched with the latest
        detection state for downstream correlation.
        """
        event.binary_prediction = int(
            result.detected
        )

        event.attack_family = (
            result.attack_family
        )

        event.confidence = float(
            result.confidence
        )