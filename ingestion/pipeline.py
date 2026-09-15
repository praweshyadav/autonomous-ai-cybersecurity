from typing import Any, Callable

from correlation.schema import SecurityEvent
from ingestion.normalizer import SecurityEventNormalizer


class IngestionPipeline:
    """
    Converts raw log records into normalized SecurityEvent objects.

    Pipeline:

        Raw log
           ↓
        Parser
           ↓
        Raw event dictionary
           ↓
        Normalizer
           ↓
        SecurityEvent

    This component does not perform:
        - threat detection
        - incident correlation
        - LLM investigation
        - response actions
    """

    def __init__(
        self,
        parser: Any,
        normalizer: SecurityEventNormalizer | None = None,
    ):
        if parser is None:
            raise ValueError(
                "parser cannot be None."
            )

        if not hasattr(parser, "parse"):
            raise TypeError(
                "parser must provide a parse() method."
            )

        self.parser = parser

        self.normalizer = (
            normalizer
            if normalizer is not None
            else SecurityEventNormalizer()
        )

    def process(
        self,
        raw_record: str,
        **parser_kwargs: Any,
    ) -> SecurityEvent | None:
        """
        Process one raw log record.

        Returns:
            SecurityEvent if the parser recognizes the record.
            None if the parser intentionally ignores the record.
        """

        raw_event = self.parser.parse(
            raw_record,
            **parser_kwargs,
        )

        if raw_event is None:
            return None

        return self.normalizer.normalize(
            raw_event
        )

    def process_batch(
        self,
        raw_records: list[str],
        **parser_kwargs: Any,
    ) -> list[SecurityEvent]:
        """
        Process multiple raw log records.

        Unrecognized records are skipped.
        Recognized records are normalized into SecurityEvents.
        """

        if not isinstance(
            raw_records,
            list,
        ):
            raise TypeError(
                "raw_records must be a list."
            )

        events: list[SecurityEvent] = []

        for raw_record in raw_records:
            event = self.process(
                raw_record,
                **parser_kwargs,
            )

            if event is not None:
                events.append(event)

        return events