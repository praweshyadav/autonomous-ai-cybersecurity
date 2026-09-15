from typing import Any, Iterator

from correlation.schema import SecurityEvent
from ingestion.event_router import EventRouter
from ingestion.source_ingestor import SourceIngestor


class StreamProcessor:
    """
    Connects the real-time source ingestion stream to the
    event-processing router.

    Flow:

        SourceIngestor
              ↓
        SecurityEvent
              ↓
        EventRouter
              ↓
        Detection / Correlation / Other handlers
    """

    def __init__(
        self,
        source_ingestor: SourceIngestor,
        event_router: EventRouter,
    ):
        if not isinstance(source_ingestor, SourceIngestor):
            raise TypeError(
                "source_ingestor must be a SourceIngestor."
            )

        if not isinstance(event_router, EventRouter):
            raise TypeError(
                "event_router must be an EventRouter."
            )

        self.source_ingestor = source_ingestor
        self.event_router = event_router

    def process_stream(
        self,
        poll_interval: float = 0.5,
        start_at_end: bool = True,
        **parser_kwargs: Any,
    ) -> Iterator[SecurityEvent]:
        """
        Continuously ingest and route SecurityEvents.
        """

        events = self.source_ingestor.ingest_stream(
            poll_interval=poll_interval,
            start_at_end=start_at_end,
            **parser_kwargs,
        )

        for event in events:
            if not isinstance(event, SecurityEvent):
                raise TypeError(
                    "SourceIngestor yielded an invalid event."
                )

            self.event_router.route(event)

            yield event

    def process_batch(
        self,
        events: list[SecurityEvent],
    ) -> list[SecurityEvent]:
        """
        Route an existing batch of SecurityEvents.
        """

        if not isinstance(events, list):
            raise TypeError(
                "events must be a list."
            )

        for event in events:
            if not isinstance(event, SecurityEvent):
                raise TypeError(
                    "all items in events must be SecurityEvent objects."
                )

        if not events:
            return []

        self.event_router.route_batch(events)

        return events