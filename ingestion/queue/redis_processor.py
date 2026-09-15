from typing import Any

from correlation.schema import SecurityEvent
from ingestion.event_router import EventRouter
from ingestion.queue.event_deserializer import SecurityEventDeserializer
from ingestion.queue.redis_consumer import RedisStreamConsumer


class RedisStreamProcessor:
    """
    Connects Redis Stream consumption to the existing EventRouter.

    Flow:

        Redis Stream
             ↓
        RedisStreamConsumer
             ↓
        SecurityEventDeserializer
             ↓
        SecurityEvent
             ↓
        EventRouter
             ↓
        Detection / Correlation / Other handlers
    """

    def __init__(
        self,
        consumer: RedisStreamConsumer,
        event_router: EventRouter,
        deserializer: SecurityEventDeserializer | None = None,
    ) -> None:
        if not isinstance(
            consumer,
            RedisStreamConsumer,
        ):
            raise TypeError(
                "consumer must be a RedisStreamConsumer."
            )

        if not isinstance(
            event_router,
            EventRouter,
        ):
            raise TypeError(
                "event_router must be an EventRouter."
            )

        if deserializer is not None and not isinstance(
            deserializer,
            SecurityEventDeserializer,
        ):
            raise TypeError(
                "deserializer must be a SecurityEventDeserializer."
            )

        self.consumer = consumer
        self.event_router = event_router
        self.deserializer = (
            deserializer
            if deserializer is not None
            else SecurityEventDeserializer()
        )

    def process_batch(
        self,
        count: int = 10,
    ) -> list[SecurityEvent]:
        """
        Consume a batch of Redis events, deserialize them,
        and route them through the EventRouter.

        Returns the SecurityEvents that were processed.
        """

        messages = self.consumer.read_batch(
            count=count
        )

        if not messages:
            return []

        event_data = [
            data
            for _, data in messages
        ]

        events = self.deserializer.deserialize_batch(
            event_data
        )

        self.event_router.route_batch(events)

        return events