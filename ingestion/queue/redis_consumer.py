from typing import Any

from ingestion.queue.redis_stream import RedisEventQueue


class RedisStreamConsumer:
    """
    Consumes events from a Redis Stream.

    The consumer position can be restored from a persisted
    Redis Stream ID so worker restarts do not replay events
    that were already processed.
    """

    def __init__(
        self,
        queue: RedisEventQueue,
        start_id: str = "0-0",
    ) -> None:
        if not isinstance(queue, RedisEventQueue):
            raise TypeError(
                "queue must be a RedisEventQueue."
            )

        if not isinstance(start_id, str) or not start_id:
            raise ValueError(
                "start_id must be a non-empty string."
            )

        self.queue = queue
        self.last_id = start_id

    def read_batch(
        self,
        count: int = 10,
    ) -> list[tuple[str, dict[str, Any]]]:
        """
        Read the next batch of events from the Redis Stream.
        """

        if not isinstance(count, int) or count <= 0:
            raise ValueError(
                "count must be a positive integer."
            )

        messages = self.queue.read(
            last_id=self.last_id,
            count=count,
        )

        return messages

    def acknowledge(
        self,
        message_id: str,
    ) -> None:
        """
        Advance the consumer position after successful processing.
        """

        if not isinstance(message_id, str) or not message_id:
            raise ValueError(
                "message_id must be a non-empty string."
            )

        self.last_id = message_id

    def reset(self) -> None:
        """
        Reset the consumer position to the beginning
        of the Redis Stream.
        """

        self.last_id = "0-0"
