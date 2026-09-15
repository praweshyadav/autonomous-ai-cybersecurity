from typing import Any

from ingestion.queue.redis_stream import RedisEventQueue


class RedisStreamConsumer:
    """
    Consumes events from a Redis Stream.

    This class is responsible only for reading events from Redis.
    Processing, detection, and correlation will be connected later.
    """

    def __init__(
        self,
        queue: RedisEventQueue,
    ) -> None:
        if not isinstance(queue, RedisEventQueue):
            raise TypeError(
                "queue must be a RedisEventQueue."
            )

        self.queue = queue
        self.last_id = "0-0"

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

        if messages:
            self.last_id = messages[-1][0]

        return messages

    def reset(self) -> None:
        """
        Reset the consumer position to the beginning
        of the Redis Stream.
        """

        self.last_id = "0-0"