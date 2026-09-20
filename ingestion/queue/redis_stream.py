import json
import os
from typing import Any, Iterator

import redis


class RedisEventQueue:
    """
    Redis Streams based event queue.

    Converts SecurityEvent-like objects into JSON-safe
    dictionaries and publishes them to a Redis Stream.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        stream_name: str | None = None,
    ) -> None:
        redis_url = (
            redis_url
            if redis_url is not None
            else os.getenv("REDIS_URL")
        )

        stream_name = (
            stream_name
            if stream_name is not None
            else os.getenv(
                "REDIS_STREAM_NAME",
                "security_events",
            )
        )

        if not redis_url:
            raise RuntimeError(
                "REDIS_URL environment variable is not configured."
            )
        if not isinstance(redis_url, str) or not redis_url.strip():
            raise ValueError("redis_url must be a non-empty string.")

        if not isinstance(stream_name, str) or not stream_name.strip():
            raise ValueError("stream_name must be a non-empty string.")

        self.redis_url = redis_url
        self.stream_name = stream_name

        self.client = redis.Redis.from_url(
            self.redis_url,
            decode_responses=True,
        )

    def ping(self) -> bool:
        """
        Check whether Redis is reachable.
        """
        return bool(self.client.ping())

    def publish(self, event: Any) -> str:
        """
        Publish an event to the Redis Stream.

        The event must provide a to_dict() method.
        """

        if event is None:
            raise ValueError("event cannot be None.")

        if not hasattr(event, "to_dict"):
            raise TypeError(
                "event must provide a to_dict() method."
            )

        event_data = event.to_dict()

        if not isinstance(event_data, dict):
            raise TypeError(
                "event.to_dict() must return a dictionary."
            )

        payload = json.dumps(
            event_data,
            default=str,
        )

        message_id = self.client.xadd(
            self.stream_name,
            {
                "event": payload,
            },
        )

        return str(message_id)

    def publish_batch(self, events: list[Any]) -> list[str]:
        """
        Publish multiple events to the Redis Stream.
        """

        if not isinstance(events, list):
            raise TypeError("events must be a list.")

        message_ids: list[str] = []

        for event in events:
            message_ids.append(self.publish(event))

        return message_ids

    def read(
        self,
        last_id: str = "0-0",
        count: int = 10,
    ) -> list[tuple[str, dict[str, Any]]]:
        """
        Read events from the Redis Stream.

        Parameters
        ----------
        last_id:
            Redis message ID to read after.
            Use "0-0" to read from the beginning.

        count:
            Maximum number of messages to return.

        Returns
        -------
        list
            A list of (message_id, event_data) tuples.
        """

        if not isinstance(last_id, str) or not last_id.strip():
            raise ValueError(
                "last_id must be a non-empty string."
            )

        if not isinstance(count, int) or count <= 0:
            raise ValueError(
                "count must be a positive integer."
            )

        messages = self.client.xread(
            {self.stream_name: last_id},
            count=count,
            
        )

        events: list[tuple[str, dict[str, Any]]] = []

        for _, stream_messages in messages:
            for message_id, fields in stream_messages:
                raw_event = fields.get("event")

                if raw_event is None:
                    continue

                event_data = json.loads(raw_event)

                if not isinstance(event_data, dict):
                    raise TypeError(
                        "Stored event payload must be a dictionary."
                    )

                events.append(
                    (
                        str(message_id),
                        event_data,
                    )
                )

        return events

    def read_new(
        self,
        last_id: str = "$",
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[tuple[str, dict[str, Any]]]:
        """
        Read new events arriving after last_id.

        The default "$" means only messages added after the
        call begins are returned.

        block_ms controls how long Redis waits for new events.
        """

        if not isinstance(last_id, str) or not last_id.strip():
            raise ValueError(
                "last_id must be a non-empty string."
            )

        if not isinstance(count, int) or count <= 0:
            raise ValueError(
                "count must be a positive integer."
            )

        if not isinstance(block_ms, int) or block_ms < 0:
            raise ValueError(
                "block_ms must be a non-negative integer."
            )

        messages = self.client.xread(
            {self.stream_name: last_id},
            count=count,
            block=block_ms,
        )

        events: list[tuple[str, dict[str, Any]]] = []

        for _, stream_messages in messages:
            for message_id, fields in stream_messages:
                raw_event = fields.get("event")

                if raw_event is None:
                    continue

                event_data = json.loads(raw_event)

                if not isinstance(event_data, dict):
                    raise TypeError(
                        "Stored event payload must be a dictionary."
                    )

                events.append(
                    (
                        str(message_id),
                        event_data,
                    )
                )

        return events

    def length(self) -> int:
        """
        Return the current number of messages in the stream.
        """
        return int(
            self.client.xlen(self.stream_name)
        )

    def clear(self) -> int:
        """
        Delete the stream.

        Returns 1 when the stream existed and was deleted,
        otherwise 0.
        """
        return int(
            self.client.delete(self.stream_name)
        )