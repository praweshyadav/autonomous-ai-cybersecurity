from __future__ import annotations

import os
import time
from pathlib import Path

from app.composition import build_event_router
from ingestion.event_router import EventRouter
from ingestion.queue.redis_consumer import RedisStreamConsumer
from ingestion.queue.redis_processor import RedisStreamProcessor
from ingestion.queue.redis_stream import RedisEventQueue


CHECKPOINT_PATH = Path(
    "data/runtime/redis_worker_checkpoint.txt"
)


def load_env() -> None:
    """Load local .env values when they are not already present."""

    env_path = ".env"

    if not os.path.exists(env_path):
        return

    with open(
        env_path,
        "r",
        encoding="utf-8",
    ) as env_file:
        for raw_line in env_file:
            line = raw_line.strip()

            if (
                not line
                or line.startswith("#")
                or "=" not in line
            ):
                continue

            key, value = line.split("=", 1)

            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if key and key not in os.environ:
                os.environ[key] = value


def load_checkpoint() -> str:
    """
    Load the last successfully processed Redis message ID.

    If no checkpoint exists, start from the beginning of the
    existing Redis stream.
    """

    if not CHECKPOINT_PATH.exists():
        return "0-0"

    checkpoint = CHECKPOINT_PATH.read_text(
        encoding="utf-8"
    ).strip()

    if not checkpoint:
        return "0-0"

    return checkpoint


def save_checkpoint(
    message_id: str,
) -> None:
    """
    Persist the last successfully processed Redis message ID.
    """

    CHECKPOINT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = CHECKPOINT_PATH.with_suffix(
        ".tmp"
    )

    temporary_path.write_text(
        message_id,
        encoding="utf-8",
    )

    temporary_path.replace(
        CHECKPOINT_PATH
    )


def build_processor() -> RedisStreamProcessor:
    """Build the production Redis ? EventRouter processor."""

    queue = RedisEventQueue()

    start_id = load_checkpoint()

    consumer = RedisStreamConsumer(
        queue=queue,
        start_id=start_id,
    )

    router: EventRouter = build_event_router()

    processor = RedisStreamProcessor(
        consumer=consumer,
        event_router=router,
    )

    print(
        f"Redis checkpoint: {start_id}",
        flush=True,
    )

    return processor


def flush_incident_manager(
    processor: RedisStreamProcessor,
) -> None:
    """Flush any buffered incidents before worker shutdown."""

    incident_manager = processor.event_router._handlers.get(
        "incident_manager"
    )

    if incident_manager is None:
        return

    flush = getattr(
        incident_manager,
        "flush",
        None,
    )

    if not callable(flush):
        return

    incidents = flush()

    if incidents:
        print(
            f"Flushed {len(incidents)} incident(s) before shutdown.",
            flush=True,
        )
    else:
        print(
            "No buffered incidents to flush.",
            flush=True,
        )


def main() -> None:
    """
    Continuously consume Redis events and route them
    through production processing.
    """

    load_env()

    processor = build_processor()

    print(
        "Redis worker started.",
        flush=True,
    )
    print(
        "Handlers:",
        processor.event_router.handler_names(),
        flush=True,
    )
    print(
        "Waiting for Redis events...",
        flush=True,
    )
    print(
        "Press Ctrl+C to stop.",
        flush=True,
    )

    try:
        while True:
            events = processor.process_batch(
                count=10,
            )

            if events:
                message_id = (
                    processor.last_processed_message_id
                )

                if message_id is None:
                    raise RuntimeError(
                        "Processed events without a Redis message ID."
                    )

                processor.consumer.acknowledge(
                    message_id
                )

                save_checkpoint(
                    message_id
                )

                print(
                    f"Checkpoint saved: {message_id}",
                    flush=True,
                )

                print(
                    f"Processed {len(events)} event(s).",
                    flush=True,
                )

                for event in events:
                    print(
                        f"  event_id={event.event_id} "
                        f"| type={event.event_type} "
                        f"| src_ip={event.src_ip}",
                        flush=True,
                    )

            else:
                time.sleep(1.0)

    except KeyboardInterrupt:
        print(
            "\nShutdown requested. Flushing buffered incidents...",
            flush=True,
        )

        flush_incident_manager(
            processor
        )

        print(
            "Redis worker stopped.",
            flush=True,
        )


if __name__ == "__main__":
    main()
