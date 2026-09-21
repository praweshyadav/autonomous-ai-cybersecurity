from __future__ import annotations

import os

from ingestion.collectors.tail_collector import TailCollector
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.pipeline import IngestionPipeline
from ingestion.queue.redis_stream import RedisEventQueue


def load_env() -> None:
    env_path = ".env"

    if not os.path.exists(env_path):
        return

    with open(env_path, "r", encoding="utf-8") as env_file:
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


def main() -> None:
    load_env()

    log_path = os.getenv(
        "LINUX_AUTH_LOG_PATH",
        r"C:\Users\KIIT0001\OneDrive\Desktop\auth-test.log",
    )

    collector = TailCollector(
        file_path=log_path,
        poll_interval=0.5,
        start_at_end=True,
    )

    pipeline = IngestionPipeline(LinuxAuthParser())
    queue = RedisEventQueue()

    print(f"Watching: {log_path}")
    print("Publishing new Linux authentication events to Redis...")
    print("Press Ctrl+C to stop.")

    try:
        for raw_line in collector.collect():
            try:
                event = pipeline.process(raw_line)

                if event is None:
                    continue

                message_id = queue.publish(event)

                print(
                    f"Published | "
                    f"event_id={event.event_id} | "
                    f"type={event.event_type} | "
                    f"src_ip={event.src_ip} | "
                    f"user={event.username} | "
                    f"redis_id={message_id}",
                    flush=True,
                )

            except Exception as exc:
                print(
                    f"Event processing error: {exc}",
                    flush=True,
                )

    except KeyboardInterrupt:
        print("\nLive publisher stopped.")


if __name__ == "__main__":
    main()