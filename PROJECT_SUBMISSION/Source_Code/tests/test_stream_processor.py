from pathlib import Path

import pytest

from correlation.schema import SecurityEvent
from ingestion.event_router import EventRouter
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.source_ingestor import SourceIngestor
from ingestion.stream_processor import StreamProcessor


def create_log_file(tmp_path: Path) -> Path:
    log_file = tmp_path / "linux_auth.log"

    log_file.write_text(
        "\n".join(
            [
                "Mar 10 10:15:30 server sshd[1234]: Failed password for admin from 192.168.1.10 port 54321 ssh2",
                "Mar 10 10:15:31 server sshd[1235]: Failed password for invalid user root from 192.168.1.20 port 54322 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    return log_file


def create_processor(tmp_path: Path) -> StreamProcessor:
    log_file = create_log_file(tmp_path)

    source_ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    event_router = EventRouter()

    return StreamProcessor(
        source_ingestor=source_ingestor,
        event_router=event_router,
    )


def test_stream_processor_requires_source_ingestor():
    router = EventRouter()

    with pytest.raises(TypeError):
        StreamProcessor(
            source_ingestor=None,
            event_router=router,
        )


def test_stream_processor_requires_event_router(tmp_path):
    log_file = create_log_file(tmp_path)

    source_ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    with pytest.raises(TypeError):
        StreamProcessor(
            source_ingestor=source_ingestor,
            event_router=None,
        )


def test_stream_processor_process_batch(tmp_path):
    processor = create_processor(tmp_path)

    events = processor.source_ingestor.ingest(
        year=2026,
    )

    processed = processor.process_batch(events)

    assert len(processed) == 2

    assert all(
        isinstance(event, SecurityEvent)
        for event in processed
    )


def test_stream_processor_preserves_event_order(tmp_path):
    processor = create_processor(tmp_path)

    events = processor.source_ingestor.ingest(
        year=2026,
    )

    processed = processor.process_batch(events)

    assert processed[0].username == "admin"
    assert processed[1].username == "root"


def test_stream_processor_routes_events_to_handler(tmp_path):
    processor = create_processor(tmp_path)

    received = []

    def handler(event):
        received.append(event)

    processor.event_router.register(
        "test_handler",
        handler,
    )

    events = processor.source_ingestor.ingest(
        year=2026,
    )

    processed = processor.process_batch(events)

    assert len(processed) == 2
    assert len(received) == 2

    assert received[0].event_id == processed[0].event_id
    assert received[1].event_id == processed[1].event_id


def test_stream_processor_rejects_invalid_batch(tmp_path):
    processor = create_processor(tmp_path)

    with pytest.raises(TypeError):
        processor.process_batch("not-a-list")


def test_stream_processor_rejects_invalid_event(tmp_path):
    processor = create_processor(tmp_path)

    with pytest.raises(TypeError):
        processor.process_batch(
            ["not-a-security-event"]
        )


def test_stream_processor_empty_batch(tmp_path):
    processor = create_processor(tmp_path)

    processed = processor.process_batch([])

    assert processed == []