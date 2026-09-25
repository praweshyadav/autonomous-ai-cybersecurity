from pathlib import Path
import threading
import time

import pytest

from correlation.schema import SecurityEvent
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.source_ingestor import SourceIngestor


def create_log_file(tmp_path: Path) -> Path:
    log_file = tmp_path / "linux_auth.log"

    log_file.write_text(
        "\n".join(
            [
                "Mar 10 10:15:30 server sshd[1234]: Failed password for admin from 192.168.1.10 port 54321 ssh2",
                "Mar 10 10:15:31 server sshd[1235]: Failed password for invalid user root from 192.168.1.20 port 54322 ssh2",
                "Mar 10 10:15:32 server sshd[1236]: Accepted password for student from 192.168.1.30 port 54323 ssh2",
            ]
        ),
        encoding="utf-8",
    )

    return log_file


def test_source_ingestor_ingests_complete_file(tmp_path):
    log_file = create_log_file(tmp_path)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    events = ingestor.ingest(year=2026)

    assert len(events) == 3
    assert all(isinstance(event, SecurityEvent) for event in events)


def test_source_ingestor_preserves_event_order(tmp_path):
    log_file = create_log_file(tmp_path)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    events = ingestor.ingest(year=2026)

    assert events[0].username == "admin"
    assert events[1].username == "root"
    assert events[2].username == "student"


def test_source_ingestor_normalizes_linux_fields(tmp_path):
    log_file = create_log_file(tmp_path)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    events = ingestor.ingest(year=2026)

    first_event = events[0]

    assert first_event.src_ip == "192.168.1.10"
    assert first_event.src_port == 54321
    assert first_event.dst_port == 22
    assert first_event.protocol == 6
    assert first_event.event_type == "authentication_failure"
    assert first_event.source_file == "linux_auth.log"


def test_source_ingestor_batch_limit(tmp_path):
    log_file = create_log_file(tmp_path)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    events = ingestor.ingest_batch(
        limit=2,
        year=2026,
    )

    assert len(events) == 2


def test_source_ingestor_batch_limit_preserves_order(tmp_path):
    log_file = create_log_file(tmp_path)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    events = ingestor.ingest_batch(
        limit=2,
        year=2026,
    )

    assert events[0].username == "admin"
    assert events[1].username == "root"


def test_source_ingestor_rejects_invalid_limit(tmp_path):
    log_file = create_log_file(tmp_path)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    with pytest.raises(ValueError):
        ingestor.ingest_batch(
            limit=0,
            year=2026,
        )

    with pytest.raises(ValueError):
        ingestor.ingest_batch(
            limit=-1,
            year=2026,
        )


def test_source_ingestor_rejects_missing_file(tmp_path):
    missing_file = tmp_path / "missing.log"

    ingestor = SourceIngestor(
        file_path=missing_file,
        parser=LinuxAuthParser(),
    )

    with pytest.raises(FileNotFoundError):
        ingestor.ingest(year=2026)


def test_source_ingestor_requires_parser(tmp_path):
    log_file = create_log_file(tmp_path)

    with pytest.raises(ValueError):
        SourceIngestor(
            file_path=log_file,
            parser=None,
        )


def test_source_ingestor_ingest_stream_processes_new_record(
    tmp_path,
):
    log_file = tmp_path / "linux_auth.log"

    log_file.write_text(
        "Mar 10 10:15:30 server sshd[1234]: "
        "Failed password for admin from "
        "192.168.1.10 port 54321 ssh2\n",
        encoding="utf-8",
    )

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=LinuxAuthParser(),
    )

    stream = ingestor.ingest_stream(
        poll_interval=0.01,
        start_at_end=True,
        year=2026,
    )

    received: list[SecurityEvent] = []

    def consume():
        received.append(next(stream))

    thread = threading.Thread(
        target=consume,
        daemon=True,
    )

    thread.start()

    time.sleep(0.05)

    assert received == []

    with log_file.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            "Mar 10 10:15:31 server sshd[1235]: "
            "Failed password for invalid user root from "
            "192.168.1.20 port 54322 ssh2\n"
        )
        file.flush()

    thread.join(timeout=1)

    assert len(received) == 1

    event = received[0]

    assert isinstance(event, SecurityEvent)
    assert event.username == "root"
    assert event.src_ip == "192.168.1.20"
    assert event.src_port == 54322
    assert event.dst_port == 22
    assert event.protocol == 6
    assert event.event_type == "authentication_failure"

    stream.close()