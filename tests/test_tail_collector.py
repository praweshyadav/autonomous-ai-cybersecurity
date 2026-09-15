import threading
import time

import pytest

from ingestion.collectors.tail_collector import TailCollector


def test_tail_collector_requires_file_path():
    with pytest.raises(ValueError):
        TailCollector("")


def test_tail_collector_requires_positive_poll_interval(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text("initial\n", encoding="utf-8")

    with pytest.raises(ValueError):
        TailCollector(
            log_file,
            poll_interval=0,
        )


def test_tail_collector_rejects_missing_file(tmp_path):
    log_file = tmp_path / "missing.log"

    collector = TailCollector(log_file)

    with pytest.raises(FileNotFoundError):
        next(collector.collect())


def test_tail_collector_rejects_directory(tmp_path):
    collector = TailCollector(tmp_path)

    with pytest.raises(ValueError):
        next(collector.collect())


def test_tail_collector_reads_existing_lines(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "event one\n\n event two \n",
        encoding="utf-8",
    )

    collector = TailCollector(
        log_file,
        poll_interval=0.01,
        start_at_end=False,
    )

    records = collector.collect()

    assert next(records) == "event one"
    assert next(records) == "event two"


def test_tail_collector_waits_for_new_lines(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "old event\n",
        encoding="utf-8",
    )

    collector = TailCollector(
        log_file,
        poll_interval=0.01,
        start_at_end=True,
    )

    records = collector.collect()

    received = []

    def consume():
        received.append(next(records))

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
        file.write("new event\n")
        file.flush()

    thread.join(timeout=1)

    assert received == ["new event"]


def test_tail_collector_skips_empty_lines(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "old event\n",
        encoding="utf-8",
    )

    collector = TailCollector(
        log_file,
        poll_interval=0.01,
        start_at_end=True,
    )

    records = collector.collect()

    received = []

    def consume():
        received.append(next(records))

    thread = threading.Thread(
        target=consume,
        daemon=True,
    )

    thread.start()

    time.sleep(0.05)

    with log_file.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write("\n")
        file.write("   \n")
        file.write("actual event\n")
        file.flush()

    thread.join(timeout=1)

    assert received == ["actual event"]