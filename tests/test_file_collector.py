from pathlib import Path

import pytest

from ingestion.collectors.file_collector import FileCollector


def test_collect_reads_non_empty_lines(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "line one\n"
        "\n"
        "line two\n"
        "   \n"
        "line three\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    records = list(collector.collect())

    assert records == [
        "line one",
        "line two",
        "line three",
    ]


def test_collect_preserves_record_order(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "first\n"
        "second\n"
        "third\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    records = list(collector.collect())

    assert records == [
        "first",
        "second",
        "third",
    ]


def test_collect_batch_without_limit(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "one\n"
        "two\n"
        "three\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    records = collector.collect_batch()

    assert records == [
        "one",
        "two",
        "three",
    ]


def test_collect_batch_with_limit(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "one\n"
        "two\n"
        "three\n"
        "four\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    records = collector.collect_batch(
        limit=2
    )

    assert records == [
        "one",
        "two",
    ]


def test_collect_empty_file(tmp_path):
    log_file = tmp_path / "empty.log"

    log_file.write_text(
        "",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    assert list(collector.collect()) == []
    assert collector.collect_batch() == []


def test_missing_file_raises_error(tmp_path):
    log_file = tmp_path / "missing.log"

    collector = FileCollector(log_file)

    with pytest.raises(FileNotFoundError):
        list(collector.collect())


def test_missing_file_batch_raises_error(tmp_path):
    log_file = tmp_path / "missing.log"

    collector = FileCollector(log_file)

    with pytest.raises(FileNotFoundError):
        collector.collect_batch()


def test_directory_path_is_rejected(tmp_path):
    collector = FileCollector(tmp_path)

    with pytest.raises(ValueError):
        list(collector.collect())


def test_zero_limit_is_rejected(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "line\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    with pytest.raises(ValueError):
        collector.collect_batch(limit=0)


def test_negative_limit_is_rejected(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "line\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    with pytest.raises(ValueError):
        collector.collect_batch(limit=-1)


def test_empty_path_is_rejected():
    with pytest.raises(ValueError):
        FileCollector("")


def test_collector_returns_iterator(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "line one\n"
        "line two\n",
        encoding="utf-8",
    )

    collector = FileCollector(log_file)

    records = collector.collect()

    assert hasattr(
        records,
        "__iter__",
    )

    assert list(records) == [
        "line one",
        "line two",
    ]