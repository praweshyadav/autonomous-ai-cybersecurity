from correlation.schema import SecurityEvent
from ingestion.pipeline import IngestionPipeline
from ingestion.parsers.firewall_parser import FirewallParser
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.parsers.windows_event_parser import WindowsEventParser


def test_linux_pipeline():
    log_line = (
        "Feb 14 10:30:15 server "
        "sshd[1234]: Failed password for admin "
        "from 192.168.1.50 port 54321 ssh2"
    )

    pipeline = IngestionPipeline(
        parser=LinuxAuthParser()
    )

    event = pipeline.process(
        log_line,
        year=2018,
    )

    assert isinstance(event, SecurityEvent)
    assert event.src_ip == "192.168.1.50"
    assert event.src_port == 54321
    assert event.dst_port == 22
    assert event.protocol == 6


def test_windows_pipeline():
    log_line = (
        "EventID=4625 "
        "TimeCreated=2018-02-14T10:31:20Z "
        "IpAddress=10.0.0.25 "
        "IpPort=44444 "
        "TargetUserName=hacker"
    )

    pipeline = IngestionPipeline(
        parser=WindowsEventParser()
    )

    event = pipeline.process(
        log_line
    )

    assert isinstance(event, SecurityEvent)
    assert event.src_ip == "10.0.0.25"
    assert event.src_port == 44444


def test_firewall_pipeline():
    log_line = (
        "Timestamp=2018-02-14T10:32:10Z "
        "SrcIP=192.168.1.20 "
        "SrcPort=50000 "
        "DstIP=10.0.0.20 "
        "DstPort=443 "
        "Protocol=TCP "
        "Action=DENY"
    )

    pipeline = IngestionPipeline(
        parser=FirewallParser()
    )

    event = pipeline.process(
        log_line
    )

    assert isinstance(event, SecurityEvent)
    assert event.src_ip == "192.168.1.20"
    assert event.src_port == 50000
    assert event.dst_ip == "10.0.0.20"
    assert event.dst_port == 443
    assert event.protocol == 6


def test_unrecognized_log_returns_none():
    log_line = (
        "Feb 14 10:40:00 server "
        "systemd[1]: Started some service."
    )

    pipeline = IngestionPipeline(
        parser=LinuxAuthParser()
    )

    event = pipeline.process(
        log_line,
        year=2018,
    )

    assert event is None


def test_batch_processing():
    records = [
        (
            "Feb 14 10:30:15 server "
            "sshd[1234]: Failed password for admin "
            "from 192.168.1.50 port 54321 ssh2"
        ),
        (
            "Feb 14 10:31:15 server "
            "sshd[1235]: Accepted password for alice "
            "from 10.0.0.10 port 2222 ssh2"
        ),
        (
            "Feb 14 10:40:00 server "
            "systemd[1]: Started some service."
        ),
    ]

    pipeline = IngestionPipeline(
        parser=LinuxAuthParser()
    )

    events = pipeline.process_batch(
        records,
        year=2018,
    )

    assert len(events) == 2

    assert all(
        isinstance(event, SecurityEvent)
        for event in events
    )

    assert events[0].src_ip == "192.168.1.50"
    assert events[1].src_ip == "10.0.0.10"


def test_empty_batch():
    pipeline = IngestionPipeline(
        parser=LinuxAuthParser()
    )

    events = pipeline.process_batch([])

    assert events == []


def test_pipeline_rejects_invalid_parser():
    try:
        IngestionPipeline(parser=object())
        assert False
    except TypeError:
        assert True


def test_pipeline_rejects_none_parser():
    try:
        IngestionPipeline(parser=None)
        assert False
    except ValueError:
        assert True