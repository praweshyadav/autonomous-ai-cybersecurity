from datetime import datetime, timezone

from correlation.schema import SecurityEvent
from ingestion.normalizer import SecurityEventNormalizer
from ingestion.parsers.windows_event_parser import WindowsEventParser


def test_windows_failed_logon_to_security_event():
    log_line = (
        "EventID=4625 "
        "TimeCreated=2018-02-14T10:30:15Z "
        "IpAddress=192.168.1.50 "
        "IpPort=54321 "
        "TargetUserName=admin "
        "TargetDomainName=UNIVERSITY"
    )

    parser = WindowsEventParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    assert raw_event is not None

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.event_id.startswith(
        "WINDOWS-4625-"
    )

    assert event.timestamp == datetime(
        2018,
        2,
        14,
        10,
        30,
        15,
        tzinfo=timezone.utc,
    )

    assert event.src_ip == "192.168.1.50"
    assert event.src_port == 54321

    assert event.binary_prediction == 0
    assert event.attack_family == "Benign"
    assert event.confidence == 0.0

    assert event.source_file == (
        "windows_security.log"
    )


def test_windows_successful_logon_to_security_event():
    log_line = (
        "EventID=4624 "
        "TimeCreated=2018-02-14T10:31:20Z "
        "IpAddress=10.0.0.10 "
        "IpPort=2222 "
        "TargetUserName=alice "
        "TargetDomainName=UNIVERSITY"
    )

    parser = WindowsEventParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.src_ip == "10.0.0.10"
    assert event.src_port == 2222


def test_windows_process_creation_to_security_event():
    log_line = (
        "EventID=4688 "
        "TimeCreated=2018-02-14T10:32:10Z "
        r"NewProcessName=C:\Windows\System32\cmd.exe "
        "TargetUserName=admin"
    )

    parser = WindowsEventParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.event_id.startswith(
        "WINDOWS-4688-"
    )

    assert event.timestamp == datetime(
        2018,
        2,
        14,
        10,
        32,
        10,
        tzinfo=timezone.utc,
    )


def test_windows_identity_is_preserved():
    log_line = (
        "EventID=4625 "
        "TimeCreated=2018-02-14T10:33:05Z "
        "IpAddress=172.16.0.20 "
        "IpPort=5555 "
        "TargetUserName=test"
    )

    parser = WindowsEventParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    event = normalizer.normalize(raw_event)

    assert event.event_id == raw_event["event_id"]
    assert event.timestamp == raw_event["timestamp"]
    assert event.src_ip == raw_event["src_ip"]
    assert event.src_port == raw_event["src_port"]