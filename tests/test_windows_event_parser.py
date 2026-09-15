from datetime import datetime, timezone

import pytest

from ingestion.parsers.windows_event_parser import WindowsEventParser


@pytest.fixture
def parser():
    return WindowsEventParser()


def test_successful_logon_4624(parser):
    line = (
        "EventID=4624 "
        "TimeCreated=2018-02-14T10:30:15Z "
        "IpAddress=192.168.1.50 "
        "IpPort=54321 "
        "TargetUserName=admin "
        "TargetDomainName=UNIVERSITY"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["windows_event_id"] == 4624
    assert event["event_type"] == "logon_success"

    assert event["timestamp"] == datetime(
        2018,
        2,
        14,
        10,
        30,
        15,
        tzinfo=timezone.utc,
    )

    assert event["src_ip"] == "192.168.1.50"
    assert event["src_port"] == 54321
    assert event["username"] == "admin"
    assert event["domain"] == "UNIVERSITY"

    assert event["binary_prediction"] == 0
    assert event["attack_family"] == "Benign"
    assert event["confidence"] == 0.0


def test_failed_logon_4625(parser):
    line = (
        "EventID=4625 "
        "TimeCreated=2018-02-14T10:31:20Z "
        "IpAddress=10.0.0.25 "
        "IpPort=44444 "
        "TargetUserName=hacker "
        "TargetDomainName=UNIVERSITY"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["windows_event_id"] == 4625
    assert event["event_type"] == "logon_failure"
    assert event["src_ip"] == "10.0.0.25"
    assert event["src_port"] == 44444
    assert event["username"] == "hacker"


def test_logoff_4634(parser):
    line = (
        "EventID=4634 "
        "TimeCreated=2018-02-14T10:32:10Z "
        "TargetUserName=alice"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["windows_event_id"] == 4634
    assert event["event_type"] == "logoff"
    assert event["username"] == "alice"


def test_explicit_credentials_4648(parser):
    line = (
        "EventID=4648 "
        "TimeCreated=2018-02-14T10:33:05Z "
        "TargetUserName=admin "
        "TargetDomainName=UNIVERSITY"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["windows_event_id"] == 4648
    assert (
        event["event_type"]
        == "explicit_credential_logon"
    )
    assert event["username"] == "admin"


def test_special_privilege_4672(parser):
    line = (
        "EventID=4672 "
        "TimeCreated=2018-02-14T10:34:05Z "
        "TargetUserName=administrator "
        "TargetDomainName=UNIVERSITY"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["windows_event_id"] == 4672
    assert (
        event["event_type"]
        == "special_privilege_assigned"
    )
    assert event["username"] == "administrator"


def test_process_creation_4688(parser):
    line = (
        "EventID=4688 "
        "TimeCreated=2018-02-14T10:35:05Z "
        "NewProcessName=C:\\Windows\\System32\\cmd.exe "
        "TargetUserName=admin"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["windows_event_id"] == 4688
    assert event["event_type"] == "process_creation"
    assert (
        event["process_name"]
        == r"C:\Windows\System32\cmd.exe"
    )


def test_missing_source_ip_is_allowed(parser):
    line = (
        "EventID=4625 "
        "TimeCreated=2018-02-14T10:36:05Z "
        "IpAddress=- "
        "TargetUserName=admin"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["src_ip"] is None
    assert event["username"] == "admin"


def test_unsupported_event_id_returns_none(parser):
    line = (
        "EventID=9999 "
        "TimeCreated=2018-02-14T10:37:05Z "
        "TargetUserName=admin"
    )

    event = parser.parse(line)

    assert event is None


def test_missing_event_id_returns_none(parser):
    line = (
        "TimeCreated=2018-02-14T10:38:05Z "
        "TargetUserName=admin"
    )

    event = parser.parse(line)

    assert event is None


def test_missing_timestamp_raises_error(parser):
    line = (
        "EventID=4625 "
        "IpAddress=10.0.0.25 "
        "TargetUserName=admin"
    )

    with pytest.raises(ValueError):
        parser.parse(line)


def test_invalid_timestamp_raises_error(parser):
    line = (
        "EventID=4625 "
        "TimeCreated=not-a-timestamp "
        "IpAddress=10.0.0.25"
    )

    with pytest.raises(ValueError):
        parser.parse(line)


def test_empty_line_returns_none(parser):
    assert parser.parse("") is None
    assert parser.parse("   ") is None


def test_invalid_input_type(parser):
    with pytest.raises(TypeError):
        parser.parse(123)


def test_event_id_is_deterministic(parser):
    line = (
        "EventID=4625 "
        "TimeCreated=2018-02-14T10:31:20Z "
        "IpAddress=10.0.0.25 "
        "IpPort=44444 "
        "TargetUserName=hacker"
    )

    event1 = parser.parse(line)
    event2 = parser.parse(line)

    assert event1["event_id"] == event2["event_id"]