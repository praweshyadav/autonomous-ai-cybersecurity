from datetime import datetime

import pytest

from ingestion.parsers.linux_auth_parser import LinuxAuthParser


@pytest.fixture
def parser():
    return LinuxAuthParser()


def test_failed_password(parser):
    line = (
        "Feb 14 10:30:15 server "
        "sshd[1234]: Failed password for admin "
        "from 192.168.1.50 port 54321 ssh2"
    )

    event = parser.parse(line, year=2018)

    assert event is not None
    assert event["timestamp"] == datetime(
        2018, 2, 14, 10, 30, 15
    )
    assert event["src_ip"] == "192.168.1.50"
    assert event["src_port"] == 54321
    assert event["dst_port"] == 22
    assert event["protocol"] == 6
    assert event["username"] == "admin"
    assert event["event_type"] == "authentication_failure"
    assert event["invalid_user"] is False


def test_failed_password_invalid_user(parser):
    line = (
        "Feb 14 10:31:20 server "
        "sshd[1235]: Failed password for invalid user hacker "
        "from 10.0.0.25 port 44444 ssh2"
    )

    event = parser.parse(line, year=2018)

    assert event is not None
    assert event["src_ip"] == "10.0.0.25"
    assert event["src_port"] == 44444
    assert event["username"] == "hacker"
    assert event["event_type"] == "authentication_failure"
    assert event["invalid_user"] is True


def test_accepted_password(parser):
    line = (
        "Feb 14 10:32:10 server "
        "sshd[1236]: Accepted password for alice "
        "from 10.0.0.10 port 2222 ssh2"
    )

    event = parser.parse(line, year=2018)

    assert event is not None
    assert event["src_ip"] == "10.0.0.10"
    assert event["src_port"] == 2222
    assert event["dst_port"] == 22
    assert event["username"] == "alice"
    assert event["event_type"] == "authentication_success"
    assert event["invalid_user"] is False


def test_invalid_user(parser):
    line = (
        "Feb 14 10:33:05 server "
        "sshd[1237]: Invalid user test "
        "from 172.16.0.20 port 5555"
    )

    event = parser.parse(line, year=2018)

    assert event is not None
    assert event["src_ip"] == "172.16.0.20"
    assert event["src_port"] == 5555
    assert event["username"] == "test"
    assert event["event_type"] == "invalid_user"
    assert event["invalid_user"] is True


def test_unrecognized_line_returns_none(parser):
    line = (
        "Feb 14 10:40:00 server "
        "systemd[1]: Started some service."
    )

    event = parser.parse(line, year=2018)

    assert event is None


def test_empty_line_returns_none(parser):
    assert parser.parse("", year=2018) is None
    assert parser.parse("   ", year=2018) is None


def test_invalid_input_type(parser):
    with pytest.raises(TypeError):
        parser.parse(123, year=2018)


def test_invalid_timestamp(parser):
    line = (
        "invalid timestamp "
        "sshd[1234]: Failed password for admin "
        "from 192.168.1.50 port 54321 ssh2"
    )

    with pytest.raises(ValueError):
        parser.parse(line, year=2018)


def test_deterministic_event_id(parser):
    line = (
        "Feb 14 10:30:15 server "
        "sshd[1234]: Failed password for admin "
        "from 192.168.1.50 port 54321 ssh2"
    )

    event1 = parser.parse(line, year=2018)
    event2 = parser.parse(line, year=2018)

    assert event1["event_id"] == event2["event_id"]