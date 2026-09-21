from datetime import datetime
from zoneinfo import ZoneInfo

from correlation.schema import SecurityEvent
from ingestion.normalizer import SecurityEventNormalizer
from ingestion.parsers.linux_auth_parser import LinuxAuthParser


def test_linux_auth_parser_to_security_event():
    log_line = (
        "Feb 14 10:30:15 server "
        "sshd[1234]: Failed password for admin "
        "from 192.168.1.50 port 54321 ssh2"
    )

    parser = LinuxAuthParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(
        log_line,
        year=2018,
    )

    assert raw_event is not None

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.event_id.startswith(
        "LINUX-AUTH-"
    )

    assert event.timestamp == datetime(
        2018,
        2,
        14,
        10,
        30,
        15,
        tzinfo=ZoneInfo("Asia/Kolkata"),
    )

    assert event.src_ip == "192.168.1.50"
    assert event.src_port == 54321
    assert event.dst_port == 22
    assert event.protocol == 6

    assert event.binary_prediction == 0
    assert event.attack_family == "Benign"
    assert event.confidence == 0.0

    assert event.source_file == "linux_auth.log"


def test_linux_invalid_user_to_security_event():
    log_line = (
        "Feb 14 10:31:20 server "
        "sshd[1235]: Failed password for invalid user hacker "
        "from 10.0.0.25 port 44444 ssh2"
    )

    parser = LinuxAuthParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(
        log_line,
        year=2018,
    )

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.src_ip == "10.0.0.25"
    assert event.src_port == 44444
    assert event.dst_port == 22
    assert event.protocol == 6


def test_linux_successful_login_to_security_event():
    log_line = (
        "Feb 14 10:32:10 server "
        "sshd[1236]: Accepted password for alice "
        "from 10.0.0.10 port 2222 ssh2"
    )

    parser = LinuxAuthParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(
        log_line,
        year=2018,
    )

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.src_ip == "10.0.0.10"
    assert event.src_port == 2222
    assert event.dst_port == 22
    assert event.protocol == 6


def test_parser_and_normalizer_preserve_event_identity():
    log_line = (
        "Feb 14 10:33:05 server "
        "sshd[1237]: Invalid user test "
        "from 172.16.0.20 port 5555"
    )

    parser = LinuxAuthParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(
        log_line,
        year=2018,
    )

    event = normalizer.normalize(raw_event)

    assert event.event_id == raw_event["event_id"]
    assert event.timestamp == raw_event["timestamp"]
    assert event.src_ip == raw_event["src_ip"]
    assert event.src_port == raw_event["src_port"]
    assert event.dst_port == raw_event["dst_port"]
    assert event.protocol == raw_event["protocol"]