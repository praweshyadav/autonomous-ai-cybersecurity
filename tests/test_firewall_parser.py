from datetime import datetime, timezone

import pytest

from ingestion.parsers.firewall_parser import FirewallParser


@pytest.fixture
def parser():
    return FirewallParser()


def test_tcp_deny_event(parser):
    line = (
        "Timestamp=2018-02-14T10:30:15Z "
        "SrcIP=192.168.1.50 "
        "SrcPort=54321 "
        "DstIP=10.0.0.10 "
        "DstPort=22 "
        "Protocol=TCP "
        "Action=DENY"
    )

    event = parser.parse(line)

    assert event is not None
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
    assert event["dst_ip"] == "10.0.0.10"
    assert event["dst_port"] == 22

    assert event["protocol"] == 6
    assert event["protocol_name"] == "TCP"
    assert event["firewall_action"] == "DENY"
    assert event["event_type"] == "firewall_connection"


def test_udp_allow_event(parser):
    line = (
        "Timestamp=2018-02-14T10:31:20Z "
        "SrcIP=192.168.1.20 "
        "SrcPort=50000 "
        "DstIP=10.0.0.20 "
        "DstPort=53 "
        "Protocol=UDP "
        "Action=ALLOW"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["protocol"] == 17
    assert event["protocol_name"] == "UDP"
    assert event["firewall_action"] == "ALLOW"
    assert event["dst_port"] == 53


def test_icmp_event(parser):
    line = (
        "Timestamp=2018-02-14T10:32:10Z "
        "SrcIP=192.168.1.30 "
        "DstIP=10.0.0.30 "
        "Protocol=ICMP "
        "Action=ACCEPT"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["protocol"] == 1
    assert event["protocol_name"] == "ICMP"
    assert event["firewall_action"] == "ACCEPT"

    assert event["src_port"] is None
    assert event["dst_port"] is None


def test_numeric_protocol(parser):
    line = (
        "Timestamp=2018-02-14T10:33:05Z "
        "SrcIP=10.0.0.1 "
        "SrcPort=1234 "
        "DstIP=10.0.0.2 "
        "DstPort=443 "
        "Protocol=6 "
        "Action=DROP"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["protocol"] == 6
    assert event["firewall_action"] == "DROP"


def test_supported_firewall_actions(parser):
    actions = [
        "ALLOW",
        "ACCEPT",
        "PERMIT",
        "DENY",
        "DROP",
        "REJECT",
        "BLOCK",
    ]

    for action in actions:
        line = (
            "Timestamp=2018-02-14T10:34:05Z "
            "SrcIP=10.0.0.1 "
            "DstIP=10.0.0.2 "
            "Protocol=TCP "
            f"Action={action}"
        )

        event = parser.parse(line)

        assert event is not None
        assert event["firewall_action"] == action


def test_action_is_case_insensitive(parser):
    line = (
        "Timestamp=2018-02-14T10:35:05Z "
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=TCP "
        "Action=deny"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["firewall_action"] == "DENY"


def test_missing_ports_are_allowed(parser):
    line = (
        "Timestamp=2018-02-14T10:36:05Z "
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=ICMP "
        "Action=DENY"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["src_port"] is None
    assert event["dst_port"] is None


def test_missing_action_returns_none(parser):
    line = (
        "Timestamp=2018-02-14T10:37:05Z "
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=TCP"
    )

    event = parser.parse(line)

    assert event is None


def test_unsupported_action_returns_none(parser):
    line = (
        "Timestamp=2018-02-14T10:38:05Z "
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=TCP "
        "Action=UNKNOWN"
    )

    event = parser.parse(line)

    assert event is None


def test_missing_timestamp_raises_error(parser):
    line = (
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=TCP "
        "Action=DENY"
    )

    with pytest.raises(ValueError):
        parser.parse(line)


def test_invalid_timestamp_raises_error(parser):
    line = (
        "Timestamp=not-a-timestamp "
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=TCP "
        "Action=DENY"
    )

    with pytest.raises(ValueError):
        parser.parse(line)


def test_invalid_protocol_raises_error(parser):
    line = (
        "Timestamp=2018-02-14T10:39:05Z "
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=INVALID "
        "Action=DENY"
    )

    with pytest.raises(ValueError):
        parser.parse(line)


def test_missing_source_ip_is_allowed(parser):
    line = (
        "Timestamp=2018-02-14T10:40:05Z "
        "SrcIP=- "
        "DstIP=10.0.0.2 "
        "DstPort=443 "
        "Protocol=TCP "
        "Action=DENY"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["src_ip"] is None
    assert event["dst_ip"] == "10.0.0.2"


def test_invalid_input_type(parser):
    with pytest.raises(TypeError):
        parser.parse(123)


def test_empty_line_returns_none(parser):
    assert parser.parse("") is None
    assert parser.parse("   ") is None


def test_event_id_is_deterministic(parser):
    line = (
        "Timestamp=2018-02-14T10:30:15Z "
        "SrcIP=192.168.1.50 "
        "SrcPort=54321 "
        "DstIP=10.0.0.10 "
        "DstPort=22 "
        "Protocol=TCP "
        "Action=DENY"
    )

    event1 = parser.parse(line)
    event2 = parser.parse(line)

    assert event1["event_id"] == event2["event_id"]


def test_event_id_contains_firewall_prefix(parser):
    line = (
        "Timestamp=2018-02-14T10:41:05Z "
        "SrcIP=10.0.0.1 "
        "DstIP=10.0.0.2 "
        "Protocol=TCP "
        "Action=DENY"
    )

    event = parser.parse(line)

    assert event is not None
    assert event["event_id"].startswith(
        "FIREWALL-"
    )


def test_parser_does_not_perform_detection(parser):
    line = (
        "Timestamp=2018-02-14T10:42:05Z "
        "SrcIP=10.0.0.100 "
        "SrcPort=50000 "
        "DstIP=10.0.0.10 "
        "DstPort=22 "
        "Protocol=TCP "
        "Action=DENY"
    )

    event = parser.parse(line)

    assert event is not None

    assert event["binary_prediction"] == 0
    assert event["attack_family"] == "Benign"
    assert event["confidence"] == 0.0