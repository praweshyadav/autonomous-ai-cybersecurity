from datetime import datetime, timezone

from correlation.schema import SecurityEvent
from ingestion.normalizer import SecurityEventNormalizer
from ingestion.parsers.firewall_parser import FirewallParser


def test_firewall_deny_to_security_event():
    log_line = (
        "Timestamp=2018-02-14T10:30:15Z "
        "SrcIP=192.168.1.50 "
        "SrcPort=54321 "
        "DstIP=10.0.0.10 "
        "DstPort=22 "
        "Protocol=TCP "
        "Action=DENY"
    )

    parser = FirewallParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    assert raw_event is not None

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.event_id.startswith(
        "FIREWALL-"
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
    assert event.dst_ip == "10.0.0.10"
    assert event.dst_port == 22
    assert event.protocol == 6

    assert event.binary_prediction == 0
    assert event.attack_family == "Benign"
    assert event.confidence == 0.0

    assert event.source_file == "firewall.log"


def test_firewall_udp_to_security_event():
    log_line = (
        "Timestamp=2018-02-14T10:31:20Z "
        "SrcIP=192.168.1.20 "
        "SrcPort=50000 "
        "DstIP=10.0.0.20 "
        "DstPort=53 "
        "Protocol=UDP "
        "Action=ALLOW"
    )

    parser = FirewallParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.src_ip == "192.168.1.20"
    assert event.src_port == 50000
    assert event.dst_ip == "10.0.0.20"
    assert event.dst_port == 53
    assert event.protocol == 17


def test_firewall_icmp_to_security_event():
    log_line = (
        "Timestamp=2018-02-14T10:32:10Z "
        "SrcIP=192.168.1.30 "
        "DstIP=10.0.0.30 "
        "Protocol=ICMP "
        "Action=DROP"
    )

    parser = FirewallParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    event = normalizer.normalize(raw_event)

    assert isinstance(event, SecurityEvent)

    assert event.src_ip == "192.168.1.30"
    assert event.dst_ip == "10.0.0.30"
    assert event.protocol == 1
    assert event.src_port is None
    assert event.dst_port is None


def test_firewall_identity_is_preserved():
    log_line = (
        "Timestamp=2018-02-14T10:33:05Z "
        "SrcIP=172.16.0.20 "
        "SrcPort=5555 "
        "DstIP=10.0.0.2 "
        "DstPort=443 "
        "Protocol=TCP "
        "Action=REJECT"
    )

    parser = FirewallParser()
    normalizer = SecurityEventNormalizer()

    raw_event = parser.parse(log_line)

    event = normalizer.normalize(raw_event)

    assert event.event_id == raw_event["event_id"]
    assert event.timestamp == raw_event["timestamp"]
    assert event.src_ip == raw_event["src_ip"]
    assert event.src_port == raw_event["src_port"]
    assert event.dst_ip == raw_event["dst_ip"]
    assert event.dst_port == raw_event["dst_port"]
    assert event.protocol == raw_event["protocol"]