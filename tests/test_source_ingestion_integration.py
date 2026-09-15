from pathlib import Path

import pytest

from correlation.schema import SecurityEvent
from ingestion.parsers.firewall_parser import FirewallParser
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.parsers.registry import ParserRegistry
from ingestion.parsers.windows_event_parser import WindowsEventParser
from ingestion.source_ingestor import SourceIngestor


def write_log_file(tmp_path: Path, filename: str, content: str) -> Path:
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    return file_path


def test_linux_auth_full_ingestion_path(tmp_path):
    log_file = write_log_file(
        tmp_path,
        "linux_auth.log",
        "Mar 10 10:15:30 server sshd[1234]: "
        "Failed password for admin from 192.168.1.10 port 54321 ssh2\n",
    )

    parser = ParserRegistry.create_parser("linux_auth")

    assert isinstance(parser, LinuxAuthParser)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=parser,
    )

    events = ingestor.ingest(year=2026)

    assert len(events) == 1

    event = events[0]

    assert isinstance(event, SecurityEvent)
    assert event.src_ip == "192.168.1.10"
    assert event.src_port == 54321
    assert event.dst_port == 22
    assert event.protocol == 6
    assert event.event_type == "authentication_failure"
    assert event.source_file == "linux_auth.log"


def test_windows_event_full_ingestion_path(tmp_path):
    log_file = write_log_file(
        tmp_path,
        "windows_security.log",
        (
            "EventID=4625 "
            "TimeCreated=2026-03-10T10:15:30 "
            "IpAddress=10.0.0.15 "
            "IpPort=54321 "
            "TargetUserName=administrator "
            "TargetDomainName=UNIVERSITY\n"
        ),
    )

    parser = ParserRegistry.create_parser("windows_event")

    assert isinstance(parser, WindowsEventParser)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=parser,
    )

    events = ingestor.ingest()

    assert len(events) == 1

    event = events[0]

    assert isinstance(event, SecurityEvent)
    assert event.windows_event_id == 4625
    assert event.src_ip == "10.0.0.15"
    assert event.src_port == 54321
    assert event.username == "administrator"
    assert event.domain == "UNIVERSITY"
    assert event.event_type == "logon_failure"
    assert event.source_file == "windows_security.log"


def test_firewall_full_ingestion_path(tmp_path):
    log_file = write_log_file(
        tmp_path,
        "firewall.log",
        (
            "Timestamp=2018-02-14T10:30:15Z "
            "SrcIP=10.0.0.15 "
            "SrcPort=54321 "
            "DstIP=10.0.0.20 "
            "DstPort=443 "
            "Protocol=TCP "
            "Action=DENY\n"
        ),
    )

    parser = ParserRegistry.create_parser("firewall")

    assert isinstance(parser, FirewallParser)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=parser,
    )

    events = ingestor.ingest()

    assert len(events) == 1

    event = events[0]

    assert isinstance(event, SecurityEvent)
    assert event.src_ip == "10.0.0.15"
    assert event.dst_ip == "10.0.0.20"
    assert event.src_port == 54321
    assert event.dst_port == 443
    assert event.protocol == 6
    assert event.protocol_name == "TCP"
    assert event.firewall_action == "DENY"
    assert event.event_type == "firewall_connection"
    assert event.source_file == "firewall.log"


def test_registry_and_source_ingestor_work_together(tmp_path):
    log_file = write_log_file(
        tmp_path,
        "linux_auth.log",
        "\n".join(
            [
                "Mar 10 10:15:30 server sshd[1234]: "
                "Failed password for admin from 192.168.1.10 port 54321 ssh2",
                "Mar 10 10:15:31 server sshd[1235]: "
                "Failed password for root from 192.168.1.20 port 54322 ssh2",
            ]
        ),
    )

    source_type = "linux_auth"

    parser = ParserRegistry.create_parser(source_type)

    ingestor = SourceIngestor(
        file_path=log_file,
        parser=parser,
    )

    events = ingestor.ingest(year=2026)

    assert len(events) == 2
    assert all(isinstance(event, SecurityEvent) for event in events)
    assert all(event.protocol == 6 for event in events)
    assert all(event.dst_port == 22 for event in events)


def test_integration_rejects_unknown_source_type(tmp_path):
    log_file = write_log_file(
        tmp_path,
        "unknown.log",
        "some log record\n",
    )

    with pytest.raises(ValueError, match="Unsupported source type"):
        ParserRegistry.create_parser("unknown_source")

    assert log_file.exists()