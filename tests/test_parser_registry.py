import pytest

from ingestion.parsers.firewall_parser import FirewallParser
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.parsers.registry import ParserRegistry
from ingestion.parsers.windows_event_parser import WindowsEventParser


def test_supported_sources():
    sources = ParserRegistry.supported_sources()

    assert sources == [
        "firewall",
        "linux_auth",
        "windows_event",
    ]


def test_get_linux_parser_class():
    parser_class = ParserRegistry.get_parser_class("linux_auth")

    assert parser_class is LinuxAuthParser


def test_get_windows_parser_class():
    parser_class = ParserRegistry.get_parser_class("windows_event")

    assert parser_class is WindowsEventParser


def test_get_firewall_parser_class():
    parser_class = ParserRegistry.get_parser_class("firewall")

    assert parser_class is FirewallParser


def test_create_linux_parser():
    parser = ParserRegistry.create_parser("linux_auth")

    assert isinstance(parser, LinuxAuthParser)


def test_create_windows_parser():
    parser = ParserRegistry.create_parser("windows_event")

    assert isinstance(parser, WindowsEventParser)


def test_create_firewall_parser():
    parser = ParserRegistry.create_parser("firewall")

    assert isinstance(parser, FirewallParser)


def test_source_type_is_case_insensitive():
    parser = ParserRegistry.create_parser("LINUX_AUTH")

    assert isinstance(parser, LinuxAuthParser)


def test_source_type_whitespace_is_ignored():
    parser = ParserRegistry.create_parser("  linux_auth  ")

    assert isinstance(parser, LinuxAuthParser)


def test_empty_source_type_is_rejected():
    with pytest.raises(ValueError):
        ParserRegistry.get_parser_class("")


def test_whitespace_source_type_is_rejected():
    with pytest.raises(ValueError):
        ParserRegistry.get_parser_class("   ")


def test_unsupported_source_type_is_rejected():
    with pytest.raises(ValueError, match="Unsupported source type"):
        ParserRegistry.get_parser_class("apache")


def test_non_string_source_type_is_rejected():
    with pytest.raises(TypeError):
        ParserRegistry.get_parser_class(None)