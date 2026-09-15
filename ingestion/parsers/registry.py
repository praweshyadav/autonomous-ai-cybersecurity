from typing import Any, Type

from ingestion.parsers.firewall_parser import FirewallParser
from ingestion.parsers.linux_auth_parser import LinuxAuthParser
from ingestion.parsers.windows_event_parser import WindowsEventParser


class ParserRegistry:
    """
    Registry for supported security log parsers.

    Maps a stable source name to its parser implementation.
    """

    _PARSERS: dict[str, Type[Any]] = {
        "linux_auth": LinuxAuthParser,
        "windows_event": WindowsEventParser,
        "firewall": FirewallParser,
    }

    @classmethod
    def get_parser_class(cls, source_type: str) -> Type[Any]:
        """
        Return the parser class registered for a source type.
        """
        if not isinstance(source_type, str):
            raise TypeError("source_type must be a string.")

        source_type = source_type.strip().lower()

        if not source_type:
            raise ValueError("source_type cannot be empty.")

        try:
            return cls._PARSERS[source_type]
        except KeyError:
            supported = ", ".join(sorted(cls._PARSERS))
            raise ValueError(
                f"Unsupported source type: {source_type}. "
                f"Supported types: {supported}"
            ) from None

    @classmethod
    def create_parser(cls, source_type: str) -> Any:
        """
        Create and return a parser instance.
        """
        parser_class = cls.get_parser_class(source_type)
        return parser_class()

    @classmethod
    def supported_sources(cls) -> list[str]:
        """
        Return all supported source types.
        """
        return sorted(cls._PARSERS.keys())