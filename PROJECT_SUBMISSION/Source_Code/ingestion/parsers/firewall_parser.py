import hashlib
import re
from datetime import datetime
from typing import Any


class FirewallParser:
    """
    Parser for a normalized firewall log representation.

    Expected fields include:
        Timestamp
        SrcIP
        SrcPort
        DstIP
        DstPort
        Protocol
        Action

    Example:
        Timestamp=2018-02-14T10:30:15Z
        SrcIP=192.168.1.50
        SrcPort=54321
        DstIP=10.0.0.10
        DstPort=22
        Protocol=TCP
        Action=DENY

    The parser only extracts and normalizes firewall information.
    It does not decide whether the event is malicious.
    """

    TIMESTAMP_PATTERN = re.compile(
        r"(?:Timestamp|TimeCreated|Time)\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    SRC_IP_PATTERN = re.compile(
        r"(?:SrcIP|SrcIp|SourceIP|SourceIp)\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    SRC_PORT_PATTERN = re.compile(
        r"(?:SrcPort|SourcePort)\s*[:=]\s*"
        r"(?P<value>\d+)",
        re.IGNORECASE,
    )

    DST_IP_PATTERN = re.compile(
        r"(?:DstIP|DstIp|DestinationIP|DestinationIp)\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    DST_PORT_PATTERN = re.compile(
        r"(?:DstPort|DestinationPort)\s*[:=]\s*"
        r"(?P<value>\d+)",
        re.IGNORECASE,
    )

    PROTOCOL_PATTERN = re.compile(
        r"Protocol\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    ACTION_PATTERN = re.compile(
        r"Action\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    SUPPORTED_ACTIONS = {
        "ALLOW",
        "ACCEPT",
        "PERMIT",
        "DENY",
        "DROP",
        "REJECT",
        "BLOCK",
    }

    PROTOCOL_MAP = {
        "TCP": 6,
        "UDP": 17,
        "ICMP": 1,
    }

    def parse(
        self,
        line: str,
    ) -> dict[str, Any] | None:
        """
        Parse a normalized firewall log line.

        Returns:
            A raw event dictionary for a recognized firewall
            event, or None if the line cannot be parsed.
        """

        if not isinstance(line, str):
            raise TypeError(
                "line must be a string."
            )

        line = line.strip()

        if not line:
            return None

        timestamp = self._extract_timestamp(line)

        src_ip = self._extract_value(
            self.SRC_IP_PATTERN,
            line,
        )

        dst_ip = self._extract_value(
            self.DST_IP_PATTERN,
            line,
        )

        src_port = self._extract_int(
            self.SRC_PORT_PATTERN,
            line,
        )

        dst_port = self._extract_int(
            self.DST_PORT_PATTERN,
            line,
        )

        protocol_value = self._extract_value(
            self.PROTOCOL_PATTERN,
            line,
        )

        action = self._extract_value(
            self.ACTION_PATTERN,
            line,
        )

        if action is None:
            return None

        action = action.upper()

        if action not in self.SUPPORTED_ACTIONS:
            return None

        protocol = self._normalize_protocol(
            protocol_value
        )

        event_id = self._build_event_id(
            timestamp=timestamp,
            line=line,
        )

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "src_ip": self._clean_ip(src_ip),
            "dst_ip": self._clean_ip(dst_ip),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "binary_prediction": 0,
            "attack_family": "Benign",
            "confidence": 0.0,
            "source_file": "firewall.log",
            "true_label": None,
            "true_attack_family": None,
            "event_type": "firewall_connection",
            "firewall_action": action,
            "protocol_name": protocol_value.upper()
            if protocol_value
            else None,
            "raw_log": line,
        }

    @classmethod
    def _extract_timestamp(
        cls,
        line: str,
    ) -> datetime:

        match = cls.TIMESTAMP_PATTERN.search(line)

        if not match:
            raise ValueError(
                "Firewall event is missing a timestamp."
            )

        value = match.group("value")

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid firewall timestamp: {value}"
            ) from exc

    @staticmethod
    def _extract_value(
        pattern: re.Pattern,
        line: str,
    ) -> str | None:

        match = pattern.search(line)

        if not match:
            return None

        return match.group("value")

    @staticmethod
    def _extract_int(
        pattern: re.Pattern,
        line: str,
    ) -> int | None:

        match = pattern.search(line)

        if not match:
            return None

        return int(
            match.group("value")
        )

    @classmethod
    def _normalize_protocol(
        cls,
        value: str | None,
    ) -> int | None:

        if value is None:
            return None

        normalized = value.upper()

        if normalized in cls.PROTOCOL_MAP:
            return cls.PROTOCOL_MAP[normalized]

        try:
            return int(normalized)
        except ValueError:
            raise ValueError(
                f"Unsupported protocol: {value}"
            )

    @staticmethod
    def _clean_ip(
        value: str | None,
    ) -> str | None:

        if value is None:
            return None

        if value in {
            "-",
            "0.0.0.0",
            "::",
        }:
            return None

        return value

    @staticmethod
    def _build_event_id(
        timestamp: datetime,
        line: str,
    ) -> str:

        value = (
            timestamp.isoformat()
            + "|"
            + line
        )

        digest = hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()[:16]

        return f"FIREWALL-{digest}"