import hashlib
import re
from datetime import datetime
from typing import Any


class WindowsEventParser:
    """
    Parser for common Windows Security Event Log records.

    The parser extracts security-relevant fields from a normalized
    Windows Event Log representation.

    Supported Event IDs:
        4624 -> Successful logon
        4625 -> Failed logon
        4634 -> Logoff
        4648 -> Explicit credential logon
        4672 -> Special privileges assigned
        4688 -> Process creation

    The parser performs extraction only.
    It does not determine whether an event is malicious.
    """

    SUPPORTED_EVENT_IDS = {
        4624: "logon_success",
        4625: "logon_failure",
        4634: "logoff",
        4648: "explicit_credential_logon",
        4672: "special_privilege_assigned",
        4688: "process_creation",
    }

    EVENT_ID_PATTERN = re.compile(
        r"EventID\s*[:=]\s*(?P<event_id>\d+)",
        re.IGNORECASE,
    )

    TIMESTAMP_PATTERN = re.compile(
        r"(?:TimeCreated|Timestamp|Time)\s*[:=]\s*"
        r"(?P<timestamp>\S+)",
        re.IGNORECASE,
    )

    SRC_IP_PATTERN = re.compile(
        r"(?:IpAddress|SourceIp|SourceIP|SrcIp|SrcIP)\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    SRC_PORT_PATTERN = re.compile(
        r"(?:IpPort|SourcePort|SrcPort)\s*[:=]\s*"
        r"(?P<value>\d+)",
        re.IGNORECASE,
    )

    USERNAME_PATTERN = re.compile(
        r"(?:TargetUserName|TargetUsername|UserName|Username)\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    DOMAIN_PATTERN = re.compile(
        r"(?:TargetDomainName|TargetDomain|DomainName|Domain)\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    PROCESS_NAME_PATTERN = re.compile(
        r"(?:NewProcessName|ProcessName|Image)\s*[:=]\s*"
        r"(?P<value>\S+)",
        re.IGNORECASE,
    )

    def parse(
        self,
        line: str,
    ) -> dict[str, Any] | None:
        """
        Parse a Windows Security Event Log record.

        The input is expected to be a normalized text representation
        containing fields such as EventID, TimeCreated, IpAddress,
        TargetUserName, etc.

        Returns:
            Dictionary containing extracted event information,
            or None if the event is unsupported.
        """

        if not isinstance(line, str):
            raise TypeError(
                "line must be a string."
            )

        line = line.strip()

        if not line:
            return None

        event_id = self._extract_event_id(line)

        if event_id is None:
            return None

        if event_id not in self.SUPPORTED_EVENT_IDS:
            return None

        timestamp = self._extract_timestamp(line)

        event_type = self.SUPPORTED_EVENT_IDS[
            event_id
        ]

        src_ip = self._extract_value(
            self.SRC_IP_PATTERN,
            line,
        )

        src_port = self._extract_int(
            self.SRC_PORT_PATTERN,
            line,
        )

        username = self._extract_value(
            self.USERNAME_PATTERN,
            line,
        )

        domain = self._extract_value(
            self.DOMAIN_PATTERN,
            line,
        )

        process_name = self._extract_value(
            self.PROCESS_NAME_PATTERN,
            line,
        )

        return {
            "event_id": self._build_event_id(
                event_id=event_id,
                timestamp=timestamp,
                line=line,
            ),
            "timestamp": timestamp,
            "src_ip": self._clean_ip(src_ip),
            "dst_ip": None,
            "src_port": src_port,
            "dst_port": None,
            "protocol": None,
            "binary_prediction": 0,
            "attack_family": "Benign",
            "confidence": 0.0,
            "source_file": "windows_security.log",
            "true_label": None,
            "true_attack_family": None,
            "event_type": event_type,
            "windows_event_id": event_id,
            "username": username,
            "domain": domain,
            "process_name": process_name,
            "raw_log": line,
        }

    @classmethod
    def _extract_event_id(
        cls,
        line: str,
    ) -> int | None:

        match = cls.EVENT_ID_PATTERN.search(line)

        if not match:
            return None

        return int(
            match.group("event_id")
        )

    @classmethod
    def _extract_timestamp(
        cls,
        line: str,
    ) -> datetime:

        match = cls.TIMESTAMP_PATTERN.search(line)

        if not match:
            raise ValueError(
                "Windows event is missing a timestamp."
            )

        value = match.group("timestamp")

        # Handle common ISO-8601 timestamps.
        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid Windows event timestamp: {value}"
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

    @staticmethod
    def _clean_ip(
        value: str | None,
    ) -> str | None:

        if value is None:
            return None

        # Windows commonly represents a missing IP as "-".
        if value in {"-", "::", "0.0.0.0"}:
            return None

        return value

    @staticmethod
    def _build_event_id(
        event_id: int,
        timestamp: datetime,
        line: str,
    ) -> str:

        value = (
            f"{event_id}|"
            f"{timestamp.isoformat()}|"
            f"{line}"
        )

        digest = hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()[:16]

        return f"WINDOWS-{event_id}-{digest}"