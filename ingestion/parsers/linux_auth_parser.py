import re
from datetime import datetime
from typing import Any


class LinuxAuthParser:
    """
    Parser for common Linux authentication log entries.

    Supported examples include:
        sshd: Failed password
        sshd: Accepted password
        sshd: Invalid user
        sudo authentication events

    The parser only extracts and normalizes information.
    It does not perform threat detection.
    """

    FAILED_PASSWORD_PATTERN = re.compile(
        r"(?P<process>sshd)\[(?P<pid>\d+)\]: "
        r"Failed password for "
        r"(?:(?P<invalid>invalid user) )?"
        r"(?P<username>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+) "
        r"ssh2"
    )

    ACCEPTED_PASSWORD_PATTERN = re.compile(
        r"(?P<process>sshd)\[(?P<pid>\d+)\]: "
        r"Accepted password for "
        r"(?P<username>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+) "
        r"ssh2"
    )

    INVALID_USER_PATTERN = re.compile(
        r"(?P<process>sshd)\[(?P<pid>\d+)\]: "
        r"Invalid user "
        r"(?P<username>\S+) "
        r"from (?P<src_ip>\S+) "
        r"port (?P<src_port>\d+)"
    )

    def parse(
        self,
        line: str,
        year: int | None = None,
    ) -> dict[str, Any] | None:
        """
        Parse a Linux authentication log line.

        Returns:
            A normalized raw-event dictionary if the line
            contains a supported authentication event.

            None if the line is not recognized.
        """

        if not isinstance(line, str):
            raise TypeError(
                "line must be a string."
            )

        line = line.strip()

        if not line:
            return None

        timestamp = self._parse_syslog_timestamp(
            line,
            year=year,
        )

        match = (
            self.FAILED_PASSWORD_PATTERN.search(line)
        )

        if match:
            return self._build_failed_password_event(
                line=line,
                match=match,
                timestamp=timestamp,
            )

        match = (
            self.ACCEPTED_PASSWORD_PATTERN.search(line)
        )

        if match:
            return self._build_accepted_password_event(
                line=line,
                match=match,
                timestamp=timestamp,
            )

        match = (
            self.INVALID_USER_PATTERN.search(line)
        )

        if match:
            return self._build_invalid_user_event(
                line=line,
                match=match,
                timestamp=timestamp,
            )

        return None

    def _build_failed_password_event(
        self,
        line: str,
        match: re.Match,
        timestamp: datetime,
    ) -> dict[str, Any]:

        groups = match.groupdict()

        username = groups["username"]
        src_ip = groups["src_ip"]
        src_port = int(groups["src_port"])

        invalid_user = groups.get(
            "invalid"
        ) is not None

        event_id = self._build_event_id(
            timestamp=timestamp,
            line=line,
        )

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": None,
            "src_port": src_port,
            "dst_port": 22,
            "protocol": 6,
            "binary_prediction": 0,
            "attack_family": "Benign",
            "confidence": 0.0,
            "source_file": "linux_auth.log",
            "true_label": None,
            "true_attack_family": None,
            "event_type": "authentication_failure",
            "username": username,
            "invalid_user": invalid_user,
            "raw_log": line,
        }

    def _build_accepted_password_event(
        self,
        line: str,
        match: re.Match,
        timestamp: datetime,
    ) -> dict[str, Any]:

        groups = match.groupdict()

        event_id = self._build_event_id(
            timestamp=timestamp,
            line=line,
        )

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "src_ip": groups["src_ip"],
            "dst_ip": None,
            "src_port": int(groups["src_port"]),
            "dst_port": 22,
            "protocol": 6,
            "binary_prediction": 0,
            "attack_family": "Benign",
            "confidence": 0.0,
            "source_file": "linux_auth.log",
            "true_label": None,
            "true_attack_family": None,
            "event_type": "authentication_success",
            "username": groups["username"],
            "invalid_user": False,
            "raw_log": line,
        }

    def _build_invalid_user_event(
        self,
        line: str,
        match: re.Match,
        timestamp: datetime,
    ) -> dict[str, Any]:

        groups = match.groupdict()

        event_id = self._build_event_id(
            timestamp=timestamp,
            line=line,
        )

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "src_ip": groups["src_ip"],
            "dst_ip": None,
            "src_port": int(groups["src_port"]),
            "dst_port": 22,
            "protocol": 6,
            "binary_prediction": 0,
            "attack_family": "Benign",
            "confidence": 0.0,
            "source_file": "linux_auth.log",
            "true_label": None,
            "true_attack_family": None,
            "event_type": "invalid_user",
            "username": groups["username"],
            "invalid_user": True,
            "raw_log": line,
        }

    @staticmethod
    def _parse_syslog_timestamp(
        line: str,
        year: int | None = None,
    ) -> datetime:

        if year is None:
            year = datetime.now().year

        match = re.match(
            r"^(?P<month>[A-Z][a-z]{2}) "
            r"(?P<day>\d{1,2}) "
            r"(?P<time>\d{2}:\d{2}:\d{2})",
            line,
        )

        if not match:
            raise ValueError(
                "Could not parse Linux syslog timestamp."
            )

        timestamp_string = (
            f"{year} "
            f"{match.group('month')} "
            f"{match.group('day')} "
            f"{match.group('time')}"
        )

        try:
            return datetime.strptime(
                timestamp_string,
                "%Y %b %d %H:%M:%S",
            )

        except ValueError as exc:
            raise ValueError(
                "Invalid Linux syslog timestamp."
            ) from exc

    @staticmethod
    def _build_event_id(
        timestamp: datetime,
        line: str,
    ) -> str:

        import hashlib

        value = (
            timestamp.isoformat()
            + "|"
            + line
        )

        digest = hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()[:16]

        return f"LINUX-AUTH-{digest}"