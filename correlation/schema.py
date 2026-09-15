from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class SecurityEvent:
    """
    Unified security event representation.

    Events from Linux, Windows, firewalls, network sensors,
    and other sources are normalized into this structure.

    The schema preserves both detection-related fields and
    source-specific evidence required for investigation.
    """

    # Core identity
    event_id: str
    timestamp: datetime

    # Network identity
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[int] = None
    protocol_name: Optional[str] = None

    # Detection results
    binary_prediction: int = 0
    attack_family: str = "Benign"
    confidence: float = 0.0

    # Source information
    source_file: Optional[str] = None

    # Original dataset / ground truth information
    true_label: Optional[str] = None
    true_attack_family: Optional[str] = None

    # Event classification
    event_type: Optional[str] = None

    # Windows-specific evidence
    windows_event_id: Optional[int] = None
    username: Optional[str] = None
    domain: Optional[str] = None
    process_name: Optional[str] = None

    # Firewall-specific evidence
    firewall_action: Optional[str] = None

    # Original log record
    raw_log: Optional[str] = None

    # Extensible metadata for future sources
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Convert the security event into a JSON-serializable dictionary.
        """

        data = {}

        for key, value in self.__dict__.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            else:
                data[key] = value

        return data


@dataclass
class Incident:
    """
    Correlated collection of related security events.
    """

    incident_id: str

    events: list[SecurityEvent] = field(
        default_factory=list
    )

    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    severity: str = "low"

    primary_attack_family: Optional[str] = None

    attack_families: list[str] = field(
        default_factory=list
    )

    family_distribution: dict[str, int] = field(
        default_factory=dict
    )

    confidence: float = 0.0

    src_ips: list[str] = field(
        default_factory=list
    )

    dst_ips: list[str] = field(
        default_factory=list
    )

    dst_ports: list[int] = field(
        default_factory=list
    )

    protocols: list[int] = field(
        default_factory=list
    )

    def add_event(
        self,
        event: SecurityEvent,
    ) -> None:
        """
        Add a security event to the incident and
        update incident-level aggregate information.
        """

        self.events.append(event)

        if (
            self.start_time is None
            or event.timestamp < self.start_time
        ):
            self.start_time = event.timestamp

        if (
            self.end_time is None
            or event.timestamp > self.end_time
        ):
            self.end_time = event.timestamp

        if event.attack_family not in self.attack_families:
            self.attack_families.append(
                event.attack_family
            )

        self.family_distribution[
            event.attack_family
        ] = (
            self.family_distribution.get(
                event.attack_family,
                0,
            )
            + 1
        )

        if (
            event.src_ip is not None
            and event.src_ip not in self.src_ips
        ):
            self.src_ips.append(event.src_ip)

        if (
            event.dst_ip is not None
            and event.dst_ip not in self.dst_ips
        ):
            self.dst_ips.append(event.dst_ip)

        if (
            event.dst_port is not None
            and event.dst_port not in self.dst_ports
        ):
            self.dst_ports.append(event.dst_port)

        if (
            event.protocol is not None
            and event.protocol not in self.protocols
        ):
            self.protocols.append(event.protocol)