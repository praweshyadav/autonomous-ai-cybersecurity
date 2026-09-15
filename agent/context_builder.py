from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any

from correlation.schema import Incident


@dataclass
class IncidentContext:
    """
    Structured context representing an incident for downstream
    investigation, RAG, and AI-agent reasoning.
    """

    incident_id: str
    start_time: str
    end_time: str
    duration_seconds: float

    severity: str
    primary_attack_family: str | None

    event_count: int
    confidence: float

    attack_families: list[str]
    family_distribution: dict[str, int]

    protocols: list[int]
    destination_ports: list[int]

    source_ips: list[str]
    destination_ips: list[str]


class IncidentContextBuilder:
    """
    Converts an Incident object into a deterministic,
    serializable investigation context.
    """

    def build(self, incident: Incident) -> IncidentContext:
        duration = (
            incident.end_time - incident.start_time
        ).total_seconds()

        protocols = sorted(
            {
                event.protocol
                for event in incident.events
                if event.protocol is not None
            }
        )

        return IncidentContext(
            incident_id=incident.incident_id,
            start_time=incident.start_time.isoformat(),
            end_time=incident.end_time.isoformat(),
            duration_seconds=duration,

            severity=incident.severity,
            primary_attack_family=incident.primary_attack_family,

            event_count=len(incident.events),
            confidence=incident.confidence,

            attack_families=list(incident.attack_families),
            family_distribution=dict(incident.family_distribution),

            protocols=protocols,
            destination_ports=list(incident.dst_ports),

            source_ips=list(incident.src_ips),
            destination_ips=list(incident.dst_ips),
        )

    def build_dict(self, incident: Incident) -> dict[str, Any]:
        """
        Build a JSON-serializable dictionary representation
        of the incident context.
        """

        context = self.build(incident)

        return asdict(context)