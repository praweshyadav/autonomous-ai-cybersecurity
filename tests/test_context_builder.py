from datetime import datetime, timedelta

from agent.context_builder import IncidentContextBuilder
from correlation.schema import Incident, SecurityEvent


def make_event(
    event_id: str,
    timestamp: datetime,
    attack_family: str,
    confidence: float,
    protocol: int = 6,
    dst_port: int = 21,
):
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        protocol=protocol,
        dst_port=dst_port,
        attack_family=attack_family,
        confidence=confidence,
        binary_prediction=1,
    )


def test_context_builder_preserves_incident_evidence():
    start = datetime(2018, 2, 14, 10, 33, 26)

    incident = Incident(
        incident_id="INC-000001",
        start_time=start,
        end_time=start,
    )

    for i in range(7):
        incident.add_event(
            make_event(
                f"BF-{i}",
                start + timedelta(seconds=i),
                "Brute Force",
                0.82,
            )
        )

    for i in range(3):
        incident.add_event(
            make_event(
                f"DOS-{i}",
                start + timedelta(seconds=i),
                "DoS",
                0.69,
            )
        )

    incident.primary_attack_family = "Brute Force"
    incident.severity = "high"
    incident.confidence = 0.781

    builder = IncidentContextBuilder()

    context = builder.build(incident)

    assert context.incident_id == "INC-000001"
    assert context.event_count == 10

    assert context.primary_attack_family == "Brute Force"

    assert context.family_distribution == {
        "Brute Force": 7,
        "DoS": 3,
    }

    assert context.protocols == [6]
    assert context.destination_ports == [21]

    assert context.duration_seconds == 6.0