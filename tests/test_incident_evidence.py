from datetime import datetime, timedelta

from correlation.schema import SecurityEvent
from correlation.correlator import IncidentCorrelator


def make_event(
    event_id,
    timestamp,
    family,
    confidence=0.90,
    protocol=6,
    dst_port=21,
):
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        attack_family=family,
        confidence=confidence,
        protocol=protocol,
        dst_port=dst_port,
    )


def test_incident_contains_family_distribution():

    start = datetime(
        2018,
        2,
        14,
        10,
        33,
        26,
    )

    events = []

    # 7 Brute Force events
    for i in range(7):
        events.append(
            make_event(
                event_id=f"BF-{i}",
                timestamp=start + timedelta(seconds=i),
                family="Brute Force",
                confidence=0.90,
            )
        )

    # 3 DoS events
    for i in range(3):
        events.append(
            make_event(
                event_id=f"DOS-{i}",
                timestamp=start + timedelta(seconds=10 + i),
                family="DoS",
                confidence=0.70,
            )
        )

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(events)

    # All events are close together and share
    # protocol + destination port.
    assert len(incidents) == 1

    incident = incidents[0]

    assert len(incident.events) == 10

    assert incident.primary_attack_family == "Brute Force"

    # The incident must retain the candidate families.
    assert "Brute Force" in incident.attack_families
    assert "DoS" in incident.attack_families
    
def test_incident_tracks_family_counts():

    start = datetime(
        2018,
        2,
        14,
        10,
        33,
        26,
    )

    events = []

    # 7 Brute Force events
    for i in range(7):
        events.append(
            make_event(
                event_id=f"BF-{i}",
                timestamp=start + timedelta(seconds=i),
                family="Brute Force",
                confidence=0.90,
            )
        )

    # 3 DoS events
    for i in range(3):
        events.append(
            make_event(
                event_id=f"DOS-{i}",
                timestamp=start + timedelta(seconds=10 + i),
                family="DoS",
                confidence=0.70,
            )
        )

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident.family_distribution == {
        "Brute Force": 7,
        "DoS": 3,
    }