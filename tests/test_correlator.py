from datetime import datetime, timedelta

from correlation.schema import SecurityEvent
from correlation.correlator import IncidentCorrelator


def make_event(
    event_id,
    timestamp,
    family,
    confidence=0.95,
    protocol=6,
    dst_port=22,
):
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        attack_family=family,
        confidence=confidence,
        protocol=protocol,
        dst_port=dst_port,
    )


def test_same_attack_becomes_one_incident():

    start = datetime(2018, 2, 14, 10, 0, 0)

    events = [
        make_event(
            "E1",
            start,
            "Brute Force",
        ),
        make_event(
            "E2",
            start + timedelta(seconds=5),
            "Brute Force",
        ),
        make_event(
            "E3",
            start + timedelta(seconds=10),
            "Brute Force",
        ),
    ]

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(events)

    assert len(incidents) == 1
    assert len(incidents[0].events) == 3
    assert incidents[0].primary_attack_family == "Brute Force"


def test_different_attack_families_create_separate_incidents():

    start = datetime(2018, 2, 14, 10, 0, 0)

    events = [
        make_event(
            "E1",
            start,
            "Brute Force",
        ),
        make_event(
            "E2",
            start + timedelta(seconds=5),
            "DDoS",
            dst_port=80,
        ),
    ]

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(events)

    assert len(incidents) == 2


def test_events_far_apart_create_separate_incidents():

    start = datetime(2018, 2, 14, 10, 0, 0)

    events = [
        make_event(
            "E1",
            start,
            "Brute Force",
        ),
        make_event(
            "E2",
            start + timedelta(minutes=5),
            "Brute Force",
        ),
    ]

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(events)

    assert len(incidents) == 2


def test_benign_events_are_ignored():

    start = datetime(2018, 2, 14, 10, 0, 0)

    events = [
        make_event(
            "E1",
            start,
            "Benign",
        ),
        make_event(
            "E2",
            start + timedelta(seconds=5),
            "Benign",
        ),
    ]

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(events)

    assert len(incidents) == 0
    
def test_different_families_can_belong_to_same_incident():

    start = datetime(2018, 2, 14, 10, 33, 26)

    events = [
        make_event(
            "E1",
            start,
            "Brute Force",
            confidence=0.82,
            protocol=6,
            dst_port=21,
        ),
        make_event(
            "E2",
            start + timedelta(seconds=5),
            "DoS",
            confidence=0.69,
            protocol=6,
            dst_port=21,
        ),
    ]

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(events)

    assert len(incidents) == 1

    assert len(incidents[0].events) == 2