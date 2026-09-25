from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from correlation.incident_window import IncidentWindow
from correlation.schema import SecurityEvent


def make_event(timestamp=None):
    return SecurityEvent(
        event_id=str(uuid4()),
        timestamp=timestamp or datetime.now(timezone.utc),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        dst_port=22,
        protocol=6,
        binary_prediction=1,
        attack_family="Brute Force",
        confidence=0.95,
    )


def test_incident_window_initializes_empty():
    window = IncidentWindow()

    assert window.is_empty()
    assert window.event_count == 0
    assert window.start_time is None


def test_incident_window_rejects_invalid_window_seconds():
    with pytest.raises(TypeError):
        IncidentWindow(window_seconds="60")

    with pytest.raises(ValueError):
        IncidentWindow(window_seconds=0)

    with pytest.raises(ValueError):
        IncidentWindow(window_seconds=-1)


def test_incident_window_accepts_first_event():
    window = IncidentWindow(window_seconds=60)

    timestamp = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    event = make_event(timestamp)

    assert window.can_accept(event)
    assert window.add(event)

    assert window.event_count == 1
    assert window.start_time == timestamp
    assert window.get_events() == [event]


def test_incident_window_accepts_event_inside_window():
    window = IncidentWindow(window_seconds=60)

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    first_event = make_event(base_time)
    second_event = make_event(
        base_time + timedelta(seconds=30)
    )

    assert window.add(first_event)
    assert window.can_accept(second_event)
    assert window.add(second_event)

    assert window.event_count == 2
    assert window.start_time == base_time


def test_incident_window_accepts_event_at_boundary():
    window = IncidentWindow(window_seconds=60)

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    first_event = make_event(base_time)
    boundary_event = make_event(
        base_time + timedelta(seconds=60)
    )

    assert window.add(first_event)
    assert window.can_accept(boundary_event)
    assert window.add(boundary_event)

    assert window.event_count == 2


def test_incident_window_rejects_event_outside_window():
    window = IncidentWindow(window_seconds=60)

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    first_event = make_event(base_time)
    late_event = make_event(
        base_time + timedelta(seconds=61)
    )

    assert window.add(first_event)

    assert not window.can_accept(late_event)
    assert not window.add(late_event)

    assert window.event_count == 1


def test_incident_window_get_events_returns_copy():
    window = IncidentWindow()

    event = make_event()

    window.add(event)

    events = window.get_events()
    events.clear()

    assert window.event_count == 1


def test_incident_window_flush_returns_and_clears_events():
    window = IncidentWindow()

    base_time = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            base_time + timedelta(seconds=index)
        )
        for index in range(3)
    ]

    for event in events:
        assert window.add(event)

    flushed_events = window.flush()

    assert flushed_events == events
    assert window.is_empty()
    assert window.event_count == 0
    assert window.start_time is None


def test_incident_window_clear_resets_state():
    window = IncidentWindow()

    event = make_event()
    window.add(event)

    assert window.event_count == 1

    window.clear()

    assert window.is_empty()
    assert window.event_count == 0
    assert window.start_time is None


def test_incident_window_rejects_invalid_event():
    window = IncidentWindow()

    with pytest.raises(TypeError):
        window.add("not-an-event")

    with pytest.raises(TypeError):
        window.can_accept("not-an-event")


def test_incident_window_rejects_invalid_timestamp():
    window = IncidentWindow()

    event = make_event()
    event.timestamp = "2026-09-16T10:00:00Z"

    with pytest.raises(TypeError):
        window.add(event)

def test_incident_window_rejects_naive_timestamp():
    window = IncidentWindow()

    naive_timestamp = datetime(
        2026,
        9,
        16,
        10,
        0,
        0,
    )

    event = make_event(naive_timestamp)

    with pytest.raises(ValueError):
        window.add(event)
