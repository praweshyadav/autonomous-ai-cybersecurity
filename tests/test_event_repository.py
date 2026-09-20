from datetime import datetime, timezone
from uuid import uuid4

from correlation.schema import Incident, SecurityEvent
from persistence.event_repository import EventRepository


def make_event(
    event_id: str | None = None,
    attack_family: str = "Brute Force",
) -> SecurityEvent:
    """Create a realistic SecurityEvent for repository testing."""

    return SecurityEvent(
        event_id=event_id or str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.10",
        src_port=49152,
        dst_port=22,
        protocol=6,
        protocol_name="TCP",
        binary_prediction=1,
        attack_family=attack_family,
        confidence=0.95,
        source_file="test_security.log",
        true_label="SSH-Bruteforce",
        true_attack_family="Brute Force",
        event_type="network_flow",
        metadata={
            "test": True,
            "source": "repository_test",
        },
    )


def make_incident(
    incident_id: str,
    events: list[SecurityEvent],
) -> Incident:
    """Create an Incident compatible with the current schema."""

    return Incident(
        incident_id=incident_id,
        events=events,
        start_time=events[0].timestamp,
        end_time=events[-1].timestamp,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": len(events)},
        confidence=max(event.confidence for event in events),
        src_ips=sorted(
            {
                event.src_ip
                for event in events
                if event.src_ip is not None
            }
        ),
        dst_ips=sorted(
            {
                event.dst_ip
                for event in events
                if event.dst_ip is not None
            }
        ),
        dst_ports=sorted(
            {
                event.dst_port
                for event in events
                if event.dst_port is not None
            }
        ),
        protocols=sorted(
            {
                event.protocol
                for event in events
                if event.protocol is not None
            }
        ),
    )


def cleanup_event(
    repository: EventRepository,
    event_id: str,
) -> None:
    """Remove an event if it exists."""
    repository.delete(event_id)


def cleanup_incident(
    repository: EventRepository,
    incident_id: str,
) -> None:
    """Remove an incident directly from PostgreSQL."""
    with repository._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM incidents WHERE incident_id = %s",
                (incident_id,),
            )


def test_save_and_get_event():
    repository = EventRepository()

    event = make_event()

    try:
        repository.save(event)

        loaded = repository.get_by_id(event.event_id)

        assert loaded is not None
        assert loaded.event_id == event.event_id
        assert loaded.src_ip == event.src_ip
        assert loaded.dst_ip == event.dst_ip
        assert loaded.dst_port == event.dst_port
        assert loaded.protocol == event.protocol
        assert loaded.protocol_name == event.protocol_name
        assert loaded.binary_prediction == event.binary_prediction
        assert loaded.attack_family == event.attack_family
        assert loaded.confidence == event.confidence
        assert loaded.source_file == event.source_file
        assert loaded.true_label == event.true_label
        assert loaded.true_attack_family == event.true_attack_family
        assert loaded.event_type == event.event_type
        assert loaded.metadata == event.metadata

    finally:
        cleanup_event(repository, event.event_id)


def test_get_missing_event_returns_none():
    repository = EventRepository()

    missing_id = str(uuid4())

    assert repository.get_by_id(missing_id) is None


def test_save_batch():
    repository = EventRepository()

    events = [
        make_event(),
        make_event(),
        make_event(attack_family="DoS"),
    ]

    try:
        repository.save_batch(events)

        for event in events:
            loaded = repository.get_by_id(event.event_id)

            assert loaded is not None
            assert loaded.event_id == event.event_id
            assert loaded.attack_family == event.attack_family

    finally:
        for event in events:
            cleanup_event(repository, event.event_id)


def test_save_updates_existing_event():
    repository = EventRepository()

    event = make_event()

    try:
        repository.save(event)

        event.attack_family = "DoS"
        event.confidence = 0.88

        repository.save(event)

        loaded = repository.get_by_id(event.event_id)

        assert loaded is not None
        assert loaded.attack_family == "DoS"
        assert loaded.confidence == 0.88

    finally:
        cleanup_event(repository, event.event_id)


def test_count():
    repository = EventRepository()

    initial_count = repository.count()

    events = [
        make_event(),
        make_event(),
    ]

    try:
        repository.save_batch(events)

        assert repository.count() == initial_count + 2

    finally:
        for event in events:
            cleanup_event(repository, event.event_id)


def test_link_event_to_incident():
    repository = EventRepository()

    event = make_event()
    incident_id = str(uuid4())

    try:
        repository.save(event)

        incident = make_incident(
            incident_id=incident_id,
            events=[event],
        )

        with repository._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incidents (
                        incident_id,
                        start_time,
                        end_time,
                        severity,
                        primary_family,
                        confidence,
                        event_count,
                        source_ips,
                        destination_ips,
                        destination_ports,
                        protocols,
                        family_distribution
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s::jsonb,
                        %s::jsonb, %s::jsonb
                    )
                    """,
                    (
                        incident.incident_id,
                        incident.start_time,
                        incident.end_time,
                        incident.severity,
                        incident.primary_attack_family,
                        incident.confidence,
                        len(incident.events),
                        str(incident.src_ips).replace("'", '"'),
                        str(incident.dst_ips).replace("'", '"'),
                        str(incident.dst_ports).replace("'", '"'),
                        str(incident.protocols).replace("'", '"'),
                        str(incident.family_distribution).replace(
                            "'",
                            '"',
                        ),
                    ),
                )

        repository.link_to_incident(
            incident_id=incident_id,
            event_id=event.event_id,
        )

        linked_events = repository.get_incident_events(incident_id)

        assert len(linked_events) == 1
        assert linked_events[0].event_id == event.event_id

    finally:
        cleanup_event(repository, event.event_id)
        cleanup_incident(repository, incident_id)


def test_link_multiple_events_to_incident():
    repository = EventRepository()

    events = [
        make_event(),
        make_event(),
        make_event(),
    ]

    incident_id = str(uuid4())

    try:
        repository.save_batch(events)

        incident = make_incident(
            incident_id=incident_id,
            events=events,
        )

        with repository._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incidents (
                        incident_id,
                        start_time,
                        end_time,
                        severity,
                        primary_family,
                        confidence,
                        event_count,
                        source_ips,
                        destination_ips,
                        destination_ports,
                        protocols,
                        family_distribution
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s::jsonb,
                        %s::jsonb, %s::jsonb
                    )
                    """,
                    (
                        incident.incident_id,
                        incident.start_time,
                        incident.end_time,
                        incident.severity,
                        incident.primary_attack_family,
                        incident.confidence,
                        len(incident.events),
                        '["192.168.1.100"]',
                        '["10.0.0.10"]',
                        "[22]",
                        "[6]",
                        '{"Brute Force": 3}',
                    ),
                )

        repository.link_events_to_incident(
            incident_id=incident_id,
            event_ids=[event.event_id for event in events],
        )

        linked_events = repository.get_incident_events(incident_id)

        assert len(linked_events) == 3

        linked_ids = {
            event.event_id
            for event in linked_events
        }

        expected_ids = {
            event.event_id
            for event in events
        }

        assert linked_ids == expected_ids

    finally:
        for event in events:
            cleanup_event(repository, event.event_id)

        cleanup_incident(repository, incident_id)


def test_duplicate_incident_event_link_is_ignored():
    repository = EventRepository()

    event = make_event()
    incident_id = str(uuid4())

    try:
        repository.save(event)

        incident = make_incident(
            incident_id=incident_id,
            events=[event],
        )

        with repository._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO incidents (
                        incident_id,
                        start_time,
                        end_time,
                        severity,
                        primary_family,
                        confidence,
                        event_count,
                        source_ips,
                        destination_ips,
                        destination_ports,
                        protocols,
                        family_distribution
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s::jsonb,
                        %s::jsonb, %s::jsonb
                    )
                    """,
                    (
                        incident.incident_id,
                        incident.start_time,
                        incident.end_time,
                        incident.severity,
                        incident.primary_attack_family,
                        incident.confidence,
                        len(incident.events),
                        '["192.168.1.100"]',
                        '["10.0.0.10"]',
                        "[22]",
                        "[6]",
                        '{"Brute Force": 1}',
                    ),
                )

        repository.link_to_incident(
            incident_id,
            event.event_id,
        )

        repository.link_to_incident(
            incident_id,
            event.event_id,
        )

        linked_events = repository.get_incident_events(
            incident_id,
        )

        assert len(linked_events) == 1

    finally:
        cleanup_event(repository, event.event_id)
        cleanup_incident(repository, incident_id)


def test_delete_event():
    repository = EventRepository()

    event = make_event()

    repository.save(event)

    assert repository.get_by_id(event.event_id) is not None

    deleted = repository.delete(event.event_id)

    assert deleted is True
    assert repository.get_by_id(event.event_id) is None

    deleted_again = repository.delete(event.event_id)

    assert deleted_again is False