import os
import uuid
from datetime import datetime, timezone

import psycopg
import pytest

from agent.audit.audit_event import AuditEvent
from persistence.audit_repository import AuditRepository


DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://cybersecurity:"
    "cybersecurity_dev_password"
    "@localhost:5432/cybersecurity",
)


@pytest.fixture
def repository():
    repository = AuditRepository(
        DATABASE_URL
    )

    repository.create_table()

    with psycopg.connect(
        DATABASE_URL
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "TRUNCATE TABLE audit_events"
            )

    return repository


def make_event(
    incident_id: str,
    action: str = "test_action",
    status: str = "success",
) -> AuditEvent:
    return AuditEvent(
        audit_id=f"AUD-{uuid.uuid4()}",
        timestamp=datetime.now(
            timezone.utc
        ),
        event_type="test_event",
        actor="test-system",
        incident_id=incident_id,
        action=action,
        status=status,
        reason="Repository integration test.",
        metadata={
            "test": True,
        },
    )


def test_create_table(repository):
    with psycopg.connect(
        DATABASE_URL
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.tables
                    WHERE table_name = 'audit_events'
                )
                """
            )

            row = cursor.fetchone()

    assert row[0] is True


def test_save_and_get_by_id(repository):
    event = make_event(
        "INC-DB-001"
    )

    repository.save(event)

    loaded = repository.get_by_id(
        event.audit_id
    )

    assert loaded is not None
    assert loaded.audit_id == event.audit_id
    assert loaded.event_type == event.event_type
    assert loaded.actor == event.actor
    assert loaded.incident_id == event.incident_id
    assert loaded.action == event.action
    assert loaded.status == event.status
    assert loaded.reason == event.reason
    assert loaded.metadata == event.metadata


def test_get_for_incident(repository):
    incident_id = (
        "INC-DB-002"
    )

    event1 = make_event(
        incident_id,
        action="response_plan_created",
    )

    event2 = make_event(
        incident_id,
        action="approval_created",
    )

    other_event = make_event(
        "INC-DB-OTHER",
        action="unrelated",
    )

    repository.save_batch(
        [
            event1,
            event2,
            other_event,
        ]
    )

    events = repository.get_for_incident(
        incident_id
    )

    assert len(events) == 2

    assert {
        event.action
        for event in events
    } == {
        "response_plan_created",
        "approval_created",
    }


def test_save_batch(repository):
    events = [
        make_event(
            "INC-DB-003",
            action="event_1",
        ),
        make_event(
            "INC-DB-003",
            action="event_2",
        ),
        make_event(
            "INC-DB-003",
            action="event_3",
        ),
    ]

    repository.save_batch(events)

    for event in events:
        assert (
            repository.get_by_id(
                event.audit_id
            )
            is not None
        )


def test_duplicate_audit_id_is_rejected(repository):
    event = make_event(
        "INC-DB-004"
    )

    repository.save(event)

    with pytest.raises(
        psycopg.errors.UniqueViolation
    ):
        repository.save(event)


def test_audit_events_are_append_only(repository):
    event = make_event(
        "INC-DB-005",
        action="original_action",
    )

    repository.save(event)

    loaded = repository.get_by_id(
        event.audit_id
    )

    assert loaded is not None
    assert loaded.action == (
        "original_action"
    )

    # AuditRepository intentionally exposes no
    # update() or delete() operation.
    assert not hasattr(
        repository,
        "update",
    )

    assert not hasattr(
        repository,
        "delete",
    )


def test_recent_events(repository):
    events = [
        make_event(
            "INC-DB-006",
            action="recent_1",
        ),
        make_event(
            "INC-DB-006",
            action="recent_2",
        ),
    ]

    repository.save_batch(events)

    recent = repository.list_recent(
        limit=2
    )

    assert len(recent) == 2


def test_count(repository):
    before = repository.count()

    event = make_event(
        "INC-DB-007"
    )

    repository.save(event)

    after = repository.count()

    assert after == before + 1


def test_invalid_database_url():
    with pytest.raises(
        ValueError,
        match="database_url cannot be empty",
    ):
        AuditRepository("")


def test_invalid_event_is_rejected(repository):
    with pytest.raises(
        TypeError,
        match="event must be an AuditEvent",
    ):
        repository.save(
            "not-an-event"
        )

