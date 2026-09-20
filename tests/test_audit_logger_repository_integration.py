import os
import uuid
from datetime import datetime, timezone

import pytest

from agent.audit.audit_event import AuditEvent
from agent.audit.audit_logger import AuditLogger
from persistence.audit_repository import AuditRepository


DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://cybersecurity:cybersecurity_dev_password@localhost:5432/cybersecurity",
)


@pytest.fixture
def repository():
    repo = AuditRepository(DATABASE_URL)
    repo.create_table()
    return repo


def make_event(
    incident_id="INC-INTEGRATION-001",
    event_type="test_event",
):
    return AuditEvent(
        audit_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type=event_type,
        actor="system",
        incident_id=incident_id,
        action="integration_test",
        status="success",
        reason="Audit logger integration test",
        metadata={
            "test": True,
            "component": "AuditLogger",
        },
    )


def test_logger_persists_event_to_repository(repository):
    logger = AuditLogger(repository=repository)

    event = make_event()

    recorded = logger.record(event)

    assert recorded == event
    assert logger.count() == 1

    persisted = repository.get_by_id(event.audit_id)

    assert persisted is not None
    assert persisted.audit_id == event.audit_id
    assert persisted.incident_id == event.incident_id
    assert persisted.event_type == event.event_type
    assert persisted.actor == event.actor
    assert persisted.action == event.action
    assert persisted.status == event.status
    assert persisted.reason == event.reason
    assert persisted.metadata == event.metadata


def test_logger_log_persists_event_to_repository(repository):
    logger = AuditLogger(repository=repository)

    audit_id = str(uuid.uuid4())

    event = logger.log(
        audit_id=audit_id,
        event_type="response_plan_created",
        actor="system",
        incident_id="INC-INTEGRATION-002",
        action="create_response_plan",
        status="pending_approval",
        reason="Integration test",
        metadata={
            "severity": "high",
            "approval_required": True,
        },
    )

    persisted = repository.get_by_id(audit_id)

    assert persisted is not None
    assert persisted.audit_id == audit_id
    assert persisted.event_type == "response_plan_created"
    assert persisted.incident_id == "INC-INTEGRATION-002"
    assert persisted.metadata["severity"] == "high"
    assert persisted.metadata["approval_required"] is True


def test_logger_without_repository_still_works():
    logger = AuditLogger()

    event = make_event(
        incident_id="INC-NO-REPOSITORY-001",
    )

    recorded = logger.record(event)

    assert recorded == event
    assert logger.count() == 1
    assert logger.get_all() == [event]
    assert logger.repository is None


def test_logger_repository_property(repository):
    logger = AuditLogger(repository=repository)

    assert logger.repository is repository


def test_persisted_events_can_be_retrieved_by_incident(repository):
    logger = AuditLogger(repository=repository)

    incident_id = "INC-INTEGRATION-003"

    event1 = make_event(
        incident_id=incident_id,
        event_type="response_plan_created",
    )

    event2 = make_event(
        incident_id=incident_id,
        event_type="response_policy",
    )

    logger.record(event1)
    logger.record(event2)

    persisted_events = repository.get_for_incident(incident_id)

    persisted_ids = {event.audit_id for event in persisted_events}

    assert event1.audit_id in persisted_ids
    assert event2.audit_id in persisted_ids
