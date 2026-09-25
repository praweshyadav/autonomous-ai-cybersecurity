from datetime import datetime, timezone

import pytest

from agent.audit.audit_event import AuditEvent
from agent.audit.audit_logger import AuditLogger


def test_audit_event_creation():
    event = AuditEvent.create(
        audit_id="AUD-001",
        event_type="response_approval",
        actor="analyst@university.edu",
        incident_id="INC-001",
        action="block_source_ip",
        status="approved",
        reason="Evidence reviewed.",
        metadata={
            "source_ips": [
                "10.0.0.10"
            ]
        },
    )

    assert event.audit_id == "AUD-001"
    assert event.event_type == "response_approval"
    assert event.actor == "analyst@university.edu"
    assert event.incident_id == "INC-001"
    assert event.action == "block_source_ip"
    assert event.status == "approved"
    assert event.reason == "Evidence reviewed."
    assert event.metadata["source_ips"] == [
        "10.0.0.10"
    ]
    assert isinstance(
        event.timestamp,
        datetime,
    )
    assert event.timestamp.tzinfo is not None


def test_audit_event_is_immutable():
    event = AuditEvent.create(
        audit_id="AUD-002",
        event_type="test",
        actor="system",
        incident_id="INC-002",
        action="test_action",
        status="success",
    )

    with pytest.raises(
        AttributeError
    ):
        event.status = "changed"


def test_audit_event_to_dict():
    event = AuditEvent(
        audit_id="AUD-003",
        timestamp=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        event_type="response_policy",
        actor="system",
        incident_id="INC-003",
        action="block_source_ip",
        status="allowed",
        reason="High-risk action requires approval.",
        metadata={
            "policy_rule": "HIGH_RISK_APPROVAL_REQUIRED"
        },
    )

    data = event.to_dict()

    assert data["audit_id"] == "AUD-003"
    assert data["timestamp"] == (
        "2026-01-01T00:00:00+00:00"
    )
    assert data["event_type"] == "response_policy"
    assert data["actor"] == "system"
    assert data["incident_id"] == "INC-003"
    assert data["action"] == "block_source_ip"
    assert data["status"] == "allowed"
    assert data["metadata"]["policy_rule"] == (
        "HIGH_RISK_APPROVAL_REQUIRED"
    )


def test_logger_records_events():
    logger = AuditLogger()

    event = AuditEvent.create(
        audit_id="AUD-004",
        event_type="incident_created",
        actor="system",
        incident_id="INC-004",
        action="create_incident",
        status="success",
    )

    recorded = logger.record(event)

    assert recorded is event
    assert logger.count() == 1
    assert logger.get_all() == [event]


def test_logger_log_creates_event():
    logger = AuditLogger()

    event = logger.log(
        audit_id="AUD-005",
        event_type="response_approval",
        actor="analyst@university.edu",
        incident_id="INC-005",
        action="block_source_ip",
        status="approved",
        reason="Approved after evidence review.",
    )

    assert isinstance(
        event,
        AuditEvent,
    )
    assert event.incident_id == "INC-005"
    assert event.status == "approved"
    assert logger.count() == 1


def test_logger_filters_by_incident():
    logger = AuditLogger()

    logger.log(
        audit_id="AUD-006",
        event_type="incident_created",
        actor="system",
        incident_id="INC-A",
        action="create_incident",
        status="success",
    )

    logger.log(
        audit_id="AUD-007",
        event_type="response_policy",
        actor="system",
        incident_id="INC-B",
        action="block_source_ip",
        status="allowed",
    )

    logger.log(
        audit_id="AUD-008",
        event_type="response_approval",
        actor="analyst@university.edu",
        incident_id="INC-A",
        action="block_source_ip",
        status="approved",
    )

    events = logger.get_for_incident(
        "INC-A"
    )

    assert len(events) == 2
    assert all(
        event.incident_id == "INC-A"
        for event in events
    )


def test_unknown_incident_returns_empty_list():
    logger = AuditLogger()

    events = logger.get_for_incident(
        "DOES-NOT-EXIST"
    )

    assert events == []


def test_record_rejects_invalid_event():
    logger = AuditLogger()

    with pytest.raises(
        TypeError,
        match="event must be an AuditEvent",
    ):
        logger.record("not-an-event")
