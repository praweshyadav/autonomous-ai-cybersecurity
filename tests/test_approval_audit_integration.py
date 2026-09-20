from agent.audit.audit_logger import AuditLogger
from agent.response.approval import ApprovalManager
from agent.response.response_plan import ResponseAction


def build_action():
    return ResponseAction(
        action_type="block_source_ip",
        reason="Repeated malicious activity.",
        risk_level="high",
        requires_approval=True,
        parameters={
            "source_ips": ["10.0.0.10"]
        },
    )


def test_approval_creation_is_audited():
    audit_logger = AuditLogger()
    manager = ApprovalManager(
        audit_logger=audit_logger
    )

    manager.create_pending(
        approval_id="APR-001",
        incident_id="INC-AUDIT-001",
        action=build_action(),
    )

    events = audit_logger.get_for_incident(
        "INC-AUDIT-001"
    )

    assert len(events) == 1

    event = events[0]

    assert event.event_type == "approval_created"
    assert event.actor == "system"
    assert event.action == "block_source_ip"
    assert event.status == "pending"
    assert event.metadata["approval_id"] == "APR-001"


def test_approval_decision_is_audited():
    audit_logger = AuditLogger()
    manager = ApprovalManager(
        audit_logger=audit_logger
    )

    manager.create_pending(
        approval_id="APR-002",
        incident_id="INC-AUDIT-002",
        action=build_action(),
    )

    manager.approve(
        approval_id="APR-002",
        approver="analyst@university.edu",
        reason="Evidence reviewed and action approved.",
    )

    events = audit_logger.get_for_incident(
        "INC-AUDIT-002"
    )

    assert len(events) == 2

    creation_event = events[0]
    approval_event = events[1]

    assert creation_event.event_type == (
        "approval_created"
    )

    assert approval_event.event_type == (
        "approval_approved"
    )

    assert approval_event.actor == (
        "analyst@university.edu"
    )

    assert approval_event.action == (
        "block_source_ip"
    )

    assert approval_event.status == "approved"

    assert approval_event.reason == (
        "Evidence reviewed and action approved."
    )

    assert approval_event.metadata[
        "approval_id"
    ] == "APR-002"


def test_rejection_is_audited():
    audit_logger = AuditLogger()
    manager = ApprovalManager(
        audit_logger=audit_logger
    )

    manager.create_pending(
        approval_id="APR-003",
        incident_id="INC-AUDIT-003",
        action=build_action(),
    )

    manager.reject(
        approval_id="APR-003",
        approver="analyst@university.edu",
        reason="Insufficient evidence.",
    )

    events = audit_logger.get_for_incident(
        "INC-AUDIT-003"
    )

    assert len(events) == 2

    rejection_event = events[1]

    assert rejection_event.event_type == (
        "approval_rejected"
    )

    assert rejection_event.actor == (
        "analyst@university.edu"
    )

    assert rejection_event.status == "rejected"

    assert rejection_event.reason == (
        "Insufficient evidence."
    )


def test_approval_without_audit_logger_still_works():
    manager = ApprovalManager()

    record = manager.create_pending(
        approval_id="APR-004",
        incident_id="INC-AUDIT-004",
        action=build_action(),
    )

    manager.approve(
        approval_id="APR-004",
        approver="analyst",
        reason="Approved.",
    )

    assert record.decision == "approved"
    assert manager.is_approved("APR-004")


def test_audit_events_are_not_created_for_failed_approval():
    audit_logger = AuditLogger()
    manager = ApprovalManager(
        audit_logger=audit_logger
    )

    manager.create_pending(
        approval_id="APR-005",
        incident_id="INC-AUDIT-005",
        action=build_action(),
    )

    try:
        manager.approve(
            approval_id="APR-005",
            approver="",
            reason="Invalid approver.",
        )
    except ValueError:
        pass

    events = audit_logger.get_for_incident(
        "INC-AUDIT-005"
    )

    assert len(events) == 1
    assert events[0].event_type == (
        "approval_created"
    )
