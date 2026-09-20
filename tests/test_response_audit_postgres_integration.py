import os
from datetime import datetime, timezone

from agent.audit.audit_logger import AuditLogger
from agent.llm_contract import LLMInvestigationOutput
from agent.response.response_plan import (
    ResponseAction,
    ResponsePlanner,
)
from agent.response.response_policy import ResponsePolicy
from agent.response.approval import ApprovalManager
from correlation.schema import Incident
from persistence.audit_repository import AuditRepository


DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql://cybersecurity:cybersecurity_dev_password@localhost:5432/cybersecurity",
)


def make_incident():
    return Incident(
        incident_id="INC-RESPONSE-POSTGRES-001",
        events=[],
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 5},
        confidence=0.95,
        src_ips=["192.168.1.100"],
        dst_ips=["10.0.0.5"],
        dst_ports=[22],
        protocols=[6],
    )


def make_investigation(incident_id):
    return LLMInvestigationOutput(
        incident_id=incident_id,
        summary="Brute Force activity detected.",
        threat_assessment="High risk activity requires investigation.",
        recommended_actions=[
            "block source ip",
        ],
        confidence=0.90,
    )


def make_block_action():
    return ResponseAction(
        action_type="block_source_ip",
        reason="Block the identified source IP.",
        risk_level="high",
        requires_approval=True,
        parameters={
            "source_ips": ["192.168.1.100"],
        },
    )


def test_response_planner_persists_audit_event():
    repository = AuditRepository(DATABASE_URL)
    repository.create_table()

    logger = AuditLogger(repository=repository)

    incident = make_incident()
    investigation = make_investigation(incident.incident_id)

    planner = ResponsePlanner(audit_logger=logger)

    plan = planner.build_plan(
        incident=incident,
        investigation=investigation,
    )

    assert plan.incident_id == incident.incident_id

    events = repository.get_for_incident(
        incident.incident_id
    )

    matching = [
        event
        for event in events
        if event.event_type == "response_plan_created"
    ]

    assert matching

    event = matching[-1]

    assert event.actor == "system"
    assert event.action == "create_response_plan"
    assert event.status == "pending_approval"
    assert event.metadata["severity"] == "high"
    assert event.metadata["approval_required"] is True


def test_response_policy_persists_audit_event():
    repository = AuditRepository(DATABASE_URL)
    repository.create_table()

    logger = AuditLogger(repository=repository)

    incident = make_incident()
    investigation = make_investigation(incident.incident_id)

    planner = ResponsePlanner(audit_logger=logger)

    plan = planner.build_plan(
        incident=incident,
        investigation=investigation,
    )

    policy = ResponsePolicy(audit_logger=logger)

    decisions = policy.evaluate_plan(plan)

    assert decisions

    events = repository.get_for_incident(
        incident.incident_id
    )

    matching = [
        event
        for event in events
        if event.event_type == "response_policy"
    ]

    assert matching

    event = matching[-1]

    assert event.incident_id == incident.incident_id
    assert event.actor == "system"
    assert event.status == "allowed"
    assert event.metadata["policy_version"] == "1.0"


def test_approval_manager_persists_creation_and_decision():
    repository = AuditRepository(DATABASE_URL)
    repository.create_table()

    logger = AuditLogger(repository=repository)

    manager = ApprovalManager(audit_logger=logger)

    approval = manager.create_pending(
        approval_id="APR-POSTGRES-001",
        incident_id="INC-RESPONSE-POSTGRES-002",
        action=make_block_action(),
    )

    assert approval.decision == manager.PENDING

    approved = manager.approve(
        approval_id="APR-POSTGRES-001",
        approver="security-analyst",
        reason="Approved after reviewing the incident evidence.",
    )

    assert approved.decision == manager.APPROVED

    events = repository.get_for_incident(
        "INC-RESPONSE-POSTGRES-002"
    )

    event_types = [
        event.event_type
        for event in events
    ]

    assert "approval_created" in event_types
    assert "approval_approved" in event_types

    creation_event = next(
        event
        for event in events
        if event.event_type == "approval_created"
    )

    approval_event = next(
        event
        for event in events
        if event.event_type == "approval_approved"
    )

    assert creation_event.actor == "system"
    assert creation_event.status == "pending"

    assert approval_event.actor == "security-analyst"
    assert approval_event.status == "approved"
    assert approval_event.metadata["approval_id"] == "APR-POSTGRES-001"


def test_complete_response_audit_trail_is_persisted():
    repository = AuditRepository(DATABASE_URL)
    repository.create_table()

    logger = AuditLogger(repository=repository)

    incident = make_incident()
    investigation = make_investigation(incident.incident_id)

    planner = ResponsePlanner(audit_logger=logger)

    plan = planner.build_plan(
        incident=incident,
        investigation=investigation,
    )

    policy = ResponsePolicy(audit_logger=logger)

    decisions = policy.evaluate_plan(plan)

    assert len(decisions) == len(plan.actions)

    manager = ApprovalManager(audit_logger=logger)

    approval = manager.create_pending(
        approval_id="APR-POSTGRES-002",
        incident_id=incident.incident_id,
        action=plan.actions[0],
    )

    manager.approve(
        approval_id=approval.approval_id,
        approver="security-analyst",
        reason="Approved for controlled response.",
    )

    events = repository.get_for_incident(
        incident.incident_id
    )

    event_types = [
        event.event_type
        for event in events
    ]

    assert "response_plan_created" in event_types
    assert "response_policy" in event_types
    assert "approval_created" in event_types
    assert "approval_approved" in event_types

    assert len(events) >= 4
