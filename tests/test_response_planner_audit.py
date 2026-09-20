from agent.audit.audit_logger import AuditLogger
from agent.llm_contract import LLMInvestigationOutput
from agent.response.response_plan import ResponsePlanner
from correlation.schema import Incident


def build_incident():
    return Incident(
        incident_id="INC-PLANNER-AUDIT-001",
        events=[],
        start_time=None,
        end_time=None,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 5},
        confidence=0.95,
        src_ips=["10.0.0.10"],
        dst_ips=["192.168.1.10"],
        dst_ports=[22],
        protocols=[6],
    )


def build_investigation():
    return LLMInvestigationOutput(
        incident_id="INC-PLANNER-AUDIT-001",
        summary="Brute force activity detected.",
        threat_assessment="High risk activity.",
        recommended_actions=[
            "Block source IP addresses."
        ],
        confidence=0.9,
    )


def test_response_plan_creation_is_audited():
    audit_logger = AuditLogger()

    planner = ResponsePlanner(
        audit_logger=audit_logger
    )

    plan = planner.build_plan(
        incident=build_incident(),
        investigation=build_investigation(),
    )

    events = audit_logger.get_for_incident(
        "INC-PLANNER-AUDIT-001"
    )

    assert len(events) == 1

    event = events[0]

    assert event.event_type == (
        "response_plan_created"
    )

    assert event.actor == "system"

    assert event.action == (
        "create_response_plan"
    )

    assert event.status == (
        "pending_approval"
    )

    assert event.metadata["severity"] == "high"

    assert event.metadata["action_types"] == [
        "block_source_ip"
    ]

    assert event.metadata[
        "approval_required"
    ] is True

    assert plan.incident_id == (
        "INC-PLANNER-AUDIT-001"
    )


def test_unknown_recommendation_is_recorded_as_ignored():
    audit_logger = AuditLogger()

    planner = ResponsePlanner(
        audit_logger=audit_logger
    )

    investigation = LLMInvestigationOutput(
        incident_id="INC-PLANNER-AUDIT-002",
        summary="Investigation completed.",
        threat_assessment="Uncertain.",
        recommended_actions=[
            "delete the entire server immediately",
        ],
        confidence=0.5,
    )

    incident = Incident(
        incident_id="INC-PLANNER-AUDIT-002",
        events=[],
        start_time=None,
        end_time=None,
        severity="medium",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 1},
        confidence=0.5,
        src_ips=["10.0.0.20"],
        dst_ips=["192.168.1.20"],
        dst_ports=[22],
        protocols=[6],
    )

    plan = planner.build_plan(
        incident=incident,
        investigation=investigation,
    )

    events = audit_logger.get_for_incident(
        "INC-PLANNER-AUDIT-002"
    )

    assert len(events) == 1

    event = events[0]

    assert event.metadata[
        "llm_recommendation_count"
    ] == 1

    assert event.metadata[
        "recognized_action_count"
    ] == 1

    assert event.metadata[
        "ignored_recommendation_count"
    ] == 1

    assert plan.actions[0].action_type == (
        "collect_more_evidence"
    )


def test_planner_without_audit_logger_still_works():
    planner = ResponsePlanner()

    plan = planner.build_plan(
        incident=build_incident(),
        investigation=build_investigation(),
    )

    assert plan.incident_id == (
        "INC-PLANNER-AUDIT-001"
    )

    assert len(plan.actions) == 1

    assert plan.actions[0].action_type == (
        "block_source_ip"
    )


def test_planner_audit_does_not_execute_action():
    audit_logger = AuditLogger()

    planner = ResponsePlanner(
        audit_logger=audit_logger
    )

    plan = planner.build_plan(
        incident=build_incident(),
        investigation=build_investigation(),
    )

    assert plan.actions[0].action_type == (
        "block_source_ip"
    )

    event = audit_logger.get_all()[0]

    assert event.event_type == (
        "response_plan_created"
    )

    # The planner only creates a plan.
    # No firewall/API/system action is executed.
    assert event.status == (
        "pending_approval"
    )


def test_multiple_recognized_actions_are_audited():
    audit_logger = AuditLogger()

    planner = ResponsePlanner(
        audit_logger=audit_logger
    )

    investigation = LLMInvestigationOutput(
        incident_id="INC-PLANNER-AUDIT-003",
        summary="Multiple response options identified.",
        threat_assessment="High risk.",
        recommended_actions=[
            "Collect more evidence.",
            "Rate limit source traffic.",
            "Block source IP addresses.",
        ],
        confidence=0.9,
    )

    incident = Incident(
        incident_id="INC-PLANNER-AUDIT-003",
        events=[],
        start_time=None,
        end_time=None,
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        family_distribution={"Brute Force": 10},
        confidence=0.9,
        src_ips=["10.0.0.30"],
        dst_ips=["192.168.1.30"],
        dst_ports=[22],
        protocols=[6],
    )

    plan = planner.build_plan(
        incident=incident,
        investigation=investigation,
    )

    assert len(plan.actions) == 3

    events = audit_logger.get_for_incident(
        "INC-PLANNER-AUDIT-003"
    )

    assert len(events) == 1

    event = events[0]

    assert event.metadata[
        "recognized_action_count"
    ] == 3

    assert event.metadata[
        "llm_recommendation_count"
    ] == 3

    assert event.metadata[
        "ignored_recommendation_count"
    ] == 0

    assert event.metadata["action_types"] == [
        "collect_more_evidence",
        "rate_limit_source",
        "block_source_ip",
    ]
