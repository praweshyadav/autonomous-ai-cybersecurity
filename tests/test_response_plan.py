from datetime import datetime, timezone

import pytest

from agent.llm_contract import LLMInvestigationOutput
from agent.response.response_plan import ResponsePlanner
from correlation.schema import Incident, SecurityEvent


def create_incident():
    incident = Incident(
        incident_id="INC-RESPONSE-001",
        severity="high",
    )

    incident.add_event(
        SecurityEvent(
            event_id="EVT-001",
            timestamp=datetime.now(timezone.utc),
            src_ip="10.0.0.10",
            dst_ip="192.168.1.10",
            dst_port=22,
            protocol=6,
            binary_prediction=1,
            attack_family="Brute Force",
            confidence=0.95,
            event_type="network_flow",
        )
    )

    incident.primary_attack_family = "Brute Force"
    incident.confidence = 0.95

    return incident


def create_investigation(recommendations):
    return LLMInvestigationOutput(
        incident_id="INC-RESPONSE-001",
        summary="Brute Force activity detected.",
        threat_assessment=(
            "The incident is consistent with Brute Force activity."
        ),
        recommended_actions=recommendations,
        confidence=0.9,
    )


def test_block_source_ip_requires_approval():
    incident = create_incident()

    investigation = create_investigation(
        ["Block source IP addresses."]
    )

    planner = ResponsePlanner()

    plan = planner.build_plan(
        incident,
        investigation,
    )

    assert len(plan.actions) == 1

    action = plan.actions[0]

    assert action.action_type == "block_source_ip"
    assert action.risk_level == "high"
    assert action.requires_approval is True
    assert action.parameters["source_ips"] == ["10.0.0.10"]
    assert plan.approval_required is True
    assert plan.status == "pending_approval"


def test_rate_limit_source_requires_approval():
    incident = create_incident()

    investigation = create_investigation(
        ["Apply rate limiting to the source."]
    )

    planner = ResponsePlanner()

    plan = planner.build_plan(
        incident,
        investigation,
    )

    action = plan.actions[0]

    assert action.action_type == "rate_limit_source"
    assert action.risk_level == "medium"
    assert action.requires_approval is True


def test_unknown_llm_action_is_not_executable():
    incident = create_incident()

    investigation = create_investigation(
        [
            "Run this arbitrary shell command "
            "to destroy the attacker."
        ]
    )

    planner = ResponsePlanner()

    plan = planner.build_plan(
        incident,
        investigation,
    )

    assert len(plan.actions) == 1

    action = plan.actions[0]

    assert action.action_type == "collect_more_evidence"
    assert action.risk_level == "low"


def test_block_source_ip_without_source_ip_is_not_created():
    incident = create_incident()
    incident.src_ips.clear()

    investigation = create_investigation(
        ["Block source IP addresses."]
    )

    planner = ResponsePlanner()

    plan = planner.build_plan(
        incident,
        investigation,
    )

    assert len(plan.actions) == 1
    assert plan.actions[0].action_type == "collect_more_evidence"


def test_incident_id_mismatch_is_rejected():
    incident = create_incident()

    investigation = create_investigation(
        ["Block source IP addresses."]
    )

    investigation.incident_id = "INC-DIFFERENT"

    planner = ResponsePlanner()

    with pytest.raises(
        ValueError,
        match="Incident ID mismatch",
    ):
        planner.build_plan(
            incident,
            investigation,
        )
