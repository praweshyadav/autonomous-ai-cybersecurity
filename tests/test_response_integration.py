from datetime import datetime, timezone

from agent.llm_contract import LLMInvestigationOutput
from agent.response.approval import ApprovalManager
from agent.response.response_plan import ResponsePlanner
from agent.response.response_policy import ResponsePolicy
from correlation.schema import Incident, SecurityEvent


def create_incident():
    incident = Incident(
        incident_id="INC-RESPONSE-INTEGRATION-001",
        severity="high",
    )

    incident.add_event(
        SecurityEvent(
            event_id="EVT-RESPONSE-001",
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


def test_response_pipeline_requires_human_approval():
    incident = create_incident()

    investigation = LLMInvestigationOutput(
        incident_id=incident.incident_id,
        summary="Brute Force activity detected.",
        threat_assessment=(
            "The incident is consistent with Brute Force activity."
        ),
        recommended_actions=[
            "Block source IP addresses."
        ],
        confidence=0.9,
    )

    planner = ResponsePlanner()
    policy = ResponsePolicy()
    approval_manager = ApprovalManager()

    plan = planner.build_plan(
        incident,
        investigation,
    )

    assert len(plan.actions) == 1

    action = plan.actions[0]

    assert action.action_type == "block_source_ip"
    assert action.parameters["source_ips"] == [
        "10.0.0.10"
    ]

    decisions = policy.evaluate_plan(plan)

    assert len(decisions) == 1

    decision = decisions[0]

    assert decision.allowed is True
    assert decision.requires_approval is True

    approval = approval_manager.create_pending(
        approval_id="APR-RESPONSE-001",
        incident_id=incident.incident_id,
        action=action,
    )

    assert approval.decision == "pending"
    assert approval_manager.is_approved(
        "APR-RESPONSE-001"
    ) is False

    approved = approval_manager.approve(
        approval_id="APR-RESPONSE-001",
        approver="analyst@university.edu",
        reason="Reviewed incident evidence.",
    )

    assert approved.decision == "approved"
    assert approved.incident_id == incident.incident_id
    assert approved.action_type == "block_source_ip"
    assert approval_manager.is_approved(
        "APR-RESPONSE-001"
    ) is True


def test_unknown_llm_recommendation_never_reaches_approval():
    incident = create_incident()

    investigation = LLMInvestigationOutput(
        incident_id=incident.incident_id,
        summary="Suspicious activity detected.",
        threat_assessment="Further investigation is required.",
        recommended_actions=[
            "Execute arbitrary shell command and delete files."
        ],
        confidence=0.8,
    )

    planner = ResponsePlanner()
    policy = ResponsePolicy()

    plan = planner.build_plan(
        incident,
        investigation,
    )

    assert len(plan.actions) == 1

    action = plan.actions[0]

    assert action.action_type == "collect_more_evidence"

    decisions = policy.evaluate_plan(plan)

    assert len(decisions) == 1
    assert decisions[0].allowed is True
    assert decisions[0].requires_approval is False
