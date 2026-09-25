from agent.audit.audit_logger import AuditLogger
from agent.response.response_plan import (
    ResponseAction,
    ResponsePlan,
)
from agent.response.response_policy import (
    ResponsePolicy,
)


def test_policy_decision_is_audited():
    audit_logger = AuditLogger()

    policy = ResponsePolicy(
        audit_logger=audit_logger
    )

    action = ResponseAction(
        action_type="block_source_ip",
        reason="Repeated malicious activity.",
        risk_level="high",
        requires_approval=True,
        parameters={
            "source_ips": ["10.0.0.10"]
        },
    )

    decision = policy.evaluate_action(action)

    assert decision.allowed is True
    assert decision.requires_approval is True
    assert (
        decision.policy_rule
        == "HIGH_RISK_APPROVAL_REQUIRED"
    )

    events = audit_logger.get_all()

    assert len(events) == 1

    event = events[0]

    assert event.event_type == "response_policy"
    assert event.actor == "system"
    assert event.action == "block_source_ip"
    assert event.status == "allowed"
    assert event.metadata["policy_rule"] == (
        "HIGH_RISK_APPROVAL_REQUIRED"
    )
    assert event.metadata["policy_version"] == "1.0"


def test_denied_policy_decision_is_audited():
    audit_logger = AuditLogger()

    policy = ResponsePolicy(
        audit_logger=audit_logger
    )

    action = ResponseAction(
        action_type="delete_everything",
        reason="Unknown action.",
        risk_level="high",
        requires_approval=True,
    )

    decision = policy.evaluate_action(action)

    assert decision.allowed is False
    assert (
        decision.policy_rule
        == "UNKNOWN_ACTION_DENIED"
    )

    events = audit_logger.get_all()

    assert len(events) == 1

    event = events[0]

    assert event.status == "denied"
    assert event.action == "delete_everything"
    assert event.metadata["policy_rule"] == (
        "UNKNOWN_ACTION_DENIED"
    )


def test_policy_without_audit_logger_still_works():
    policy = ResponsePolicy()

    action = ResponseAction(
        action_type="collect_more_evidence",
        reason="Need additional evidence.",
        risk_level="low",
        requires_approval=False,
    )

    decision = policy.evaluate_action(action)

    assert decision.allowed is True
    assert decision.requires_approval is False
    assert (
        decision.policy_rule
        == "LOW_RISK_AUTO_ALLOWED"
    )


def test_plan_policy_evaluation_audits_every_action():
    audit_logger = AuditLogger()

    policy = ResponsePolicy(
        audit_logger=audit_logger
    )

    plan = ResponsePlan(
        incident_id="INC-POLICY-AUDIT-001",
        severity="high",
        actions=[
            ResponseAction(
                action_type="collect_more_evidence",
                reason="Gather more evidence.",
                risk_level="low",
                requires_approval=False,
            ),
            ResponseAction(
                action_type="block_source_ip",
                reason="Block malicious source.",
                risk_level="high",
                requires_approval=True,
                parameters={
                    "source_ips": ["10.0.0.10"]
                },
            ),
        ],
    )

    decisions = policy.evaluate_plan(plan)

    assert len(decisions) == 2
    assert len(audit_logger.get_all()) == 2

    assert (
        audit_logger.get_all()[0].action
        == "collect_more_evidence"
    )

    assert (
        audit_logger.get_all()[1].action
        == "block_source_ip"
    )


def test_policy_audit_does_not_execute_action():
    audit_logger = AuditLogger()

    policy = ResponsePolicy(
        audit_logger=audit_logger
    )

    action = ResponseAction(
        action_type="isolate_host",
        reason="Potential compromise.",
        risk_level="high",
        requires_approval=True,
        parameters={
            "destination_ips": [
                "192.168.1.10"
            ]
        },
    )

    policy.evaluate_action(action)

    # The policy layer only records a decision.
    # No execution mechanism exists here.
    assert action.action_type == "isolate_host"

    event = audit_logger.get_all()[0]

    assert event.event_type == "response_policy"
    assert event.status == "allowed"
