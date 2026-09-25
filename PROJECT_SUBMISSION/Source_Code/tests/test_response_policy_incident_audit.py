from agent.audit.audit_logger import AuditLogger
from agent.response.response_plan import (
    ResponseAction,
    ResponsePlan,
)
from agent.response.response_policy import (
    ResponsePolicy,
)


def test_policy_plan_audit_contains_incident_id():
    audit_logger = AuditLogger()

    policy = ResponsePolicy(
        audit_logger=audit_logger
    )

    plan = ResponsePlan(
        incident_id="INC-POLICY-001",
        severity="high",
        actions=[
            ResponseAction(
                action_type="collect_more_evidence",
                reason="Gather additional evidence.",
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

    events = audit_logger.get_for_incident(
        "INC-POLICY-001"
    )

    assert len(events) == 2

    assert events[0].incident_id == (
        "INC-POLICY-001"
    )

    assert events[1].incident_id == (
        "INC-POLICY-001"
    )

    assert events[0].action == (
        "collect_more_evidence"
    )

    assert events[1].action == (
        "block_source_ip"
    )


def test_policy_plan_audit_preserves_policy_rule():
    audit_logger = AuditLogger()

    policy = ResponsePolicy(
        audit_logger=audit_logger
    )

    plan = ResponsePlan(
        incident_id="INC-POLICY-002",
        severity="high",
        actions=[
            ResponseAction(
                action_type="block_source_ip",
                reason="Malicious source detected.",
                risk_level="high",
                requires_approval=True,
                parameters={
                    "source_ips": ["10.0.0.10"]
                },
            )
        ],
    )

    policy.evaluate_plan(plan)

    events = audit_logger.get_for_incident(
        "INC-POLICY-002"
    )

    assert len(events) == 1

    event = events[0]

    assert event.metadata["policy_rule"] == (
        "HIGH_RISK_APPROVAL_REQUIRED"
    )

    assert event.metadata["policy_version"] == "1.0"

    assert event.metadata[
        "requires_approval"
    ] is True


def test_direct_action_audit_has_no_fake_incident_id():
    audit_logger = AuditLogger()

    policy = ResponsePolicy(
        audit_logger=audit_logger
    )

    action = ResponseAction(
        action_type="block_source_ip",
        reason="Test action.",
        risk_level="high",
        requires_approval=True,
        parameters={
            "source_ips": ["10.0.0.10"]
        },
    )

    policy.evaluate_action(action)

    events = audit_logger.get_all()

    assert len(events) == 1

    # We deliberately do not fabricate an incident ID.
    assert events[0].incident_id == ""


def test_invalid_plan_is_rejected():
    policy = ResponsePolicy()

    try:
        policy.evaluate_plan("not-a-plan")
    except TypeError as exc:
        assert str(exc) == (
            "plan must be a ResponsePlan."
        )
    else:
        raise AssertionError(
            "Expected TypeError."
        )


def test_empty_plan_incident_id_is_rejected():
    policy = ResponsePolicy()

    plan = ResponsePlan(
        incident_id="",
        severity="high",
        actions=[],
    )

    try:
        policy.evaluate_plan(plan)
    except ValueError as exc:
        assert str(exc) == (
            "plan.incident_id must be a non-empty string."
        )
    else:
        raise AssertionError(
            "Expected ValueError."
        )
