from agent.response.response_plan import (
    ResponseAction,
    ResponsePlan,
)
from agent.response.response_policy import (
    ResponsePolicy,
)


def create_action(
    action_type,
    risk_level,
    requires_approval,
):
    return ResponseAction(
        action_type=action_type,
        reason="test",
        risk_level=risk_level,
        requires_approval=requires_approval,
        parameters={},
    )


def test_low_risk_action_is_allowed_without_approval():
    policy = ResponsePolicy()

    action = create_action(
        "collect_more_evidence",
        "low",
        False,
    )

    decision = policy.evaluate_action(action)

    assert decision.allowed is True
    assert decision.requires_approval is False
    assert decision.policy_rule == (
        "LOW_RISK_AUTO_ALLOWED"
    )


def test_medium_risk_action_requires_approval():
    policy = ResponsePolicy()

    action = create_action(
        "rate_limit_source",
        "medium",
        True,
    )

    decision = policy.evaluate_action(action)

    assert decision.allowed is True
    assert decision.requires_approval is True
    assert decision.policy_rule == (
        "MEDIUM_RISK_APPROVAL_REQUIRED"
    )


def test_high_risk_action_requires_approval():
    policy = ResponsePolicy()

    action = create_action(
        "block_source_ip",
        "high",
        True,
    )

    decision = policy.evaluate_action(action)

    assert decision.allowed is True
    assert decision.requires_approval is True
    assert decision.policy_rule == (
        "HIGH_RISK_APPROVAL_REQUIRED"
    )


def test_unknown_action_is_denied():
    policy = ResponsePolicy()

    action = create_action(
        "execute_arbitrary_command",
        "high",
        True,
    )

    decision = policy.evaluate_action(action)

    assert decision.allowed is False
    assert decision.requires_approval is True
    assert decision.policy_rule == (
        "UNKNOWN_ACTION_DENIED"
    )


def test_plan_evaluates_all_actions():
    policy = ResponsePolicy()

    plan = ResponsePlan(
        incident_id="INC-POLICY-001",
        severity="high",
        actions=[
            create_action(
                "collect_more_evidence",
                "low",
                False,
            ),
            create_action(
                "block_source_ip",
                "high",
                True,
            ),
        ],
    )

    decisions = policy.evaluate_plan(plan)

    assert len(decisions) == 2
    assert decisions[0].allowed is True
    assert decisions[0].requires_approval is False
    assert decisions[1].allowed is True
    assert decisions[1].requires_approval is True
