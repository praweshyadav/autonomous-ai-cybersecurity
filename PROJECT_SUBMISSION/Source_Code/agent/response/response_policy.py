from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from agent.audit.audit_logger import AuditLogger
from agent.response.response_plan import ResponseAction, ResponsePlan


@dataclass(frozen=True)
class PolicyDecision:
    action_type: str
    allowed: bool
    requires_approval: bool
    reason: str
    policy_rule: str
    metadata: dict[str, Any]


class ResponsePolicy:
    POLICY_VERSION = "1.0"

    LOW_RISK_ACTIONS = {
        "collect_more_evidence",
    }

    MEDIUM_RISK_ACTIONS = {
        "rate_limit_source",
    }

    HIGH_RISK_ACTIONS = {
        "block_source_ip",
        "isolate_host",
        "disable_account",
    }

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
    ):
        self.audit_logger = audit_logger

    def evaluate_action(
        self,
        action: ResponseAction,
    ) -> PolicyDecision:
        """
        Evaluate one response action.

        This method does not have incident context, so an audit
        event created here cannot reliably contain an incident ID.
        """

        decision = self._evaluate(action)

        self._audit_action(
            action=action,
            decision=decision,
            incident_id="",
        )

        return decision

    def evaluate_plan(
        self,
        plan: ResponsePlan,
    ) -> list[PolicyDecision]:
        """
        Evaluate every action in a response plan.

        Because ResponsePlan contains the incident ID, audit events
        created through this method are correctly associated with
        the incident.
        """

        if not isinstance(
            plan,
            ResponsePlan,
        ):
            raise TypeError(
                "plan must be a ResponsePlan."
            )

        if not isinstance(
            plan.incident_id,
            str,
        ) or not plan.incident_id.strip():
            raise ValueError(
                "plan.incident_id must be a non-empty string."
            )

        decisions: list[PolicyDecision] = []

        for action in plan.actions:
            decision = self._evaluate(action)

            self._audit_action(
                action=action,
                decision=decision,
                incident_id=plan.incident_id,
            )

            decisions.append(decision)

        return decisions

    def _evaluate(
        self,
        action: ResponseAction,
    ) -> PolicyDecision:
        if not isinstance(
            action,
            ResponseAction,
        ):
            raise TypeError(
                "action must be a ResponseAction."
            )

        if action.action_type in self.LOW_RISK_ACTIONS:
            return PolicyDecision(
                action_type=action.action_type,
                allowed=True,
                requires_approval=False,
                reason=(
                    "Low-risk evidence collection "
                    "is allowed automatically."
                ),
                policy_rule="LOW_RISK_AUTO_ALLOWED",
                metadata={
                    "policy_version": self.POLICY_VERSION,
                    "risk_level": action.risk_level,
                },
            )

        if action.action_type in self.MEDIUM_RISK_ACTIONS:
            return PolicyDecision(
                action_type=action.action_type,
                allowed=True,
                requires_approval=True,
                reason=(
                    "Medium-risk response requires "
                    "human approval."
                ),
                policy_rule="MEDIUM_RISK_APPROVAL_REQUIRED",
                metadata={
                    "policy_version": self.POLICY_VERSION,
                    "risk_level": action.risk_level,
                },
            )

        if action.action_type in self.HIGH_RISK_ACTIONS:
            return PolicyDecision(
                action_type=action.action_type,
                allowed=True,
                requires_approval=True,
                reason=(
                    "High-risk response requires "
                    "human approval."
                ),
                policy_rule="HIGH_RISK_APPROVAL_REQUIRED",
                metadata={
                    "policy_version": self.POLICY_VERSION,
                    "risk_level": action.risk_level,
                },
            )

        return PolicyDecision(
            action_type=action.action_type,
            allowed=False,
            requires_approval=True,
            reason=(
                "Unknown response action is denied."
            ),
            policy_rule="UNKNOWN_ACTION_DENIED",
            metadata={
                "policy_version": self.POLICY_VERSION,
                "risk_level": action.risk_level,
            },
        )

    def _audit_action(
        self,
        action: ResponseAction,
        decision: PolicyDecision,
        incident_id: str,
    ) -> None:
        """
        Record the policy decision.

        This records a decision only. It never executes the action.
        """

        if self.audit_logger is None:
            return

        self.audit_logger.log(
            audit_id=f"AUD-{uuid4()}",
            event_type="response_policy",
            actor="system",
            incident_id=incident_id,
            action=action.action_type,
            status=(
                "allowed"
                if decision.allowed
                else "denied"
            ),
            reason=decision.reason,
            metadata={
                "policy_rule": decision.policy_rule,
                "policy_version": self.POLICY_VERSION,
                "requires_approval": (
                    decision.requires_approval
                ),
            },
        )
