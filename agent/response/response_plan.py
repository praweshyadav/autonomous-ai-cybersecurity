from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from correlation.schema import Incident
from agent.audit.audit_logger import AuditLogger
from agent.llm_contract import LLMInvestigationOutput


@dataclass(frozen=True)
class ResponseAction:
    """
    A normalized response action.

    The action is selected from a controlled allowlist.
    The LLM never directly creates executable actions.
    """

    action_type: str
    reason: str
    risk_level: str
    requires_approval: bool
    parameters: dict[str, Any] = field(
        default_factory=dict
    )


@dataclass
class ResponsePlan:
    """
    Controlled response plan generated from an incident
    and its investigation result.

    This plan describes what may be considered for response.
    It does not execute anything.
    """

    incident_id: str
    severity: str
    actions: list[ResponseAction] = field(
        default_factory=list
    )
    approval_required: bool = True
    status: str = "pending_approval"
    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class ResponsePlanner:
    """
    Converts investigation findings into a controlled response plan.

    Important security boundary:

    - LLM output is treated as untrusted.
    - Only recognized actions are converted into ResponseAction.
    - Unknown free-form recommendations are ignored.
    - No action is executed here.
    """

    ALLOWED_ACTIONS = {
        "collect_more_evidence",
        "rate_limit_source",
        "block_source_ip",
        "isolate_host",
        "disable_account",
    }

    HIGH_RISK_ACTIONS = {
        "block_source_ip",
        "isolate_host",
        "disable_account",
    }

    MEDIUM_RISK_ACTIONS = {
        "rate_limit_source",
    }

    LOW_RISK_ACTIONS = {
        "collect_more_evidence",
    }

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
    ):
        self.audit_logger = audit_logger

    def build_plan(
        self,
        incident: Incident,
        investigation: LLMInvestigationOutput,
    ) -> ResponsePlan:
        """
        Build a controlled response plan.

        No external action is performed.
        """

        self._validate_inputs(
            incident,
            investigation,
        )

        actions: list[ResponseAction] = []

        recommendations = (
            investigation.recommended_actions
        )

        ignored_recommendation_count = 0

        for recommendation in recommendations:
            normalized = self._normalize_action(
                recommendation
            )

            if normalized is None:
                ignored_recommendation_count += 1
                continue

            action = self._create_action(
                normalized,
                incident,
                investigation,
            )

            if action is not None:
                actions.append(action)
            else:
                ignored_recommendation_count += 1

        if not actions:
            actions.append(
                self._create_default_evidence_action(
                    incident,
                    investigation,
                )
            )

        plan = ResponsePlan(
            incident_id=incident.incident_id,
            severity=incident.severity,
            actions=actions,
            approval_required=any(
                action.requires_approval
                for action in actions
            ),
            status="pending_approval",
            metadata={
                "source": "response_planner",
                "llm_recommendation_count": len(
                    recommendations
                ),
                "recognized_action_count": len(
                    actions
                ),
                "ignored_recommendation_count": (
                    ignored_recommendation_count
                ),
            },
        )

        self._audit_plan(
            plan=plan,
            investigation=investigation,
        )

        return plan

    def _audit_plan(
        self,
        plan: ResponsePlan,
        investigation: LLMInvestigationOutput,
    ) -> None:
        """
        Record creation of a controlled response plan.

        This records the plan only. It does not execute
        any response action.
        """

        if self.audit_logger is None:
            return

        self.audit_logger.log(
            audit_id=f"AUD-{uuid4()}",
            event_type="response_plan_created",
            actor="system",
            incident_id=plan.incident_id,
            action="create_response_plan",
            status=plan.status,
            reason=(
                "Controlled response plan generated "
                "from investigation recommendations."
            ),
            metadata={
                "severity": plan.severity,
                "action_types": [
                    action.action_type
                    for action in plan.actions
                ],
                "risk_levels": [
                    action.risk_level
                    for action in plan.actions
                ],
                "approval_required": (
                    plan.approval_required
                ),
                "llm_recommendation_count": (
                    len(
                        investigation.recommended_actions
                    )
                ),
                "recognized_action_count": (
                    plan.metadata.get(
                        "recognized_action_count",
                        0,
                    )
                ),
                "ignored_recommendation_count": (
                    plan.metadata.get(
                        "ignored_recommendation_count",
                        0,
                    )
                ),
            },
        )

    def _create_action(
        self,
        action_type: str,
        incident: Incident,
        investigation: LLMInvestigationOutput,
    ) -> ResponseAction | None:
        """
        Convert a recognized recommendation into a
        controlled ResponseAction.
        """

        if action_type == "collect_more_evidence":
            return ResponseAction(
                action_type=action_type,
                reason=(
                    "Additional evidence should be collected "
                    "before taking a higher-risk response action."
                ),
                risk_level="low",
                requires_approval=False,
                parameters={
                    "incident_id": incident.incident_id,
                },
            )

        if action_type == "rate_limit_source":
            if not incident.src_ips:
                return None

            return ResponseAction(
                action_type=action_type,
                reason=(
                    "Rate limiting was recommended for the "
                    "identified source IP addresses."
                ),
                risk_level="medium",
                requires_approval=True,
                parameters={
                    "incident_id": incident.incident_id,
                    "source_ips": list(
                        incident.src_ips
                    ),
                },
            )

        if action_type == "block_source_ip":
            if not incident.src_ips:
                return None

            return ResponseAction(
                action_type=action_type,
                reason=(
                    "Blocking was recommended for source "
                    "IP addresses associated with the incident."
                ),
                risk_level="high",
                requires_approval=True,
                parameters={
                    "incident_id": incident.incident_id,
                    "source_ips": list(
                        incident.src_ips
                    ),
                },
            )

        if action_type == "isolate_host":
            return ResponseAction(
                action_type=action_type,
                reason=(
                    "Host isolation was recommended by "
                    "the investigation."
                ),
                risk_level="high",
                requires_approval=True,
                parameters={
                    "incident_id": incident.incident_id,
                    "destination_ips": list(
                        incident.dst_ips
                    ),
                },
            )

        if action_type == "disable_account":
            return ResponseAction(
                action_type=action_type,
                reason=(
                    "Account disabling was recommended by "
                    "the investigation."
                ),
                risk_level="high",
                requires_approval=True,
                parameters={
                    "incident_id": incident.incident_id,
                },
            )

        return None

    def _create_default_evidence_action(
        self,
        incident: Incident,
        investigation: LLMInvestigationOutput,
    ) -> ResponseAction:
        return ResponseAction(
            action_type="collect_more_evidence",
            reason=(
                "No recognized response action was produced. "
                "Collect additional evidence before taking "
                "a higher-risk action."
            ),
            risk_level="low",
            requires_approval=False,
            parameters={
                "incident_id": incident.incident_id,
            },
        )

    @classmethod
    def _normalize_action(
        cls,
        recommendation: str,
    ) -> str | None:
        """
        Map controlled action names from recommendation text.

        This deliberately does not attempt to interpret arbitrary
        natural-language commands as executable instructions.
        """

        if not isinstance(
            recommendation,
            str,
        ):
            return None

        text = recommendation.strip().lower()

        mappings = {
            "collect_more_evidence": (
                "collect more evidence",
                "gather more evidence",
                "collect additional evidence",
                "gather additional evidence",
            ),
            "rate_limit_source": (
                "rate limit",
                "rate-limit",
                "rate limiting",
            ),
            "block_source_ip": (
                "block source ip",
                "block the source ip",
                "block attacking ip",
                "block attacker ip",
            ),
            "isolate_host": (
                "isolate host",
                "isolate the host",
                "host isolation",
            ),
            "disable_account": (
                "disable account",
                "disable the account",
                "account disable",
            ),
        }

        for action_type, phrases in mappings.items():
            for phrase in phrases:
                if phrase in text:
                    return action_type

        return None

    @staticmethod
    def _validate_inputs(
        incident: Incident,
        investigation: LLMInvestigationOutput,
    ) -> None:
        if not isinstance(
            incident,
            Incident,
        ):
            raise TypeError(
                "incident must be an Incident."
            )

        if not isinstance(
            investigation,
            LLMInvestigationOutput,
        ):
            raise TypeError(
                "investigation must be an "
                "LLMInvestigationOutput."
            )

        if (
            investigation.incident_id
            != incident.incident_id
        ):
            raise ValueError(
                "Incident ID mismatch between incident "
                "and investigation output."
            )

        if not isinstance(
            investigation.recommended_actions,
            list,
        ):
            raise TypeError(
                "investigation.recommended_actions "
                "must be a list."
            )

        for recommendation in (
            investigation.recommended_actions
        ):
            if not isinstance(
                recommendation,
                str,
            ):
                raise TypeError(
                    "Every recommended action must "
                    "be a string."
                )
