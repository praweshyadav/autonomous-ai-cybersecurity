from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from agent.audit.audit_logger import AuditLogger
from agent.response.response_plan import ResponseAction


@dataclass
class ApprovalRecord:
    approval_id: str
    incident_id: str
    action_type: str
    decision: str
    approver: str
    decided_at: datetime
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ApprovalManager:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

    VALID_DECISIONS = {
        APPROVED,
        REJECTED,
    }

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
    ):
        self._records: dict[str, ApprovalRecord] = {}
        self.audit_logger = audit_logger

    def create_pending(
        self,
        approval_id: str,
        incident_id: str,
        action: ResponseAction,
    ) -> ApprovalRecord:
        """
        Create a pending approval request.

        A response action is never executed here.
        """

        self._validate_action(action)

        if not isinstance(
            approval_id,
            str,
        ) or not approval_id.strip():
            raise ValueError(
                "approval_id must be a non-empty string."
            )

        if not isinstance(
            incident_id,
            str,
        ) or not incident_id.strip():
            raise ValueError(
                "incident_id must be a non-empty string."
            )

        if approval_id in self._records:
            raise ValueError(
                f"Approval ID already exists: {approval_id}"
            )

        record = ApprovalRecord(
            approval_id=approval_id,
            incident_id=incident_id,
            action_type=action.action_type,
            decision=self.PENDING,
            approver="",
            decided_at=datetime.now(timezone.utc),
            reason="",
            metadata={
                "risk_level": action.risk_level,
                "requires_approval": action.requires_approval,
                "parameters": dict(action.parameters),
            },
        )

        self._records[approval_id] = record

        self._audit(
            event_type="approval_created",
            actor="system",
            incident_id=incident_id,
            action=action.action_type,
            status=self.PENDING,
            reason="Human approval required before response action.",
            metadata={
                "approval_id": approval_id,
                "risk_level": action.risk_level,
            },
        )

        return record

    def approve(
        self,
        approval_id: str,
        approver: str,
        reason: str = "",
    ) -> ApprovalRecord:
        """
        Approve a pending response action.
        """

        return self._decide(
            approval_id=approval_id,
            decision=self.APPROVED,
            approver=approver,
            reason=reason,
        )

    def reject(
        self,
        approval_id: str,
        approver: str,
        reason: str = "",
    ) -> ApprovalRecord:
        """
        Reject a pending response action.
        """

        return self._decide(
            approval_id=approval_id,
            decision=self.REJECTED,
            approver=approver,
            reason=reason,
        )

    def get(
        self,
        approval_id: str,
    ) -> ApprovalRecord:
        """
        Retrieve an approval record.
        """

        if approval_id not in self._records:
            raise KeyError(
                f"Unknown approval ID: {approval_id}"
            )

        return self._records[approval_id]

    def is_approved(
        self,
        approval_id: str,
    ) -> bool:
        """
        Return True only when the approval has been approved.
        """

        return (
            self.get(approval_id).decision
            == self.APPROVED
        )

    def _decide(
        self,
        approval_id: str,
        decision: str,
        approver: str,
        reason: str,
    ) -> ApprovalRecord:
        if decision not in self.VALID_DECISIONS:
            raise ValueError(
                f"Invalid approval decision: {decision}"
            )

        record = self.get(approval_id)

        if record.decision != self.PENDING:
            raise ValueError(
                "Only pending approvals can be decided."
            )

        if not isinstance(
            approver,
            str,
        ) or not approver.strip():
            raise ValueError(
                "approver must be a non-empty string."
            )

        if not isinstance(
            reason,
            str,
        ):
            raise TypeError(
                "reason must be a string."
            )

        record.decision = decision
        record.approver = approver
        record.reason = reason
        record.decided_at = datetime.now(
            timezone.utc
        )

        self._audit(
            event_type=(
                "approval_approved"
                if decision == self.APPROVED
                else "approval_rejected"
            ),
            actor=approver,
            incident_id=record.incident_id,
            action=record.action_type,
            status=decision,
            reason=reason,
            metadata={
                "approval_id": record.approval_id,
            },
        )

        return record

    def _audit(
        self,
        event_type: str,
        actor: str,
        incident_id: str,
        action: str,
        status: str,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Write an audit event when an AuditLogger is configured.

        Approval functionality remains usable without an audit logger,
        preserving backward compatibility with existing callers.
        """

        if self.audit_logger is None:
            return

        self.audit_logger.log(
            audit_id=f"AUD-{uuid4()}",
            event_type=event_type,
            actor=actor,
            incident_id=incident_id,
            action=action,
            status=status,
            reason=reason,
            metadata=metadata,
        )

    @staticmethod
    def _validate_action(
        action: ResponseAction,
    ) -> None:
        if not isinstance(
            action,
            ResponseAction,
        ):
            raise TypeError(
                "action must be a ResponseAction."
            )
