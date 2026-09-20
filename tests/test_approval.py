from agent.response.approval import ApprovalManager
from agent.response.response_plan import ResponseAction


def create_action():
    return ResponseAction(
        action_type="block_source_ip",
        reason="Block malicious source.",
        risk_level="high",
        requires_approval=True,
        parameters={
            "source_ips": [
                "10.0.0.10"
            ]
        },
    )


def test_create_pending_approval():
    manager = ApprovalManager()

    record = manager.create_pending(
        approval_id="APR-001",
        incident_id="INC-001",
        action=create_action(),
    )

    assert record.approval_id == "APR-001"
    assert record.incident_id == "INC-001"
    assert record.action_type == "block_source_ip"
    assert record.decision == "pending"
    assert record.approver == ""
    assert manager.is_approved("APR-001") is False


def test_pending_approval_can_be_approved():
    manager = ApprovalManager()

    manager.create_pending(
        approval_id="APR-002",
        incident_id="INC-002",
        action=create_action(),
    )

    record = manager.approve(
        approval_id="APR-002",
        approver="analyst@university.edu",
        reason="Evidence reviewed.",
    )

    assert record.decision == "approved"
    assert record.approver == "analyst@university.edu"
    assert record.reason == "Evidence reviewed."
    assert manager.is_approved("APR-002") is True


def test_pending_approval_can_be_rejected():
    manager = ApprovalManager()

    manager.create_pending(
        approval_id="APR-003",
        incident_id="INC-003",
        action=create_action(),
    )

    record = manager.reject(
        approval_id="APR-003",
        approver="analyst@university.edu",
        reason="Insufficient evidence.",
    )

    assert record.decision == "rejected"
    assert record.approver == "analyst@university.edu"
    assert manager.is_approved("APR-003") is False


def test_approved_action_cannot_be_changed():
    manager = ApprovalManager()

    manager.create_pending(
        approval_id="APR-004",
        incident_id="INC-004",
        action=create_action(),
    )

    manager.approve(
        approval_id="APR-004",
        approver="analyst@university.edu",
    )

    try:
        manager.reject(
            approval_id="APR-004",
            approver="another@university.edu",
        )
        assert False
    except ValueError as exc:
        assert "Only pending approvals" in str(exc)


def test_rejected_action_cannot_be_approved():
    manager = ApprovalManager()

    manager.create_pending(
        approval_id="APR-005",
        incident_id="INC-005",
        action=create_action(),
    )

    manager.reject(
        approval_id="APR-005",
        approver="analyst@university.edu",
    )

    try:
        manager.approve(
            approval_id="APR-005",
            approver="another@university.edu",
        )
        assert False
    except ValueError as exc:
        assert "Only pending approvals" in str(exc)


def test_duplicate_approval_id_is_rejected():
    manager = ApprovalManager()

    manager.create_pending(
        approval_id="APR-006",
        incident_id="INC-006",
        action=create_action(),
    )

    try:
        manager.create_pending(
            approval_id="APR-006",
            incident_id="INC-007",
            action=create_action(),
        )
        assert False
    except ValueError as exc:
        assert "already exists" in str(exc)


def test_missing_approver_is_rejected():
    manager = ApprovalManager()

    manager.create_pending(
        approval_id="APR-007",
        incident_id="INC-007",
        action=create_action(),
    )

    try:
        manager.approve(
            approval_id="APR-007",
            approver="",
        )
        assert False
    except ValueError as exc:
        assert "approver" in str(exc)


def test_unknown_approval_id_is_rejected():
    manager = ApprovalManager()

    try:
        manager.is_approved("DOES-NOT-EXIST")
        assert False
    except KeyError:
        pass
