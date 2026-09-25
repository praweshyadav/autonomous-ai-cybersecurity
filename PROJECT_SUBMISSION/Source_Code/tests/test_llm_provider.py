from agent.llm_contract import (
    AgentEvidence,
    AgentMITRETechnique,
    LLMInvestigationInput,
    LLMInvestigationOutput,
)
from agent.mock_llm_provider import MockLLMProvider


def build_input():
    return LLMInvestigationInput(
        incident_id="INC-TEST-001",
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=[
            "Brute Force",
        ],
        event_count=905,
        duration_seconds=298.0,
        confidence=0.8222,
        family_distribution={
            "Brute Force": 905,
        },
        protocols=[6],
        destination_ports=[21],
        source_ips=[],
        destination_ips=[],
        evidence=[
            AgentEvidence(
                evidence_id="E001",
                source="incident_correlation",
                description="905 correlated events.",
                evidence_type="observed",
            )
        ],
        mitre_techniques=[
            AgentMITRETechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                relevance="high",
                relevance_score=0.8426,
                reason="Family alignment.",
            )
        ],
    )


def test_mock_provider_returns_structured_output():
    provider = MockLLMProvider()

    result = provider.investigate(
        build_input()
    )

    assert isinstance(
        result,
        LLMInvestigationOutput,
    )

    assert result.incident_id == "INC-TEST-001"

    assert result.threat_assessment == "High"

    assert len(result.hypotheses) == 1

    assert (
        "Brute Force"
        in result.hypotheses[0].hypothesis
    )

    assert len(
        result.technique_assessments
    ) == 1

    assert (
        result.technique_assessments[0].technique_id
        == "T1110"
    )

    assert result.confidence == 0.80

    assert result.metadata["provider"] == "mock"


def test_mock_provider_does_not_create_response_execution():
    provider = MockLLMProvider()

    result = provider.investigate(
        build_input()
    )

    assert hasattr(
        result,
        "recommended_actions",
    )

    assert not hasattr(
        result,
        "execute_actions",
    )

    assert not hasattr(
        result,
        "tool_calls",
    )