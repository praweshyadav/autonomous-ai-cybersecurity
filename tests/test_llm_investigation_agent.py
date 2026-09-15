from agent.context_builder import IncidentContext
from agent.incident_rag import IncidentRAGResult
from agent.investigation import (
    InvestigationEvidence,
    InvestigationResult,
    InvestigationTechnique,
)
from agent.llm_investigation_agent import (
    LLMInvestigationAgent,
)
from agent.mock_llm_provider import MockLLMProvider


class FakeRAGResult:
    def __init__(self, title, score):
        self.title = title
        self.score = score


def build_context():
    return IncidentContext(
        incident_id="INC-TEST-001",
        start_time="2018-02-14T10:33:26",
        end_time="2018-02-14T10:38:24",
        duration_seconds=298.0,
        severity="high",
        primary_attack_family="Brute Force",
        event_count=905,
        confidence=0.8222,
        attack_families=[
            "Brute Force",
            "DoS",
        ],
        family_distribution={
            "Brute Force": 825,
            "DoS": 80,
        },
        protocols=[6],
        destination_ports=[21],
        source_ips=[],
        destination_ips=[],
    )


def build_investigation():
    return InvestigationResult(
        incident_id="INC-TEST-001",
        summary="Likely brute-force activity.",
        threat_assessment="High",
        attack_families=[
            "Brute Force",
            "DoS",
        ],
        evidence=[
            InvestigationEvidence(
                source="incident_correlation",
                description="905 correlated events.",
                evidence_type="observed",
            )
        ],
        mitre_techniques=[
            InvestigationTechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                relevance="high",
                confidence=0.8426,
            )
        ],
        confidence=0.8222,
        recommended_actions=[
            "Review authentication logs."
        ],
        metadata={
            "evaluated_mitre_count": 1,
        },
    )


def build_rag_result():
    return IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="Cybersecurity investigation.",
        results=[
            FakeRAGResult(
                title="T1110 - Brute Force",
                score=0.4630,
            )
        ],
    )


def test_agent_orchestrates_investigation():
    agent = LLMInvestigationAgent(
        provider=MockLLMProvider()
    )

    result = agent.investigate(
        context=build_context(),
        investigation=build_investigation(),
        rag_result=build_rag_result(),
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


def test_agent_returns_only_structured_output():
    agent = LLMInvestigationAgent(
        provider=MockLLMProvider()
    )

    result = agent.investigate(
        context=build_context(),
        investigation=build_investigation(),
        rag_result=build_rag_result(),
    )

    assert result.incident_id == "INC-TEST-001"

    assert hasattr(
        result,
        "recommended_actions",
    )

    assert hasattr(
        result,
        "next_investigation_steps",
    )

    assert hasattr(
        result,
        "evidence_gaps",
    )

    assert not hasattr(
        result,
        "execute_actions",
    )