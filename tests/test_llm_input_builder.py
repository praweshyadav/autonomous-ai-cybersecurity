from agent.context_builder import IncidentContext
from agent.incident_rag import IncidentRAGResult
from agent.investigation import (
    InvestigationEvidence,
    InvestigationResult,
    InvestigationTechnique,
)
from agent.llm_input_builder import LLMInputBuilder


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
            ),
            InvestigationEvidence(
                source="mitre_attack_rag",
                description="T1110 is highly relevant.",
                evidence_type="retrieved",
            ),
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
            "evaluated_mitre_count": 2,
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
            ),
            FakeRAGResult(
                title="T1498 - Network Denial of Service",
                score=0.4505,
            ),
        ],
    )


def test_builds_llm_input():
    builder = LLMInputBuilder()

    result = builder.build(
        context=build_context(),
        investigation=build_investigation(),
        rag_result=build_rag_result(),
    )

    assert result.incident_id == "INC-TEST-001"

    assert result.primary_attack_family == "Brute Force"

    assert result.event_count == 905

    assert len(result.evidence) == 2

    assert result.evidence[0].evidence_id == "E001"
    assert result.evidence[1].evidence_id == "E002"

    assert len(result.mitre_techniques) == 1

    assert (
        result.mitre_techniques[0].technique_id
        == "T1110"
    )

    assert (
        result.mitre_techniques[0].relevance
        == "high"
    )

    assert (
        result.mitre_techniques[0].relevance_score
        == 0.8426
    )

    assert (
        "0.4630"
        in result.mitre_techniques[0].reason
    )


def test_low_relevance_mitre_result_is_not_sent_to_llm():
    builder = LLMInputBuilder()

    result = builder.build(
        context=build_context(),
        investigation=build_investigation(),
        rag_result=build_rag_result(),
    )

    technique_ids = [
        technique.technique_id
        for technique in result.mitre_techniques
    ]

    assert "T1110" in technique_ids
    assert "T1498" not in technique_ids


def test_investigation_metadata_is_preserved():
    builder = LLMInputBuilder()

    result = builder.build(
        context=build_context(),
        investigation=build_investigation(),
        rag_result=build_rag_result(),
    )

    assert (
        result.metadata["evaluated_mitre_count"]
        == 2
    )

    assert (
        result.metadata["investigation_confidence"]
        == 0.8222
    )

    assert (
        result.metadata["investigation_threat_assessment"]
        == "High"
    )