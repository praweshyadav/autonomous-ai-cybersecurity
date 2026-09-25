from agent.context_builder import IncidentContext
from agent.investigation import (
    InvestigationResult,
)
from agent.investigation_engine import (
    InvestigationEngine,
)
from agent.incident_rag import IncidentRAGResult


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
        confidence=0.8123,
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


def build_rag_result():
    return IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="Cybersecurity incident investigation.",
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


def test_investigation_engine_returns_structured_result():
    engine = InvestigationEngine()

    result = engine.investigate(
        context=build_context(),
        rag_result=build_rag_result(),
    )

    assert isinstance(
        result,
        InvestigationResult,
    )

    assert result.incident_id == "INC-TEST-001"

    assert result.threat_assessment == "High"

    assert result.attack_families == [
        "Brute Force",
        "DoS",
    ]

    assert len(result.evidence) >= 5

    # Two techniques were evaluated,
    # but only the relevant one is promoted.
    assert result.metadata[
        "evaluated_mitre_count"
    ] == 2

    assert len(
        result.mitre_techniques
    ) == 1

    assert (
        result.mitre_techniques[0].technique_id
        == "T1110"
    )

    assert (
        result.mitre_techniques[0].relevance
        == "high"
    )

    assert (
        result.mitre_techniques[0].confidence
        >= 0.75
    )

    assert len(
        result.hypotheses
    ) == 1

    assert (
        "Brute Force"
        in result.hypotheses[0].description
    )

    assert result.confidence > 0.0

    assert len(
        result.recommended_actions
    ) >= 1


def test_low_relevance_techniques_are_not_promoted():
    engine = InvestigationEngine()

    rag_result = IncidentRAGResult(
        incident_id="INC-TEST-002",
        query="test",
        results=[
            FakeRAGResult(
                title="T1110 - Brute Force",
                score=0.50,
            ),
            FakeRAGResult(
                title="T1498 - Network Denial of Service",
                score=0.40,
            ),
        ],
    )

    result = engine.investigate(
        context=build_context(),
        rag_result=rag_result,
    )

    assert result.metadata[
        "evaluated_mitre_count"
    ] == 2

    technique_ids = [
        technique.technique_id
        for technique in result.mitre_techniques
    ]

    assert "T1110" in technique_ids
    assert "T1498" not in technique_ids


def test_brute_force_recommendations_are_generated():
    engine = InvestigationEngine()

    result = engine.investigate(
        context=build_context(),
        rag_result=build_rag_result(),
    )

    actions_text = " ".join(
        result.recommended_actions
    ).lower()

    assert "authentication" in actions_text

    assert "source" in actions_text

    assert "destination port" in actions_text


def test_empty_rag_results_still_produce_investigation():
    engine = InvestigationEngine()

    rag_result = IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="test",
        results=[],
    )

    result = engine.investigate(
        context=build_context(),
        rag_result=rag_result,
    )

    assert isinstance(
        result,
        InvestigationResult,
    )

    assert result.incident_id == "INC-TEST-001"

    assert len(
        result.evidence
    ) >= 5

    assert result.confidence == 0.8123

    assert len(
        result.mitre_techniques
    ) == 0

    assert result.metadata[
        "evaluated_mitre_count"
    ] == 0