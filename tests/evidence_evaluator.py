from agent.context_builder import IncidentContext
from agent.evidence_evaluator import (
    EvidenceEvaluator,
    EvaluatedEvidence,
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


def test_brute_force_technique_gets_high_relevance():
    evaluator = EvidenceEvaluator()

    rag_result = IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="test",
        results=[
            FakeRAGResult(
                title="T1110 - Brute Force",
                score=0.4630,
            ),
        ],
    )

    results = evaluator.evaluate(
        context=build_context(),
        rag_result=rag_result,
    )

    assert len(results) == 1

    result = results[0]

    assert isinstance(
        result,
        EvaluatedEvidence,
    )

    assert result.technique_id == "T1110"
    assert result.technique_name == "Brute Force"

    assert result.relevance_score > 0.75
    assert result.relevance == "high"

    assert (
        "primary attack family"
        in result.reason.lower()
    )


def test_unrelated_technique_gets_lower_relevance():
    evaluator = EvidenceEvaluator()

    rag_result = IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="test",
        results=[
            FakeRAGResult(
                title="T1583.003 - Virtual Private Server",
                score=0.4598,
            ),
        ],
    )

    results = evaluator.evaluate(
        context=build_context(),
        rag_result=rag_result,
    )

    assert len(results) == 1

    result = results[0]

    assert result.technique_id == "T1583.003"

    assert result.relevance_score < 0.75
    assert result.relevance in {
        "low",
        "medium",
    }


def test_duplicate_techniques_are_removed():
    evaluator = EvidenceEvaluator()

    rag_result = IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="test",
        results=[
            FakeRAGResult(
                title="T1110 - Brute Force",
                score=0.4630,
            ),
            FakeRAGResult(
                title="T1110 - Brute Force",
                score=0.4374,
            ),
            FakeRAGResult(
                title="T1498 - Network Denial of Service",
                score=0.4505,
            ),
            FakeRAGResult(
                title="T1498 - Network Denial of Service",
                score=0.4424,
            ),
        ],
    )

    results = evaluator.evaluate(
        context=build_context(),
        rag_result=rag_result,
    )

    assert len(results) == 2

    technique_ids = [
        result.technique_id
        for result in results
    ]

    assert technique_ids.count("T1110") == 1
    assert technique_ids.count("T1498") == 1


def test_results_are_sorted_by_relevance():
    evaluator = EvidenceEvaluator()

    rag_result = IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="test",
        results=[
            FakeRAGResult(
                title="T1583.003 - Virtual Private Server",
                score=0.4598,
            ),
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

    results = evaluator.evaluate(
        context=build_context(),
        rag_result=rag_result,
    )

    assert len(results) == 3

    relevance_scores = [
        result.relevance_score
        for result in results
    ]

    assert relevance_scores == sorted(
        relevance_scores,
        reverse=True,
    )


def test_empty_rag_results_return_empty_evidence():
    evaluator = EvidenceEvaluator()

    rag_result = IncidentRAGResult(
        incident_id="INC-TEST-001",
        query="test",
        results=[],
    )

    results = evaluator.evaluate(
        context=build_context(),
        rag_result=rag_result,
    )

    assert results == []