import pytest

from agent.llm_contract import (
    AgentEvidence,
    AgentMITRETechnique,
    LLMInvestigationInput,
)
from agent.ollama_llm_provider import OllamaLLMProvider


def create_real_test_input():
    return LLMInvestigationInput(
        incident_id="INC-REAL-001",
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        event_count=100,
        duration_seconds=60.0,
        confidence=0.90,
        family_distribution={
            "Brute Force": 100
        },
        protocols=[6],
        destination_ports=[21],
        source_ips=[],
        destination_ips=[],
        evidence=[
            AgentEvidence(
                evidence_id="E001",
                source="detection",
                description=(
                    "100 network events were classified "
                    "as Brute Force activity."
                ),
                evidence_type="observed",
            )
        ],
        mitre_techniques=[
            AgentMITRETechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                relevance="high",
                relevance_score=0.84,
                reason=(
                    "Technique aligns with the "
                    "primary attack family."
                ),
            )
        ],
    )


@pytest.mark.integration
def test_real_ollama_investigation():
    provider = OllamaLLMProvider(
        model="gemma3:4b",
        timeout=120,
    )

    investigation_input = create_real_test_input()

    result = provider.investigate(
        investigation_input
    )

    assert result.incident_id == "INC-REAL-001"
    assert isinstance(result.summary, str)
    assert len(result.summary) > 0

    assert isinstance(
        result.threat_assessment,
        str,
    )
    assert len(result.threat_assessment) > 0

    assert 0.0 <= result.confidence <= 1.0

    for technique in result.technique_assessments:
        assert technique.technique_id == "T1110"

    for hypothesis in result.hypotheses:
        for evidence_id in (
            hypothesis.supporting_evidence_ids
        ):
            assert evidence_id == "E001"

        for evidence_id in (
            hypothesis.contradicting_evidence_ids
        ):
            assert evidence_id == "E001"

    print()
    print("===== REAL OLLAMA RESULT =====")
    print(f"Incident ID : {result.incident_id}")
    print(f"Summary     : {result.summary}")
    print(
        f"Threat      : {result.threat_assessment}"
    )
    print(
        f"Confidence  : {result.confidence}"
    )

    print("\nHypotheses:")
    for hypothesis in result.hypotheses:
        print(
            f"- {hypothesis.hypothesis} "
            f"(confidence={hypothesis.confidence:.4f})"
        )

    print("\nMITRE Assessments:")
    for technique in result.technique_assessments:
        print(
            f"- {technique.technique_id} - "
            f"{technique.technique_name} "
            f"(confidence={technique.confidence:.4f})"
        )

    print("\nEvidence Gaps:")
    for gap in result.evidence_gaps:
        print(f"- {gap}")

    print("\nNext Investigation Steps:")
    for step in result.next_investigation_steps:
        print(f"- {step}")

    print("\nRecommended Actions:")
    for action in result.recommended_actions:
        print(f"- {action}")