from agent.llm_contract import (
    AgentEvidence,
    AgentMITRETechnique,
    LLMInvestigationInput,
)
from agent.ollama_llm_provider import OllamaLLMProvider


def test_real_ollama_provider():
    investigation_input = LLMInvestigationInput(
        incident_id="INC-OLLAMA-REAL-001",
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=[
            "Brute Force",
        ],
        event_count=10,
        duration_seconds=30.0,
        confidence=0.95,
        family_distribution={
            "Brute Force": 10,
        },
        protocols=[6],
        destination_ports=[22],
        source_ips=[
            "10.0.0.10",
        ],
        destination_ips=[
            "192.168.1.10",
        ],
        evidence=[
            AgentEvidence(
                evidence_id="E001",
                source="detection",
                description=(
                    "The detection engine classified "
                    "the network activity as Brute Force "
                    "with high confidence."
                ),
                evidence_type="observed",
                confidence=0.95,
            ),
            AgentEvidence(
                evidence_id="E002",
                source="correlation",
                description=(
                    "Multiple events from the same source "
                    "targeted destination port 22."
                ),
                evidence_type="observed",
                confidence=0.90,
            ),
        ],
        mitre_techniques=[
            AgentMITRETechnique(
                technique_id="T1110",
                technique_name="T1110 - Brute Force",
                relevance="high",
                relevance_score=0.90,
                reason=(
                    "The observed activity is classified "
                    "as Brute Force."
                ),
            ),
        ],
    )

    provider = OllamaLLMProvider(
        model="gemma3:4b",
        timeout=180,
    )

    result = provider.investigate(
        investigation_input
    )

    assert result.incident_id == (
        "INC-OLLAMA-REAL-001"
    )

    assert result.summary

    assert result.threat_assessment

    assert 0.0 <= result.confidence <= 1.0

    assert result.metadata["provider"] == "ollama"

    assert result.metadata["model"] == "gemma3:4b"

    for hypothesis in result.hypotheses:
        for evidence_id in (
            hypothesis.supporting_evidence_ids
            + hypothesis.contradicting_evidence_ids
        ):
            assert evidence_id in {
                "E001",
                "E002",
            }

    for assessment in (
        result.technique_assessments
    ):
        assert assessment.technique_id == "T1110"
        assert (
            assessment.technique_name
            == "T1110 - Brute Force"
        )

        for evidence_id in (
            assessment.supporting_evidence_ids
        ):
            assert evidence_id in {
                "E001",
                "E002",
            }

    print("\n=== REAL OLLAMA RESULT ===")

    print(
        "Incident:",
        result.incident_id,
    )

    print(
        "Summary:",
        result.summary,
    )

    print(
        "Threat:",
        result.threat_assessment,
    )

    print(
        "Confidence:",
        result.confidence,
    )

    print(
        "Hypotheses:",
        result.hypotheses,
    )

    print(
        "MITRE assessments:",
        result.technique_assessments,
    )

    print(
        "Evidence gaps:",
        result.evidence_gaps,
    )

    print(
        "Next steps:",
        result.next_investigation_steps,
    )

    print(
        "Recommended actions:",
        result.recommended_actions,
    )

    print(
        "Uncertainty:",
        result.uncertainty,
    )
