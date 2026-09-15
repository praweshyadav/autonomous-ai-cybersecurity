import json

import pytest

from agent.llm_contract import (
    AgentEvidence,
    AgentMITRETechnique,
    LLMInvestigationInput,
)
from agent.ollama_llm_provider import OllamaLLMProvider


def create_test_input():
    return LLMInvestigationInput(
        incident_id="INC-VALIDATION-001",
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
                description="100 events classified as Brute Force.",
                evidence_type="observed",
            )
        ],
        mitre_techniques=[
            AgentMITRETechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                relevance="high",
                relevance_score=0.84,
                reason="Technique aligns with the primary attack family.",
            )
        ],
    )


def create_valid_output():
    return {
        "incident_id": "INC-VALIDATION-001",
        "summary": "Possible brute force activity.",
        "threat_assessment": "High",
        "hypotheses": [
            {
                "hypothesis": (
                    "The activity is consistent with "
                    "a brute force attack."
                ),
                "supporting_evidence_ids": ["E001"],
                "contradicting_evidence_ids": [],
                "confidence": 0.85,
            }
        ],
        "technique_assessments": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "assessment": (
                    "The supplied evidence supports "
                    "the Brute Force technique."
                ),
                "supporting_evidence_ids": ["E001"],
                "confidence": 0.84,
            }
        ],
        "evidence_gaps": [
            "Authentication logs are required for confirmation."
        ],
        "next_investigation_steps": [
            "Review authentication logs."
        ],
        "recommended_actions": [
            "Investigate the affected system."
        ],
        "confidence": 0.82,
        "uncertainty": [
            "Network flow data alone does not confirm successful authentication."
        ],
    }


def test_valid_output_is_accepted():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    provider._validate_output(
        output,
        investigation_input,
    )


def test_reject_non_object_output():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    with pytest.raises(
        ValueError,
        match="JSON object",
    ):
        provider._validate_output(
            ["invalid"],
            investigation_input,
        )


def test_reject_non_string_incident_id():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["incident_id"] = 12345

    with pytest.raises(
        ValueError,
        match="incident_id must be a string",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_non_string_summary():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["summary"] = 123

    with pytest.raises(
        ValueError,
        match="summary must be a string",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_invalid_top_level_confidence():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["confidence"] = 1.5

    with pytest.raises(
        ValueError,
        match="between 0 and 1",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_non_list_hypotheses():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["hypotheses"] = "not a list"

    with pytest.raises(
        ValueError,
        match="must be a list",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_invalid_hypothesis_confidence():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["hypotheses"][0]["confidence"] = 2.0

    with pytest.raises(
        ValueError,
        match="Hypothesis confidence",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_unknown_hypothesis_evidence():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["hypotheses"][0][
        "supporting_evidence_ids"
    ] = ["E999"]

    with pytest.raises(
        ValueError,
        match="unknown evidence ID",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_unknown_mitre_technique():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["technique_assessments"][0][
        "technique_id"
    ] = "T9999"

    with pytest.raises(
        ValueError,
        match="was not supplied",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_mismatched_mitre_name():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["technique_assessments"][0][
        "technique_name"
    ] = "Network Denial of Service"

    with pytest.raises(
        ValueError,
        match="mismatched MITRE",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_invalid_mitre_confidence():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["technique_assessments"][0][
        "confidence"
    ] = -0.5

    with pytest.raises(
        ValueError,
        match="MITRE technique confidence",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_unknown_mitre_evidence():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["technique_assessments"][0][
        "supporting_evidence_ids"
    ] = ["E999"]

    with pytest.raises(
        ValueError,
        match="unknown evidence ID",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_non_string_evidence_gap():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["evidence_gaps"] = [
        "Valid gap",
        12345,
    ]

    with pytest.raises(
        ValueError,
        match="must be a string",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_reject_non_string_next_step():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    output["next_investigation_steps"] = [
        "Review logs",
        {"invalid": "object"},
    ]

    with pytest.raises(
        ValueError,
        match="must be a string",
    ):
        provider._validate_output(
            output,
            investigation_input,
        )


def test_parse_valid_output_after_validation():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()
    output = create_valid_output()

    result = provider._parse_output(
        json.dumps(output),
        investigation_input,
    )

    assert result.incident_id == "INC-VALIDATION-001"
    assert result.confidence == 0.82
    assert len(result.hypotheses) == 1
    assert len(result.technique_assessments) == 1
    assert (
        result.technique_assessments[0].technique_id
        == "T1110"
    )