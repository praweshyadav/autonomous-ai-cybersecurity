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
        incident_id="INC-TEST-001",
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


def test_provider_initialization():
    provider = OllamaLLMProvider()

    assert provider.model == "gemma3:4b"
    assert provider.base_url == "http://127.0.0.1:11434"
    assert provider.timeout == 120


def test_build_prompt_contains_required_information():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    prompt = provider._build_prompt(
        investigation_input
    )

    assert "INC-TEST-001" in prompt
    assert "Brute Force" in prompt
    assert "T1110" in prompt
    assert "E001" in prompt
    assert "Do not invent" in prompt
    assert "Return JSON" in prompt


def test_parse_valid_output():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    response = {
        "incident_id": "INC-TEST-001",
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
                    "The technique is supported by "
                    "the observed brute force activity."
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
            (
                "Network flow data alone does not confirm "
                "successful authentication."
            )
        ],
    }

    result = provider._parse_output(
        json.dumps(response),
        investigation_input,
    )

    assert result.incident_id == "INC-TEST-001"
    assert result.summary == "Possible brute force activity."
    assert result.threat_assessment == "High"
    assert result.confidence == 0.82

    assert len(result.hypotheses) == 1

    assert result.hypotheses[0].hypothesis.startswith(
        "The activity is consistent"
    )

    assert len(result.technique_assessments) == 1

    assert (
        result.technique_assessments[0].technique_id
        == "T1110"
    )

    assert result.metadata["provider"] == "ollama"
    assert result.metadata["model"] == "gemma3:4b"


def test_reject_wrong_incident_id():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    response = {
        "incident_id": "INC-WRONG",
        "summary": "Test summary",
        "threat_assessment": "High",
        "confidence": 0.8,
    }

    with pytest.raises(
        ValueError,
        match="unexpected incident_id",
    ):
        provider._parse_output(
            json.dumps(response),
            investigation_input,
        )


def test_reject_unknown_mitre_technique():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    response = {
        "incident_id": "INC-TEST-001",
        "summary": "Test summary",
        "threat_assessment": "High",
        "technique_assessments": [
            {
                "technique_id": "T9999",
                "technique_name": "Unknown Technique",
                "assessment": "Unsupported technique.",
                "supporting_evidence_ids": [],
                "confidence": 0.8,
            }
        ],
        "confidence": 0.8,
    }

    with pytest.raises(
        ValueError,
        match="was not supplied",
    ):
        provider._parse_output(
            json.dumps(response),
            investigation_input,
        )


def test_reject_unknown_evidence_id():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    response = {
        "incident_id": "INC-TEST-001",
        "summary": "Test summary",
        "threat_assessment": "High",
        "hypotheses": [
            {
                "hypothesis": "Test hypothesis",
                "supporting_evidence_ids": ["E999"],
                "contradicting_evidence_ids": [],
                "confidence": 0.8,
            }
        ],
        "confidence": 0.8,
    }

    with pytest.raises(
        ValueError,
        match="unknown evidence ID",
    ):
        provider._parse_output(
            json.dumps(response),
            investigation_input,
        )


def test_reject_invalid_confidence():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    response = {
        "incident_id": "INC-TEST-001",
        "summary": "Test summary",
        "threat_assessment": "High",
        "confidence": 1.5,
    }

    with pytest.raises(
        ValueError,
        match="between 0 and 1",
    ):
        provider._parse_output(
            json.dumps(response),
            investigation_input,
        )


def test_reject_invalid_json():
    provider = OllamaLLMProvider()

    investigation_input = create_test_input()

    with pytest.raises(
        ValueError,
        match="invalid JSON",
    ):
        provider._parse_output(
            "THIS IS NOT JSON",
            investigation_input,
        )