import json

import pytest

from agent.llm_contract import (
    AgentEvidence,
    AgentMITRETechnique,
    LLMInvestigationInput,
)
from agent.ollama_llm_provider import OllamaLLMProvider


def make_input():
    return LLMInvestigationInput(
        incident_id="INC-TEST-001",
        severity="high",
        primary_attack_family="Brute Force",
        attack_families=["Brute Force"],
        event_count=10,
        duration_seconds=30.0,
        confidence=0.95,
        family_distribution={
            "Brute Force": 10,
        },
        protocols=[6],
        destination_ports=[22],
        source_ips=["10.0.0.10"],
        destination_ips=["192.168.1.10"],
        evidence=[
            AgentEvidence(
                evidence_id="E001",
                source="detection",
                description="Repeated SSH connection attempts.",
                evidence_type="observed",
                confidence=0.95,
            )
        ],
        mitre_techniques=[
            AgentMITRETechnique(
                technique_id="T1110",
                technique_name="T1110 - Brute Force",
                relevance="high",
                relevance_score=0.90,
                reason="The incident is classified as Brute Force.",
            )
        ],
    )


class FakeOllamaProvider(OllamaLLMProvider):
    def __init__(self, response):
        super().__init__(
            model="test-model",
            base_url="http://127.0.0.1:11434",
        )
        self.response = response

    def _request(self, payload):
        return {
            "message": {
                "content": json.dumps(self.response)
            }
        }


def valid_output():
    return {
        "incident_id": "INC-TEST-001",
        "summary": "Repeated SSH authentication attempts were observed.",
        "threat_assessment": "High",
        "hypotheses": [
            {
                "hypothesis": "The activity is consistent with brute force behavior.",
                "supporting_evidence_ids": ["E001"],
                "contradicting_evidence_ids": [],
                "confidence": 0.80,
            }
        ],
        "technique_assessments": [
            {
                "technique_id": "T1110",
                "technique_name": "T1110 - Brute Force",
                "assessment": "The supplied evidence supports this technique.",
                "supporting_evidence_ids": ["E001"],
                "confidence": 0.90,
            }
        ],
        "evidence_gaps": [
            "Host authentication logs are not available."
        ],
        "next_investigation_steps": [
            "Review authentication logs."
        ],
        "recommended_actions": [
            "Investigate the affected host before response."
        ],
        "confidence": 0.85,
        "uncertainty": [
            "Only network evidence is currently available."
        ],
    }


def test_valid_output_is_accepted():
    provider = FakeOllamaProvider(
        valid_output()
    )

    result = provider.investigate(
        make_input()
    )

    assert result.incident_id == "INC-TEST-001"

    assert result.summary

    assert result.threat_assessment == "High"

    assert result.confidence == 0.85

    assert len(result.hypotheses) == 1

    assert (
        result.hypotheses[0]
        .supporting_evidence_ids
        == ["E001"]
    )

    assert len(result.technique_assessments) == 1

    assert (
        result.technique_assessments[0]
        .technique_id
        == "T1110"
    )


def test_unknown_incident_id_is_rejected():
    output = valid_output()

    output["incident_id"] = "INC-FABRICATED-999"

    provider = FakeOllamaProvider(output)

    with pytest.raises(
        ValueError,
        match="unexpected incident_id",
    ):
        provider.investigate(
            make_input()
        )


def test_unknown_evidence_id_is_rejected():
    output = valid_output()

    output["hypotheses"][0][
        "supporting_evidence_ids"
    ] = ["E999"]

    provider = FakeOllamaProvider(output)

    with pytest.raises(
        ValueError,
        match="unknown evidence ID",
    ):
        provider.investigate(
            make_input()
        )


def test_unknown_mitre_technique_is_rejected():
    output = valid_output()

    output["technique_assessments"][0][
        "technique_id"
    ] = "T9999"

    output["technique_assessments"][0][
        "technique_name"
    ] = "T9999 - Fabricated Technique"

    provider = FakeOllamaProvider(output)

    with pytest.raises(
        ValueError,
        match="not supplied",
    ):
        provider.investigate(
            make_input()
        )


def test_mismatched_mitre_name_is_rejected():
    output = valid_output()

    output["technique_assessments"][0][
        "technique_name"
    ] = "T1110 - Something Else"

    provider = FakeOllamaProvider(output)

    with pytest.raises(
        ValueError,
        match="mismatched MITRE technique name",
    ):
        provider.investigate(
            make_input()
        )


def test_invalid_confidence_is_rejected():
    output = valid_output()

    output["confidence"] = 1.5

    provider = FakeOllamaProvider(output)

    with pytest.raises(
        ValueError,
        match="between 0 and 1",
    ):
        provider.investigate(
            make_input()
        )


def test_unknown_evidence_in_mitre_assessment_is_rejected():
    output = valid_output()

    output["technique_assessments"][0][
        "supporting_evidence_ids"
    ] = ["E999"]

    provider = FakeOllamaProvider(output)

    with pytest.raises(
        ValueError,
        match="unknown evidence ID",
    ):
        provider.investigate(
            make_input()
        )


def test_missing_required_field_is_rejected():
    output = valid_output()

    del output["summary"]

    provider = FakeOllamaProvider(output)

    with pytest.raises(
        ValueError,
        match="missing required field",
    ):
        provider.investigate(
            make_input()
        )
