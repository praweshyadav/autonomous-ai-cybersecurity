import pytest

from agent.llm_contract import (
    AgentEvidence,
    AgentMITRETechnique,
    LLMInvestigationInput,
)
from agent.ollama_llm_provider import OllamaLLMProvider


def build_test_input():
    return LLMInvestigationInput(
        incident_id="INC-GROUNDING-001",
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
                    "Repeated authentication attempts "
                    "against destination port 22."
                ),
                evidence_type="observed",
                confidence=0.95,
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


def test_validator_rejects_invented_ip():
    provider = OllamaLLMProvider()

    investigation_input = build_test_input()

    malicious_output = {
        "incident_id": "INC-GROUNDING-001",
        "summary": (
            "A brute force attack originated from "
            "192.168.99.99."
        ),
        "threat_assessment": (
            "The attacker at 192.168.99.99 is attempting "
            "to gain unauthorized access."
        ),
        "hypotheses": [
            {
                "hypothesis": (
                    "The attacker at 192.168.99.99 is "
                    "attempting credential guessing."
                ),
                "supporting_evidence_ids": [
                    "E001",
                ],
                "contradicting_evidence_ids": [],
                "confidence": 0.95,
            }
        ],
        "technique_assessments": [
            {
                "technique_id": "T1110",
                "technique_name": "T1110 - Brute Force",
                "assessment": (
                    "The activity is consistent with "
                    "Brute Force."
                ),
                "supporting_evidence_ids": [
                    "E001",
                ],
                "confidence": 0.90,
            }
        ],
        "evidence_gaps": [],
        "next_investigation_steps": [],
        "recommended_actions": [],
        "confidence": 0.95,
        "uncertainty": [],
    }

    with pytest.raises(ValueError):
        provider._validate_output(
            malicious_output,
            investigation_input,
        )