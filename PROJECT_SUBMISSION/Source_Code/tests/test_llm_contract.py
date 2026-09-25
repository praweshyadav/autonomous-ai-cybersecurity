from agent.llm_contract import (
    AgentEvidence,
    AgentHypothesis,
    AgentMITRETechnique,
    AgentTechniqueAssessment,
    LLMInvestigationInput,
    LLMInvestigationOutput,
)


def build_input():
    return LLMInvestigationInput(
        incident_id="INC-TEST-001",
        severity="High",
        primary_attack_family="Brute Force",
        attack_families=[
            "Brute Force",
            "DoS",
        ],
        event_count=905,
        duration_seconds=298.0,
        confidence=0.8222,
        family_distribution={
            "Brute Force": 825,
            "DoS": 80,
        },
        protocols=[6],
        destination_ports=[21],
        source_ips=[],
        destination_ips=[],
        evidence=[
            AgentEvidence(
                evidence_id="E001",
                source="incident_correlation",
                description=(
                    "Incident contains 905 correlated events."
                ),
                evidence_type="observed",
            )
        ],
        mitre_techniques=[
            AgentMITRETechnique(
                technique_id="T1110",
                technique_name="Brute Force",
                relevance="high",
                relevance_score=0.8426,
                reason=(
                    "Technique aligns with the primary "
                    "attack family."
                ),
            )
        ],
    )


def test_llm_investigation_input():
    data = build_input()

    assert data.incident_id == "INC-TEST-001"
    assert data.primary_attack_family == "Brute Force"
    assert data.event_count == 905

    assert len(data.evidence) == 1
    assert data.evidence[0].evidence_id == "E001"

    assert len(data.mitre_techniques) == 1
    assert data.mitre_techniques[0].technique_id == "T1110"


def test_llm_investigation_output():
    output = LLMInvestigationOutput(
        incident_id="INC-TEST-001",
        summary="Likely brute-force activity.",
        threat_assessment="High",
        hypotheses=[
            AgentHypothesis(
                hypothesis=(
                    "The activity is consistent with "
                    "brute-force authentication attempts."
                ),
                supporting_evidence_ids=["E001"],
                confidence=0.91,
            )
        ],
        technique_assessments=[
            AgentTechniqueAssessment(
                technique_id="T1110",
                technique_name="Brute Force",
                assessment=(
                    "Strongly supported by the incident evidence."
                ),
                supporting_evidence_ids=["E001"],
                confidence=0.89,
            )
        ],
        evidence_gaps=[
            "Authentication logs are required for confirmation."
        ],
        next_investigation_steps=[
            "Review authentication failure logs."
        ],
        recommended_actions=[
            "Investigate the source systems."
        ],
        confidence=0.88,
        uncertainty=[
            "Network flow data alone cannot confirm "
            "successful authentication compromise."
        ],
    )

    assert output.incident_id == "INC-TEST-001"
    assert output.threat_assessment == "High"

    assert len(output.hypotheses) == 1
    assert len(output.technique_assessments) == 1

    assert output.technique_assessments[0].technique_id == "T1110"

    assert len(output.evidence_gaps) == 1
    assert len(output.next_investigation_steps) == 1
    assert len(output.recommended_actions) == 1

    assert 0.0 <= output.confidence <= 1.0