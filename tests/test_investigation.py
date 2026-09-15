from agent.investigation import (
    InvestigationEvidence,
    InvestigationHypothesis,
    InvestigationResult,
    InvestigationTechnique,
)


def test_investigation_result_structure():
    evidence = InvestigationEvidence(
        source="CIC-IDS2018",
        description="905 network events were correlated into the incident.",
        evidence_type="observed",
    )

    technique = InvestigationTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        relevance="Consistent with the observed brute-force activity.",
        confidence=0.95,
    )

    hypothesis = InvestigationHypothesis(
        description="The incident represents a brute-force attack.",
        supporting_evidence=[
            "905 correlated events",
            "Destination port 21",
        ],
        contradicting_evidence=[],
        confidence=0.90,
    )

    result = InvestigationResult(
        incident_id="INC-000003",
        summary="Potential brute-force attack detected.",
        threat_assessment="High",
        attack_families=["Brute Force", "DoS"],
        evidence=[evidence],
        mitre_techniques=[technique],
        hypotheses=[hypothesis],
        confidence=0.90,
        recommended_actions=[
            "Investigate the source of the authentication attempts.",
            "Review FTP authentication logs.",
        ],
        metadata={
            "event_count": 905,
            "destination_port": 21,
        },
    )

    assert result.incident_id == "INC-000003"
    assert result.summary == "Potential brute-force attack detected."
    assert result.threat_assessment == "High"

    assert "Brute Force" in result.attack_families
    assert len(result.evidence) == 1
    assert result.evidence[0].evidence_type == "observed"

    assert len(result.mitre_techniques) == 1
    assert result.mitre_techniques[0].technique_id == "T1110"

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].confidence == 0.90

    assert result.confidence == 0.90

    assert len(result.recommended_actions) == 2

    assert result.metadata["event_count"] == 905
    assert result.metadata["destination_port"] == 21


def test_default_fields_are_initialized():
    result = InvestigationResult(
        incident_id="INC-TEST-001",
        summary="Test incident",
        threat_assessment="Low",
    )

    assert result.attack_families == []
    assert result.evidence == []
    assert result.mitre_techniques == []
    assert result.hypotheses == []
    assert result.confidence == 0.0
    assert result.recommended_actions == []
    assert result.metadata == {}