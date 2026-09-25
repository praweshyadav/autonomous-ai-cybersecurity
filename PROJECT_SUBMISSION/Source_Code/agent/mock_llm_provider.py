from agent.llm_contract import (
    AgentHypothesis,
    AgentTechniqueAssessment,
    LLMInvestigationInput,
    LLMInvestigationOutput,
)
from agent.llm_provider import LLMProvider


class MockLLMProvider(LLMProvider):
    """
    Deterministic LLM substitute used for testing.

    This does not perform real AI reasoning.
    """

    def investigate(
        self,
        investigation_input: LLMInvestigationInput,
    ) -> LLMInvestigationOutput:

        family = (
            investigation_input.primary_attack_family
            or "unknown"
        )

        hypotheses = [
            AgentHypothesis(
                hypothesis=(
                    f"The observed activity is consistent "
                    f"with a {family} attack."
                ),
                supporting_evidence_ids=[
                    evidence.evidence_id
                    for evidence in investigation_input.evidence
                    if evidence.evidence_type == "observed"
                ],
                contradicting_evidence_ids=[],
                confidence=0.80,
            )
        ]

        technique_assessments = [
            AgentTechniqueAssessment(
                technique_id=technique.technique_id,
                technique_name=technique.technique_name,
                assessment=(
                    "The technique is supported by the "
                    "evaluated incident evidence."
                ),
                supporting_evidence_ids=[
                    evidence.evidence_id
                    for evidence in investigation_input.evidence
                    if evidence.evidence_type == "observed"
                ],
                confidence=technique.relevance_score,
            )
            for technique in investigation_input.mitre_techniques
        ]

        return LLMInvestigationOutput(
            incident_id=investigation_input.incident_id,
            summary=(
                f"Investigation indicates possible "
                f"{family} activity."
            ),
            threat_assessment=(
                investigation_input.severity.capitalize()
            ),
            hypotheses=hypotheses,
            technique_assessments=technique_assessments,
            evidence_gaps=[
                "Additional host and authentication telemetry "
                "may be required for confirmation."
            ],
            next_investigation_steps=[
                "Review supporting security telemetry.",
                "Validate the identified attack behavior.",
            ],
            recommended_actions=[
                "Investigate the affected systems "
                "before taking response actions."
            ],
            confidence=0.80,
            uncertainty=[
                "The investigation is based on the "
                "currently available evidence."
            ],
            metadata={
                "provider": "mock",
            },
        )