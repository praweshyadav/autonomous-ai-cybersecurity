from agent.context_builder import IncidentContext
from agent.incident_rag import IncidentRAGResult
from agent.investigation import InvestigationResult
from agent.llm_contract import (
    AgentEvidence,
    AgentMITRETechnique,
    LLMInvestigationInput,
)


class LLMInputBuilder:
    """
    Converts deterministic investigation outputs into the
    controlled input contract expected by the LLM agent.

    The LLM receives structured and evaluated evidence only.
    """

    def build(
        self,
        context: IncidentContext,
        investigation: InvestigationResult,
        rag_result: IncidentRAGResult,
    ) -> LLMInvestigationInput:

        evidence = []

        for index, item in enumerate(
            investigation.evidence,
            start=1,
        ):
            evidence.append(
                AgentEvidence(
                    evidence_id=f"E{index:03d}",
                    source=item.source,
                    description=item.description,
                    evidence_type=item.evidence_type,
                )
            )

        mitre_techniques = []

        for technique in investigation.mitre_techniques:
            matching_evidence = next(
                (
                    item
                    for item in rag_result.results
                    if getattr(item, "title", "").startswith(
                        technique.technique_id + " - "
                    )
                ),
                None,
            )

            reason = ""

            if matching_evidence is not None:
                reason = (
                    f"Retrieved with semantic similarity "
                    f"score {float(matching_evidence.score):.4f}."
                )

            mitre_techniques.append(
                AgentMITRETechnique(
                    technique_id=technique.technique_id,
                    technique_name=technique.technique_name,
                    relevance=technique.relevance,
                    relevance_score=technique.confidence,
                    reason=reason,
                )
            )

        return LLMInvestigationInput(
            incident_id=context.incident_id,
            severity=context.severity,
            primary_attack_family=context.primary_attack_family,
            attack_families=context.attack_families,
            event_count=context.event_count,
            duration_seconds=context.duration_seconds,
            confidence=context.confidence,
            family_distribution=context.family_distribution,
            protocols=context.protocols,
            destination_ports=context.destination_ports,
            source_ips=context.source_ips,
            destination_ips=context.destination_ips,
            evidence=evidence,
            mitre_techniques=mitre_techniques,
            metadata={
                "investigation_confidence": investigation.confidence,
                "investigation_threat_assessment": (
                    investigation.threat_assessment
                ),
                "evaluated_mitre_count": investigation.metadata.get(
                    "evaluated_mitre_count",
                    0,
                ),
            },
        )