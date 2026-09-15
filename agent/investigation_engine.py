from agent.context_builder import IncidentContext
from agent.evidence_evaluator import (
    EvidenceEvaluator,
    EvaluatedEvidence,
)
from agent.incident_rag import IncidentRAGResult
from agent.investigation import (
    InvestigationEvidence,
    InvestigationHypothesis,
    InvestigationResult,
    InvestigationTechnique,
)


class InvestigationEngine:
    """
    Deterministic investigation engine.

    Converts incident context and evaluated RAG evidence into
    a structured investigation result.

    No LLM is used here.

    Important:
        Raw RAG retrieval is not treated as confirmed evidence.
        MITRE results are first evaluated by EvidenceEvaluator.
    """

    def __init__(
        self,
        evidence_evaluator: EvidenceEvaluator | None = None,
    ):
        self.evidence_evaluator = (
            evidence_evaluator
            if evidence_evaluator is not None
            else EvidenceEvaluator()
        )

    def investigate(
        self,
        context: IncidentContext,
        rag_result: IncidentRAGResult,
    ) -> InvestigationResult:

        # -----------------------------------------------------
        # 1. Evaluate retrieved MITRE evidence
        # -----------------------------------------------------

        evaluated_evidence = (
            self.evidence_evaluator.evaluate(
                context=context,
                rag_result=rag_result,
            )
        )

        # -----------------------------------------------------
        # 2. Build evidence from observed incident facts
        #    and evaluated MITRE knowledge
        # -----------------------------------------------------

        evidence = self._build_evidence(
            context=context,
            evaluated_evidence=evaluated_evidence,
        )

        # -----------------------------------------------------
        # 3. Extract only relevant MITRE techniques
        # -----------------------------------------------------

        mitre_techniques = (
            self._extract_mitre_techniques(
                evaluated_evidence=evaluated_evidence,
            )
        )

        # -----------------------------------------------------
        # 4. Build hypotheses from observed evidence
        # -----------------------------------------------------

        hypotheses = self._build_hypotheses(
            context=context,
            evidence=evidence,
        )

        # -----------------------------------------------------
        # 5. Calculate investigation confidence
        # -----------------------------------------------------

        confidence = self._calculate_confidence(
            context=context,
            evaluated_evidence=evaluated_evidence,
        )

        # -----------------------------------------------------
        # 6. Build investigation result
        # -----------------------------------------------------

        summary = self._build_summary(
            context
        )

        threat_assessment = (
            self._build_threat_assessment(
                context
            )
        )

        recommended_actions = (
            self._build_recommended_actions(
                context
            )
        )

        return InvestigationResult(
            incident_id=context.incident_id,
            summary=summary,
            threat_assessment=threat_assessment,
            attack_families=context.attack_families,
            evidence=evidence,
            mitre_techniques=mitre_techniques,
            hypotheses=hypotheses,
            confidence=confidence,
            recommended_actions=recommended_actions,
            metadata={
                "event_count": context.event_count,
                "duration_seconds": context.duration_seconds,
                "family_distribution": context.family_distribution,
                "protocols": context.protocols,
                "destination_ports": context.destination_ports,
                "evaluated_mitre_count": len(
                    evaluated_evidence
                ),
            },
        )

    def _build_evidence(
        self,
        context: IncidentContext,
        evaluated_evidence: list[
            EvaluatedEvidence
        ],
    ) -> list[InvestigationEvidence]:

        evidence = []

        # -----------------------------------------------------
        # Observed evidence
        # -----------------------------------------------------

        evidence.append(
            InvestigationEvidence(
                source="incident_correlation",
                description=(
                    f"Incident {context.incident_id} contains "
                    f"{context.event_count} correlated events."
                ),
                evidence_type="observed",
            )
        )

        if context.primary_attack_family:
            evidence.append(
                InvestigationEvidence(
                    source="attack_family_classifier",
                    description=(
                        "The primary predicted attack family is "
                        f"{context.primary_attack_family}."
                    ),
                    evidence_type="observed",
                )
            )

        if context.family_distribution:

            distribution = ", ".join(
                f"{family}: {count}"
                for family, count in sorted(
                    context.family_distribution.items()
                )
            )

            evidence.append(
                InvestigationEvidence(
                    source="incident_correlation",
                    description=(
                        "The incident family distribution is "
                        f"{distribution}."
                    ),
                    evidence_type="observed",
                )
            )

        if context.protocols:
            evidence.append(
                InvestigationEvidence(
                    source="network_telemetry",
                    description=(
                        "Observed network protocols: "
                        + ", ".join(
                            str(protocol)
                            for protocol in context.protocols
                        )
                        + "."
                    ),
                    evidence_type="observed",
                )
            )

        if context.destination_ports:
            evidence.append(
                InvestigationEvidence(
                    source="network_telemetry",
                    description=(
                        "Observed destination ports: "
                        + ", ".join(
                            str(port)
                            for port in context.destination_ports
                        )
                        + "."
                    ),
                    evidence_type="observed",
                )
            )

        # -----------------------------------------------------
        # Evaluated RAG evidence
        #
        # Only HIGH and MEDIUM relevance are included.
        # LOW relevance retrievals are deliberately excluded
        # from the investigation evidence.
        # -----------------------------------------------------

        for item in evaluated_evidence:

            if item.relevance == "low":
                continue

            evidence.append(
                InvestigationEvidence(
                    source="mitre_attack_rag",
                    description=(
                        f"MITRE ATT&CK technique "
                        f"{item.technique_id} - "
                        f"{item.technique_name} was assessed as "
                        f"{item.relevance} relevance "
                        f"(relevance score="
                        f"{item.relevance_score:.4f}). "
                        f"{item.reason}"
                    ),
                    evidence_type="retrieved",
                )
            )

        return evidence

    def _extract_mitre_techniques(
        self,
        evaluated_evidence: list[
            EvaluatedEvidence
        ],
    ) -> list[InvestigationTechnique]:

        techniques = []

        for item in evaluated_evidence:

            # Do not promote low-relevance retrievals
            # into investigation findings.
            if item.relevance == "low":
                continue

            techniques.append(
                InvestigationTechnique(
                    technique_id=item.technique_id,
                    technique_name=item.technique_name,
                    relevance=item.relevance,
                    confidence=item.relevance_score,
                )
            )

        return techniques

    def _build_hypotheses(
        self,
        context: IncidentContext,
        evidence: list[InvestigationEvidence],
    ) -> list[InvestigationHypothesis]:

        hypotheses = []

        primary_family = (
            context.primary_attack_family
        )

        if (
            primary_family
            and primary_family != "Benign"
        ):

            supporting = [
                item.description
                for item in evidence
                if item.evidence_type == "observed"
            ]

            hypotheses.append(
                InvestigationHypothesis(
                    description=(
                        f"The observed activity is consistent "
                        f"with a {primary_family} attack."
                    ),
                    supporting_evidence=supporting,
                    contradicting_evidence=[],
                    confidence=self._family_confidence(
                        context
                    ),
                )
            )

        return hypotheses

    def _calculate_confidence(
        self,
        context: IncidentContext,
        evaluated_evidence: list[
            EvaluatedEvidence
        ],
    ) -> float:

        incident_confidence = max(
            0.0,
            min(
                1.0,
                float(context.confidence),
            ),
        )

        relevant_scores = [
            item.relevance_score
            for item in evaluated_evidence
            if item.relevance != "low"
        ]

        if not relevant_scores:
            return round(
                incident_confidence,
                4,
            )

        best_relevance = max(
            relevant_scores
        )

        confidence = (
            incident_confidence * 0.70
            + best_relevance * 0.30
        )

        return round(
            max(
                0.0,
                min(
                    1.0,
                    confidence,
                ),
            ),
            4,
        )

    def _family_confidence(
        self,
        context: IncidentContext,
    ) -> float:

        if not context.family_distribution:
            return max(
                0.0,
                min(
                    1.0,
                    float(context.confidence),
                ),
            )

        total = sum(
            context.family_distribution.values()
        )

        if total <= 0:
            return 0.0

        primary_count = (
            context.family_distribution.get(
                context.primary_attack_family,
                0,
            )
        )

        return round(
            primary_count / total,
            4,
        )

    def _build_summary(
        self,
        context: IncidentContext,
    ) -> str:

        if context.primary_attack_family:
            return (
                f"Incident {context.incident_id} contains "
                f"{context.event_count} correlated network events "
                f"with {context.primary_attack_family} as the "
                f"primary predicted attack family."
            )

        return (
            f"Incident {context.incident_id} contains "
            f"{context.event_count} correlated network events."
        )

    def _build_threat_assessment(
        self,
        context: IncidentContext,
    ) -> str:

        if context.severity:
            return context.severity.capitalize()

        if context.primary_attack_family in {
            "DDoS",
            "Infiltration",
        }:
            return "Critical"

        if context.primary_attack_family in {
            "DoS",
            "Brute Force",
            "Web Attack",
        }:
            return "High"

        if context.event_count >= 20:
            return "Medium"

        return "Low"

    def _build_recommended_actions(
        self,
        context: IncidentContext,
    ) -> list[str]:

        actions = []

        family = context.primary_attack_family

        if family == "Brute Force":

            actions.extend(
                [
                    "Review authentication logs for repeated failures.",
                    "Identify and investigate the source systems generating the activity.",
                    "Review the targeted service and destination port.",
                ]
            )

        elif family in {
            "DoS",
            "DDoS",
        }:

            actions.extend(
                [
                    "Review traffic volume and affected services.",
                    "Identify the primary source systems generating the traffic.",
                    "Assess whether rate limiting or traffic filtering is required.",
                ]
            )

        elif family == "Web Attack":

            actions.extend(
                [
                    "Review web server and application logs.",
                    "Inspect requests associated with the affected service.",
                    "Check for evidence of successful exploitation.",
                ]
            )

        elif family == "Infiltration":

            actions.extend(
                [
                    "Investigate the affected host for signs of compromise.",
                    "Review authentication and process activity.",
                    "Preserve relevant forensic evidence.",
                ]
            )

        elif family == "Bot":

            actions.extend(
                [
                    "Identify potentially compromised hosts.",
                    "Review outbound network connections.",
                    "Investigate persistence and command-and-control activity.",
                ]
            )

        else:

            actions.append(
                "Review the incident evidence and validate the detection."
            )

        return actions