from dataclasses import dataclass

from agent.context_builder import IncidentContext
from agent.incident_rag import IncidentRAGResult


@dataclass
class EvaluatedEvidence:
    """
    A RAG result evaluated against the actual incident context.

    retrieval_score:
        Semantic similarity returned by the vector database.

    relevance_score:
        Incident-specific relevance after considering the
        actual security evidence.

    The relevance score is NOT a probability that the
    technique occurred.
    """

    technique_id: str
    technique_name: str
    retrieval_score: float
    relevance_score: float
    relevance: str
    reason: str


class EvidenceEvaluator:
    """
    Evaluates retrieved MITRE ATT&CK knowledge against
    structured incident evidence.

    This layer does not confirm that a technique occurred.

    It only determines how relevant the retrieved knowledge
    is to the observed incident.
    """

    def evaluate(
        self,
        context: IncidentContext,
        rag_result: IncidentRAGResult,
    ) -> list[EvaluatedEvidence]:

        evaluated = []
        seen = set()

        for result in rag_result.results:

            title = self._get_value(
                result,
                "title",
            )

            score = self._get_value(
                result,
                "score",
            )

            if not title:
                continue

            technique_id, technique_name = (
                self._parse_mitre_title(title)
            )

            if technique_id is None:
                continue

            # Multiple chunks may belong to the same
            # MITRE technique.
            if technique_id in seen:
                continue

            seen.add(technique_id)

            retrieval_score = self._clamp(
                float(score or 0.0)
            )

            relevance_score, reason = (
                self._calculate_relevance(
                    context=context,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    retrieval_score=retrieval_score,
                )
            )

            evaluated.append(
                EvaluatedEvidence(
                    technique_id=technique_id,
                    technique_name=technique_name,
                    retrieval_score=retrieval_score,
                    relevance_score=relevance_score,
                    relevance=self._relevance_label(
                        relevance_score
                    ),
                    reason=reason,
                )
            )

        evaluated.sort(
            key=lambda item: item.relevance_score,
            reverse=True,
        )

        return evaluated

    def _calculate_relevance(
        self,
        context: IncidentContext,
        technique_id: str,
        technique_name: str,
        retrieval_score: float,
    ) -> tuple[float, str]:

        # -------------------------------------------------
        # IMPORTANT:
        #
        # Semantic similarity is only one part of the
        # relevance calculation.
        #
        # Incident-specific evidence receives more weight.
        # -------------------------------------------------

        score = retrieval_score * 0.20

        reasons = []

        primary_family = (
            context.primary_attack_family
            or ""
        ).lower()

        technique_name_lower = (
            technique_name.lower()
        )

        # -------------------------------------------------
        # 1. Attack-family alignment
        # -------------------------------------------------

        family_match = False

        if (
            primary_family == "brute force"
            and (
                "brute force" in technique_name_lower
                or technique_id.startswith("T1110")
            )
        ):
            family_match = True

        elif (
            primary_family in {"dos", "ddos"}
            and (
                "denial of service"
                in technique_name_lower
                or technique_id.startswith("T1498")
                or technique_id.startswith("T1499")
            )
        ):
            family_match = True

        elif (
            primary_family == "web attack"
            and (
                "web" in technique_name_lower
                or "application" in technique_name_lower
            )
        ):
            family_match = True

        elif (
            primary_family == "infiltration"
            and (
                "exploit" in technique_name_lower
                or "command" in technique_name_lower
                or "credential" in technique_name_lower
            )
        ):
            family_match = True

        elif (
            primary_family == "bot"
            and (
                "command and control"
                in technique_name_lower
                or "application layer protocol"
                in technique_name_lower
            )
        ):
            family_match = True

        if family_match:
            score += 0.50

            reasons.append(
                "Technique aligns with the primary attack family."
            )

        # -------------------------------------------------
        # 2. Network/service evidence
        # -------------------------------------------------

        if context.destination_ports:

            if (
                "remote service"
                in technique_name_lower
                or "network service"
                in technique_name_lower
            ):
                score += 0.05

                reasons.append(
                    "Technique is related to network/service activity."
                )

        # -------------------------------------------------
        # 3. Event volume
        # -------------------------------------------------

        if context.event_count >= 100:

            score += 0.05

            reasons.append(
                "The incident contains a substantial number "
                "of correlated events."
            )

        # -------------------------------------------------
        # 4. Dominant attack family
        # -------------------------------------------------

        if context.family_distribution:

            total = sum(
                context.family_distribution.values()
            )

            primary_count = (
                context.family_distribution.get(
                    context.primary_attack_family,
                    0,
                )
            )

            if total > 0:

                primary_ratio = (
                    primary_count / total
                )

                if primary_ratio >= 0.80:

                    score += 0.20

                    reasons.append(
                        "The primary attack family dominates "
                        "the incident evidence."
                    )

        score = self._clamp(score)

        if not reasons:

            reasons.append(
                "Relevance is primarily based on semantic "
                "retrieval similarity; incident-specific "
                "support is limited."
            )

        return (
            round(score, 4),
            " ".join(reasons),
        )

    @staticmethod
    def _relevance_label(
        score: float,
    ) -> str:

        if score >= 0.75:
            return "high"

        if score >= 0.50:
            return "medium"

        return "low"

    @staticmethod
    def _parse_mitre_title(
        title: str,
    ) -> tuple[str | None, str]:

        title = title.strip()

        if " - " not in title:
            return None, title

        technique_id, technique_name = (
            title.split(
                " - ",
                1,
            )
        )

        technique_id = technique_id.strip()
        technique_name = technique_name.strip()

        if not technique_id.startswith("T"):
            return None, title

        return (
            technique_id,
            technique_name,
        )

    @staticmethod
    def _get_value(
        result,
        field: str,
    ):

        value = getattr(
            result,
            field,
            None,
        )

        if value is None and isinstance(
            result,
            dict,
        ):
            value = result.get(field)

        return value

    @staticmethod
    def _clamp(
        value: float,
    ) -> float:

        return max(
            0.0,
            min(
                1.0,
                value,
            ),
        )