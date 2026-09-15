from dataclasses import dataclass, field
from typing import Any


@dataclass
class InvestigationEvidence:
    """
    A single piece of evidence used during incident investigation.

    Evidence must distinguish observed facts from conclusions.
    """

    source: str
    description: str
    evidence_type: str = "observed"


@dataclass
class InvestigationTechnique:
    """
    MITRE ATT&CK technique associated with the investigation.
    """

    technique_id: str
    technique_name: str
    relevance: str
    confidence: float


@dataclass
class InvestigationHypothesis:
    """
    A possible explanation for the incident.

    A hypothesis is not automatically treated as fact.
    """

    description: str
    supporting_evidence: list[str] = field(
        default_factory=list
    )
    contradicting_evidence: list[str] = field(
        default_factory=list
    )
    confidence: float = 0.0


@dataclass
class InvestigationResult:
    """
    Structured result produced by the investigation agent.

    This is the contract between:
        Incident/RAG
              ↓
        Investigation Agent
              ↓
        Response Planner
              ↓
        Dashboard/API
    """

    incident_id: str

    summary: str

    threat_assessment: str

    attack_families: list[str] = field(
        default_factory=list
    )

    evidence: list[InvestigationEvidence] = field(
        default_factory=list
    )

    mitre_techniques: list[InvestigationTechnique] = field(
        default_factory=list
    )

    hypotheses: list[InvestigationHypothesis] = field(
        default_factory=list
    )

    confidence: float = 0.0

    recommended_actions: list[str] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )