from dataclasses import dataclass
from typing import Any

from correlation.schema import Incident

from agent.context_builder import (
    IncidentContext,
    IncidentContextBuilder,
)
from agent.incident_rag import (
    IncidentRAG,
    IncidentRAGResult,
)
from agent.investigation import (
    InvestigationResult,
)
from agent.investigation_engine import (
    InvestigationEngine,
)
from agent.llm_contract import (
    LLMInvestigationOutput,
)
from agent.llm_investigation_agent import (
    LLMInvestigationAgent,
)


@dataclass
class InvestigationOrchestrationResult:
    """
    Complete result produced by the investigation pipeline.

    The result preserves every important stage of investigation:

        Incident
            ↓
        IncidentContext
            ↓
        IncidentRAGResult
            ↓
        InvestigationResult
            ↓
        optional LLMInvestigationOutput

    The LLM output is optional so the deterministic investigation
    pipeline can operate even when an LLM provider is unavailable.
    """

    incident_id: str

    context: IncidentContext

    rag_result: IncidentRAGResult

    investigation: InvestigationResult

    llm_output: LLMInvestigationOutput | None = None

    metadata: dict[str, Any] | None = None


class InvestigationOrchestrator:
    """
    Coordinates the complete cybersecurity incident investigation
    pipeline.

    Responsibilities:

    1. Build structured incident context.
    2. Retrieve relevant cybersecurity knowledge through RAG.
    3. Evaluate evidence through the deterministic investigation engine.
    4. Optionally pass the controlled investigation context to an LLM.
    5. Return all intermediate and final investigation results.

    This class does not:
        - perform detection
        - correlate events
        - persist incidents
        - execute response actions
    """

    def __init__(
        self,
        context_builder: IncidentContextBuilder | None = None,
        incident_rag: IncidentRAG | None = None,
        investigation_engine: InvestigationEngine | None = None,
        llm_agent: LLMInvestigationAgent | None = None,
    ) -> None:

        self.context_builder = (
            context_builder
            if context_builder is not None
            else IncidentContextBuilder()
        )

        self.incident_rag = (
            incident_rag
            if incident_rag is not None
            else IncidentRAG()
        )

        self.investigation_engine = (
            investigation_engine
            if investigation_engine is not None
            else InvestigationEngine()
        )

        self.llm_agent = llm_agent

    def investigate(
        self,
        incident: Incident,
        top_k: int = 5,
        use_llm: bool = False,
    ) -> InvestigationOrchestrationResult:
        """
        Execute the complete investigation pipeline.

        Parameters
        ----------
        incident:
            Completed correlated security incident.

        top_k:
            Number of RAG results to retrieve.

        use_llm:
            Whether to execute the optional LLM investigation stage.

        Returns
        -------
        InvestigationOrchestrationResult
            Complete deterministic investigation result plus
            optional LLM output.
        """

        self._validate_incident(incident)

        if not isinstance(top_k, int):
            raise TypeError(
                "top_k must be an integer."
            )

        if top_k <= 0:
            raise ValueError(
                "top_k must be greater than zero."
            )

        if not isinstance(use_llm, bool):
            raise TypeError(
                "use_llm must be a boolean."
            )

        if use_llm and self.llm_agent is None:
            raise RuntimeError(
                "use_llm=True requires an LLMInvestigationAgent."
            )

        # ---------------------------------------------------------
        # Stage 1: Build structured incident context.
        # ---------------------------------------------------------

        context = self.context_builder.build(
            incident
        )

        # ---------------------------------------------------------
        # Stage 2: Retrieve cybersecurity knowledge.
        # ---------------------------------------------------------

        rag_result = self.incident_rag.investigate(
            context=context,
            top_k=top_k,
        )

        # ---------------------------------------------------------
        # Stage 3: Deterministic investigation.
        # ---------------------------------------------------------

        investigation = self.investigation_engine.investigate(
            context=context,
            rag_result=rag_result,
        )

        # ---------------------------------------------------------
        # Stage 4: Optional controlled LLM investigation.
        # ---------------------------------------------------------

        llm_output = None

        if use_llm:
            llm_output = self.llm_agent.investigate(
                context=context,
                investigation=investigation,
                rag_result=rag_result,
            )

        # ---------------------------------------------------------
        # Final orchestration result.
        # ---------------------------------------------------------

        metadata = {
            "rag_result_count": len(
                rag_result.results
            ),
            "investigation_confidence": (
                investigation.confidence
            ),
            "llm_used": use_llm,
        }

        return InvestigationOrchestrationResult(
            incident_id=incident.incident_id,
            context=context,
            rag_result=rag_result,
            investigation=investigation,
            llm_output=llm_output,
            metadata=metadata,
        )

    def investigate_deterministic(
        self,
        incident: Incident,
        top_k: int = 5,
    ) -> InvestigationOrchestrationResult:
        """
        Run investigation without invoking an LLM.

        This is the preferred path for deterministic testing
        and environments where an LLM provider is unavailable.
        """

        return self.investigate(
            incident=incident,
            top_k=top_k,
            use_llm=False,
        )

    def investigate_with_llm(
        self,
        incident: Incident,
        top_k: int = 5,
    ) -> InvestigationOrchestrationResult:
        """
        Run the complete investigation pipeline including
        the configured LLM investigation agent.
        """

        return self.investigate(
            incident=incident,
            top_k=top_k,
            use_llm=True,
        )

    def close(self) -> None:
        """
        Release resources owned by the RAG component.

        The orchestrator does not own the LLM agent or its provider.
        """

        close_method = getattr(
            self.incident_rag,
            "close",
            None,
        )

        if callable(close_method):
            close_method()

    @staticmethod
    def _validate_incident(
        incident: Incident,
    ) -> None:

        if not isinstance(
            incident,
            Incident,
        ):
            raise TypeError(
                "incident must be an Incident."
            )
