from agent.context_builder import IncidentContext
from agent.incident_rag import IncidentRAGResult
from agent.investigation import InvestigationResult
from agent.llm_contract import LLMInvestigationOutput
from agent.llm_input_builder import LLMInputBuilder
from agent.llm_provider import LLMProvider


class LLMInvestigationAgent:
    """
    Orchestrates the deterministic investigation pipeline
    and passes the controlled investigation context to an LLM.

    The provider is responsible only for investigation reasoning.
    It cannot directly execute response actions.
    """

    def __init__(
        self,
        provider: LLMProvider,
        input_builder: LLMInputBuilder | None = None,
    ):
        self.provider = provider

        self.input_builder = (
            input_builder
            if input_builder is not None
            else LLMInputBuilder()
        )

    def investigate(
        self,
        context: IncidentContext,
        investigation: InvestigationResult,
        rag_result: IncidentRAGResult,
    ) -> LLMInvestigationOutput:

        llm_input = self.input_builder.build(
            context=context,
            investigation=investigation,
            rag_result=rag_result,
        )

        return self.provider.investigate(
            llm_input
        )