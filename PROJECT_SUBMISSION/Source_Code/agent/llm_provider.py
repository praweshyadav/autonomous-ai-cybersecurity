from abc import ABC, abstractmethod

from agent.llm_contract import (
    LLMInvestigationInput,
    LLMInvestigationOutput,
)


class LLMProvider(ABC):
    """
    Abstract interface for an LLM used by the
    cybersecurity investigation agent.

    The investigation system depends on this interface,
    not on a specific LLM vendor or model.
    """

    @abstractmethod
    def investigate(
        self,
        investigation_input: LLMInvestigationInput,
    ) -> LLMInvestigationOutput:
        """
        Analyze the investigation input and return
        a structured investigation result.
        """
        raise NotImplementedError