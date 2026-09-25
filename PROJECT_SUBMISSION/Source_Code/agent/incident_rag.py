from dataclasses import dataclass

from agent.context_builder import IncidentContext
from rag.retriever.query_engine import RAGQueryEngine


@dataclass
class IncidentRAGResult:
    """
    RAG results associated with an incident.
    """

    incident_id: str
    query: str
    results: list


class IncidentRAG:
    """
    Connects structured incident context to the cybersecurity
    knowledge retrieval system.

    Flow:

        IncidentContext
              ↓
        Investigation Query
              ↓
        RAGQueryEngine
              ↓
        MITRE ATT&CK Results

    Resource ownership:

        If IncidentRAG creates the RAGQueryEngine itself,
        IncidentRAG owns it and is responsible for closing it.

        If a query engine is supplied by the caller,
        the caller owns it and IncidentRAG will not close it.
    """

    def __init__(
        self,
        query_engine: RAGQueryEngine | None = None,
    ):
        if query_engine is None:
            self.query_engine = RAGQueryEngine()
            self._owns_query_engine = True
        else:
            self.query_engine = query_engine
            self._owns_query_engine = False

        self._closed = False

    def build_query(
        self,
        context: IncidentContext,
    ) -> str:
        """
        Convert structured incident information into a
        natural-language cybersecurity retrieval query.

        This function is deterministic and does not use an LLM.
        """

        if self._closed:
            raise RuntimeError(
                "IncidentRAG is already closed."
            )

        parts = []

        if context.primary_attack_family:
            parts.append(
                f"Primary attack family: "
                f"{context.primary_attack_family}"
            )

        if context.attack_families:
            parts.append(
                "Observed attack families: "
                + ", ".join(context.attack_families)
            )

        if context.family_distribution:
            family_counts = ", ".join(
                f"{family} ({count} events)"
                for family, count
                in sorted(
                    context.family_distribution.items()
                )
            )

            parts.append(
                "Attack family distribution: "
                + family_counts
            )

        if context.protocols:
            parts.append(
                "Protocols: "
                + ", ".join(
                    str(protocol)
                    for protocol in context.protocols
                )
            )

        if context.destination_ports:
            parts.append(
                "Destination ports: "
                + ", ".join(
                    str(port)
                    for port in context.destination_ports
                )
            )

        return (
            "Cybersecurity incident investigation. "
            + ". ".join(parts)
        )

    def investigate(
        self,
        context: IncidentContext,
        top_k: int = 5,
    ) -> IncidentRAGResult:
        """
        Retrieve cybersecurity knowledge relevant to an incident.
        """

        if self._closed:
            raise RuntimeError(
                "IncidentRAG is already closed."
            )

        query = self.build_query(context)

        results = self.query_engine.query(
            query=query,
            top_k=top_k,
        )

        return IncidentRAGResult(
            incident_id=context.incident_id,
            query=query,
            results=results,
        )

    def close(self) -> None:
        """
        Release the underlying RAGQueryEngine if this
        IncidentRAG instance owns it.

        Calling close() multiple times is safe.
        """

        if self._closed:
            return

        if self._owns_query_engine:
            close_method = getattr(
                self.query_engine,
                "close",
                None,
            )

            if callable(close_method):
                close_method()

        self._closed = True

    def __enter__(self):
        """
        Support usage as a context manager.
        """

        if self._closed:
            raise RuntimeError(
                "IncidentRAG is already closed."
            )

        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        """
        Automatically release resources when leaving
        a context manager.
        """

        self.close()

    def __del__(self) -> None:
        """
        Best-effort cleanup if the object is garbage collected.
        """

        try:
            self.close()
        except Exception:
            pass