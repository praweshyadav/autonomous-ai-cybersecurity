from correlation.schema import Incident
from knowledge_graph.repository import Neo4jGraphRepository


class Neo4jIncidentPersistenceAdapter:
    """
    Persists correlated Incidents into Neo4j.

    Responsibility:

        Incident
            ↓
        Neo4jGraphRepository
            ↓
        Neo4j Knowledge Graph
    """

    def __init__(
        self,
        repository: Neo4jGraphRepository | None = None,
    ) -> None:
        self.repository = (
            repository
            if repository is not None
            else Neo4jGraphRepository()
        )

    def __call__(
        self,
        incident: Incident,
    ) -> None:
        self.process(incident)

    def process(
        self,
        incident: Incident,
    ) -> None:
        if not isinstance(
            incident,
            Incident,
        ):
            raise TypeError(
                "incident must be an Incident."
            )

        self.repository.save_incident(incident)

    def process_batch(
        self,
        incidents: list[Incident],
    ) -> list[None]:
        if not isinstance(
            incidents,
            list,
        ):
            raise TypeError(
                "incidents must be a list."
            )

        for incident in incidents:
            if not isinstance(
                incident,
                Incident,
            ):
                raise TypeError(
                    "all items in incidents must be Incident objects."
                )

        for incident in incidents:
            self.process(incident)

        return [None] * len(incidents)

    def close(self) -> None:
        """Close the underlying Neo4j repository."""
        self.repository.close()
