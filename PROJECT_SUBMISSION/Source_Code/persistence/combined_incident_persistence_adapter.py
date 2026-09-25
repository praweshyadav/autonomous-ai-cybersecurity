from correlation.schema import Incident


class CombinedIncidentPersistenceAdapter:
    """
    Persists each completed Incident through multiple persistence
    adapters.

    Current persistence targets:

        Incident
            ↓
        ┌───────────────┬────────────────┐
        ↓               ↓
    PostgreSQL         Neo4j
      adapter          adapter

    The adapter intentionally knows only about the common
    process_batch() interface.
    """

    def __init__(
        self,
        postgres_adapter,
        neo4j_adapter,
    ) -> None:
        if not callable(
            getattr(
                postgres_adapter,
                "process_batch",
                None,
            )
        ):
            raise TypeError(
                "postgres_adapter must provide a "
                "callable process_batch() method."
            )

        if not callable(
            getattr(
                neo4j_adapter,
                "process_batch",
                None,
            )
        ):
            raise TypeError(
                "neo4j_adapter must provide a "
                "callable process_batch() method."
            )

        self.postgres_adapter = postgres_adapter
        self.neo4j_adapter = neo4j_adapter

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

        self.process_batch([incident])

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

        if not incidents:
            return []

        self.postgres_adapter.process_batch(
            incidents
        )

        self.neo4j_adapter.process_batch(
            incidents
        )

        return [None] * len(incidents)

    def close(self) -> None:
        """
        Close persistence adapters that expose close().
        """

        postgres_close = getattr(
            self.postgres_adapter,
            "close",
            None,
        )

        if callable(postgres_close):
            postgres_close()

        neo4j_close = getattr(
            self.neo4j_adapter,
            "close",
            None,
        )

        if callable(neo4j_close):
            neo4j_close()
