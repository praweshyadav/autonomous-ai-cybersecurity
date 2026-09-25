from correlation.schema import Incident
from persistence.incident_persistence_service import (
    IncidentPersistenceService,
)


class IncidentPersistenceAdapter:
    """
    Persists correlated Incidents using the
    IncidentPersistenceService.

    Responsibility:

        Incident
            ?
        Persistence Service
            ?
        PostgreSQL
    """

    def __init__(
        self,
        persistence_service: IncidentPersistenceService | None = None,
    ) -> None:
        self.persistence_service = (
            persistence_service
            if persistence_service is not None
            else IncidentPersistenceService()
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

        self.persistence_service.save_incident_with_events(
            incident
        )

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
