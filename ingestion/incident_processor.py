from correlation.correlation_adapter import CorrelationAdapter
from correlation.schema import Incident, SecurityEvent
from persistence.incident_persistence_adapter import (
    IncidentPersistenceAdapter,
)


class IncidentProcessor:
    """
    Coordinates correlation and incident persistence.

    Flow:

        SecurityEvents
             ?
        CorrelationAdapter
             ?
           Incident
             ?
        IncidentPersistenceAdapter
             ?
          PostgreSQL

    This class deliberately does not perform detection or
    event routing. Those responsibilities remain in their
    existing components.
    """

    def __init__(
        self,
        correlation_adapter: CorrelationAdapter,
        persistence_adapter: IncidentPersistenceAdapter,
    ) -> None:
        if not isinstance(
            correlation_adapter,
            CorrelationAdapter,
        ):
            raise TypeError(
                "correlation_adapter must be a CorrelationAdapter."
            )

        if not isinstance(
            persistence_adapter,
            IncidentPersistenceAdapter,
        ):
            raise TypeError(
                "persistence_adapter must be an "
                "IncidentPersistenceAdapter."
            )

        self.correlation_adapter = correlation_adapter
        self.persistence_adapter = persistence_adapter

    def process(
        self,
        events: list[SecurityEvent],
    ) -> list[Incident]:
        """
        Correlate the supplied security events and persist
        the resulting incidents.

        The supplied events are added to the correlation
        adapter, correlated, persisted, and then removed
        from the adapter's working buffer.
        """

        if not isinstance(
            events,
            list,
        ):
            raise TypeError(
                "events must be a list."
            )

        for event in events:
            if not isinstance(
                event,
                SecurityEvent,
            ):
                raise TypeError(
                    "all items in events must be SecurityEvent objects."
                )

        if not events:
            return []

        self.correlation_adapter.process_batch(
            events
        )

        incidents = self.correlation_adapter.correlate()

        if incidents:
            self.persistence_adapter.process_batch(
                incidents
            )

        self.correlation_adapter.clear()

        return incidents
