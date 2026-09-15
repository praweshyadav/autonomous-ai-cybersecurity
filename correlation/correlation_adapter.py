from correlation.correlator import IncidentCorrelator
from correlation.schema import Incident, SecurityEvent


class CorrelationAdapter:
    """
    Adapts individual SecurityEvents from the EventRouter
    to the IncidentCorrelator.

    The adapter maintains a buffer of events and can produce
    correlated incidents from the accumulated events.
    """

    def __init__(
        self,
        correlator: IncidentCorrelator | None = None,
    ):
        self.correlator = (
            correlator
            if correlator is not None
            else IncidentCorrelator()
        )

        self._events: list[SecurityEvent] = []

    def __call__(
        self,
        event: SecurityEvent,
    ) -> None:
        self.process(event)

    def process(
        self,
        event: SecurityEvent,
    ) -> None:
        if not isinstance(event, SecurityEvent):
            raise TypeError(
                "event must be a SecurityEvent."
            )

        self._events.append(event)

    def process_batch(
        self,
        events: list[SecurityEvent],
    ) -> list[None]:
        if not isinstance(events, list):
            raise TypeError(
                "events must be a list."
            )

        for event in events:
            if not isinstance(event, SecurityEvent):
                raise TypeError(
                    "all items in events must be SecurityEvent objects."
                )

        self._events.extend(events)

        return [None] * len(events)

    def correlate(
        self,
    ) -> list[Incident]:
        """
        Correlate all currently buffered events.
        """

        if not self._events:
            return []

        return self.correlator.correlate(
            self._events
        )

    def get_events(
        self,
    ) -> list[SecurityEvent]:
        """
        Return a copy of the buffered events.
        """

        return list(self._events)

    def clear(self) -> None:
        """
        Clear the buffered events.
        """

        self._events.clear()