from correlation.incident_window import IncidentWindow
from correlation.correlator import IncidentCorrelator
from correlation.schema import Incident, SecurityEvent


class IncidentManager:
    """
    Manages a continuously arriving stream of SecurityEvents.

    Responsibilities:

    1. Maintain the active IncidentWindow.
    2. Flush the window when an event falls outside it.
    3. Correlate flushed events into Incidents.
    4. Assign process-level incident IDs.
    5. Persist completed incidents.
    6. Expose callable and batch interfaces for EventRouter.

    Redis batch boundaries do NOT define incident boundaries.
    The IncidentWindow determines when correlation occurs.
    """

    def __init__(
        self,
        window: IncidentWindow,
        correlator: IncidentCorrelator,
        persistence_adapter,
    ) -> None:
        if not isinstance(window, IncidentWindow):
            raise TypeError(
                "window must be an IncidentWindow."
            )

        if not isinstance(
            correlator,
            IncidentCorrelator,
        ):
            raise TypeError(
                "correlator must be an IncidentCorrelator."
            )

        if not callable(
            getattr(
                persistence_adapter,
                "process_batch",
                None,
            )
        ):
            raise TypeError(
                "persistence_adapter must provide a "
                "callable process_batch() method."
            )

        self.window = window
        self.correlator = correlator
        self.persistence_adapter = persistence_adapter

        self._next_incident_number = 1

    def __call__(
        self,
        event: SecurityEvent,
    ) -> list[Incident]:
        """
        Make IncidentManager directly callable by EventRouter.
        """
        return self.process_event(event)

    def process_event(
        self,
        event: SecurityEvent,
    ) -> list[Incident]:
        """
        Process one SecurityEvent.

        Returns completed incidents if the incoming event causes
        the current incident window to flush.
        """
        self._validate_event(event)

        if self.window.is_empty():
            accepted = self.window.add(event)

            if not accepted:
                raise RuntimeError(
                    "Failed to add event to an empty IncidentWindow."
                )

            return []

        if self.window.can_accept(event):
            accepted = self.window.add(event)

            if not accepted:
                raise RuntimeError(
                    "IncidentWindow rejected an event it previously "
                    "reported as acceptable."
                )

            return []

        incidents = self.flush()

        accepted = self.window.add(event)

        if not accepted:
            raise RuntimeError(
                "Failed to add event to a new IncidentWindow."
            )

        return incidents

    def process_batch(
        self,
        events: list[SecurityEvent],
    ) -> list[list[Incident]]:
        """
        Process SecurityEvents in input order.

        Each input event produces one result list.

        The active IncidentWindow is preserved across calls, so
        Redis batch boundaries do not become incident boundaries.
        """
        if not isinstance(events, list):
            raise TypeError(
                "events must be a list."
            )

        for event in events:
            self._validate_event(event)

        if not events:
            return []

        results: list[list[Incident]] = []

        for event in events:
            results.append(
                self.process_event(event)
            )

        return results

    def flush(self) -> list[Incident]:
        """
        Flush the active IncidentWindow.

        Buffered events are correlated into incidents and completed
        incidents are persisted.
        """
        events = self.window.flush()

        if not events:
            return []

        incidents = self.correlator.correlate(events)

        if not incidents:
            return []

        self._assign_incident_ids(incidents)

        self.persistence_adapter.process_batch(
            incidents
        )

        return incidents

    def reset(self) -> None:
        """
        Discard currently buffered events.

        Incident numbering is preserved.
        """
        self.window.clear()

    @property
    def buffered_event_count(self) -> int:
        """
        Number of events currently buffered.
        """
        return self.window.event_count

    @property
    def next_incident_number(self) -> int:
        """
        Return the next process-level incident number.
        """
        return self._next_incident_number

    def _assign_incident_ids(
        self,
        incidents: list[Incident],
    ) -> None:
        """
        Assign continuous incident IDs within this manager process.
        """
        for incident in incidents:
            incident.incident_id = (
                f"INC-{self._next_incident_number:06d}"
            )

            self._next_incident_number += 1

    @staticmethod
    def _validate_event(
        event: SecurityEvent,
    ) -> None:
        """
        Validate an incoming SecurityEvent.
        """
        if not isinstance(
            event,
            SecurityEvent,
        ):
            raise TypeError(
                "event must be a SecurityEvent."
            )

