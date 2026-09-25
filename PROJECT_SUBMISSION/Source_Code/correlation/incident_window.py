from __future__ import annotations

from datetime import datetime, timedelta

from correlation.schema import SecurityEvent


class IncidentWindow:
    """
    Maintains a time-bounded collection of SecurityEvents.

    The window is based on event timestamps, not wall-clock time.

    Responsibilities:
        - Accept security events.
        - Track the earliest event timestamp.
        - Determine whether an event belongs to the current window.
        - Return and clear the current window when flushed.

    This class does NOT:
        - perform detection,
        - correlate events,
        - create incidents,
        - persist data,
        - call an LLM.
    """

    def __init__(
        self,
        window_seconds: int = 60,
    ) -> None:
        if not isinstance(window_seconds, int):
            raise TypeError(
                "window_seconds must be an integer."
            )

        if window_seconds <= 0:
            raise ValueError(
                "window_seconds must be greater than zero."
            )

        self.window_seconds = window_seconds
        self._events: list[SecurityEvent] = []
        self._start_time: datetime | None = None

    @property
    def start_time(self) -> datetime | None:
        """
        Return the timestamp of the first event in the window.
        """
        return self._start_time

    @property
    def event_count(self) -> int:
        """
        Return the number of events currently in the window.
        """
        return len(self._events)

    def is_empty(self) -> bool:
        """
        Return True when the window contains no events.
        """
        return not self._events

    def can_accept(
        self,
        event: SecurityEvent,
    ) -> bool:
        """
        Determine whether an event falls within the current
        timestamp-based window.

        An empty window accepts the first event.

        For an active window, the event is accepted when its
        timestamp is no more than window_seconds after the
        window start.
        """

        self._validate_event(event)

        if self._start_time is None:
            return True

        elapsed = event.timestamp - self._start_time

        return elapsed <= timedelta(
            seconds=self.window_seconds
        )

    def add(
        self,
        event: SecurityEvent,
    ) -> bool:
        """
        Add an event to the current window.

        Returns:
            True  -> event was accepted.
            False -> event falls outside the current window.
        """

        self._validate_event(event)

        if not self.can_accept(event):
            return False

        if self._start_time is None:
            self._start_time = event.timestamp

        self._events.append(event)

        return True

    def get_events(self) -> list[SecurityEvent]:
        """
        Return a copy of the current events.
        """
        return list(self._events)

    def flush(self) -> list[SecurityEvent]:
        """
        Return all events currently in the window and
        reset the window.
        """

        events = list(self._events)

        self.clear()

        return events

    def clear(self) -> None:
        """
        Remove all events and reset the window.
        """
        self._events.clear()
        self._start_time = None

    @staticmethod
    def _validate_event(
        event: SecurityEvent,
    ) -> None:
        if not isinstance(
            event,
            SecurityEvent,
        ):
            raise TypeError(
                "event must be a SecurityEvent."
            )

        if not isinstance(
            event.timestamp,
            datetime,
        ):
            raise TypeError(
                "event.timestamp must be a datetime."
            )

        if (
            event.timestamp.tzinfo is None
            or event.timestamp.utcoffset() is None
        ):
            raise ValueError(
                "event.timestamp must be timezone-aware."
            )
