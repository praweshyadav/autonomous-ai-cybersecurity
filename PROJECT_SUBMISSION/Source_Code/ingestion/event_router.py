from collections.abc import Callable
from typing import Any

from correlation.schema import SecurityEvent


EventHandler = Callable[[SecurityEvent], Any]


class EventRouter:
    """
    Routes normalized SecurityEvents to registered handlers.

    The router does not perform detection, correlation, storage,
    or response actions itself. It only dispatches events.

    Handlers that provide a process_batch(events) method can
    receive batches without falling back to per-event processing.

    Example architecture:

        SecurityEvent
             |
             v
        EventRouter
          /   |   \
         /    |    \
    Detection Storage Correlation
    Handler  Handler   Handler
    """

    def __init__(self) -> None:
        self._handlers: dict[str, EventHandler] = {}

    def register(
        self,
        name: str,
        handler: EventHandler,
    ) -> None:
        """
        Register a handler under a unique name.
        """
        if not isinstance(name, str):
            raise TypeError("handler name must be a string.")

        name = name.strip()

        if not name:
            raise ValueError("handler name cannot be empty.")

        if not callable(handler):
            raise TypeError("handler must be callable.")

        if name in self._handlers:
            raise ValueError(
                f"Handler already registered: {name}"
            )

        self._handlers[name] = handler

    def unregister(self, name: str) -> None:
        """
        Remove a registered handler.
        """
        if not isinstance(name, str):
            raise TypeError("handler name must be a string.")

        name = name.strip()

        if name not in self._handlers:
            raise KeyError(
                f"Handler not registered: {name}"
            )

        del self._handlers[name]

    def route(
        self,
        event: SecurityEvent,
    ) -> dict[str, Any]:
        """
        Route one SecurityEvent to every registered handler.

        Returns a dictionary containing each handler's result.
        """
        if not isinstance(event, SecurityEvent):
            raise TypeError(
                "event must be a SecurityEvent."
            )

        results: dict[str, Any] = {}

        for name, handler in self._handlers.items():
            results[name] = handler(event)

        return results

    def route_batch(
        self,
        events: list[SecurityEvent],
    ) -> list[dict[str, Any]]:
        """
        Route a batch of SecurityEvents.

        If a handler provides a process_batch(events) method,
        that method is used once for the entire batch.

        Otherwise, the handler is called once per event.

        Results are returned in the same order as the input
        events.
        """
        if not isinstance(events, list):
            raise TypeError("events must be a list.")

        for event in events:
            if not isinstance(
                event,
                SecurityEvent,
            ):
                raise TypeError(
                    "all items in events must be "
                    "SecurityEvent objects."
                )

        if not events:
            return []

        batch_results: dict[str, list[Any]] = {}

        for name, handler in self._handlers.items():

            process_batch = getattr(
                handler,
                "process_batch",
                None,
            )

            if callable(process_batch):
                handler_results = process_batch(
                    events
                )

                if not isinstance(
                    handler_results,
                    list,
                ):
                    raise TypeError(
                        f"Batch handler '{name}' must return "
                        "a list of results."
                    )

                if len(handler_results) != len(events):
                    raise RuntimeError(
                        f"Batch handler '{name}' returned "
                        "a different number of results "
                        "than input events."
                    )

                batch_results[name] = handler_results

            else:
                batch_results[name] = [
                    handler(event)
                    for event in events
                ]

        return [
            {
                name: batch_results[name][index]
                for name in self._handlers
            }
            for index in range(len(events))
        ]

    def handler_names(self) -> list[str]:
        """
        Return registered handler names.
        """
        return list(self._handlers.keys())

    def has_handler(
        self,
        name: str,
    ) -> bool:
        """
        Check whether a handler is registered.
        """
        if not isinstance(name, str):
            raise TypeError(
                "handler name must be a string."
            )

        return name.strip() in self._handlers

    def clear(self) -> None:
        """
        Remove all registered handlers.
        """
        self._handlers.clear()