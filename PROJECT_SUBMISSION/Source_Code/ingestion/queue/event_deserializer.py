from datetime import datetime
from typing import Any

from correlation.schema import SecurityEvent


class SecurityEventDeserializer:
    """
    Reconstructs SecurityEvent objects from dictionaries
    received from the Redis Stream.
    """

    @staticmethod
    def _deserialize_metadata(
        metadata: Any,
    ) -> dict[str, Any]:
        """
        Restore numeric CICFlowMeter feature values after
        Redis JSON serialization.

        JSON serialization can represent all values as strings
        depending on the producer/consumer path. CICFlowMeter
        features must be numeric before reaching the ML models.
        """

        if metadata is None:
            return {}

        if not isinstance(metadata, dict):
            raise TypeError(
                "metadata must be a dictionary."
            )

        normalized: dict[str, Any] = {}

        for key, value in metadata.items():
            if isinstance(value, str):
                stripped = value.strip()

                if stripped == "":
                    normalized[key] = value
                    continue

                try:
                    normalized[key] = float(stripped)
                    continue
                except ValueError:
                    normalized[key] = value
                    continue

            normalized[key] = value

        return normalized

    def deserialize(
        self,
        event_data: dict[str, Any],
    ) -> SecurityEvent:
        """
        Convert a Redis event dictionary into a SecurityEvent.
        """

        if not isinstance(event_data, dict):
            raise TypeError(
                "event_data must be a dictionary."
            )

        required_fields = {
            "event_id",
            "timestamp",
        }

        missing_fields = required_fields - event_data.keys()

        if missing_fields:
            raise ValueError(
                f"Missing required fields: {sorted(missing_fields)}"
            )

        timestamp = event_data["timestamp"]

        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except ValueError as exc:
                raise ValueError(
                    "timestamp must be a valid ISO-8601 datetime string."
                ) from exc

        if not isinstance(timestamp, datetime):
            raise TypeError(
                "timestamp must be a datetime or ISO-8601 string."
            )

        metadata = self._deserialize_metadata(
            event_data.get(
                "metadata",
                {},
            )
        )

        return SecurityEvent(
            event_id=str(event_data["event_id"]),
            timestamp=timestamp,

            src_ip=event_data.get("src_ip"),
            dst_ip=event_data.get("dst_ip"),
            src_port=event_data.get("src_port"),
            dst_port=event_data.get("dst_port"),
            protocol=event_data.get("protocol"),
            protocol_name=event_data.get("protocol_name"),

            binary_prediction=int(
                event_data.get("binary_prediction", 0)
            ),
            attack_family=event_data.get(
                "attack_family",
                "Benign",
            ),
            confidence=float(
                event_data.get("confidence", 0.0)
            ),

            source_file=event_data.get("source_file"),

            true_label=event_data.get("true_label"),
            true_attack_family=event_data.get(
                "true_attack_family"
            ),

            event_type=event_data.get("event_type"),

            windows_event_id=event_data.get(
                "windows_event_id"
            ),
            username=event_data.get("username"),
            domain=event_data.get("domain"),
            process_name=event_data.get("process_name"),

            firewall_action=event_data.get(
                "firewall_action"
            ),

            raw_log=event_data.get("raw_log"),

            metadata=metadata,
        )

    def deserialize_batch(
        self,
        events: list[dict[str, Any]],
    ) -> list[SecurityEvent]:
        """
        Deserialize a batch of Redis event dictionaries.
        """

        if not isinstance(events, list):
            raise TypeError(
                "events must be a list."
            )

        return [
            self.deserialize(event)
            for event in events
        ]
