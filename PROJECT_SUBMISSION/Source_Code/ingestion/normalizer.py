from datetime import datetime
from typing import Any, Optional

from correlation.schema import SecurityEvent


class SecurityEventNormalizer:
    """
    Converts parser output into the project's unified
    SecurityEvent representation.

    The normalizer validates and standardizes incoming events.
    It does not perform threat detection.
    """

    def normalize(
        self,
        raw_event: dict[str, Any],
    ) -> SecurityEvent:
        if not isinstance(raw_event, dict):
            raise TypeError(
                "raw_event must be a dictionary."
            )

        event_id = raw_event.get("event_id")

        if not event_id:
            raise ValueError(
                "raw_event must contain event_id."
            )

        timestamp = self._parse_timestamp(
            raw_event.get("timestamp")
        )

        confidence = float(
            raw_event.get(
                "confidence",
                0.0,
            )
        )

        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1."
            )

        binary_prediction = int(
            raw_event.get(
                "binary_prediction",
                0,
            )
        )

        if binary_prediction not in {0, 1}:
            raise ValueError(
                "binary_prediction must be 0 or 1."
            )

        metadata = raw_event.get(
            "metadata",
            {},
        )

        if not isinstance(metadata, dict):
            raise TypeError(
                "metadata must be a dictionary."
            )

        return SecurityEvent(
            event_id=str(event_id),
            timestamp=timestamp,

            src_ip=self._optional_string(
                raw_event.get("src_ip")
            ),
            dst_ip=self._optional_string(
                raw_event.get("dst_ip")
            ),
            src_port=self._optional_int(
                raw_event.get("src_port")
            ),
            dst_port=self._optional_int(
                raw_event.get("dst_port")
            ),
            protocol=self._optional_int(
                raw_event.get("protocol")
            ),
            protocol_name=self._optional_string(
                raw_event.get("protocol_name")
            ),

            binary_prediction=binary_prediction,
            attack_family=str(
                raw_event.get(
                    "attack_family",
                    "Benign",
                )
            ),
            confidence=confidence,

            source_file=self._optional_string(
                raw_event.get("source_file")
            ),

            true_label=self._optional_string(
                raw_event.get("true_label")
            ),
            true_attack_family=self._optional_string(
                raw_event.get(
                    "true_attack_family"
                )
            ),

            event_type=self._optional_string(
                raw_event.get("event_type")
            ),

            windows_event_id=self._optional_int(
                raw_event.get(
                    "windows_event_id"
                )
            ),
            username=self._optional_string(
                raw_event.get("username")
            ),
            domain=self._optional_string(
                raw_event.get("domain")
            ),
            process_name=self._optional_string(
                raw_event.get("process_name")
            ),

            firewall_action=self._optional_string(
                raw_event.get(
                    "firewall_action"
                )
            ),

            raw_log=self._optional_string(
                raw_event.get("raw_log")
            ),

            metadata=dict(metadata),
        )

    def _parse_timestamp(
        self,
        value: Any,
    ) -> datetime:
        if isinstance(value, datetime):
            return value

        if not isinstance(value, str):
            raise ValueError(
                "timestamp must be a datetime "
                "or ISO-format string."
            )

        try:
            return datetime.fromisoformat(
                value
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid timestamp: {value}"
            ) from exc

    @staticmethod
    def _optional_string(
        value: Any,
    ) -> Optional[str]:
        if value is None:
            return None

        return str(value)

    @staticmethod
    def _optional_int(
        value: Any,
    ) -> Optional[int]:
        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid integer value: {value}"
            ) from exc