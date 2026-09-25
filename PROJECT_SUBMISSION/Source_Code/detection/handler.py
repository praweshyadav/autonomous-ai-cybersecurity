from dataclasses import dataclass
from typing import Any

import pandas as pd

from correlation.schema import SecurityEvent
from detection.feature_adapter import FeatureAdapter
from detection.model_loader import (
    AttackFamilyModelBundle,
    BinaryModelBundle,
)


@dataclass
class DetectionResult:
    """
    Result produced by the detection handler.
    """

    event_id: str
    detected: bool
    attack_family: str
    confidence: float
    detector_type: str
    supported: bool
    reason: str = ""


class DetectionHandler:
    """
    Adapter between SecurityEvent objects and the trained
    CIC-IDS XGBoost detection models.

    Network-flow features are expected to be stored inside
    SecurityEvent.metadata.

    Linux, Windows, and firewall events remain outside the
    CIC-IDS network-flow detection boundary.
    """

    NETWORK_FLOW_EVENT_TYPES = {
        "network_flow",
        "cicflow",
        "cicflowmeter",
    }

    DETECTOR_TYPE = "cic_ids_xgboost"

    def __init__(self) -> None:
        self._binary_model: BinaryModelBundle | None = None
        self._family_model: AttackFamilyModelBundle | None = None
        self._feature_adapter: FeatureAdapter | None = None

    def attach_models(
        self,
        binary_model: BinaryModelBundle,
        family_model: AttackFamilyModelBundle,
    ) -> None:
        """
        Attach validated trained model bundles.
        """
        if binary_model is None:
            raise ValueError(
                "binary_model cannot be None."
            )

        if family_model is None:
            raise ValueError(
                "family_model cannot be None."
            )

        if not isinstance(
            binary_model,
            BinaryModelBundle,
        ):
            raise TypeError(
                "binary_model must be a BinaryModelBundle."
            )

        if not isinstance(
            family_model,
            AttackFamilyModelBundle,
        ):
            raise TypeError(
                "family_model must be an "
                "AttackFamilyModelBundle."
            )

        self._binary_model = binary_model
        self._family_model = family_model

        self._feature_adapter = FeatureAdapter(
            binary_feature_names=(
                binary_model.feature_names
            ),
            family_feature_columns=(
                family_model.feature_columns
            ),
        )

    def is_supported(
        self,
        event: SecurityEvent,
    ) -> bool:
        """
        Determine whether the event belongs to the current
        network-flow detection boundary.
        """
        if not isinstance(event, SecurityEvent):
            raise TypeError(
                "event must be a SecurityEvent."
            )

        if event.event_type is None:
            return False

        return (
            event.event_type.strip().lower()
            in self.NETWORK_FLOW_EVENT_TYPES
        )

    def _metadata_dataframe(
        self,
        event: SecurityEvent,
    ) -> pd.DataFrame:
        """
        Convert network-flow metadata into a one-row DataFrame.
        """
        if not isinstance(event.metadata, dict):
            raise TypeError(
                "SecurityEvent.metadata must be a dictionary."
            )

        if not event.metadata:
            raise ValueError(
                "Network-flow event contains no CIC-IDS "
                "features in metadata."
            )

        return pd.DataFrame([event.metadata])

    def detect(
        self,
        event: SecurityEvent,
    ) -> DetectionResult:
        """
        Run binary detection followed by attack-family
        classification.
        """
        if not isinstance(event, SecurityEvent):
            raise TypeError(
                "event must be a SecurityEvent."
            )

        if not self.is_supported(event):
            return DetectionResult(
                event_id=event.event_id,
                detected=False,
                attack_family="Unknown",
                confidence=0.0,
                detector_type=self.DETECTOR_TYPE,
                supported=False,
                reason=(
                    "Event type is outside the current "
                    "CIC-IDS network-flow detection boundary."
                ),
            )

        if self._binary_model is None:
            raise RuntimeError(
                "Binary detection model is not attached."
            )

        if self._family_model is None:
            raise RuntimeError(
                "Attack-family detection model is not attached."
            )

        if self._feature_adapter is None:
            raise RuntimeError(
                "Feature adapter is not initialized."
            )

        dataframe = self._metadata_dataframe(event)

        binary_features = (
            self._feature_adapter.to_binary_features(
                dataframe
            )
        )

        family_features = (
            self._feature_adapter.to_family_features(
                dataframe
            )
        )

        binary_prediction = int(
            self._binary_model.model.predict(
                binary_features
            )[0]
        )

        binary_probabilities = (
            self._binary_model.model.predict_proba(
                binary_features
            )[0]
        )

        attack_probability = float(
            binary_probabilities[1]
        )

        family_prediction = int(
            self._family_model.model.predict(
                family_features
            )[0]
        )

        family_probabilities = (
            self._family_model.model.predict_proba(
                family_features
            )[0]
        )

        attack_family = str(
            self._family_model.label_encoder.inverse_transform(
                [family_prediction]
            )[0]
        )

        family_confidence = float(
            family_probabilities[
                family_prediction
            ]
        )

        if binary_prediction == 0:
            attack_family = "Benign"
            confidence = float(
                binary_probabilities[0]
            )
        else:
            confidence = min(
                attack_probability,
                family_confidence,
            )

        return DetectionResult(
            event_id=event.event_id,
            detected=bool(binary_prediction),
            attack_family=attack_family,
            confidence=confidence,
            detector_type=self.DETECTOR_TYPE,
            supported=True,
            reason=(
                "CIC-IDS binary detection and "
                "attack-family classification completed."
            ),
        )

    def detect_batch(
        self,
        events: list[SecurityEvent],
    ) -> list[DetectionResult]:
        """
        Process a batch of SecurityEvents using vectorized
        model inference.

        Supported network-flow events are combined into
        batch DataFrames so that the binary detector and
        attack-family classifier each perform inference
        once for the complete batch.

        Unsupported events are returned explicitly without
        entering the CIC-IDS detection models.

        Result order always matches the input event order.
        """
        if not isinstance(events, list):
            raise TypeError(
                "events must be a list."
            )

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

        # ---------------------------------------------------------
        # 1. Separate supported and unsupported events
        # ---------------------------------------------------------

        supported_events: list[
            tuple[int, SecurityEvent]
        ] = []

        results_by_index: dict[
            int,
            DetectionResult,
        ] = {}

        for index, event in enumerate(events):

            if not self.is_supported(event):
                results_by_index[index] = DetectionResult(
                    event_id=event.event_id,
                    detected=False,
                    attack_family="Unknown",
                    confidence=0.0,
                    detector_type=self.DETECTOR_TYPE,
                    supported=False,
                    reason=(
                        "Event type is outside the current "
                        "CIC-IDS network-flow detection boundary."
                    ),
                )
            else:
                supported_events.append(
                    (index, event)
                )

        # ---------------------------------------------------------
        # 2. If there are no supported events, return immediately
        # ---------------------------------------------------------

        if not supported_events:
            return [
                results_by_index[index]
                for index in range(len(events))
            ]

        # ---------------------------------------------------------
        # 3. Validate attached models
        # ---------------------------------------------------------

        if self._binary_model is None:
            raise RuntimeError(
                "Binary detection model is not attached."
            )

        if self._family_model is None:
            raise RuntimeError(
                "Attack-family detection model is not attached."
            )

        if self._feature_adapter is None:
            raise RuntimeError(
                "Feature adapter is not initialized."
            )

        # ---------------------------------------------------------
        # 4. Build one DataFrame for all supported events
        # ---------------------------------------------------------

        metadata_rows: list[dict[str, Any]] = []

        for _, event in supported_events:

            if not isinstance(event.metadata, dict):
                raise TypeError(
                    "SecurityEvent.metadata must be a dictionary."
                )

            if not event.metadata:
                raise ValueError(
                    "Network-flow event contains no CIC-IDS "
                    "features in metadata."
                )

            metadata_rows.append(event.metadata)

        dataframe = pd.DataFrame(
            metadata_rows
        )

        # ---------------------------------------------------------
        # 5. Convert to model-specific feature matrices
        # ---------------------------------------------------------

        binary_features = (
            self._feature_adapter.to_binary_features(
                dataframe
            )
        )

        family_features = (
            self._feature_adapter.to_family_features(
                dataframe
            )
        )

        # ---------------------------------------------------------
        # 6. Perform ONE binary model inference
        # ---------------------------------------------------------

        binary_predictions = (
            self._binary_model.model.predict(
                binary_features
            )
        )

        binary_probabilities = (
            self._binary_model.model.predict_proba(
                binary_features
            )
        )

        # ---------------------------------------------------------
        # 7. Perform ONE attack-family model inference
        # ---------------------------------------------------------

        family_predictions = (
            self._family_model.model.predict(
                family_features
            )
        )

        family_probabilities = (
            self._family_model.model.predict_proba(
                family_features
            )
        )

        # ---------------------------------------------------------
        # 8. Convert model outputs into DetectionResults
        # ---------------------------------------------------------

        for row_index, (
            original_index,
            event,
        ) in enumerate(supported_events):

            binary_prediction = int(
                binary_predictions[row_index]
            )

            binary_probability_row = (
                binary_probabilities[row_index]
            )

            attack_probability = float(
                binary_probability_row[1]
            )

            benign_probability = float(
                binary_probability_row[0]
            )

            family_prediction = int(
                family_predictions[row_index]
            )

            family_probability_row = (
                family_probabilities[row_index]
            )

            family_name = str(
                self._family_model.label_encoder.inverse_transform(
                    [family_prediction]
                )[0]
            )

            family_confidence = float(
                family_probability_row[
                    family_prediction
                ]
            )

            # -----------------------------------------------------
            # Preserve EXACT same confidence semantics as detect()
            # -----------------------------------------------------

            if binary_prediction == 0:

                attack_family = "Benign"

                confidence = benign_probability

            else:

                attack_family = family_name

                confidence = min(
                    attack_probability,
                    family_confidence,
                )

            results_by_index[original_index] = (
                DetectionResult(
                    event_id=event.event_id,
                    detected=bool(binary_prediction),
                    attack_family=attack_family,
                    confidence=confidence,
                    detector_type=self.DETECTOR_TYPE,
                    supported=True,
                    reason=(
                        "CIC-IDS binary detection and "
                        "attack-family classification completed."
                    ),
                )
            )

        # ---------------------------------------------------------
        # 9. Restore original input order
        # ---------------------------------------------------------

        return [
            results_by_index[index]
            for index in range(len(events))
        ]