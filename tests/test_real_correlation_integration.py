from pathlib import Path

import joblib
import pandas as pd

from correlation.event_builder import build_security_event
from correlation.correlator import IncidentCorrelator
from detection.handler import DetectionHandler
from detection.model_loader import (
    AttackFamilyModelBundle,
    BinaryModelBundle,
)


BASE_DIR = Path(__file__).resolve().parent.parent


DATA_PATH = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "splits"
    / "train.csv"
)


BINARY_MODEL_PATH = (
    BASE_DIR
    / "detection"
    / "models"
    / "xgboost_binary_detector.joblib"
)


FAMILY_MODEL_PATH = (
    BASE_DIR
    / "detection"
    / "models"
    / "xgboost_attack_family_classifier.joblib"
)


def load_handler():
    binary_package = joblib.load(
        BINARY_MODEL_PATH
    )

    family_package = joblib.load(
        FAMILY_MODEL_PATH
    )

    binary_bundle = BinaryModelBundle(
        model=binary_package["model"],
        feature_names=binary_package["feature_names"],
    )

    family_bundle = AttackFamilyModelBundle(
        model=family_package["model"],
        label_encoder=family_package["label_encoder"],
        feature_columns=family_package["feature_columns"],
    )

    handler = DetectionHandler()

    handler.attach_models(
        binary_model=binary_bundle,
        family_model=family_bundle,
    )

    return handler


def test_real_cic_ids_detection_to_correlation():

    dataframe = pd.read_csv(
        DATA_PATH,
        nrows=50_000,
    )

    handler = load_handler()

    # ---------------------------------------------------------
    # 1. Build SecurityEvent objects
    # ---------------------------------------------------------

    events = []

    for index, row in dataframe.iterrows():

        event = build_security_event(
            row=row,
            event_id=f"REAL-CORR-{index:06d}",
            attack_family="Unknown",
            confidence=0.0,
            binary_prediction=0,
            true_label=row["Label"],
        )

        events.append(event)

    assert len(events) == 50_000

    # ---------------------------------------------------------
    # 2. Run optimized batch detection
    # ---------------------------------------------------------

    detection_results = handler.detect_batch(
        events
    )

    assert len(detection_results) == len(events)

    # ---------------------------------------------------------
    # 3. Apply detection results to events
    # ---------------------------------------------------------

    for event, result in zip(
        events,
        detection_results,
    ):

        event.binary_prediction = result.detected
        event.attack_family = result.attack_family
        event.confidence = result.confidence

    # ---------------------------------------------------------
    # 4. Verify attack events exist
    # ---------------------------------------------------------

    attack_events = [
        event
        for event in events
        if event.binary_prediction == 1 and event.attack_family != "Benign"
    ]

    assert attack_events

    # ---------------------------------------------------------
    # 5. Correlate detected events
    # ---------------------------------------------------------

    correlator = IncidentCorrelator(
        time_window_seconds=60,
    )

    incidents = correlator.correlate(
        events
    )

    assert incidents

    # ---------------------------------------------------------
    # 6. Validate incidents
    # ---------------------------------------------------------

    assert all(
        incident.events
        for incident in incidents
    )

    assert all(
        incident.primary_attack_family is not None
        for incident in incidents
    )

    # ---------------------------------------------------------
    # 7. Ensure all detected attacks were correlated
    # ---------------------------------------------------------

    total_correlated_events = sum(
        len(incident.events)
        for incident in incidents
    )

    assert total_correlated_events == len(
        attack_events
    )
