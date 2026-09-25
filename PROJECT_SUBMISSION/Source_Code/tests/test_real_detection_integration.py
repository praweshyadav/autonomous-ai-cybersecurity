from pathlib import Path

import joblib
import pandas as pd

from correlation.event_builder import build_security_event
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


def test_real_cic_ids_row_reaches_detection():
    assert DATA_PATH.exists()
    assert BINARY_MODEL_PATH.exists()
    assert FAMILY_MODEL_PATH.exists()

    row = pd.read_csv(
        DATA_PATH,
        nrows=1,
    ).iloc[0]

    handler = load_handler()

    event = build_security_event(
        row=row,
        event_id="REAL-CIC-001",
        attack_family="Unknown",
        confidence=0.0,
        binary_prediction=0,
        true_label=row["Label"],
    )

    result = handler.detect(event)

    assert result.event_id == "REAL-CIC-001"
    assert result.supported is True
    assert result.detector_type == "cic_ids_xgboost"

    assert result.attack_family in {
        "Benign",
        "Brute Force",
        "DDoS",
        "DoS",
        "Web Attack",
    }

    assert 0.0 <= result.confidence <= 1.0


def test_real_cic_ids_attack_row_is_detected():
    dataframe = pd.read_csv(
        DATA_PATH,
        nrows=200_000,
    )

    attack_rows = dataframe[
        dataframe["BinaryLabel"] == 1
    ]

    assert not attack_rows.empty

    row = attack_rows.iloc[0]

    handler = load_handler()

    event = build_security_event(
        row=row,
        event_id="REAL-CIC-ATTACK-001",
        attack_family="Unknown",
        confidence=0.0,
        binary_prediction=0,
        true_label=row["Label"],
    )

    result = handler.detect(event)

    assert result.supported is True
    assert result.detected is True
    assert result.attack_family != "Benign"
    assert 0.0 <= result.confidence <= 1.0


def test_real_cic_ids_benign_row_is_processed():
    dataframe = pd.read_csv(
        DATA_PATH,
        nrows=200_000,
    )

    benign_rows = dataframe[
        dataframe["BinaryLabel"] == 0
    ]

    assert not benign_rows.empty

    row = benign_rows.iloc[0]

    handler = load_handler()

    event = build_security_event(
        row=row,
        event_id="REAL-CIC-BENIGN-001",
        attack_family="Unknown",
        confidence=0.0,
        binary_prediction=0,
        true_label=row["Label"],
    )

    result = handler.detect(event)

    assert result.supported is True
    assert result.detected is False
    assert result.attack_family == "Benign"
    assert 0.0 <= result.confidence <= 1.0