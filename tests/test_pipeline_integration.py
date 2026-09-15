from pathlib import Path

import joblib
import pandas as pd

from correlation.event_builder import build_security_event
from correlation.correlator import IncidentCorrelator


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv"
)

BINARY_MODEL_FILE = (
    PROJECT_ROOT
    / "detection"
    / "models"
    / "xgboost_binary_detector.joblib"
)

FAMILY_MODEL_FILE = (
    PROJECT_ROOT
    / "detection"
    / "models"
    / "xgboost_attack_family_classifier.joblib"
)


SAMPLE_SIZE = 100


# ---------------------------------------------------------
# Columns that are never model features
# ---------------------------------------------------------

NON_FEATURE_COLUMNS = {
    "Label",
    "AttackFamily",
    "BinaryLabel",
    "SourceFile",
    "Timestamp",
}


# ---------------------------------------------------------
# Feature preparation
# ---------------------------------------------------------

def prepare_features(
    df: pd.DataFrame,
    feature_names,
) -> pd.DataFrame:
    """
    Prepare features using the exact feature list belonging
    to the model being evaluated.
    """

    X = df.drop(
        columns=[
            column
            for column in NON_FEATURE_COLUMNS
            if column in df.columns
        ],
        errors="ignore",
    ).copy()

    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    X = X.replace(
        [float("inf"), float("-inf")],
        0,
    )

    X = X.fillna(0)

    # IMPORTANT:
    # Preserve the exact training feature order.
    X = X.reindex(
        columns=feature_names,
        fill_value=0,
    )

    return X


# ---------------------------------------------------------
# Integration test
# ---------------------------------------------------------

def test_real_pipeline_integration():

    # -----------------------------------------------------
    # Verify files
    # -----------------------------------------------------

    assert DATA_FILE.exists(), (
        f"Dataset file not found: {DATA_FILE}"
    )

    assert BINARY_MODEL_FILE.exists(), (
        f"Binary model not found: {BINARY_MODEL_FILE}"
    )

    assert FAMILY_MODEL_FILE.exists(), (
        f"Attack-family model not found: {FAMILY_MODEL_FILE}"
    )

    # -----------------------------------------------------
    # Load binary detector package
    # -----------------------------------------------------

    binary_package = joblib.load(
        BINARY_MODEL_FILE
    )

    assert isinstance(binary_package, dict)

    assert "model" in binary_package
    assert "feature_names" in binary_package

    binary_model = binary_package["model"]
    binary_feature_names = binary_package["feature_names"]

    # -----------------------------------------------------
    # Load attack-family classifier package
    # -----------------------------------------------------

    family_package = joblib.load(
        FAMILY_MODEL_FILE
    )

    assert isinstance(family_package, dict)

    assert "model" in family_package
    assert "label_encoder" in family_package
    assert "feature_columns" in family_package

    family_model = family_package["model"]
    label_encoder = family_package["label_encoder"]
    family_feature_names = family_package["feature_columns"]

    # -----------------------------------------------------
    # Load real CIC-IDS2018 sample
    # -----------------------------------------------------

    df = pd.read_csv(
        DATA_FILE,
        nrows=SAMPLE_SIZE,
    )

    assert len(df) == SAMPLE_SIZE

    # -----------------------------------------------------
    # Prepare features separately for each model
    # -----------------------------------------------------

    X_binary = prepare_features(
        df,
        binary_feature_names,
    )

    X_family = prepare_features(
        df,
        family_feature_names,
    )

    # -----------------------------------------------------
    # Verify feature dimensions
    # -----------------------------------------------------

    assert X_binary.shape[1] == len(
        binary_feature_names
    )

    assert X_family.shape[1] == len(
        family_feature_names
    )

    # -----------------------------------------------------
    # Binary detection
    # -----------------------------------------------------

    binary_predictions = binary_model.predict(
        X_binary
    )

    binary_probabilities = binary_model.predict_proba(
        X_binary
    )

    attack_probabilities = binary_probabilities[:, 1]

    # -----------------------------------------------------
    # Attack-family classification
    # -----------------------------------------------------

    family_predictions_encoded = family_model.predict(
        X_family
    )

    family_probabilities = family_model.predict_proba(
        X_family
    )

    family_predictions = label_encoder.inverse_transform(
        family_predictions_encoded.astype(int)
    )

    family_confidences = family_probabilities.max(
        axis=1
    )

    # -----------------------------------------------------
    # Validate prediction output
    # -----------------------------------------------------

    assert len(binary_predictions) == SAMPLE_SIZE
    assert len(attack_probabilities) == SAMPLE_SIZE

    assert len(family_predictions) == SAMPLE_SIZE
    assert len(family_confidences) == SAMPLE_SIZE

    assert (
        (attack_probabilities >= 0).all()
        and (attack_probabilities <= 1).all()
    )

    assert (
        (family_confidences >= 0).all()
        and (family_confidences <= 1).all()
    )

    # -----------------------------------------------------
    # Build SecurityEvents
    # -----------------------------------------------------

    events = []

    for index, row in df.iterrows():

        binary_prediction = int(
            binary_predictions[index]
        )

        attack_family = str(
            family_predictions[index]
        )

        confidence = float(
            family_confidences[index]
        )

        true_label = (
            str(row["Label"])
            if "Label" in row
            else None
        )

        event = build_security_event(
            row=row,
            event_id=f"E-{index + 1:06d}",
            attack_family=attack_family,
            confidence=confidence,
            binary_prediction=binary_prediction,
            true_label=true_label,
        )

        events.append(event)

    # -----------------------------------------------------
    # Validate SecurityEvents
    # -----------------------------------------------------

    assert len(events) == SAMPLE_SIZE

    for event in events:

        assert event.event_id.startswith("E-")

        assert event.timestamp is not None

        assert event.attack_family in {
            "Benign",
            "Brute Force",
            "DDoS",
            "DoS",
            "Web Attack",
        }

        assert 0.0 <= event.confidence <= 1.0

        assert event.binary_prediction in {
            0,
            1,
        }

    # -----------------------------------------------------
    # Correlation
    # -----------------------------------------------------

    correlator = IncidentCorrelator(
        time_window_seconds=60
    )

    incidents = correlator.correlate(
        events
    )

    # -----------------------------------------------------
    # Validate incidents
    # -----------------------------------------------------

    assert isinstance(
        incidents,
        list,
    )

    for incident in incidents:

        assert incident.incident_id.startswith(
            "INC-"
        )

        assert (
            incident.start_time
            <= incident.end_time
        )

        assert len(
            incident.events
        ) > 0

        assert (
            incident.primary_attack_family
            is not None
        )

        assert incident.severity in {
            "low",
            "medium",
            "high",
            "critical",
        }

        assert (
            0.0
            <= incident.confidence
            <= 1.0
        )