from pathlib import Path
from collections import Counter

import joblib
import pandas as pd

from correlation.event_builder import build_security_event
from correlation.correlator import IncidentCorrelator


# ============================================================
# Paths
# ============================================================

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


# ============================================================
# Configuration
# ============================================================

SAMPLE_SIZE = 10_000

TIME_WINDOW_SECONDS = 60

NON_FEATURE_COLUMNS = {
    "Label",
    "AttackFamily",
    "BinaryLabel",
    "SourceFile",
    "Timestamp",
}


# ============================================================
# Feature preparation
# ============================================================

def prepare_features(
    df: pd.DataFrame,
    feature_names,
) -> pd.DataFrame:
    """
    Prepare features using the exact feature schema
    belonging to the model.
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

    X = X.reindex(
        columns=feature_names,
        fill_value=0,
    )

    return X


# ============================================================
# Main pipeline
# ============================================================

def main():

    print("=" * 70)
    print("INCIDENT CORRELATION SAMPLE")
    print("=" * 70)

    # --------------------------------------------------------
    # Verify files
    # --------------------------------------------------------

    if not DATA_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_FILE}"
        )

    if not BINARY_MODEL_FILE.exists():
        raise FileNotFoundError(
            f"Binary model not found: {BINARY_MODEL_FILE}"
        )

    if not FAMILY_MODEL_FILE.exists():
        raise FileNotFoundError(
            f"Family model not found: {FAMILY_MODEL_FILE}"
        )

    # --------------------------------------------------------
    # Load models
    # --------------------------------------------------------

    print("\n[1/6] Loading models...")

    binary_package = joblib.load(
        BINARY_MODEL_FILE
    )

    family_package = joblib.load(
        FAMILY_MODEL_FILE
    )

    binary_model = binary_package["model"]
    binary_feature_names = binary_package["feature_names"]

    family_model = family_package["model"]
    label_encoder = family_package["label_encoder"]
    family_feature_names = family_package["feature_columns"]

    print(
        f"Binary model features : {len(binary_feature_names)}"
    )

    print(
        f"Family model features : {len(family_feature_names)}"
    )

    # --------------------------------------------------------
    # Load real dataset sample
    # --------------------------------------------------------

    print(
        f"\n[2/6] Loading {SAMPLE_SIZE:,} real network flows..."
    )

    df = pd.read_csv(
        DATA_FILE,
        nrows=SAMPLE_SIZE,
    )

    print(
        f"Loaded rows: {len(df):,}"
    )

    # --------------------------------------------------------
    # Prepare model inputs
    # --------------------------------------------------------

    print("\n[3/6] Preparing model features...")

    X_binary = prepare_features(
        df,
        binary_feature_names,
    )

    X_family = prepare_features(
        df,
        family_feature_names,
    )

    # --------------------------------------------------------
    # Binary detection
    # --------------------------------------------------------

    print("\n[4/6] Running binary detector...")

    binary_predictions = binary_model.predict(
        X_binary
    )

    binary_probabilities = binary_model.predict_proba(
        X_binary
    )

    attack_probabilities = binary_probabilities[:, 1]

    binary_attack_count = int(
        (binary_predictions == 1).sum()
    )

    print(
        f"Predicted attacks : {binary_attack_count:,}"
    )

    print(
        f"Predicted benign  : "
        f"{SAMPLE_SIZE - binary_attack_count:,}"
    )

    # --------------------------------------------------------
    # Attack-family classification
    # --------------------------------------------------------

    print("\n[5/6] Running attack-family classifier...")

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

    # --------------------------------------------------------
    # Build SecurityEvents
    # --------------------------------------------------------

    print("\nBuilding SecurityEvents...")

    events = []

    for index, row in df.iterrows():

        event = build_security_event(
            row=row,
            event_id=f"E-{index + 1:06d}",

            attack_family=str(
                family_predictions[index]
            ),

            confidence=float(
                family_confidences[index]
            ),

            binary_prediction=int(
                binary_predictions[index]
            ),

            true_label=(
                str(row["Label"])
                if "Label" in row
                else None
            ),
        )

        events.append(event)

    print(
        f"SecurityEvents created: {len(events):,}"
    )

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    print("\nCorrelating events into incidents...")

    correlator = IncidentCorrelator(
        time_window_seconds=TIME_WINDOW_SECONDS
    )

    incidents = correlator.correlate(
        events
    )

    print(
        f"Incidents generated: {len(incidents):,}"
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("INCIDENT SUMMARY")
    print("=" * 70)

    if not incidents:
        print("\nNo attack incidents were generated.")
        return

    family_counter = Counter(
        incident.primary_attack_family
        for incident in incidents
    )

    severity_counter = Counter(
        incident.severity
        for incident in incidents
    )

    print("\nIncidents by attack family:")

    for family, count in family_counter.most_common():
        print(
            f"  {family:<20} {count:>6}"
        )

    print("\nIncidents by severity:")

    for severity, count in severity_counter.most_common():
        print(
            f"  {severity:<20} {count:>6}"
        )

    # --------------------------------------------------------
    # Detailed incident output
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("FIRST 10 INCIDENTS")
    print("=" * 70)

    for incident in incidents[:10]:

        duration = (
            incident.end_time
            - incident.start_time
        )

        print("\n" + "-" * 70)

        print(
            f"Incident ID       : "
            f"{incident.incident_id}"
        )

        print(
            f"Attack Family     : "
            f"{incident.primary_attack_family}"
        )

        print(
            f"Severity           : "
            f"{incident.severity}"
        )

        print(
            f"Confidence         : "
            f"{incident.confidence:.4f}"
        )

        print(
            f"Events             : "
            f"{len(incident.events)}"
        )

        print(
            f"Start              : "
            f"{incident.start_time}"
        )

        print(
            f"End                : "
            f"{incident.end_time}"
        )

        print(
            f"Duration           : "
            f"{duration}"
        )
        
        print(f"Family distribution: {incident.family_distribution}")

        protocols = sorted(
        set(
        event.protocol
        for event in incident.events
        if event.protocol is not None
            )
        )

        print(
            f"Protocols          : {protocols}"
        )

        print(
            f"Destination ports  : "
            f"{incident.dst_ports}"
        )


if __name__ == "__main__":
    main()