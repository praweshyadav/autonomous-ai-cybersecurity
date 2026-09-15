from pathlib import Path

import joblib
import pandas as pd

from agent.context_builder import IncidentContextBuilder
from agent.incident_rag import IncidentRAG
from correlation.correlator import IncidentCorrelator
from correlation.event_builder import build_security_event


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_FILE = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv"
)

BINARY_MODEL_FILE = (
    BASE_DIR
    / "detection"
    / "models"
    / "xgboost_binary_detector_known_attack.joblib"
)

FAMILY_MODEL_FILE = (
    BASE_DIR
    / "detection"
    / "models"
    / "xgboost_attack_family_classifier.joblib"
)


# ============================================================
# FEATURE PREPARATION
# ============================================================

def prepare_binary_features(
    df: pd.DataFrame,
    feature_names: list[str],
) -> pd.DataFrame:
    """
    Prepare real CIC-IDS2018 rows exactly according to the
    binary detector's saved feature schema.
    """

    X = df[feature_names].copy()

    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    X = X.replace(
        [float("inf"), float("-inf")],
        pd.NA,
    )

    X = X.fillna(0)

    return X


def prepare_family_features(
    df: pd.DataFrame,
    feature_columns: list[str],
) -> pd.DataFrame:
    """
    Prepare real CIC-IDS2018 rows according to the attack-family
    classifier's saved feature schema.
    """

    X = df[feature_columns].copy()

    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    X = X.replace(
        [float("inf"), float("-inf")],
        pd.NA,
    )

    X = X.fillna(0)

    return X


# ============================================================
# REAL END-TO-END TEST
# ============================================================

def test_real_incident_rag_pipeline():

    # ========================================================
    # 1. Verify required files
    # ========================================================

    assert DATA_FILE.exists(), (
        f"Dataset not found: {DATA_FILE}"
    )

    assert BINARY_MODEL_FILE.exists(), (
        f"Binary model not found: {BINARY_MODEL_FILE}"
    )

    assert FAMILY_MODEL_FILE.exists(), (
        f"Family model not found: {FAMILY_MODEL_FILE}"
    )

    # ========================================================
    # 2. Load real CIC-IDS2018 traffic
    # ========================================================

    df = pd.read_csv(
        DATA_FILE,
        nrows=1000,
        low_memory=False,
    )

    assert len(df) == 1000

    assert "Timestamp" in df.columns
    assert "Label" in df.columns

    # ========================================================
    # 3. Load binary detector
    # ========================================================

    binary_package = joblib.load(
        BINARY_MODEL_FILE
    )

    binary_model = binary_package["model"]

    binary_feature_names = (
        binary_package["feature_names"]
    )

    # ========================================================
    # 4. Load attack-family classifier
    # ========================================================

    family_package = joblib.load(
        FAMILY_MODEL_FILE
    )

    family_model = family_package["model"]

    family_label_encoder = (
        family_package["label_encoder"]
    )

    family_feature_columns = (
        family_package["feature_columns"]
    )

    # ========================================================
    # 5. Prepare binary-model features
    # ========================================================

    X_binary = prepare_binary_features(
        df,
        binary_feature_names,
    )

    assert list(X_binary.columns) == (
        binary_feature_names
    )

    # ========================================================
    # 6. Prepare family-model features
    # ========================================================

    X_family = prepare_family_features(
        df,
        family_feature_columns,
    )

    assert list(X_family.columns) == (
        family_feature_columns
    )

    # ========================================================
    # 7. Run binary detector
    # ========================================================

    binary_predictions = (
        binary_model.predict(
            X_binary
        )
    )

    binary_probabilities = (
        binary_model.predict_proba(
            X_binary
        )
    )

    assert len(binary_predictions) == 1000
    assert len(binary_probabilities) == 1000

    # ========================================================
    # 8. Run attack-family classifier
    # ========================================================

    family_predictions_encoded = (
        family_model.predict(
            X_family
        )
    )

    family_probabilities = (
        family_model.predict_proba(
            X_family
        )
    )

    assert len(family_predictions_encoded) == 1000
    assert len(family_probabilities) == 1000

    # Convert numeric class IDs back into attack-family names.
    family_predictions = (
        family_label_encoder.inverse_transform(
            family_predictions_encoded.astype(int)
        )
    )

    assert len(family_predictions) == 1000

    # ========================================================
    # 9. Build SecurityEvents
    # ========================================================

    events = []

    for index, (_, row) in enumerate(
        df.iterrows()
    ):

        # -----------------------------------------------
        # Binary prediction
        # -----------------------------------------------

        binary_prediction = int(
            binary_predictions[index]
        )

        binary_confidence = float(
            binary_probabilities[index].max()
        )

        # -----------------------------------------------
        # Attack-family prediction
        # -----------------------------------------------

        attack_family = str(
            family_predictions[index]
        )

        family_confidence = float(
            family_probabilities[index].max()
        )

        # -----------------------------------------------
        # Combined confidence
        #
        # Use the weaker of the two model confidences.
        # -----------------------------------------------

        confidence = min(
            binary_confidence,
            family_confidence,
        )

        # -----------------------------------------------
        # Create SecurityEvent
        # -----------------------------------------------

        event = build_security_event(
            row=row,
            event_id=f"REAL-EVENT-{index:06d}",
            attack_family=attack_family,
            confidence=confidence,
            binary_prediction=binary_prediction,
            true_label=str(row["Label"]),
        )

        events.append(event)

    assert len(events) == 1000

    # ========================================================
    # 10. Correlate SecurityEvents into incidents
    # ========================================================

    correlator = IncidentCorrelator()

    incidents = correlator.correlate(
        events
    )

    assert len(incidents) > 0

    # ========================================================
    # 11. Select the largest incident
    # ========================================================

    incident = max(
        incidents,
        key=lambda item: len(item.events),
    )

    assert len(incident.events) > 0

    # ========================================================
    # 12. Build structured IncidentContext
    # ========================================================

    context_builder = IncidentContextBuilder()

    context = context_builder.build(
        incident
    )

    assert context.incident_id == (
        incident.incident_id
    )

    assert context.event_count > 0

    assert context.primary_attack_family is not None

    # ========================================================
    # 13. Connect IncidentContext to real RAG
    # ========================================================

    incident_rag = IncidentRAG()

    result = incident_rag.investigate(
        context=context,
        top_k=5,
    )

    # ========================================================
    # 14. Validate RAG response
    # ========================================================

    assert result.incident_id == (
        context.incident_id
    )

    assert result.query

    assert len(result.results) == 5

    # ========================================================
    # 15. Validate every retrieved MITRE result
    # ========================================================

    for rag_result in result.results:

        assert rag_result.chunk_id
        assert rag_result.document_id
        assert rag_result.title
        assert rag_result.source
        assert rag_result.content

        assert isinstance(
            rag_result.score,
            float,
        )

    # ========================================================
    # 16. Print pipeline results
    # ========================================================

    print()
    print("=" * 70)
    print("REAL INCIDENT -> RAG INTEGRATION")
    print("=" * 70)

    print(
        f"Incident ID        : "
        f"{context.incident_id}"
    )

    print(
        f"Severity           : "
        f"{context.severity}"
    )

    print(
        f"Primary family     : "
        f"{context.primary_attack_family}"
    )

    print(
        f"Event count        : "
        f"{context.event_count}"
    )

    print(
        f"Family distribution: "
        f"{context.family_distribution}"
    )

    print()
    print("Investigation query:")
    print(result.query)

    print()
    print("Top MITRE ATT&CK results:")

    for rank, rag_result in enumerate(
        result.results,
        start=1,
    ):

        print(
            f"{rank}. "
            f"{rag_result.title} "
            f"(score={rag_result.score:.4f})"
        )

    # ========================================================
    # 17. Explicitly release the local Qdrant filesystem lock
    # ========================================================

    incident_rag.close()