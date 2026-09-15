import joblib
import pandas as pd

from agent.context_builder import IncidentContextBuilder
from correlation.correlator import IncidentCorrelator
from correlation.event_builder import build_security_event


def prepare_features(df, feature_names):
    """
    Prepare network-flow features using the exact feature
    order expected by a trained model.
    """
    X = df.reindex(columns=feature_names).copy()

    for column in X.columns:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    X = X.replace([float("inf"), float("-inf")], 0)
    X = X.fillna(0)

    return X


def test_real_pipeline_produces_incident_contexts():
    # ------------------------------------------------------------
    # 1. Load trained models
    # ------------------------------------------------------------

    binary_package = joblib.load(
        "detection/models/xgboost_binary_detector.joblib"
    )

    family_package = joblib.load(
        "detection/models/xgboost_attack_family_classifier.joblib"
    )

    binary_model = binary_package["model"]
    binary_features = binary_package["feature_names"]

    family_model = family_package["model"]
    family_encoder = family_package["label_encoder"]
    family_features = family_package["feature_columns"]

    # ------------------------------------------------------------
    # 2. Load real network-flow data
    # ------------------------------------------------------------

    data_path = (
        "data/processed/cse_cic_ids2018/"
        "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv"
    )

    df = pd.read_csv(data_path, nrows=1000)

    assert len(df) == 1000

    # ------------------------------------------------------------
    # 3. Prepare binary-detector features
    # ------------------------------------------------------------

    X_binary = prepare_features(
        df,
        binary_features,
    )

    # ------------------------------------------------------------
    # 4. Binary detection
    # ------------------------------------------------------------

    binary_predictions = binary_model.predict(X_binary)
    binary_probabilities = binary_model.predict_proba(X_binary)[:, 1]

    assert len(binary_predictions) == 1000
    assert len(binary_probabilities) == 1000

    # ------------------------------------------------------------
    # 5. Prepare attack-family features
    # ------------------------------------------------------------

    X_family = prepare_features(
        df,
        family_features,
    )

    # ------------------------------------------------------------
    # 6. Attack-family classification
    # ------------------------------------------------------------

    family_predictions = family_model.predict(X_family)
    family_probabilities = family_model.predict_proba(X_family)

    predicted_families = family_encoder.inverse_transform(
        family_predictions.astype(int)
    )

    family_confidences = family_probabilities.max(axis=1)

    assert len(predicted_families) == 1000
    assert len(family_confidences) == 1000

    # ------------------------------------------------------------
    # 7. Build SecurityEvents
    # ------------------------------------------------------------

    events = []

    for index, row in df.iterrows():

        event = build_security_event(
            row=row,
            event_id=f"TEST-{index:06d}",
            attack_family=str(predicted_families[index]),
            confidence=float(family_confidences[index]),
            binary_prediction=int(binary_predictions[index]),
            true_label=str(row["Label"]),
        )

        events.append(event)

    assert len(events) == 1000

    # ------------------------------------------------------------
    # 8. Correlate events into incidents
    # ------------------------------------------------------------

    correlator = IncidentCorrelator(
        time_window_seconds=60,
        correlation_threshold=4,
    )

    incidents = correlator.correlate(events)

    assert len(incidents) > 0

    # ------------------------------------------------------------
    # 9. Build AI-ready incident contexts
    # ------------------------------------------------------------

    context_builder = IncidentContextBuilder()

    contexts = [
        context_builder.build(incident)
        for incident in incidents
    ]

    # ------------------------------------------------------------
    # 10. Validate contexts
    # ------------------------------------------------------------

    assert len(contexts) == len(incidents)

    for context in contexts:

        assert context.incident_id
        assert context.start_time
        assert context.end_time

        assert context.event_count > 0

        assert context.primary_attack_family is not None

        assert context.family_distribution

        assert isinstance(
            context.family_distribution,
            dict,
        )

        assert isinstance(
            context.attack_families,
            list,
        )

        assert context.duration_seconds >= 0

        assert 0.0 <= context.confidence <= 1.0