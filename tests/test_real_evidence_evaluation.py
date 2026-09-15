from pathlib import Path

import joblib
import pandas as pd

from agent.context_builder import IncidentContextBuilder
from agent.evidence_evaluator import (
    EvidenceEvaluator,
    EvaluatedEvidence,
)
from agent.incident_rag import IncidentRAG
from correlation.correlator import IncidentCorrelator
from correlation.event_builder import build_security_event


DATA_FILE = Path(
    "data/processed/cse_cic_ids2018/"
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv"
)

BINARY_MODEL_FILE = Path(
    "detection/models/"
    "xgboost_binary_detector_known_attack.joblib"
)

FAMILY_MODEL_FILE = Path(
    "detection/models/"
    "xgboost_attack_family_classifier.joblib"
)


def test_real_incident_evidence_evaluation():
    # ---------------------------------------------------------
    # 1. Verify required files
    # ---------------------------------------------------------

    assert DATA_FILE.exists(), (
        f"Dataset not found: {DATA_FILE}"
    )

    assert BINARY_MODEL_FILE.exists(), (
        f"Binary model not found: {BINARY_MODEL_FILE}"
    )

    assert FAMILY_MODEL_FILE.exists(), (
        f"Family model not found: {FAMILY_MODEL_FILE}"
    )

    # ---------------------------------------------------------
    # 2. Load real CIC-IDS2018 data
    # ---------------------------------------------------------

    df = pd.read_csv(
        DATA_FILE,
        nrows=1000,
    )

    assert len(df) == 1000

    # ---------------------------------------------------------
    # 3. Load trained models
    # ---------------------------------------------------------

    binary_package = joblib.load(
        BINARY_MODEL_FILE
    )

    family_package = joblib.load(
        FAMILY_MODEL_FILE
    )

    binary_model = binary_package["model"]
    binary_features = binary_package["feature_names"]

    family_model = family_package["model"]
    family_encoder = family_package["label_encoder"]
    family_features = family_package["feature_columns"]

    # ---------------------------------------------------------
    # 4. Prepare binary features
    # ---------------------------------------------------------

    X_binary = df[binary_features].copy()

    X_binary = X_binary.apply(
        pd.to_numeric,
        errors="coerce",
    ).fillna(0)

    # ---------------------------------------------------------
    # 5. Binary prediction
    # ---------------------------------------------------------

    binary_predictions = binary_model.predict(
        X_binary
    )

    # ---------------------------------------------------------
    # 6. Prepare family classifier features
    # ---------------------------------------------------------

    X_family = df[family_features].copy()

    X_family = X_family.apply(
        pd.to_numeric,
        errors="coerce",
    ).fillna(0)

    # ---------------------------------------------------------
    # 7. Attack-family prediction
    # ---------------------------------------------------------

    family_predictions_encoded = (
        family_model.predict(X_family)
    )

    family_predictions_encoded = (
        family_predictions_encoded.astype(int)
    )

    family_predictions = (
        family_encoder.inverse_transform(
            family_predictions_encoded
        )
    )

    family_probabilities = (
        family_model.predict_proba(X_family)
    )

    family_confidences = (
        family_probabilities.max(axis=1)
    )

    # ---------------------------------------------------------
    # 8. Build SecurityEvents
    # ---------------------------------------------------------

    events = []

    for index, row in df.iterrows():

        event = build_security_event(
            row=row,
            event_id=f"REAL-EVAL-{index:06d}",
            attack_family=str(
                family_predictions[index]
            ),
            confidence=float(
                family_confidences[index]
            ),
            binary_prediction=int(
                binary_predictions[index]
            ),
            true_label=str(
                row["Label"]
            ),
        )

        events.append(event)

    assert len(events) == 1000

    # ---------------------------------------------------------
    # 9. Correlate events
    # ---------------------------------------------------------

    correlator = IncidentCorrelator()

    incidents = correlator.correlate(
        events
    )

    assert len(incidents) > 0

    # Select largest real incident
    incident = max(
        incidents,
        key=lambda item: len(item.events),
    )

    # ---------------------------------------------------------
    # 10. Build incident context
    # ---------------------------------------------------------

    context_builder = IncidentContextBuilder()

    context = context_builder.build(
        incident
    )

    assert context.event_count == len(
        incident.events
    )

    # ---------------------------------------------------------
    # 11. Run MITRE RAG
    # ---------------------------------------------------------

    incident_rag = IncidentRAG()

    rag_result = incident_rag.investigate(
        context=context,
        top_k=5,
    )

    assert len(
        rag_result.results
    ) == 5

    # ---------------------------------------------------------
    # 12. Evaluate retrieved evidence
    # ---------------------------------------------------------

    evaluator = EvidenceEvaluator()

    evaluated_evidence = (
        evaluator.evaluate(
            context=context,
            rag_result=rag_result,
        )
    )

    assert len(
        evaluated_evidence
    ) > 0

    assert all(
        isinstance(
            item,
            EvaluatedEvidence,
        )
        for item in evaluated_evidence
    )

    # ---------------------------------------------------------
    # 13. Validate relevance scores
    # ---------------------------------------------------------

    for item in evaluated_evidence:

        assert 0.0 <= (
            item.retrieval_score
        ) <= 1.0

        assert 0.0 <= (
            item.relevance_score
        ) <= 1.0

        assert item.relevance in {
            "low",
            "medium",
            "high",
        }

        assert item.technique_id.startswith(
            "T"
        )

    # ---------------------------------------------------------
    # 14. Verify sorting
    # ---------------------------------------------------------

    relevance_scores = [
        item.relevance_score
        for item in evaluated_evidence
    ]

    assert relevance_scores == sorted(
        relevance_scores,
        reverse=True,
    )

    # ---------------------------------------------------------
    # 15. Print actual investigation evidence
    # ---------------------------------------------------------

    print()
    print("=" * 70)
    print(
        "REAL INCIDENT -> EVIDENCE EVALUATION"
    )
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
    print(
        "Evaluated MITRE evidence:"
    )

    for index, item in enumerate(
        evaluated_evidence,
        start=1,
    ):

        print(
            f"{index}. "
            f"{item.technique_id} - "
            f"{item.technique_name}"
        )

        print(
            f"   Retrieval score : "
            f"{item.retrieval_score:.4f}"
        )

        print(
            f"   Relevance score : "
            f"{item.relevance_score:.4f}"
        )

        print(
            f"   Relevance       : "
            f"{item.relevance}"
        )

        print(
            f"   Reason          : "
            f"{item.reason}"
        )

    print()
    print("PASSED")

    # ---------------------------------------------------------
    # 16. Explicitly release the local Qdrant filesystem lock
    # ---------------------------------------------------------

    incident_rag.close()