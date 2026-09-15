from pathlib import Path

import joblib
import pandas as pd

from agent.context_builder import IncidentContextBuilder
from agent.incident_rag import IncidentRAG
from agent.investigation import InvestigationResult
from agent.investigation_engine import InvestigationEngine
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


def test_real_incident_investigation():
    # ---------------------------------------------------------
    # 1. Verify required files exist
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
    # 2. Load a real sample from CIC-IDS2018
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
    # 4. Prepare binary detector features
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

    binary_probabilities = (
        binary_model.predict_proba(X_binary)[:, 1]
    )

    # ---------------------------------------------------------
    # 6. Prepare attack-family classifier features
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
    # 8. Convert predictions into SecurityEvents
    # ---------------------------------------------------------

    events = []

    for index, row in df.iterrows():

        event = build_security_event(
            row=row,
            event_id=f"REAL-INV-{index:06d}",
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
    # 9. Correlate real events into incidents
    # ---------------------------------------------------------

    correlator = IncidentCorrelator()

    incidents = correlator.correlate(events)

    assert len(incidents) > 0

    # Select the largest incident
    incident = max(
        incidents,
        key=lambda item: len(item.events),
    )

    # ---------------------------------------------------------
    # 10. Build IncidentContext
    # ---------------------------------------------------------

    context_builder = IncidentContextBuilder()

    context = context_builder.build(
        incident
    )

    assert context.incident_id == (
        incident.incident_id
    )

    assert context.event_count == len(
        incident.events
    )

    # ---------------------------------------------------------
    # 11. Run IncidentRAG
    # ---------------------------------------------------------

    incident_rag = IncidentRAG()

    rag_result = incident_rag.investigate(
        context=context,
        top_k=5,
    )

    assert rag_result.incident_id == (
        context.incident_id
    )

    assert len(rag_result.results) == 5

    # ---------------------------------------------------------
    # 12. Run InvestigationEngine
    # ---------------------------------------------------------

    investigation_engine = (
        InvestigationEngine()
    )

    investigation = (
        investigation_engine.investigate(
            context=context,
            rag_result=rag_result,
        )
    )

    # ---------------------------------------------------------
    # 13. Validate InvestigationResult
    # ---------------------------------------------------------

    assert isinstance(
        investigation,
        InvestigationResult,
    )

    assert investigation.incident_id == (
        context.incident_id
    )

    assert investigation.summary

    assert investigation.threat_assessment

    assert len(
        investigation.evidence
    ) > 0

    assert len(
        investigation.mitre_techniques
    ) > 0

    assert len(
        investigation.hypotheses
    ) > 0

    assert investigation.confidence > 0.0

    assert len(
        investigation.recommended_actions
    ) > 0

    # ---------------------------------------------------------
    # 14. Display the complete result
    # ---------------------------------------------------------

    print()
    print("=" * 70)
    print("REAL INCIDENT -> INVESTIGATION INTEGRATION")
    print("=" * 70)

    print(
        f"Incident ID        : "
        f"{investigation.incident_id}"
    )

    print(
        f"Severity           : "
        f"{investigation.threat_assessment}"
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

    print(
        f"Confidence         : "
        f"{investigation.confidence:.4f}"
    )

    print()
    print("Summary:")
    print(
        investigation.summary
    )

    print()
    print("Evidence:")

    for index, item in enumerate(
        investigation.evidence,
        start=1,
    ):
        print(
            f"{index}. "
            f"[{item.evidence_type}] "
            f"{item.description}"
        )

    print()
    print("MITRE ATT&CK techniques:")

    for technique in (
        investigation.mitre_techniques
    ):
        print(
            f"- {technique.technique_id} - "
            f"{technique.technique_name} "
            f"(confidence="
            f"{technique.confidence:.4f})"
        )

    print()
    print("Hypotheses:")

    for hypothesis in (
        investigation.hypotheses
    ):
        print(
            f"- {hypothesis.description} "
            f"(confidence="
            f"{hypothesis.confidence:.4f})"
        )

    print()
    print("Recommended actions:")

    for action in (
        investigation.recommended_actions
    ):
        print(f"- {action}")

    print()
    print("PASSED")

    # ---------------------------------------------------------
    # 15. Explicitly release the local Qdrant filesystem lock
    # ---------------------------------------------------------

    incident_rag.close()