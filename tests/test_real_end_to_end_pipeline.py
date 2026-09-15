import joblib
import pandas as pd
import pytest

from agent.context_builder import IncidentContextBuilder
from agent.evidence_evaluator import EvidenceEvaluator
from agent.incident_rag import IncidentRAG
from agent.investigation_engine import InvestigationEngine
from agent.llm_input_builder import LLMInputBuilder
from agent.llm_investigation_agent import LLMInvestigationAgent
from agent.ollama_llm_provider import OllamaLLMProvider

from correlation.correlator import IncidentCorrelator
from correlation.event_builder import build_security_event


DATA_FILE = (
    "data/processed/cse_cic_ids2018/"
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv"
)

BINARY_MODEL_FILE = (
    "detection/models/"
    "xgboost_binary_detector_known_attack.joblib"
)

FAMILY_MODEL_FILE = (
    "detection/models/"
    "xgboost_attack_family_classifier.joblib"
)


def load_model_package(path):
    package = joblib.load(path)

    assert isinstance(package, dict)

    return package


def prepare_features(
    dataframe,
    feature_columns,
):
    """
    Prepare real CIC-IDS2018 rows according to the
    feature columns stored with the trained model.
    """

    features = dataframe.copy()

    # Remove columns that are not model features.
    columns_to_drop = [
        "Label",
        "SourceFile",
    ]

    for column in columns_to_drop:
        if column in features.columns:
            features = features.drop(
                columns=column
            )

    # Convert Timestamp into a numeric representation
    # if it is part of the trained feature set.
    if "Timestamp" in features.columns:
        timestamp = pd.to_datetime(
            features["Timestamp"],
            format="%d/%m/%Y %H:%M:%S",
            errors="coerce",
        )

        features["Timestamp"] = (
            timestamp.astype("int64") // 10**9
        )

    # Make sure all expected model columns exist.
    missing_columns = [
        column
        for column in feature_columns
        if column not in features.columns
    ]

    if missing_columns:
        raise AssertionError(
            "Missing model features: "
            f"{missing_columns[:10]}"
        )

    features = features[
        feature_columns
    ].copy()

    # Convert everything to numeric.
    for column in features.columns:
        features[column] = pd.to_numeric(
            features[column],
            errors="coerce",
        )

    # Replace invalid numeric values.
    features = features.replace(
        [float("inf"), float("-inf")],
        0,
    )

    features = features.fillna(0)

    return features


@pytest.mark.integration
def test_real_end_to_end_pipeline():

    # ==================================================
    # 1. Load real CIC-IDS2018 data
    # ==================================================

    dataframe = pd.read_csv(
        DATA_FILE,
        nrows=1000,
    )

    assert len(dataframe) == 1000

    print()
    print("=" * 70)
    print("REAL END-TO-END CYBERSECURITY PIPELINE")
    print("=" * 70)

    print(
        f"Loaded real flows : {len(dataframe)}"
    )

    # ==================================================
    # 2. Load binary detection model
    # ==================================================

    binary_package = load_model_package(
        BINARY_MODEL_FILE
    )

    binary_model = binary_package["model"]
    binary_features = binary_package[
        "feature_names"
    ]

    print(
        f"Binary features   : {len(binary_features)}"
    )

    # ==================================================
    # 3. Load attack-family model
    # ==================================================

    family_package = load_model_package(
        FAMILY_MODEL_FILE
    )

    family_model = family_package["model"]
    family_encoder = family_package[
        "label_encoder"
    ]
    family_features = family_package[
        "feature_columns"
    ]

    print(
        f"Family features   : {len(family_features)}"
    )

    # ==================================================
    # 4. Prepare features
    # ==================================================

    binary_X = prepare_features(
        dataframe,
        binary_features,
    )

    family_X = prepare_features(
        dataframe,
        family_features,
    )

    # ==================================================
    # 5. Binary prediction
    # ==================================================

    binary_predictions = binary_model.predict(
        binary_X
    )

    binary_probabilities = (
        binary_model.predict_proba(
            binary_X
        )[:, 1]
    )

    print(
        f"Binary attacks    : "
        f"{int(binary_predictions.sum())}"
    )

    # ==================================================
    # 6. Attack-family prediction
    # ==================================================

    family_predictions_encoded = (
        family_model.predict(
            family_X
        )
    )

    family_probabilities = (
        family_model.predict_proba(
            family_X
        )
    )

    family_predictions = (
        family_encoder.inverse_transform(
            family_predictions_encoded
        )
    )

    family_confidences = (
        family_probabilities.max(
            axis=1
        )
    )

    print(
        "Family predictions: "
        f"{len(family_predictions)}"
    )

    # ==================================================
    # 7. Build SecurityEvents
    # ==================================================

    events = []

    for index, row in dataframe.iterrows():

        event = build_security_event(
            row=row,
            event_id=f"REAL-EVENT-{index + 1:04d}",
            attack_family=str(
                family_predictions[index]
            ),
            confidence=float(
                family_confidences[index]
            ),
            binary_prediction=int(
                binary_predictions[index]
            ),
            true_label=row.get("Label"),
        )

        events.append(event)

    assert len(events) == 1000

    print(
        f"SecurityEvents    : {len(events)}"
    )

    # ==================================================
    # 8. Correlate incidents
    # ==================================================

    correlator = IncidentCorrelator(
        time_window_seconds=60,
        correlation_threshold=4,
    )

    incidents = correlator.correlate(
        events
    )

    print(
        f"Incidents created : {len(incidents)}"
    )

    assert len(incidents) > 0

    # ==================================================
    # 9. Build incident contexts
    # ==================================================

    context_builder = IncidentContextBuilder()

    contexts = [
        context_builder.build(
            incident
        )
        for incident in incidents
    ]

    # Select the largest incident for investigation.
    largest_index = max(
        range(len(incidents)),
        key=lambda index: len(
            incidents[index].events
        ),
    )

    incident = incidents[largest_index]
    context = contexts[largest_index]

    print()
    print("--- SELECTED INCIDENT ---")
    print(
        f"Incident ID       : "
        f"{context.incident_id}"
    )
    print(
        f"Severity          : "
        f"{context.severity}"
    )
    print(
        f"Primary family    : "
        f"{context.primary_attack_family}"
    )
    print(
        f"Event count       : "
        f"{context.event_count}"
    )
    print(
        f"Family distribution: "
        f"{context.family_distribution}"
    )

    # ==================================================
    # 10. MITRE RAG
    # ==================================================

    incident_rag = IncidentRAG()

    rag_result = incident_rag.investigate(
        context=context,
        top_k=5,
    )

    assert rag_result.incident_id == (
        context.incident_id
    )

    print()
    print("--- MITRE RAG ---")

    for index, result in enumerate(
        rag_result.results,
        start=1,
    ):
        print(
            f"{index}. "
            f"{result.title} "
            f"(score={result.score:.4f})"
        )

    # ==================================================
    # 11. Evidence evaluation
    # ==================================================

    evidence_evaluator = EvidenceEvaluator()

    evaluated_evidence = (
        evidence_evaluator.evaluate(
            context=context,
            rag_result=rag_result,
        )
    )

    print()
    print("--- EVIDENCE EVALUATION ---")

    for evidence in evaluated_evidence:
        print(
            f"{evidence.technique_id} - "
            f"{evidence.technique_name} | "
            f"relevance={evidence.relevance} | "
            f"score={evidence.relevance_score:.4f}"
        )

    # ==================================================
    # 12. Deterministic investigation
    # ==================================================

    investigation_engine = (
        InvestigationEngine(
            evidence_evaluator=evidence_evaluator
        )
    )

    investigation = (
        investigation_engine.investigate(
            context=context,
            rag_result=rag_result,
        )
    )

    print()
    print("--- DETERMINISTIC INVESTIGATION ---")
    print(
        f"Confidence        : "
        f"{investigation.confidence:.4f}"
    )
    print(
        f"Threat assessment : "
        f"{investigation.threat_assessment}"
    )

    print("MITRE techniques:")

    for technique in (
        investigation.mitre_techniques
    ):
        print(
            f"- {technique.technique_id} - "
            f"{technique.technique_name} "
            f"(confidence="
            f"{technique.confidence:.4f})"
        )

    # ==================================================
    # 13. Build LLM input
    # ==================================================

    input_builder = LLMInputBuilder()

    llm_input = input_builder.build(
        context=context,
        investigation=investigation,
        rag_result=rag_result,
    )

    assert (
        llm_input.incident_id
        == context.incident_id
    )

    print()
    print("--- LLM INPUT ---")
    print(
        f"Evidence supplied : "
        f"{len(llm_input.evidence)}"
    )
    print(
        f"MITRE supplied    : "
        f"{len(llm_input.mitre_techniques)}"
    )

    # ==================================================
    # 14. Real Gemma 3 4B
    # ==================================================

    provider = OllamaLLMProvider(
        model="gemma3:4b",
        timeout=120,
    )

    llm_agent = LLMInvestigationAgent(
        provider=provider,
        input_builder=input_builder,
    )

    llm_result = llm_agent.investigate(
        context=context,
        investigation=investigation,
        rag_result=rag_result,
    )

    # ==================================================
    # 15. Validate final result
    # ==================================================

    assert (
        llm_result.incident_id
        == context.incident_id
    )

    assert isinstance(
        llm_result.summary,
        str,
    )

    assert len(
        llm_result.summary
    ) > 0

    assert isinstance(
        llm_result.threat_assessment,
        str,
    )

    assert 0.0 <= (
        llm_result.confidence
    ) <= 1.0

    # ==================================================
    # 16. Final output
    # ==================================================

    print()
    print("=" * 70)
    print("FINAL GEMMA INVESTIGATION")
    print("=" * 70)

    print(
        f"Incident ID       : "
        f"{llm_result.incident_id}"
    )

    print(
        f"Confidence        : "
        f"{llm_result.confidence:.4f}"
    )

    print(
        f"Summary           : "
        f"{llm_result.summary}"
    )

    print(
        f"Threat assessment : "
        f"{llm_result.threat_assessment}"
    )

    print()
    print("Hypotheses:")

    for hypothesis in (
        llm_result.hypotheses
    ):
        print(
            f"- {hypothesis.hypothesis} "
            f"(confidence="
            f"{hypothesis.confidence:.4f})"
        )

    print()
    print("MITRE assessments:")

    for technique in (
        llm_result.technique_assessments
    ):
        print(
            f"- {technique.technique_id} - "
            f"{technique.technique_name} "
            f"(confidence="
            f"{technique.confidence:.4f})"
        )

    print()
    print("Evidence gaps:")

    for gap in llm_result.evidence_gaps:
        print(f"- {gap}")

    print()
    print("Next investigation steps:")

    for step in (
        llm_result.next_investigation_steps
    ):
        print(f"- {step}")

    print()
    print("Recommended actions:")

    for action in (
        llm_result.recommended_actions
    ):
        print(f"- {action}")

    print()
    print("=" * 70)
    print("END-TO-END PIPELINE PASSED")
    print("=" * 70)

    # Explicitly release the local Qdrant filesystem lock.
    incident_rag.close()