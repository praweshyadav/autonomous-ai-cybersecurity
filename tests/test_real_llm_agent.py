from pathlib import Path

import joblib
import pandas as pd

from agent.context_builder import IncidentContextBuilder
from agent.incident_rag import IncidentRAG
from agent.investigation_engine import InvestigationEngine
from agent.llm_investigation_agent import LLMInvestigationAgent
from agent.mock_llm_provider import MockLLMProvider
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


def test_real_incident_to_llm_agent():
    # ---------------------------------------------------------
    # 1. Load real CIC-IDS2018 data
    # ---------------------------------------------------------

    df = pd.read_csv(
        DATA_FILE,
        nrows=1000,
    )

    assert len(df) == 1000

    # ---------------------------------------------------------
    # 2. Load real trained models
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
    # 3. Prepare model features
    # ---------------------------------------------------------

    X_binary = df[binary_features]

    X_family = df[family_features]

    # ---------------------------------------------------------
    # 4. Real binary detection
    # ---------------------------------------------------------

    binary_predictions = (
        binary_model.predict(X_binary)
    )

    binary_probabilities = (
        binary_model.predict_proba(X_binary)
    )

    # ---------------------------------------------------------
    # 5. Real attack-family classification
    # ---------------------------------------------------------

    family_predictions = (
        family_model.predict(X_family)
    )

    family_probabilities = (
        family_model.predict_proba(X_family)
    )

    family_names = (
        family_encoder.inverse_transform(
            family_predictions.astype(int)
        )
    )

    # ---------------------------------------------------------
    # 6. Build real SecurityEvents
    # ---------------------------------------------------------

    events = []

    for index, row in df.iterrows():

        binary_prediction = int(
            binary_predictions[index]
        )

        binary_confidence = float(
            binary_probabilities[index].max()
        )

        attack_family = str(
            family_names[index]
        )

        event = build_security_event(
            row=row,
            event_id=f"EVT-{index + 1:06d}",
            attack_family=attack_family,
            confidence=binary_confidence,
            binary_prediction=binary_prediction,
            true_label=row.get("Label"),
        )

        events.append(event)

    assert len(events) == 1000

    # ---------------------------------------------------------
    # 7. Real incident correlation
    # ---------------------------------------------------------

    correlator = IncidentCorrelator()

    incidents = correlator.correlate(
        events
    )

    assert len(incidents) > 0

    largest_incident = max(
        incidents,
        key=lambda incident: len(
            incident.events
        ),
    )

    # ---------------------------------------------------------
    # 8. Build real incident context
    # ---------------------------------------------------------

    context_builder = IncidentContextBuilder()

    context = context_builder.build(
        largest_incident
    )

    assert context.event_count > 0

    # ---------------------------------------------------------
    # 9. Real MITRE RAG
    # ---------------------------------------------------------

    incident_rag = IncidentRAG()

    rag_result = incident_rag.investigate(
        context=context,
        top_k=5,
    )

    assert rag_result.incident_id == (
        context.incident_id
    )

    assert len(
        rag_result.results
    ) == 5

    # ---------------------------------------------------------
    # 10. Real evidence-aware investigation
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

    assert investigation.incident_id == (
        context.incident_id
    )

    # ---------------------------------------------------------
    # 11. LLM agent with mock provider
    #
    # Everything before this point is REAL.
    # Only the LLM itself is mocked.
    # ---------------------------------------------------------

    agent = LLMInvestigationAgent(
        provider=MockLLMProvider()
    )

    llm_result = agent.investigate(
        context=context,
        investigation=investigation,
        rag_result=rag_result,
    )

    # ---------------------------------------------------------
    # 12. Validate structured LLM output
    # ---------------------------------------------------------

    assert llm_result.incident_id == (
        context.incident_id
    )

    assert llm_result.threat_assessment == (
        context.severity.capitalize()
    )

    assert len(
        llm_result.hypotheses
    ) >= 1

    assert len(
        llm_result.technique_assessments
    ) >= 1

    # Only evaluated techniques should reach
    # the LLM input/output.
    technique_ids = {
        technique.technique_id
        for technique in (
            llm_result.technique_assessments
        )
    }

    assert "T1110" in technique_ids

    assert (
        "T1498" not in technique_ids
    )

    assert (
        llm_result.metadata["provider"]
        == "mock"
    )

    assert 0.0 <= (
        llm_result.confidence
    ) <= 1.0

    # ---------------------------------------------------------
    # 13. Print the real end-to-end result
    # ---------------------------------------------------------

    print()
    print("=" * 70)
    print("REAL INCIDENT -> LLM AGENT INTEGRATION")
    print("=" * 70)

    print(
        f"Incident ID        : "
        f"{context.incident_id}"
    )

    print(
        f"Severity           : "
        f"{context.severity.capitalize()}"
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
        f"Investigation conf.: "
        f"{investigation.confidence}"
    )

    print(
        f"LLM confidence     : "
        f"{llm_result.confidence}"
    )

    print()
    print("LLM Summary:")
    print(llm_result.summary)

    print()
    print("LLM Threat Assessment:")
    print(llm_result.threat_assessment)

    print()
    print("LLM Hypotheses:")

    for hypothesis in llm_result.hypotheses:
        print(
            f"- {hypothesis.hypothesis} "
            f"(confidence="
            f"{hypothesis.confidence:.4f})"
        )

    print()
    print("LLM MITRE Assessments:")

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
    print("Evidence Gaps:")

    for gap in llm_result.evidence_gaps:
        print(f"- {gap}")

    print()
    print("Next Investigation Steps:")

    for step in (
        llm_result.next_investigation_steps
    ):
        print(f"- {step}")

    print()
    print("Recommended Actions:")

    for action in (
        llm_result.recommended_actions
    ):
        print(f"- {action}")

    print()
    print("=" * 70)
    print("PASSED")
    print("=" * 70)

    # ---------------------------------------------------------
    # 14. Explicitly release the local Qdrant filesystem lock
    # ---------------------------------------------------------

    incident_rag.close()