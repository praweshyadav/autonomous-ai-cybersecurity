from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pandas as pd

from agent.context_builder import IncidentContextBuilder
from agent.incident_rag import IncidentRAG
from agent.investigation_engine import InvestigationEngine
from correlation.correlator import IncidentCorrelator
from correlation.event_builder import build_security_event
from detection.handler import DetectionHandler
from detection.model_loader import DetectionModelLoader
from ingestion.detection_adapter import DetectionAdapter


PROJECT_ROOT = Path(__file__).resolve().parents[1]

BINARY_MODEL_PATH = (
    PROJECT_ROOT
    / "detection"
    / "models"
    / "xgboost_binary_detector.joblib"
)

FAMILY_MODEL_PATH = (
    PROJECT_ROOT
    / "detection"
    / "models"
    / "xgboost_attack_family_classifier.joblib"
)

TRAIN_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "splits"
    / "train.csv"
)


def create_detection_adapter() -> DetectionAdapter:
    loader = DetectionModelLoader()

    binary_bundle = loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    family_bundle = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    handler = DetectionHandler()

    handler.attach_models(
        binary_bundle,
        family_bundle,
    )

    return DetectionAdapter(handler)


def load_attack_rows():
    dataframe = pd.read_csv(
        TRAIN_PATH,
        nrows=200_000,
        low_memory=False,
    )

    attack_rows = dataframe[
        dataframe["BinaryLabel"] == 1
    ]

    if len(attack_rows) < 5:
        raise RuntimeError(
            "Fewer than 5 attack rows were found."
        )

    return attack_rows.head(5)


def test_real_incident_to_rag_to_investigation():

    print()
    print("=" * 70)
    print("REAL INCIDENT -> RAG -> INVESTIGATION")
    print("=" * 70)

    # ---------------------------------------------------------
    # 1. Load real attack data
    # ---------------------------------------------------------

    attack_rows = load_attack_rows()

    print()
    print("[1/6] Loaded real CIC-IDS2018 attack rows.")
    print(
        f"      Attack rows: {len(attack_rows)}"
    )

    # ---------------------------------------------------------
    # 2. Run real XGBoost detection
    # ---------------------------------------------------------

    detection_adapter = create_detection_adapter()

    events = []

    base_time = datetime(
        2026,
        9,
        17,
        6,
        0,
        0,
        tzinfo=timezone.utc,
    )

    for index, (_, row) in enumerate(
        attack_rows.iterrows()
    ):

        event = build_security_event(
            row=row,
            event_id=uuid4(),
            attack_family="Unknown",
            confidence=0.0,
            binary_prediction=0,
            true_label=row["Label"],
        )

        event.timestamp = (
            base_time
            + timedelta(seconds=index)
        )

        event.src_ip = "192.168.50.10"
        event.dst_ip = "10.0.50.20"

        detection_result = detection_adapter.process(
            event
        )

        # DetectionAdapter returns DetectionResult.
        # Apply the result to the SecurityEvent for
        # the downstream correlation layer.
        event.binary_prediction = (
            int(detection_result.detected)
        )

        event.attack_family = (
            detection_result.attack_family
        )

        event.confidence = (
            detection_result.confidence
        )

        events.append(event)

    print()
    print(
        "[2/6] Real XGBoost detection completed."
    )

    for event in events:
        print(
            f"      detected={event.binary_prediction} | "
            f"family={event.attack_family} | "
            f"confidence={event.confidence:.4f}"
        )

    assert len(events) == 5

    assert all(
        event.binary_prediction == 1
        for event in events
    )

    assert all(
        event.attack_family != "Benign"
        for event in events
    )

    # ---------------------------------------------------------
    # 3. Correlate into an incident
    # ---------------------------------------------------------

    correlator = IncidentCorrelator(
        time_window_seconds=60,
        correlation_threshold=4,
    )

    incidents = correlator.correlate(
        events
    )

    assert len(incidents) >= 1

    incident = max(
        incidents,
        key=lambda item: len(item.events),
    )

    assert len(incident.events) == 5

    print()
    print(
        "[3/6] Incident correlation completed."
    )

    print(
        f"      Incident ID : "
        f"{incident.incident_id}"
    )

    print(
        f"      Family      : "
        f"{incident.primary_attack_family}"
    )

    print(
        f"      Severity    : "
        f"{incident.severity}"
    )

    print(
        f"      Events      : "
        f"{len(incident.events)}"
    )

    # ---------------------------------------------------------
    # 4. Build structured incident context
    # ---------------------------------------------------------

    context_builder = IncidentContextBuilder()

    context = context_builder.build(
        incident
    )

    assert (
        context.incident_id
        == incident.incident_id
    )

    assert context.event_count == 5

    assert (
        context.primary_attack_family
        is not None
    )

    print()
    print(
        "[4/6] Incident context created."
    )

    print(
        f"      Primary family : "
        f"{context.primary_attack_family}"
    )

    print(
        f"      Event count    : "
        f"{context.event_count}"
    )

    print(
        f"      Families       : "
        f"{context.family_distribution}"
    )

    # ---------------------------------------------------------
    # 5. Run real MITRE RAG
    # ---------------------------------------------------------

    incident_rag = IncidentRAG()

    try:

        rag_result = incident_rag.investigate(
            context=context,
            top_k=5,
        )

        assert (
            rag_result.incident_id
            == context.incident_id
        )

        assert rag_result.query

        assert len(
            rag_result.results
        ) == 5

        print()
        print(
            "[5/6] Real MITRE RAG completed."
        )

        print()
        print(
            "      Investigation query:"
        )

        print(
            f"      {rag_result.query}"
        )

        print()
        print(
            "      Retrieved MITRE knowledge:"
        )

        for rank, result in enumerate(
            rag_result.results,
            start=1,
        ):

            print(
                f"      {rank}. "
                f"{result.title} "
                f"(score={result.score:.4f})"
            )

        for result in rag_result.results:

            assert result.chunk_id
            assert result.document_id
            assert result.title
            assert result.source
            assert result.content

            assert isinstance(
                result.score,
                float,
            )

        # -----------------------------------------------------
        # 6. Run deterministic investigation
        # -----------------------------------------------------

        investigation_engine = (
            InvestigationEngine()
        )

        investigation = (
            investigation_engine.investigate(
                context=context,
                rag_result=rag_result,
            )
        )

        assert (
            investigation.incident_id
            == context.incident_id
        )

        assert investigation.summary

        assert investigation.threat_assessment

        assert 0.0 <= (
            investigation.confidence
        ) <= 1.0

        print()
        print(
            "[6/6] Deterministic investigation completed."
        )

        print()
        print(
            "--- INVESTIGATION RESULT ---"
        )

        print(
            f"      Incident ID  : "
            f"{investigation.incident_id}"
        )

        print(
            f"      Confidence   : "
            f"{investigation.confidence:.4f}"
        )

        print(
            f"      Threat       : "
            f"{investigation.threat_assessment}"
        )

        print()
        print(
            "      Summary:"
        )

        print(
            f"      {investigation.summary}"
        )

        print()
        print(
            "      MITRE techniques:"
        )

        for technique in (
            investigation.mitre_techniques
        ):

            print(
                f"      - "
                f"{technique.technique_id} - "
                f"{technique.technique_name} "
                f"(confidence="
                f"{technique.confidence:.4f})"
            )

        print()
        print(
            "      Hypotheses:"
        )

        for hypothesis in (
            investigation.hypotheses
        ):

            print(
                f"      - "
                f"{hypothesis.description} "
                f"(confidence="
                f"{hypothesis.confidence:.4f})"
            )

        assert (
            investigation.evidence
            is not None
        )

        assert (
            investigation.hypotheses
            is not None
        )

        assert (
            investigation.mitre_techniques
            is not None
        )

    finally:
        incident_rag.close()

    print()
    print("=" * 70)
    print(
        "PASS: Incident -> Context -> RAG -> Investigation"
    )
    print("=" * 70)
    print()



