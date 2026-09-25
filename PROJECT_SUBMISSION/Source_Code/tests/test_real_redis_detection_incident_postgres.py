from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pandas as pd
import psycopg

from correlation.correlator import IncidentCorrelator
from correlation.event_builder import build_security_event
from correlation.incident_manager import IncidentManager
from correlation.incident_window import IncidentWindow
from detection.handler import DetectionHandler
from detection.model_loader import DetectionModelLoader
from ingestion.detection_adapter import DetectionAdapter
from ingestion.event_router import EventRouter
from ingestion.queue.redis_consumer import RedisStreamConsumer
from ingestion.queue.redis_processor import RedisStreamProcessor
from ingestion.queue.redis_stream import RedisEventQueue
from persistence.incident_persistence_adapter import IncidentPersistenceAdapter


PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATABASE_URL = (
    "postgresql://cybersecurity:"
    "cybersecurity_dev_password@localhost:5432/cybersecurity"
)

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


def create_detection_handler() -> DetectionHandler:
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

    return handler


def load_attack_row():
    dataframe = pd.read_csv(
        TRAIN_PATH,
        nrows=200_000,
        low_memory=False,
    )

    attack_rows = dataframe[
        dataframe["BinaryLabel"] == 1
    ]

    if attack_rows.empty:
        raise RuntimeError(
            "No attack row found in training split."
        )

    return attack_rows.iloc[0]


def create_attack_event(
    attack_row,
    timestamp: datetime,
    src_ip: str,
    dst_ip: str,
):
    event = build_security_event(
        row=attack_row,
        event_id=uuid4(),
        attack_family="Unknown",
        confidence=0.0,
        binary_prediction=0,
        true_label=attack_row["Label"],
    )

    event.timestamp = timestamp
    event.src_ip = src_ip
    event.dst_ip = dst_ip

    return event


def cleanup_database(event_ids, incident_ids):
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:

            if incident_ids:
                cursor.execute(
                    """
                    DELETE FROM incident_events
                    WHERE incident_id = ANY(%s)
                    """,
                    (
                        [str(i) for i in incident_ids],
                    ),
                )

                cursor.execute(
                    """
                    DELETE FROM incidents
                    WHERE incident_id = ANY(%s)
                    """,
                    (
                        [str(i) for i in incident_ids],
                    ),
                )

            if event_ids:
                cursor.execute(
                    """
                    DELETE FROM security_events
                    WHERE event_id = ANY(%s)
                    """,
                    (
                        [str(i) for i in event_ids],
                    ),
                )


def test_real_redis_detection_incident_postgres():

    queue_name = (
        "test_real_detection_incident_postgres_"
        + uuid4().hex
    )

    queue = RedisEventQueue(
        stream_name=queue_name
    )

    consumer = RedisStreamConsumer(
        queue
    )

    detection_handler = create_detection_handler()

    detection_adapter = DetectionAdapter(
        detection_handler
    )

    # Use the existing production adapter interface.
    persistence_adapter = IncidentPersistenceAdapter()

    incident_manager = IncidentManager(
        window=IncidentWindow(
            window_seconds=60
        ),
        correlator=IncidentCorrelator(
            time_window_seconds=60,
            correlation_threshold=4,
        ),
        persistence_adapter=persistence_adapter,
    )

    router = EventRouter()

    router.register(
        "detection",
        detection_adapter,
    )

    router.register(
        "incident_manager",
        incident_manager,
    )

    processor = RedisStreamProcessor(
        consumer=consumer,
        event_router=router,
    )

    attack_row = load_attack_row()

    base_time = datetime(
        2026,
        9,
        17,
        6,
        0,
        0,
        tzinfo=timezone.utc,
    )

    event_ids = []
    incident_ids = []

    try:
        events = []

        for index in range(5):
            event = create_attack_event(
                attack_row=attack_row,
                timestamp=(
                    base_time
                    + timedelta(seconds=index)
                ),
                src_ip="192.168.50.10",
                dst_ip="10.0.50.20",
            )

            events.append(event)
            event_ids.append(event.event_id)

        print()
        print("=" * 70)
        print("REAL END-TO-END INTEGRATION TEST")
        print("=" * 70)

        print()
        print("[1/7] Publishing attack events to Redis...")

        queue.publish_batch(events)

        print(
            f"      Published {len(events)} events."
        )

        print()
        print("[2/7] Processing Redis batch...")

        processed_events = processor.process_batch(
            count=10
        )

        assert len(processed_events) == 5

        print(
            f"      Processed {len(processed_events)} events."
        )

        print()
        print("[3/7] Verifying real XGBoost detection...")

        for event in processed_events:
            print(
                f"      {event.event_id} | "
                f"detected={event.binary_prediction} | "
                f"family={event.attack_family} | "
                f"confidence={event.confidence:.4f}"
            )

        assert all(
            event.binary_prediction == 1
            for event in processed_events
        )

        assert all(
            event.attack_family != "Benign"
            for event in processed_events
        )

        print(
            "      XGBoost detection verified."
        )

        print()
        print("[4/7] Verifying IncidentManager buffer...")

        assert (
            incident_manager.buffered_event_count
            == 5
        )

        print(
            "      5 events are inside the active "
            "60-second incident window."
        )

        print()
        print("[5/7] Flushing incident window...")

        incidents = incident_manager.flush()

        assert len(incidents) >= 1

        incident_ids = [
            incident.incident_id
            for incident in incidents
        ]

        print(
            f"      Created {len(incidents)} incident(s)."
        )

        for incident in incidents:
            print(
                f"      Incident: {incident.incident_id}"
            )
            print(
                f"      Family:   "
                f"{incident.primary_attack_family}"
            )
            print(
                f"      Severity: "
                f"{incident.severity}"
            )
            print(
                f"      Events:   "
                f"{len(incident.events)}"
            )

        assert any(
            len(incident.events) == 5
            for incident in incidents
        )

        print()
        print("[6/7] Verifying PostgreSQL persistence...")

        with psycopg.connect(
            DATABASE_URL
        ) as connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM incidents
                    WHERE incident_id = ANY(%s)
                    """,
                    (
                        [
                            str(i)
                            for i in incident_ids
                        ],
                    ),
                )

                incident_count = cursor.fetchone()[0]

                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM security_events
                    WHERE event_id = ANY(%s)
                    """,
                    (
                        [
                            str(i)
                            for i in event_ids
                        ],
                    ),
                )

                event_count = cursor.fetchone()[0]

                cursor.execute(
                    """
                    SELECT COUNT(*)
                    FROM incident_events
                    WHERE incident_id = ANY(%s)
                    AND event_id = ANY(%s)
                    """,
                    (
                        [
                            str(i)
                            for i in incident_ids
                        ],
                        [
                            str(i)
                            for i in event_ids
                        ],
                    ),
                )

                link_count = cursor.fetchone()[0]

        print(
            f"      Persisted incidents: {incident_count}"
        )

        print(
            f"      Persisted events:    {event_count}"
        )

        print(
            f"      Incident-event links: {link_count}"
        )

        assert incident_count >= 1
        assert event_count == 5
        assert link_count == 5

        print()
        print("[7/7] End-to-end verification complete.")

        print()
        print("=" * 70)
        print("PASS: Redis -> Detection -> Correlation -> PostgreSQL")
        print("=" * 70)
        print()

    finally:
        queue.clear()

        cleanup_database(
            event_ids=event_ids,
            incident_ids=incident_ids,
        )
