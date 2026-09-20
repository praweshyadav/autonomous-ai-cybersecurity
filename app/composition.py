from pathlib import Path

from correlation.correlator import IncidentCorrelator
from correlation.incident_manager import IncidentManager
from correlation.incident_window import IncidentWindow
from detection.handler import DetectionHandler
from detection.model_loader import DetectionModelLoader
from ingestion.detection_adapter import DetectionAdapter
from ingestion.event_router import EventRouter
from persistence.incident_persistence_adapter import (
    IncidentPersistenceAdapter,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

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


def build_event_router() -> EventRouter:
    """
    Build the production event-processing graph.

    Processing order:

        SecurityEvent
            ?
        DetectionAdapter
            ?
        IncidentManager
            ?
        IncidentCorrelator
            ?
        PostgreSQL
    """

    model_loader = DetectionModelLoader()

    binary_model = model_loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    family_model = model_loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    detection_handler = DetectionHandler()

    detection_handler.attach_models(
        binary_model=binary_model,
        family_model=family_model,
    )

    detection_adapter = DetectionAdapter(
        detection_handler
    )

    persistence_adapter = IncidentPersistenceAdapter()

    incident_manager = IncidentManager(
        window=IncidentWindow(
            window_seconds=60
        ),
        correlator=IncidentCorrelator(),
        persistence_adapter=persistence_adapter,
    )

    router = EventRouter()

    # Registration order is intentional.
    # Detection must enrich the SecurityEvent before
    # IncidentManager performs correlation.
    router.register(
        "detection",
        detection_adapter,
    )

    router.register(
        "incident_manager",
        incident_manager,
    )

    return router
