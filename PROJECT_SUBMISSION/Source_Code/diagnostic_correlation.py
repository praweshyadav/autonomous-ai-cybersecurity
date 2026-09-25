import pandas as pd

from correlation.event_builder import build_security_event
from correlation.correlator import IncidentCorrelator
from detection.handler import DetectionHandler
from detection.model_loader import DetectionModelLoader


DATA_PATH = r"data\raw\cse_cic_ids2018\Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"

BINARY_MODEL_PATH = r"detection\models\xgboost_binary_detector.joblib"
FAMILY_MODEL_PATH = r"detection\models\xgboost_attack_family_classifier.joblib"


def load_handler():
    loader = DetectionModelLoader()

    binary_bundle = loader.load_binary_model(
        BINARY_MODEL_PATH
    )

    family_bundle = loader.load_attack_family_model(
        FAMILY_MODEL_PATH
    )

    handler = DetectionHandler()

    handler.attach_models(
        binary_model=binary_bundle,
        family_model=family_bundle,
    )

    return handler


dataframe = pd.read_csv(
    DATA_PATH,
    nrows=50_000,
)

handler = load_handler()

events = []

for index, row in dataframe.iterrows():
    event = build_security_event(
        row=row,
        event_id=f"REAL-CORR-{index:06d}",
        attack_family="Unknown",
        confidence=0.0,
        binary_prediction=0,
        true_label=row["Label"],
    )

    events.append(event)


detection_results = handler.detect_batch(events)


for event, result in zip(events, detection_results):
    event.binary_prediction = result.detected
    event.attack_family = result.attack_family
    event.confidence = result.confidence


attack_events = [
    event
    for event in events
    if event.binary_prediction == 1
]


correlator = IncidentCorrelator(
    time_window_seconds=60,
)

incidents = correlator.correlate(events)


correlated_ids = {
    event.event_id
    for incident in incidents
    for event in incident.events
}

attack_ids = {
    event.event_id
    for event in attack_events
}

missing_ids = attack_ids - correlated_ids


print()
print("=" * 70)
print("CORRELATION DIAGNOSTIC")
print("=" * 70)

print(f"Total events          : {len(events)}")
print(f"Detected attacks      : {len(attack_events)}")
print(f"Correlated events     : {len(correlated_ids)}")
print(f"Missing detected      : {len(missing_ids)}")
print()


for event_id in sorted(missing_ids):

    event = next(
        event
        for event in attack_events
        if event.event_id == event_id
    )

    print("MISSING EVENT")
    print(f"event_id       : {event.event_id}")
    print(f"timestamp      : {event.timestamp}")
    print(f"binary_prediction: {event.binary_prediction}")
    print(f"attack_family  : {event.attack_family}")
    print(f"confidence     : {event.confidence}")
    print(f"src_ip         : {event.src_ip}")
    print(f"dst_ip         : {event.dst_ip}")
    print(f"src_port       : {event.src_port}")
    print(f"dst_port       : {event.dst_port}")
    print(f"protocol       : {event.protocol}")
    print(f"true_label     : {event.true_label}")
    print(f"event_type     : {event.event_type}")
    print()


print("=" * 70)




