import pandas as pd

from correlation.event_builder import build_security_event
from detection.handler import DetectionHandler
from detection.model_loader import DetectionModelLoader


DATA_PATH = r"data\raw\cse_cic_ids2018\Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"

BINARY_MODEL_PATH = r"detection\models\xgboost_binary_detector.joblib"
FAMILY_MODEL_PATH = r"detection\models\xgboost_attack_family_classifier.joblib"

TARGET_INDEX = 45088


loader = DetectionModelLoader()

binary_bundle = loader.load_binary_model(BINARY_MODEL_PATH)
family_bundle = loader.load_attack_family_model(FAMILY_MODEL_PATH)

handler = DetectionHandler()

handler.attach_models(
    binary_model=binary_bundle,
    family_model=family_bundle,
)

dataframe = pd.read_csv(
    DATA_PATH,
    skiprows=range(1, TARGET_INDEX + 1),
    nrows=1,
)

row = dataframe.iloc[0]

event = build_security_event(
    row=row,
    event_id=f"REAL-CORR-{TARGET_INDEX:06d}",
    attack_family="Unknown",
    confidence=0.0,
    binary_prediction=0,
    true_label=row["Label"],
)

result = handler.detect(event)

print()
print("=" * 70)
print("SINGLE EVENT DETECTION DIAGNOSTIC")
print("=" * 70)

print(f"Event ID             : {event.event_id}")
print(f"Timestamp            : {event.timestamp}")
print(f"True label           : {event.true_label}")
print(f"Event type           : {event.event_type}")
print()

print("DETECTION RESULT")
print("-" * 70)
print(f"Detected             : {result.detected}")
print(f"Attack family        : {result.attack_family}")
print(f"Confidence           : {result.confidence}")
print(f"Detector type        : {result.detector_type}")
print(f"Supported            : {result.supported}")
print(f"Reason               : {result.reason}")
print()

print("EVENT NETWORK FIELDS")
print("-" * 70)
print(f"Source IP            : {event.src_ip}")
print(f"Destination IP       : {event.dst_ip}")
print(f"Source port          : {event.src_port}")
print(f"Destination port     : {event.dst_port}")
print(f"Protocol             : {event.protocol}")
print()

print("RAW DATASET LABEL")
print("-" * 70)
print(f"Label                : {row['Label']}")

print()
print("=" * 70)
