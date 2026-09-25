import pandas as pd

from correlation.event_builder import build_security_event
from detection.handler import DetectionHandler
from detection.model_loader import DetectionModelLoader


DATA_PATH = r"data\raw\cse_cic_ids2018\Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"

BINARY_MODEL_PATH = r"detection\models\xgboost_binary_detector.joblib"
FAMILY_MODEL_PATH = r"detection\models\xgboost_attack_family_classifier.joblib"


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
    nrows=50_000,
)

events = []

for index, row in dataframe.iterrows():

    event = build_security_event(
        row=row,
        event_id=f"REAL-DIAG-{index:06d}",
        attack_family="Unknown",
        confidence=0.0,
        binary_prediction=0,
        true_label=row["Label"],
    )

    events.append(event)


results = handler.detect_batch(events)


benign_false_positives = []

for event, result in zip(events, results):

    if (
        event.true_label == "Benign"
        and result.detected
    ):
        benign_false_positives.append(
            (event, result)
        )


print()
print("=" * 70)
print("BINARY DETECTOR DIAGNOSTIC")
print("=" * 70)

print(f"Total events              : {len(events)}")
print(
    f"Detected by binary model : "
    f"{sum(result.detected for result in results)}"
)
print(
    f"Benign false positives    : "
    f"{len(benign_false_positives)}"
)
print()

for event, result in benign_false_positives[:20]:

    print(
        f"{event.event_id} | "
        f"label={event.true_label} | "
        f"detected={result.detected} | "
        f"family={result.attack_family} | "
        f"confidence={result.confidence:.6f} | "
        f"protocol={event.protocol} | "
        f"dst_port={event.dst_port}"
    )

print()
print("=" * 70)
