from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TEST_PATH = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "known_attack_eval"
    / "test.csv"
)

MODEL_PATH = (
    BASE_DIR
    / "detection"
    / "models"
    / "xgboost_binary_detector_known_attack.joblib"
)


# ============================================================
# CONFIGURATION
# ============================================================

CHUNK_SIZE = 200_000


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    print("=" * 70)
    print("LOADING KNOWN-ATTACK DETECTOR")
    print("=" * 70)

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found:\n{MODEL_PATH}"
        )

    saved_data = joblib.load(MODEL_PATH)

    model = saved_data["model"]
    feature_names = saved_data["feature_names"]

    print("Model loaded successfully.")
    print(f"Expected features: {len(feature_names)}")

    return model, feature_names


# ============================================================
# EVALUATE
# ============================================================

def evaluate(model, feature_names):

    print()
    print("=" * 70)
    print("EVALUATING ON COMPLETELY UNSEEN CAPTURE FILE")
    print("=" * 70)

    print(f"Test file: {TEST_PATH}")

    if not TEST_PATH.exists():
        raise FileNotFoundError(
            f"Test file not found:\n{TEST_PATH}"
        )

    y_true_chunks = []
    y_probability_chunks = []
    label_chunks = []

    total_rows = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            TEST_PATH,
            chunksize=CHUNK_SIZE
        ),
        start=1
    ):

        print(
            f"Processing test chunk {chunk_number}..."
        )

        # ----------------------------------------------------
        # True binary labels
        # ----------------------------------------------------

        y_true = chunk["BinaryLabel"].astype("int8")

        # ----------------------------------------------------
        # Original attack labels
        # ----------------------------------------------------

        original_labels = (
            chunk["Label"]
            .astype(str)
            .str.strip()
        )

        # ----------------------------------------------------
        # Make sure every model feature exists
        # ----------------------------------------------------

        missing_features = [
            feature
            for feature in feature_names
            if feature not in chunk.columns
        ]

        if missing_features:
            raise ValueError(
                "Test dataset is missing features:\n"
                + "\n".join(missing_features)
            )

        # ----------------------------------------------------
        # Select EXACTLY the features used during training
        # ----------------------------------------------------

        X = chunk[feature_names].copy()

        # Convert to numeric
        X = X.apply(
            pd.to_numeric,
            errors="coerce"
        )

        # Handle invalid values
        X = X.replace(
            [float("inf"), float("-inf")],
            pd.NA
        )

        X = X.fillna(0)

        # ----------------------------------------------------
        # Predict attack probability
        # ----------------------------------------------------

        probabilities = model.predict_proba(X)[:, 1]

        y_true_chunks.append(y_true)
        y_probability_chunks.append(
            pd.Series(probabilities)
        )
        label_chunks.append(original_labels)

        total_rows += len(chunk)

    # ========================================================
    # COMBINE RESULTS
    # ========================================================

    y_true = pd.concat(
        y_true_chunks,
        ignore_index=True
    )

    y_probability = pd.concat(
        y_probability_chunks,
        ignore_index=True
    )

    original_labels = pd.concat(
        label_chunks,
        ignore_index=True
    )

    # ========================================================
    # DEFAULT THRESHOLD
    # ========================================================

    threshold = 0.5

    y_pred = (
        y_probability >= threshold
    ).astype("int8")

    # ========================================================
    # OVERALL RESULTS
    # ========================================================

    print()
    print("=" * 70)
    print("KNOWN-ATTACK TEST RESULTS")
    print("=" * 70)

    print(
        f"Total test rows: {total_rows:,}"
    )

    print()
    print("Confusion Matrix")
    print("----------------")

    cm = confusion_matrix(
        y_true,
        y_pred
    )

    print(cm)

    print()
    print("Classification Report")
    print("---------------------")

    print(
        classification_report(
            y_true,
            y_pred,
            target_names=[
                "Benign",
                "Attack"
            ],
            digits=4,
            zero_division=0
        )
    )

    # ========================================================
    # ROC-AUC
    # ========================================================

    roc_auc = roc_auc_score(
        y_true,
        y_probability
    )

    # ========================================================
    # PR-AUC
    # ========================================================

    pr_auc = average_precision_score(
        y_true,
        y_probability
    )

    print()
    print("=" * 70)
    print("ADDITIONAL METRICS")
    print("=" * 70)

    print(
        f"ROC-AUC : {roc_auc:.6f}"
    )

    print(
        f"PR-AUC  : {pr_auc:.6f}"
    )

    print(
        f"Decision threshold: {threshold}"
    )

    # ========================================================
    # PER-ATTACK-FAMILY RESULTS
    # ========================================================

    print()
    print("=" * 70)
    print("PER-ATTACK-FAMILY RESULTS")
    print("=" * 70)

    attack_mask = y_true == 1

    attack_labels = original_labels[
        attack_mask
    ]

    attack_predictions = y_pred[
        attack_mask
    ]

    attack_probabilities = y_probability[
        attack_mask
    ]

    for attack_type in sorted(
        attack_labels.unique()
    ):

        mask = (
            attack_labels == attack_type
        )

        total = int(mask.sum())

        detected = int(
            attack_predictions[mask].sum()
        )

        recall = (
            detected / total
            if total > 0
            else 0.0
        )

        avg_probability = (
            attack_probabilities[mask].mean()
            if total > 0
            else 0.0
        )

        print()
        print(f"Attack: {attack_type}")
        print(f"  Total samples       : {total:,}")
        print(f"  Detected            : {detected:,}")
        print(f"  Missed              : {total - detected:,}")
        print(f"  Recall              : {recall:.4f}")
        print(
            f"  Average probability : "
            f"{avg_probability:.6f}"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    model, feature_names = load_model()

    evaluate(
        model,
        feature_names
    )


if __name__ == "__main__":
    main()