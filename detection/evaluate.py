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

VALIDATION_PATH = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "splits"
    / "validation.csv"
)

MODEL_PATH = (
    BASE_DIR
    / "detection"
    / "models"
    / "xgboost_binary_detector.joblib"
)


# ============================================================
# CONFIGURATION
# ============================================================

CHUNK_SIZE = 200_000

NON_FEATURE_COLUMNS = {
    "Label",
    "BinaryLabel",
    "SourceFile",
    "Timestamp",
}


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    print("=" * 70)
    print("Loading trained model")
    print("=" * 70)

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found:\n{MODEL_PATH}"
        )

    saved_data = joblib.load(MODEL_PATH)

    model = saved_data["model"]
    feature_names = saved_data["feature_names"]

    print(f"Model loaded successfully.")
    print(f"Expected features: {len(feature_names)}")

    return model, feature_names


# ============================================================
# EVALUATE VALIDATION DATA
# ============================================================

def evaluate(model, feature_names):

    print()
    print("=" * 70)
    print("Evaluating validation dataset")
    print("=" * 70)

    if not VALIDATION_PATH.exists():
        raise FileNotFoundError(
            f"Validation file not found:\n{VALIDATION_PATH}"
        )

    y_true_chunks = []
    y_probability_chunks = []

    total_rows = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            VALIDATION_PATH,
            chunksize=CHUNK_SIZE
        ),
        start=1
    ):

        print(f"Processing validation chunk {chunk_number}...")

        # ----------------------------------------------------
        # True labels
        # ----------------------------------------------------

        y_true = chunk["BinaryLabel"].astype("int8")

        # ----------------------------------------------------
        # Select exactly the same features used during training
        # ----------------------------------------------------

        missing_features = [
            feature
            for feature in feature_names
            if feature not in chunk.columns
        ]

        if missing_features:
            raise ValueError(
                "Validation dataset is missing features:\n"
                + "\n".join(missing_features)
            )

        X = chunk[feature_names].copy()

        # ----------------------------------------------------
        # Numeric conversion
        # ----------------------------------------------------

        X = X.apply(
            pd.to_numeric,
            errors="coerce"
        )

        # ----------------------------------------------------
        # Handle infinity / missing values
        # ----------------------------------------------------

        X = X.replace(
            [float("inf"), float("-inf")],
            pd.NA
        )

        X = X.fillna(0)

        # ----------------------------------------------------
        # Predict probability of ATTACK
        # ----------------------------------------------------

        probabilities = model.predict_proba(X)[:, 1]

        y_true_chunks.append(y_true)
        y_probability_chunks.append(probabilities)

        total_rows += len(chunk)

    # --------------------------------------------------------
    # Combine results
    # --------------------------------------------------------

    y_true = pd.concat(
        y_true_chunks,
        ignore_index=True
    )

    y_probability = pd.Series(
        pd.concat(
            [
                pd.Series(x)
                for x in y_probability_chunks
            ],
            ignore_index=True
        )
    )

    # --------------------------------------------------------
    # Default threshold
    # --------------------------------------------------------

    threshold = 0.7

    y_pred = (
        y_probability >= threshold
    ).astype("int8")

    # ========================================================
    # RESULTS
    # ========================================================

    print()
    print("=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    print(f"Total validation rows: {total_rows:,}")

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
            digits=4
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

    print(f"ROC-AUC : {roc_auc:.6f}")
    print(f"PR-AUC  : {pr_auc:.6f}")

    print()
    print(f"Decision threshold: {threshold}")

    return {
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": cm,
    }


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