from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)


# ============================================================
# CONFIGURATION
# ============================================================

TEST_PATH = Path(
    "data/processed/cse_cic_ids2018/"
    "splits/known_family/test.csv"
)

MODEL_PATH = Path(
    "detection/models/"
    "xgboost_attack_family_classifier.joblib"
)

CHUNK_SIZE = 200_000


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    print("=" * 80)
    print("LOADING ATTACK FAMILY CLASSIFIER")
    print("=" * 80)

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found:\n{MODEL_PATH}"
        )

    package = joblib.load(MODEL_PATH)

    model = package["model"]
    label_encoder = package["label_encoder"]
    feature_columns = package["feature_columns"]

    print()
    print("Model loaded successfully.")

    print()
    print("Classes:")

    for class_id, class_name in enumerate(
        label_encoder.classes_
    ):
        print(
            f"{class_id} -> {class_name}"
        )

    print()
    print(
        f"Expected features: "
        f"{len(feature_columns)}"
    )

    return (
        model,
        label_encoder,
        feature_columns,
    )


# ============================================================
# LOAD TEST DATA
# ============================================================

def load_test_data():

    print()
    print("=" * 80)
    print("LOADING FINAL TEST DATA")
    print("=" * 80)

    if not TEST_PATH.exists():
        raise FileNotFoundError(
            f"Test file not found:\n{TEST_PATH}"
        )

    chunks = []

    for chunk in pd.read_csv(
        TEST_PATH,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):
        chunks.append(chunk)

    df = pd.concat(
        chunks,
        ignore_index=True,
    )

    print()
    print(
        f"Test rows: {len(df):,}"
    )

    return df


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(
    df,
    feature_columns,
):

    # --------------------------------------------------------
    # Make sure the test dataset contains exactly the
    # features expected by the trained model.
    # --------------------------------------------------------

    missing_columns = [
        column
        for column in feature_columns
        if column not in df.columns
    ]

    if missing_columns:

        raise ValueError(
            "Missing feature columns:\n"
            + "\n".join(missing_columns)
        )

    # --------------------------------------------------------
    # Preserve exact feature order
    # --------------------------------------------------------

    X = df[
        feature_columns
    ].copy()

    # --------------------------------------------------------
    # Convert features to numeric
    # --------------------------------------------------------

    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce",
        )

    # --------------------------------------------------------
    # Handle infinite values
    # --------------------------------------------------------

    X = X.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    # --------------------------------------------------------
    # Handle missing values
    # --------------------------------------------------------

    X = X.fillna(0)

    return X


# ============================================================
# EVALUATE TEST SET
# ============================================================

def evaluate_test_set(
    model,
    label_encoder,
    feature_columns,
    df,
):

    print()
    print("=" * 80)
    print("FINAL TEST EVALUATION")
    print("=" * 80)

    # --------------------------------------------------------
    # Ground truth
    # --------------------------------------------------------

    y_true_text = (
        df["AttackFamily"]
        .astype(str)
    )

    y_true = label_encoder.transform(
        y_true_text
    )

    # --------------------------------------------------------
    # Features
    # --------------------------------------------------------

    X = prepare_features(
        df,
        feature_columns,
    )

    print()
    print(
        f"Test features: {X.shape[1]}"
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    print()
    print("Generating final test predictions...")

    y_pred = model.predict(X)

    y_prob = model.predict_proba(X)

    # --------------------------------------------------------
    # Accuracy
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_true,
        y_pred,
    )

    # --------------------------------------------------------
    # Macro metrics
    # --------------------------------------------------------

    (
        precision_macro,
        recall_macro,
        f1_macro,
        _,
    ) = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )

    # --------------------------------------------------------
    # Weighted metrics
    # --------------------------------------------------------

    (
        precision_weighted,
        recall_weighted,
        f1_weighted,
        _,
    ) = precision_recall_fscore_support(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    # --------------------------------------------------------
    # Overall metrics
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("FINAL TEST METRICS")
    print("=" * 80)

    print(
        f"Accuracy          : {accuracy:.6f}"
    )

    print(
        f"Macro Precision   : {precision_macro:.6f}"
    )

    print(
        f"Macro Recall      : {recall_macro:.6f}"
    )

    print(
        f"Macro F1          : {f1_macro:.6f}"
    )

    print(
        f"Weighted Precision: {precision_weighted:.6f}"
    )

    print(
        f"Weighted Recall   : {recall_weighted:.6f}"
    )

    print(
        f"Weighted F1       : {f1_weighted:.6f}"
    )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("FINAL TEST CLASSIFICATION REPORT")
    print("=" * 80)

    report = classification_report(
        y_true,
        y_pred,
        labels=np.arange(
            len(label_encoder.classes_)
        ),
        target_names=label_encoder.classes_,
        digits=6,
        zero_division=0,
    )

    print(report)

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=np.arange(
            len(label_encoder.classes_)
        ),
    )

    print()
    print("=" * 80)
    print("FINAL TEST CONFUSION MATRIX")
    print("=" * 80)

    class_names = (
        label_encoder.classes_
    )

    print(
        f"{'Actual / Predicted':<20}",
        end="",
    )

    for name in class_names:

        print(
            f"{name:>15}",
            end="",
        )

    print()

    print("-" * 95)

    for i, name in enumerate(
        class_names
    ):

        print(
            f"{name:<20}",
            end="",
        )

        for j in range(
            len(class_names)
        ):

            print(
                f"{cm[i, j]:>15,}",
                end="",
            )

        print()

    # --------------------------------------------------------
    # Per-family analysis
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("FINAL TEST PER-FAMILY ANALYSIS")
    print("=" * 80)

    (
        precision,
        recall,
        f1,
        support,
    ) = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=np.arange(
            len(label_encoder.classes_)
        ),
        zero_division=0,
    )

    for i, class_name in enumerate(
        class_names
    ):

        print()
        print(
            f"{class_name}"
        )

        print(
            f"  Precision : "
            f"{precision[i]:.6f}"
        )

        print(
            f"  Recall    : "
            f"{recall[i]:.6f}"
        )

        print(
            f"  F1        : "
            f"{f1[i]:.6f}"
        )

        print(
            f"  Support   : "
            f"{support[i]:,}"
        )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = np.max(
        y_prob,
        axis=1,
    )

    print()
    print("=" * 80)
    print("FINAL TEST CONFIDENCE")
    print("=" * 80)

    print(
        f"Mean confidence   : "
        f"{confidence.mean():.6f}"
    )

    print(
        f"Median confidence : "
        f"{np.median(confidence):.6f}"
    )

    print(
        f"Minimum confidence: "
        f"{confidence.min():.6f}"
    )

    print(
        f"Maximum confidence: "
        f"{confidence.max():.6f}"
    )

    return {
        "accuracy": accuracy,
        "macro_precision": precision_macro,
        "macro_recall": recall_macro,
        "macro_f1": f1_macro,
        "weighted_precision": precision_weighted,
        "weighted_recall": recall_weighted,
        "weighted_f1": f1_weighted,
        "confusion_matrix": cm,
        "y_true": y_true,
        "y_pred": y_pred,
        "y_prob": y_prob,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 80)
    print("ATTACK FAMILY CLASSIFIER — FINAL TEST")
    print("=" * 80)

    # --------------------------------------------------------
    # Load model
    # --------------------------------------------------------

    (
        model,
        label_encoder,
        feature_columns,
    ) = load_model()

    # --------------------------------------------------------
    # Load test data
    # --------------------------------------------------------

    df = load_test_data()

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    results = evaluate_test_set(
        model,
        label_encoder,
        feature_columns,
        df,
    )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("FINAL TEST EVALUATION COMPLETE")
    print("=" * 80)

    print()
    print(
        f"Test Accuracy : "
        f"{results['accuracy']:.6f}"
    )

    print(
        f"Test Macro F1 : "
        f"{results['macro_f1']:.6f}"
    )


if __name__ == "__main__":
    main()