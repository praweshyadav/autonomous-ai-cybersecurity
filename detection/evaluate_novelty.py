from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_ROOT
    / "detection"
    / "models"
    / "isolation_forest_benign.joblib"
)

VALIDATION_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "splits"
    / "validation.csv"
)

CHUNK_SIZE = 100_000

# Candidate anomaly thresholds.
# Higher anomaly_score = more anomalous.
THRESHOLDS = [
    -0.20,
    -0.15,
    -0.10,
    -0.05,
    0.00,
    0.05,
    0.10,
    0.15,
    0.20,
]


NON_FEATURE_COLUMNS = {
    "Timestamp",
    "Label",
    "BinaryLabel",
    "AttackFamily",
    "SourceFile",
}


def load_artifact():
    print("=" * 70)
    print("LOADING NOVELTY DETECTOR")
    print("=" * 70)

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Novelty model not found:\n{MODEL_PATH}"
        )

    artifact = joblib.load(MODEL_PATH)

    required_keys = {
        "model",
        "feature_names",
        "training_samples",
        "algorithm",
    }

    missing = required_keys - set(artifact.keys())

    if missing:
        raise ValueError(
            f"Novelty artifact is missing keys: {sorted(missing)}"
        )

    model = artifact["model"]
    feature_names = artifact["feature_names"]

    print(f"Model path       : {MODEL_PATH}")
    print(f"Algorithm        : {artifact['algorithm']}")
    print(f"Training samples : {artifact['training_samples']}")
    print(f"Features         : {len(feature_names)}")
    print(f"Model type       : {type(model).__name__}")
    print()

    return artifact


def prepare_features(df, feature_names):
    missing_features = [
        column
        for column in feature_names
        if column not in df.columns
    ]

    if missing_features:
        raise ValueError(
            "Validation data is missing required feature columns: "
            f"{missing_features}"
        )

    X = df[feature_names].copy()

    for column in feature_names:
        X[column] = pd.to_numeric(X[column], errors="coerce")

    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    if X.shape[1] != 78:
        raise ValueError(
            f"Expected 78 features, got {X.shape[1]}"
        )

    return X


def calculate_anomaly_score(model, X):
    """
    IsolationForest.decision_function():

        higher  = more normal
        lower   = more anomalous

    We invert it so that:

        higher anomaly_score = more anomalous
        lower anomaly_score  = more normal
    """

    decision_scores = model.decision_function(X)

    anomaly_scores = -decision_scores

    return anomaly_scores


def evaluate_threshold(y_true, anomaly_scores, threshold):
    predictions = (anomaly_scores >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        predictions,
        labels=[0, 1],
    ).ravel()

    benign_count = tn + fp
    attack_count = tp + fn

    fpr = fp / benign_count if benign_count else 0.0
    recall = tp / attack_count if attack_count else 0.0

    precision = precision_score(
        y_true,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        predictions,
        zero_division=0,
    )

    return {
        "threshold": threshold,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "fpr": fpr,
        "recall": recall,
        "precision": precision,
        "f1": f1,
    }


def print_score_distribution(name, scores):
    print(f"\n{name} anomaly-score distribution")
    print("-" * 70)

    percentiles = [0, 1, 5, 25, 50, 75, 95, 99, 100]

    values = np.percentile(scores, percentiles)

    for percentile, value in zip(percentiles, values):
        print(
            f"{percentile:>3}th percentile : "
            f"{value:.6f}"
        )

    print(f"Mean             : {np.mean(scores):.6f}")
    print(f"Std              : {np.std(scores):.6f}")
    print(f"Min              : {np.min(scores):.6f}")
    print(f"Max              : {np.max(scores):.6f}")


def select_threshold(results):
    """
    Select a validation threshold.

    Goal:
        Keep benign false-positive rate <= 1%
        while maximizing Infiltration recall.

    If multiple thresholds satisfy the FPR constraint,
    choose the one with the highest recall.

    If recall ties, choose the threshold with the
    lowest FPR.

    This threshold is calibrated ONLY on validation data.
    """

    acceptable = [
        result
        for result in results
        if result["fpr"] <= 0.01
    ]

    if not acceptable:
        print(
            "\nWARNING: No candidate threshold achieved "
            "FPR <= 1%."
        )

        # Fall back to the threshold with the lowest FPR.
        selected = min(
            results,
            key=lambda result: (
                result["fpr"],
                -result["recall"],
            ),
        )

        return selected

    selected = max(
        acceptable,
        key=lambda result: (
            result["recall"],
            -result["fpr"],
        ),
    )

    return selected


def main():
    print("=" * 70)
    print("NOVELTY DETECTOR VALIDATION")
    print("=" * 70)

    if not VALIDATION_PATH.exists():
        raise FileNotFoundError(
            f"Validation file not found:\n{VALIDATION_PATH}"
        )

    artifact = load_artifact()

    model = artifact["model"]
    feature_names = artifact["feature_names"]

    print("=" * 70)
    print("SCANNING VALIDATION DATA")
    print("=" * 70)

    print(f"Validation file : {VALIDATION_PATH}")
    print(f"Chunk size      : {CHUNK_SIZE:,}")
    print()

    all_scores = []
    all_labels = []
    all_families = []

    total_rows = 0
    benign_rows = 0
    infiltration_rows = 0

    reader = pd.read_csv(
        VALIDATION_PATH,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    )

    for chunk_number, df in enumerate(reader, start=1):
        X = prepare_features(
            df,
            feature_names,
        )

        scores = calculate_anomaly_score(
            model,
            X,
        )

        # Validation labels:
        # Benign = 0
        # Infiltration = 1
        y = (
            df["AttackFamily"]
            .astype(str)
            .eq("Infiltration")
            .astype(int)
            .to_numpy()
        )

        all_scores.append(scores)
        all_labels.append(y)

        if "AttackFamily" in df.columns:
            all_families.append(
                df["AttackFamily"]
                .astype(str)
                .value_counts()
            )

        chunk_rows = len(df)
        total_rows += chunk_rows

        chunk_benign = int((y == 0).sum())
        chunk_infiltration = int((y == 1).sum())

        benign_rows += chunk_benign
        infiltration_rows += chunk_infiltration

        print(
            f"Chunk {chunk_number:>2}: "
            f"rows={chunk_rows:,} | "
            f"benign={chunk_benign:,} | "
            f"infiltration={chunk_infiltration:,}"
        )

    anomaly_scores = np.concatenate(all_scores)
    y_true = np.concatenate(all_labels)

    print()
    print("=" * 70)
    print("VALIDATION DATA SUMMARY")
    print("=" * 70)

    print(f"Total rows       : {total_rows:,}")
    print(f"Benign rows      : {benign_rows:,}")
    print(f"Infiltration     : {infiltration_rows:,}")
    print(f"Score count      : {len(anomaly_scores):,}")
    print()

    if total_rows != 613_071:
        print(
            f"WARNING: Expected 613,071 validation rows, "
            f"found {total_rows:,}."
        )

    if benign_rows == 0:
        raise ValueError("No benign validation rows found.")

    if infiltration_rows == 0:
        raise ValueError(
            "No Infiltration validation rows found."
        )

    print_score_distribution(
        "BENIGN",
        anomaly_scores[y_true == 0],
    )

    print_score_distribution(
        "INFILTRATION",
        anomaly_scores[y_true == 1],
    )

    print()
    print("=" * 70)
    print("THRESHOLD CALIBRATION")
    print("=" * 70)

    print(
        "\nPositive prediction means: "
        "NOVEL / ANOMALOUS"
    )

    print(
        "\nTarget calibration constraint:"
        "\n  Benign FPR <= 1%"
        "\n  Maximize Infiltration recall"
    )

    results = []

    for threshold in THRESHOLDS:
        result = evaluate_threshold(
            y_true,
            anomaly_scores,
            threshold,
        )

        results.append(result)

    print()

    print(
        f"{'Threshold':>10} "
        f"{'FPR':>10} "
        f"{'Recall':>10} "
        f"{'Precision':>10} "
        f"{'F1':>10} "
        f"{'FP':>10} "
        f"{'TP':>10}"
    )

    print("-" * 80)

    for result in results:
        print(
            f"{result['threshold']:>10.3f} "
            f"{result['fpr']:>10.4f} "
            f"{result['recall']:>10.4f} "
            f"{result['precision']:>10.4f} "
            f"{result['f1']:>10.4f} "
            f"{result['fp']:>10,} "
            f"{result['tp']:>10,}"
        )

    selected = select_threshold(results)

    print()
    print("=" * 70)
    print("SELECTED VALIDATION THRESHOLD")
    print("=" * 70)

    print(f"Threshold : {selected['threshold']:.6f}")
    print(f"FPR       : {selected['fpr']:.6f}")
    print(f"Recall    : {selected['recall']:.6f}")
    print(f"Precision : {selected['precision']:.6f}")
    print(f"F1        : {selected['f1']:.6f}")
    print(f"TN        : {selected['tn']:,}")
    print(f"FP        : {selected['fp']:,}")
    print(f"FN        : {selected['fn']:,}")
    print(f"TP        : {selected['tp']:,}")

    print()
    print("=" * 70)
    print("IMPORTANT")
    print("=" * 70)

    print(
        "This threshold was calibrated using VALIDATION data only."
    )

    print(
        "The TEST dataset has NOT been used for threshold selection."
    )

    print(
        "Do not change the threshold based on test performance."
    )

    print()
    print("=" * 70)
    print("NOVELTY VALIDATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
