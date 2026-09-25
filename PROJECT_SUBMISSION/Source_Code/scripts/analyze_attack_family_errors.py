from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

VALIDATION_PATH = Path(
    "data/processed/cse_cic_ids2018/"
    "splits/known_family/validation.csv"
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

    package = joblib.load(
        MODEL_PATH
    )

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

    return (
        model,
        label_encoder,
        feature_columns,
    )


# ============================================================
# LOAD VALIDATION DATA
# ============================================================

def load_validation_data():

    print()
    print("=" * 80)
    print("LOADING VALIDATION DATA")
    print("=" * 80)

    if not VALIDATION_PATH.exists():
        raise FileNotFoundError(
            f"Validation file not found:\n"
            f"{VALIDATION_PATH}"
        )

    chunks = []

    for chunk in pd.read_csv(
        VALIDATION_PATH,
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
        f"Validation rows: "
        f"{len(df):,}"
    )

    return df


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(
    df,
    feature_columns,
):

    # Use exactly the same features and ordering
    # used during model training.

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

    X = df[
        feature_columns
    ].copy()

    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce",
        )

    X = X.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    X = X.fillna(0)

    return X


# ============================================================
# GENERATE PREDICTIONS
# ============================================================

def generate_predictions(
    df,
    model,
    label_encoder,
    feature_columns,
):

    print()
    print("=" * 80)
    print("GENERATING VALIDATION PREDICTIONS")
    print("=" * 80)

    X = prepare_features(
        df,
        feature_columns,
    )

    # --------------------------------------------------------
    # Ground truth
    # --------------------------------------------------------

    actual_family = (
        df["AttackFamily"]
        .astype(str)
    )

    actual_raw_label = (
        df["Label"]
        .astype(str)
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    predicted_ids = model.predict(X)

    predicted_family = (
        label_encoder
        .inverse_transform(
            predicted_ids.astype(int)
        )
    )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    probabilities = (
        model.predict_proba(X)
    )

    confidence = (
        np.max(
            probabilities,
            axis=1,
        )
    )

    # --------------------------------------------------------
    # Store results
    # --------------------------------------------------------

    results = pd.DataFrame(
        {
            "ActualFamily": actual_family,
            "PredictedFamily": predicted_family,
            "ActualRawLabel": actual_raw_label,
            "Confidence": confidence,
        }
    )

    return results


# ============================================================
# OVERALL ERROR SUMMARY
# ============================================================

def print_overall_errors(results):

    print()
    print("=" * 80)
    print("OVERALL ERROR SUMMARY")
    print("=" * 80)

    total = len(results)

    correct = (
        results["ActualFamily"]
        == results["PredictedFamily"]
    ).sum()

    incorrect = total - correct

    print()
    print(
        f"Total predictions : {total:,}"
    )

    print(
        f"Correct           : {correct:,}"
    )

    print(
        f"Incorrect         : {incorrect:,}"
    )

    print(
        f"Error rate        : "
        f"{incorrect / total * 100:.4f}%"
    )


# ============================================================
# FAMILY-LEVEL ERROR ANALYSIS
# ============================================================

def print_family_errors(results):

    print()
    print("=" * 80)
    print("FAMILY-LEVEL ERROR ANALYSIS")
    print("=" * 80)

    errors = results[
        results["ActualFamily"]
        != results["PredictedFamily"]
    ]

    if errors.empty:

        print()
        print("No classification errors found.")

        return

    # --------------------------------------------------------
    # Group by actual family
    # --------------------------------------------------------

    print()
    print("Errors by actual family:")

    actual_counts = (
        errors["ActualFamily"]
        .value_counts()
    )

    for family, count in actual_counts.items():

        print(
            f"{family:<20}"
            f"{count:>12,}"
        )

    # --------------------------------------------------------
    # Detailed actual -> predicted pairs
    # --------------------------------------------------------

    print()
    print(
        "Most common misclassification pairs:"
    )

    pair_counts = (
        errors
        .groupby(
            [
                "ActualFamily",
                "PredictedFamily",
            ]
        )
        .size()
        .sort_values(
            ascending=False
        )
    )

    for (
        (actual, predicted),
        count,
    ) in pair_counts.items():

        print(
            f"{actual:<20}"
            f" -> "
            f"{predicted:<20}"
            f"{count:>10,}"
        )


# ============================================================
# RAW LABEL ERROR ANALYSIS
# ============================================================

def print_raw_label_errors(results):

    print()
    print("=" * 80)
    print("RAW ATTACK LABEL ERROR ANALYSIS")
    print("=" * 80)

    errors = results[
        results["ActualFamily"]
        != results["PredictedFamily"]
    ]

    if errors.empty:

        print()
        print("No errors found.")

        return

    # --------------------------------------------------------
    # Raw attack label → predicted family
    # --------------------------------------------------------

    raw_errors = (
        errors
        .groupby(
            [
                "ActualRawLabel",
                "ActualFamily",
                "PredictedFamily",
            ]
        )
        .size()
        .sort_values(
            ascending=False
        )
    )

    print()

    for (
        (
            raw_label,
            actual_family,
            predicted_family,
        ),
        count,
    ) in raw_errors.items():

        print(
            f"{raw_label:<30}"
            f"({actual_family:<15})"
            f" -> "
            f"{predicted_family:<15}"
            f"{count:>8,}"
        )


# ============================================================
# CONFIDENCE ANALYSIS OF ERRORS
# ============================================================

def print_error_confidence(results):

    print()
    print("=" * 80)
    print("CONFIDENCE ANALYSIS OF INCORRECT PREDICTIONS")
    print("=" * 80)

    errors = results[
        results["ActualFamily"]
        != results["PredictedFamily"]
    ].copy()

    if errors.empty:

        print()
        print("No errors found.")

        return

    print()

    print(
        f"Mean confidence   : "
        f"{errors['Confidence'].mean():.6f}"
    )

    print(
        f"Median confidence : "
        f"{errors['Confidence'].median():.6f}"
    )

    print(
        f"Minimum confidence: "
        f"{errors['Confidence'].min():.6f}"
    )

    print(
        f"Maximum confidence: "
        f"{errors['Confidence'].max():.6f}"
    )

    # --------------------------------------------------------
    # Confidence buckets
    # --------------------------------------------------------

    bins = [
        0.0,
        0.60,
        0.70,
        0.80,
        0.90,
        0.95,
        0.99,
        1.01,
    ]

    labels = [
        "< 0.60",
        "0.60-0.70",
        "0.70-0.80",
        "0.80-0.90",
        "0.90-0.95",
        "0.95-0.99",
        ">= 0.99",
    ]

    buckets = pd.cut(
        errors["Confidence"],
        bins=bins,
        labels=labels,
        right=False,
    )

    print()
    print(
        "Incorrect predictions by confidence:"
    )

    counts = (
        buckets
        .value_counts()
        .sort_index()
    )

    for bucket, count in counts.items():

        print(
            f"{str(bucket):<12}"
            f"{count:>12,}"
        )


# ============================================================
# HIGH-CONFIDENCE ERRORS
# ============================================================

def print_high_confidence_errors(
    results,
    threshold=0.90,
):

    print()
    print("=" * 80)
    print(
        f"HIGH-CONFIDENCE ERRORS "
        f"(confidence >= {threshold:.2f})"
    )
    print("=" * 80)

    errors = results[
        (
            results["ActualFamily"]
            != results["PredictedFamily"]
        )
        &
        (
            results["Confidence"]
            >= threshold
        )
    ].copy()

    if errors.empty:

        print()
        print(
            "No high-confidence errors found."
        )

        return

    pair_counts = (
        errors
        .groupby(
            [
                "ActualFamily",
                "PredictedFamily",
            ]
        )
        .size()
        .sort_values(
            ascending=False
        )
    )

    print()

    for (
        (actual, predicted),
        count,
    ) in pair_counts.items():

        print(
            f"{actual:<20}"
            f" -> "
            f"{predicted:<20}"
            f"{count:>10,}"
        )

    print()

    print(
        f"Total high-confidence errors: "
        f"{len(errors):,}"
    )


# ============================================================
# ERROR RATE BY RAW LABEL
# ============================================================

def print_raw_label_error_rates(
    results,
):

    print()
    print("=" * 80)
    print("ERROR RATE BY RAW ATTACK LABEL")
    print("=" * 80)

    results = results.copy()

    results["Correct"] = (
        results["ActualFamily"]
        == results["PredictedFamily"]
    )

    summary = (
        results
        .groupby("ActualRawLabel")
        .agg(
            total=("Correct", "size"),
            correct=("Correct", "sum"),
        )
    )

    summary["errors"] = (
        summary["total"]
        - summary["correct"]
    )

    summary["error_rate"] = (
        summary["errors"]
        / summary["total"]
        * 100
    )

    summary = summary.sort_values(
        "error_rate",
        ascending=False,
    )

    print()

    for raw_label, row in summary.iterrows():

        print(
            f"{raw_label:<30}"
            f"Total={int(row['total']):>8,} "
            f"Errors={int(row['errors']):>8,} "
            f"ErrorRate={row['error_rate']:>8.4f}%"
        )


# ============================================================
# SAVE ERROR RESULTS
# ============================================================

def save_errors(results):

    output_dir = Path(
        "data/processed/cse_cic_ids2018/"
        "splits/known_family"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    error_path = (
        output_dir
        / "validation_errors.csv"
    )

    errors = results[
        results["ActualFamily"]
        != results["PredictedFamily"]
    ].copy()

    errors.to_csv(
        error_path,
        index=False,
    )

    print()
    print(
        f"Saved {len(errors):,} errors -> "
        f"{error_path}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 80)
    print("ATTACK FAMILY ERROR ANALYSIS")
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
    # Load validation data
    # --------------------------------------------------------

    df = load_validation_data()

    # --------------------------------------------------------
    # Generate predictions
    # --------------------------------------------------------

    results = generate_predictions(
        df,
        model,
        label_encoder,
        feature_columns,
    )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    print_overall_errors(
        results
    )

    print_family_errors(
        results
    )

    print_raw_label_errors(
        results
    )

    print_error_confidence(
        results
    )

    print_high_confidence_errors(
        results,
        threshold=0.90,
    )

    print_raw_label_error_rates(
        results
    )

    # --------------------------------------------------------
    # Save errors
    # --------------------------------------------------------

    save_errors(
        results
    )

    # --------------------------------------------------------
    # Complete
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("ATTACK FAMILY ERROR ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()