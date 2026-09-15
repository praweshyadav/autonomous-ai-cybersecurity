from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder


# ============================================================
# CONFIGURATION
# ============================================================

TRAIN_PATH = Path(
    "data/processed/cse_cic_ids2018/"
    "splits/known_family/train.csv"
)

MODEL_DIR = Path("detection/models")

MODEL_PATH = (
    MODEL_DIR / "xgboost_attack_family_classifier.joblib"
)

CHUNK_SIZE = 200_000

RANDOM_STATE = 42


# ============================================================
# COLUMNS NOT USED AS FEATURES
# ============================================================

NON_FEATURE_COLUMNS = {
    "Label",
    "AttackFamily",
    "BinaryLabel",
    "SourceFile",
    "Timestamp",
}


# ============================================================
# LOAD TRAINING DATA
# ============================================================

def load_training_data():

    print("=" * 80)
    print("LOADING ATTACK FAMILY TRAINING DATA")
    print("=" * 80)

    if not TRAIN_PATH.exists():
        raise FileNotFoundError(
            f"Training file not found:\n{TRAIN_PATH}"
        )

    chunks = []

    for chunk in pd.read_csv(
        TRAIN_PATH,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):

        chunks.append(chunk)

    df = pd.concat(
        chunks,
        ignore_index=True,
    )

    print(
        f"Training rows: {len(df):,}"
    )

    return df


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(df):

    print()
    print("=" * 80)
    print("PREPARING FEATURES")
    print("=" * 80)

    # --------------------------------------------------------
    # Separate target
    # --------------------------------------------------------

    y = df["AttackFamily"].copy()

    # --------------------------------------------------------
    # Remove non-feature columns
    # --------------------------------------------------------

    feature_columns = [
        column
        for column in df.columns
        if column not in NON_FEATURE_COLUMNS
    ]

    X = df[feature_columns].copy()

    # --------------------------------------------------------
    # Convert all features to numeric
    # --------------------------------------------------------

    for column in X.columns:

        X[column] = pd.to_numeric(
            X[column],
            errors="coerce",
        )

    # --------------------------------------------------------
    # Replace infinite values
    # --------------------------------------------------------

    X = X.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    # --------------------------------------------------------
    # Fill remaining missing values
    # --------------------------------------------------------

    X = X.fillna(0)

    print(
        f"Number of features: {X.shape[1]}"
    )

    print()
    print("Features:")

    for i, column in enumerate(
        X.columns,
        start=1,
    ):
        print(
            f"{i:>3}. {column}"
        )

    return X, y, feature_columns


# ============================================================
# ENCODE ATTACK FAMILIES
# ============================================================

def encode_target(y):

    print()
    print("=" * 80)
    print("ENCODING ATTACK FAMILIES")
    print("=" * 80)

    label_encoder = LabelEncoder()

    y_encoded = label_encoder.fit_transform(y)

    print()

    print("Class mapping:")

    for index, class_name in enumerate(
        label_encoder.classes_
    ):

        print(
            f"{index} -> {class_name}"
        )

    print()

    print("Class distribution:")

    counts = pd.Series(y).value_counts()

    for class_name, count in counts.items():

        percentage = (
            count / len(y)
        ) * 100

        print(
            f"{class_name:<20}"
            f"{count:>12,} "
            f"{percentage:>8.4f}%"
        )

    return (
        y_encoded,
        label_encoder,
    )


# ============================================================
# CALCULATE CLASS WEIGHTS
# ============================================================

def calculate_sample_weights(y_encoded):

    print()
    print("=" * 80)
    print("CALCULATING CLASS WEIGHTS")
    print("=" * 80)

    class_counts = np.bincount(
        y_encoded
    )

    n_classes = len(
        class_counts
    )

    total = len(
        y_encoded
    )

    # Balanced weighting:
    #
    # weight_i =
    #     total_samples /
    #     (number_of_classes * class_samples_i)
    #

    class_weights = (
        total
        / (
            n_classes
            * class_counts
        )
    )

    print()

    for class_id, count in enumerate(
        class_counts
    ):

        print(
            f"Class {class_id}: "
            f"{count:,} samples, "
            f"weight={class_weights[class_id]:.4f}"
        )

    sample_weights = (
        class_weights[y_encoded]
    )

    return sample_weights


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(
    X,
    y_encoded,
    sample_weights,
):

    print()
    print("=" * 80)
    print("TRAINING XGBOOST ATTACK FAMILY CLASSIFIER")
    print("=" * 80)

    model = XGBClassifier(
        objective="multi:softprob",

        num_class=len(
            np.unique(y_encoded)
        ),

        n_estimators=400,

        max_depth=8,

        learning_rate=0.1,

        subsample=0.8,

        colsample_bytree=0.8,

        eval_metric="mlogloss",

        tree_method="hist",

        random_state=RANDOM_STATE,

        n_jobs=-1,
    )

    print()
    print("Starting training...")

    model.fit(
        X,
        y_encoded,
        sample_weight=sample_weights,
    )

    print()
    print("Training complete.")

    return model


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(
    model,
    label_encoder,
    feature_columns,
):

    print()
    print("=" * 80)
    print("SAVING MODEL")
    print("=" * 80)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    model_package = {
        "model": model,
        "label_encoder": label_encoder,
        "feature_columns": feature_columns,
    }

    joblib.dump(
        model_package,
        MODEL_PATH,
    )

    print()
    print(
        f"Model saved to:\n{MODEL_PATH}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 80)
    print("ATTACK FAMILY CLASSIFIER TRAINING")
    print("=" * 80)

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    df = load_training_data()

    # --------------------------------------------------------
    # Prepare features
    # --------------------------------------------------------

    X, y, feature_columns = (
        prepare_features(df)
    )

    # --------------------------------------------------------
    # Encode target
    # --------------------------------------------------------

    (
        y_encoded,
        label_encoder,
    ) = encode_target(y)

    # --------------------------------------------------------
    # Class weights
    # --------------------------------------------------------

    sample_weights = (
        calculate_sample_weights(
            y_encoded
        )
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    model = train_model(
        X,
        y_encoded,
        sample_weights,
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    save_model(
        model,
        label_encoder,
        feature_columns,
    )

    print()
    print("=" * 80)
    print("ATTACK FAMILY CLASSIFIER COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()