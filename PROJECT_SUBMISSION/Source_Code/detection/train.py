from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import classification_report
from xgboost import XGBClassifier


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TRAIN_PATH = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "splits"
    / "train.csv"
)

MODEL_DIR = BASE_DIR / "detection" / "models"
MODEL_PATH = MODEL_DIR / "xgboost_binary_detector.joblib"


# ============================================================
# CONFIGURATION
# ============================================================

CHUNK_SIZE = 200_000

# Columns that should NOT be used as ML features.
#
# Timestamp is excluded because we don't want the model
# learning the date/time of the attack campaign.
NON_FEATURE_COLUMNS = {
    "Label",
    "BinaryLabel",
    "SourceFile",
    "Timestamp",
}


# ============================================================
# LOAD TRAINING DATA
# ============================================================

def load_training_data():
    print("=" * 70)
    print("Loading training dataset")
    print("=" * 70)

    print(f"Train file: {TRAIN_PATH}")

    if not TRAIN_PATH.exists():
        raise FileNotFoundError(
            f"Training file not found:\n{TRAIN_PATH}"
        )

    feature_chunks = []
    label_chunks = []

    total_rows = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(TRAIN_PATH, chunksize=CHUNK_SIZE),
        start=1
    ):
        print(f"Processing chunk {chunk_number}...")

        # Separate target
        y = chunk["BinaryLabel"].astype("int8")

        # Remove non-feature columns
        feature_columns = [
            column
            for column in chunk.columns
            if column not in NON_FEATURE_COLUMNS
        ]

        X = chunk[feature_columns].copy()

        # Ensure everything is numeric
        X = X.apply(pd.to_numeric, errors="coerce")

        # Replace infinite values
        X = X.replace([float("inf"), float("-inf")], pd.NA)

        # Fill remaining missing values
        X = X.fillna(0)

        feature_chunks.append(X)
        label_chunks.append(y)

        total_rows += len(chunk)

    X = pd.concat(feature_chunks, ignore_index=True)
    y = pd.concat(label_chunks, ignore_index=True)

    print()
    print(f"Total training rows: {total_rows}")
    print(f"Features: {X.shape[1]}")
    print()

    return X, y


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(X, y):

    print("=" * 70)
    print("Training XGBoost binary detector")
    print("=" * 70)

    benign_count = int((y == 0).sum())
    attack_count = int((y == 1).sum())

    print(f"Benign samples : {benign_count:,}")
    print(f"Attack samples : {attack_count:,}")

    if attack_count == 0:
        raise ValueError("No attack samples found.")

    if benign_count == 0:
        raise ValueError("No benign samples found.")

    # Handle class imbalance.
    #
    # scale_pos_weight tells XGBoost how much more important
    # positive/attack examples should be.
    scale_pos_weight = benign_count / attack_count

    print(
        f"scale_pos_weight: "
        f"{scale_pos_weight:.4f}"
    )

    model = XGBClassifier(
        objective="binary:logistic",

        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,

        subsample=0.8,
        colsample_bytree=0.8,

        scale_pos_weight=scale_pos_weight,

        eval_metric="logloss",

        tree_method="hist",

        random_state=42,

        n_jobs=-1,
    )

    print()
    print("Starting training...")

    model.fit(X, y)

    print()
    print("Training completed.")

    return model


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(model, feature_names):

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        {
            "model": model,
            "feature_names": list(feature_names),
        },
        MODEL_PATH
    )

    print()
    print("=" * 70)
    print("MODEL SAVED")
    print("=" * 70)
    print(MODEL_PATH)


# ============================================================
# MAIN
# ============================================================

def main():

    X_train, y_train = load_training_data()

    model = train_model(
        X_train,
        y_train
    )

    save_model(
        model,
        X_train.columns
    )

    print()
    print("Binary detector training finished successfully.")


if __name__ == "__main__":
    main()