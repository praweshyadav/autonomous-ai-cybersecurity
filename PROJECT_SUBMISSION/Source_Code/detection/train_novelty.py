from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

PROCESSED_DIR = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
)

MODEL_DIR = BASE_DIR / "detection" / "models"

MODEL_PATH = (
    MODEL_DIR
    / "isolation_forest_benign.joblib"
)


# ============================================================
# CONFIGURATION
# ============================================================

RANDOM_STATE = 42

TOTAL_SAMPLES = 100_000

CHUNK_SIZE = 200_000

N_ESTIMATORS = 200

N_JOBS = -1

CONTAMINATION = "auto"


# ============================================================
# TRAINING SOURCE FILES
# ============================================================

TRAIN_FILES = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter_clean.csv",
]


# ============================================================
# NON-FEATURE COLUMNS
# ============================================================

NON_FEATURE_COLUMNS = {
    "Timestamp",
    "Label",
    "BinaryLabel",
    "AttackFamily",
    "SourceFile",
}


# ============================================================
# SAMPLE ALLOCATION
# ============================================================

BASE_SAMPLES_PER_FILE = (
    TOTAL_SAMPLES // len(TRAIN_FILES)
)

EXTRA_SAMPLES = (
    TOTAL_SAMPLES % len(TRAIN_FILES)
)

SAMPLES_PER_FILE = [
    BASE_SAMPLES_PER_FILE
    + (1 if index < EXTRA_SAMPLES else 0)
    for index in range(len(TRAIN_FILES))
]


# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

def validate_configuration():

    print("=" * 70)
    print("NOVELTY DETECTOR CONFIGURATION")
    print("=" * 70)

    print(
        f"Total target samples : "
        f"{TOTAL_SAMPLES:,}"
    )

    print(
        f"Training files       : "
        f"{len(TRAIN_FILES)}"
    )

    print(
        f"Base samples/file    : "
        f"{BASE_SAMPLES_PER_FILE:,}"
    )

    print(
        f"Extra samples        : "
        f"{EXTRA_SAMPLES}"
    )

    print(
        f"Isolation trees      : "
        f"{N_ESTIMATORS}"
    )

    print(
        f"Random state         : "
        f"{RANDOM_STATE}"
    )

    print(
        f"n_jobs               : "
        f"{N_JOBS}"
    )

    print()
    print("Sample allocation:")

    for filename, sample_count in zip(
        TRAIN_FILES,
        SAMPLES_PER_FILE,
    ):

        print(
            f"  {filename}: "
            f"{sample_count:,}"
        )

    if sum(SAMPLES_PER_FILE) != TOTAL_SAMPLES:

        raise ValueError(
            "Sample allocation does not equal "
            "TOTAL_SAMPLES."
        )

    for filename in TRAIN_FILES:

        path = PROCESSED_DIR / filename

        if not path.exists():

            raise FileNotFoundError(
                f"Training file not found:\n{path}"
            )


# ============================================================
# RESERVOIR SAMPLE
# ============================================================

def sample_benign_from_file(
    file_path: Path,
    sample_size: int,
    seed: int,
):
    """
    Uniformly sample benign rows from a source CSV.

    The source file is processed in chunks.
    Only the current chunk and the reservoir
    are kept in memory.

    Every benign row has an equal probability
    of being included in the final reservoir.
    """

    print()
    print("-" * 70)

    print(
        f"Sampling: "
        f"{file_path.name}"
    )

    print("-" * 70)

    rng = np.random.default_rng(seed)

    reservoir = []

    benign_seen = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            file_path,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ),
        start=1,
    ):

        # ----------------------------------------------------
        # Remove accidental header rows
        # ----------------------------------------------------

        chunk = chunk[
            chunk["Label"]
            .astype(str)
            .str.strip()
            != "Label"
        ].copy()

        if chunk.empty:
            continue

        # ----------------------------------------------------
        # Keep benign traffic only
        # ----------------------------------------------------

        benign = chunk[
            chunk["Label"]
            .astype(str)
            .str.strip()
            == "Benign"
        ].copy()

        if benign.empty:
            continue

        # ----------------------------------------------------
        # Reservoir sampling
        # ----------------------------------------------------

        for row in benign.itertuples(
            index=False,
            name=None,
        ):

            benign_seen += 1

            if len(reservoir) < sample_size:

                reservoir.append(row)

            else:

                replacement_index = rng.integers(
                    0,
                    benign_seen,
                )

                if replacement_index < sample_size:

                    reservoir[
                        replacement_index
                    ] = row

        print(
            f"Chunk {chunk_number}: "
            f"benign={len(benign):,}, "
            f"seen={benign_seen:,}, "
            f"reservoir={len(reservoir):,}"
        )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    if benign_seen < sample_size:

        raise ValueError(
            f"File contains only "
            f"{benign_seen:,} benign rows, "
            f"but {sample_size:,} samples "
            f"were requested:\n"
            f"{file_path}"
        )

    if len(reservoir) != sample_size:

        raise ValueError(
            f"Expected reservoir size "
            f"{sample_size:,}, "
            f"got {len(reservoir):,}."
        )

    # --------------------------------------------------------
    # Reconstruct DataFrame
    # --------------------------------------------------------

    sampled = pd.DataFrame(
        reservoir,
        columns=chunk.columns,
    )

    # --------------------------------------------------------
    # Add provenance
    # --------------------------------------------------------

    sampled["SourceFile"] = file_path.name

    # --------------------------------------------------------
    # Shuffle
    # --------------------------------------------------------

    sampled = sampled.sample(
        frac=1.0,
        random_state=seed,
    ).reset_index(drop=True)

    print()
    print(
        f"Total benign rows seen : "
        f"{benign_seen:,}"
    )

    print(
        f"Rows sampled           : "
        f"{len(sampled):,}"
    )

    print(
        f"Source                 : "
        f"{sampled['SourceFile'].iloc[0]}"
    )

    return sampled


# ============================================================
# BUILD REFERENCE DATASET
# ============================================================

def build_reference_dataset():

    print()
    print("=" * 70)
    print("BUILDING BENIGN NOVELTY REFERENCE DATASET")
    print("=" * 70)

    sampled_chunks = []

    for index, filename in enumerate(
        TRAIN_FILES
    ):

        file_path = (
            PROCESSED_DIR / filename
        )

        sample_size = (
            SAMPLES_PER_FILE[index]
        )

        sampled = sample_benign_from_file(
            file_path=file_path,
            sample_size=sample_size,
            seed=RANDOM_STATE + index,
        )

        sampled_chunks.append(
            sampled
        )

    reference = pd.concat(
        sampled_chunks,
        ignore_index=True,
    )

    # --------------------------------------------------------
    # Final shuffle
    # --------------------------------------------------------

    reference = reference.sample(
        frac=1.0,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    # --------------------------------------------------------
    # Validate total size
    # --------------------------------------------------------

    if len(reference) != TOTAL_SAMPLES:

        raise ValueError(
            f"Expected "
            f"{TOTAL_SAMPLES:,} reference rows, "
            f"got {len(reference):,}."
        )

    print()
    print("=" * 70)
    print("REFERENCE DATASET READY")
    print("=" * 70)

    print(
        f"Rows    : "
        f"{len(reference):,}"
    )

    print(
        f"Columns : "
        f"{len(reference.columns)}"
    )

    print()
    print("Source distribution:")

    print(
        reference["SourceFile"]
        .value_counts()
    )

    print()
    print("Label distribution:")

    print(
        reference["Label"]
        .value_counts()
    )

    return reference


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(reference):

    print()
    print("=" * 70)
    print("PREPARING NOVELTY FEATURES")
    print("=" * 70)

    feature_names = [
        column
        for column in reference.columns
        if column not in NON_FEATURE_COLUMNS
    ]

    print(
        f"Feature count: "
        f"{len(feature_names)}"
    )

    if len(feature_names) != 78:

        raise ValueError(
            f"Expected 78 CICFlowMeter "
            f"features, found "
            f"{len(feature_names)}."
        )

    X = reference[
        feature_names
    ].copy()

    # --------------------------------------------------------
    # Numeric conversion
    # --------------------------------------------------------

    X = X.apply(
        pd.to_numeric,
        errors="coerce",
    )

    # --------------------------------------------------------
    # Replace infinities
    # --------------------------------------------------------

    X = X.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    # --------------------------------------------------------
    # Match existing preprocessing
    # --------------------------------------------------------

    X = X.fillna(0)

    print(
        f"Feature matrix shape: "
        f"{X.shape}"
    )

    print(
        f"NaN values after preprocessing: "
        f"{int(X.isna().sum().sum())}"
    )

    print(
        f"Inf values after preprocessing: "
        f"{int(np.isinf(X.to_numpy()).sum())}"
    )

    return X, feature_names


# ============================================================
# TRAIN ISOLATION FOREST
# ============================================================

def train_model(X):

    print()
    print("=" * 70)
    print("TRAINING ISOLATION FOREST")
    print("=" * 70)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=N_JOBS,
    )

    print()
    print("Starting training...")

    model.fit(X)

    print()
    print("Training completed.")

    return model


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(
    model,
    feature_names,
):

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    artifact = {
        "model": model,
        "feature_names": list(feature_names),
        "training_samples": TOTAL_SAMPLES,
        "samples_per_file": list(
            SAMPLES_PER_FILE
        ),
        "source_files": list(
            TRAIN_FILES
        ),
        "random_state": RANDOM_STATE,
        "algorithm": "IsolationForest",
    }

    joblib.dump(
        artifact,
        MODEL_PATH,
    )

    print()
    print("=" * 70)
    print("NOVELTY MODEL SAVED")
    print("=" * 70)

    print(
        f"Model path: "
        f"{MODEL_PATH}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    validate_configuration()

    reference = (
        build_reference_dataset()
    )

    X, feature_names = (
        prepare_features(reference)
    )

    model = train_model(X)

    save_model(
        model=model,
        feature_names=feature_names,
    )

    print()
    print("=" * 70)
    print("NOVELTY DETECTOR TRAINING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
