from pathlib import Path

import pandas as pd


# =========================================================
# Paths
# =========================================================

PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")
SPLIT_DIR = PROCESSED_DIR / "splits"


# =========================================================
# Configuration
# =========================================================

CHUNK_SIZE = 200_000

TRAIN_FILES = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter_clean.csv",
]

VALIDATION_FILES = [
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv",
]

TEST_FILES = [
    "Friday-02-03-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter_clean.csv",
]


# =========================================================
# Columns
# =========================================================

TARGET_COLUMN = "Label"
TIMESTAMP_COLUMN = "Timestamp"


# =========================================================
# Prepare one file
# =========================================================

def prepare_file(file: Path) -> pd.DataFrame:

    print(f"Reading: {file.name}")

    df = pd.read_csv(
        file,
        low_memory=False,
    )

    # -----------------------------------------------------
    # Parse timestamp
    # -----------------------------------------------------

    df[TIMESTAMP_COLUMN] = pd.to_datetime(
        df[TIMESTAMP_COLUMN],
        dayfirst=True,
        errors="coerce",
    )

    # -----------------------------------------------------
    # Check invalid timestamps
    # -----------------------------------------------------

    invalid_timestamps = (
        df[TIMESTAMP_COLUMN].isna().sum()
    )

    if invalid_timestamps > 0:

        print(
            f"  WARNING: removing "
            f"{invalid_timestamps:,} invalid timestamps"
        )

        df = df.dropna(
            subset=[TIMESTAMP_COLUMN]
        )

    # -----------------------------------------------------
    # Binary label
    #
    # 0 = Benign
    # 1 = Attack
    # -----------------------------------------------------

    df["BinaryLabel"] = (
        df[TARGET_COLUMN] != "Benign"
    ).astype("int8")

    # -----------------------------------------------------
    # Keep source information
    # -----------------------------------------------------

    df["SourceFile"] = file.name

    return df


# =========================================================
# Load selected files
# =========================================================

def load_files(
    filenames: list[str],
) -> pd.DataFrame:

    datasets = []

    for filename in filenames:

        file = PROCESSED_DIR / filename

        if not file.exists():

            raise FileNotFoundError(
                f"Required file not found:\n{file}"
            )

        df = prepare_file(file)

        datasets.append(df)

    if not datasets:

        raise ValueError(
            "No files were loaded."
        )

    return pd.concat(
        datasets,
        ignore_index=True,
    )


# =========================================================
# Print label distribution
# =========================================================

def print_distribution(
    name: str,
    df: pd.DataFrame,
) -> None:

    print()
    print("=" * 70)
    print(name)
    print("=" * 70)

    print(
        f"Total rows: {len(df):,}"
    )

    print()
    print("Multiclass distribution:")

    counts = (
        df[TARGET_COLUMN]
        .value_counts()
    )

    for label, count in counts.items():

        percentage = (
            count / len(df) * 100
        )

        print(
            f"  {label:<30} "
            f"{count:>12,} "
            f"({percentage:>8.4f}%)"
        )

    # -----------------------------------------------------
    # Binary distribution
    # -----------------------------------------------------

    print()
    print("Binary distribution:")

    binary_counts = (
        df["BinaryLabel"]
        .value_counts()
        .sort_index()
    )

    for binary_label, count in binary_counts.items():

        name_label = (
            "Benign"
            if binary_label == 0
            else "Attack"
        )

        percentage = (
            count / len(df) * 100
        )

        print(
            f"  {name_label:<10} "
            f"{count:>12,} "
            f"({percentage:>8.4f}%)"
        )


# =========================================================
# Save dataframe
# =========================================================

def save_dataset(
    df: pd.DataFrame,
    filename: str,
) -> None:

    output_file = SPLIT_DIR / filename

    print(
        f"Saving: {output_file}"
    )

    df.to_csv(
        output_file,
        index=False,
    )

    print(
        f"Saved {len(df):,} rows"
    )


# =========================================================
# Verify split
# =========================================================

def verify_split(
    train_df: pd.DataFrame,
    validation_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> None:

    print()
    print("=" * 70)
    print("SPLIT VERIFICATION")
    print("=" * 70)

    # -----------------------------------------------------
    # Check row counts
    # -----------------------------------------------------

    total = (
        len(train_df)
        + len(validation_df)
        + len(test_df)
    )

    print()
    print(f"Training rows:   {len(train_df):,}")
    print(f"Validation rows: {len(validation_df):,}")
    print(f"Test rows:       {len(test_df):,}")
    print(f"Total rows:      {total:,}")

    # -----------------------------------------------------
    # Check source-file overlap
    # -----------------------------------------------------

    train_sources = set(
        train_df["SourceFile"].unique()
    )

    validation_sources = set(
        validation_df["SourceFile"].unique()
    )

    test_sources = set(
        test_df["SourceFile"].unique()
    )

    print()
    print("Source files:")

    print(
        f"  Train:      {sorted(train_sources)}"
    )

    print(
        f"  Validation: {sorted(validation_sources)}"
    )

    print(
        f"  Test:       {sorted(test_sources)}"
    )

    # -----------------------------------------------------
    # Verify no file overlap
    # -----------------------------------------------------

    assert train_sources.isdisjoint(
        validation_sources
    )

    assert train_sources.isdisjoint(
        test_sources
    )

    assert validation_sources.isdisjoint(
        test_sources
    )

    print()
    print(
        "✓ No source-file overlap detected."
    )

    # -----------------------------------------------------
    # Check timestamps
    # -----------------------------------------------------

    train_max = train_df[TIMESTAMP_COLUMN].max()
    validation_min = validation_df[TIMESTAMP_COLUMN].min()
    validation_max = validation_df[TIMESTAMP_COLUMN].max()
    test_min = test_df[TIMESTAMP_COLUMN].min()

    print()
    print("Timestamp boundaries:")

    print(
        f"  Train latest:       {train_max}"
    )

    print(
        f"  Validation earliest: {validation_min}"
    )

    print(
        f"  Validation latest:   {validation_max}"
    )

    print(
        f"  Test earliest:       {test_min}"
    )


# =========================================================
# Main
# =========================================================

def main() -> None:

    print()
    print("=" * 70)
    print("CSE-CIC-IDS2018 FILE-AWARE DATASET SPLITTING")
    print("=" * 70)

    # -----------------------------------------------------
    # Check directories
    # -----------------------------------------------------

    if not PROCESSED_DIR.exists():

        raise FileNotFoundError(
            f"Processed directory not found:\n"
            f"{PROCESSED_DIR}"
        )

    SPLIT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # -----------------------------------------------------
    # Show split design
    # -----------------------------------------------------

    print()
    print("Split design:")
    print()
    print("TRAINING FILES:")

    for filename in TRAIN_FILES:
        print(f"  - {filename}")

    print()
    print("VALIDATION FILES:")

    for filename in VALIDATION_FILES:
        print(f"  - {filename}")

    print()
    print("TEST FILES:")

    for filename in TEST_FILES:
        print(f"  - {filename}")

    # -----------------------------------------------------
    # Load datasets
    # -----------------------------------------------------

    print()
    print("=" * 70)
    print("LOADING TRAINING DATA")
    print("=" * 70)

    train_df = load_files(
        TRAIN_FILES
    )

    print()
    print("=" * 70)
    print("LOADING VALIDATION DATA")
    print("=" * 70)

    validation_df = load_files(
        VALIDATION_FILES
    )

    print()
    print("=" * 70)
    print("LOADING TEST DATA")
    print("=" * 70)

    test_df = load_files(
        TEST_FILES
    )

    # -----------------------------------------------------
    # Sort each split chronologically
    # -----------------------------------------------------

    train_df = train_df.sort_values(
        TIMESTAMP_COLUMN
    ).reset_index(drop=True)

    validation_df = validation_df.sort_values(
        TIMESTAMP_COLUMN
    ).reset_index(drop=True)

    test_df = test_df.sort_values(
        TIMESTAMP_COLUMN
    ).reset_index(drop=True)

    # -----------------------------------------------------
    # Print distributions
    # -----------------------------------------------------

    print_distribution(
        "TRAINING SET",
        train_df,
    )

    print_distribution(
        "VALIDATION SET",
        validation_df,
    )

    print_distribution(
        "TEST SET",
        test_df,
    )

    # -----------------------------------------------------
    # Verify
    # -----------------------------------------------------

    verify_split(
        train_df,
        validation_df,
        test_df,
    )

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    print()
    print("=" * 70)
    print("SAVING SPLITS")
    print("=" * 70)

    save_dataset(
        train_df,
        "train.csv",
    )

    save_dataset(
        validation_df,
        "validation.csv",
    )

    save_dataset(
        test_df,
        "test.csv",
    )

    # -----------------------------------------------------
    # Complete
    # -----------------------------------------------------

    print()
    print("=" * 70)
    print("DATASET SPLIT COMPLETE")
    print("=" * 70)


# =========================================================
# Entry point
# =========================================================

if __name__ == "__main__":
    main()