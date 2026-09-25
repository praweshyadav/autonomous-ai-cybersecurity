from pathlib import Path
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")

OUTPUT_DIR = (
    PROCESSED_DIR
    / "splits"
    / "known_family"
)

CHUNK_SIZE = 200_000

TRAIN_RATIO = 0.70
VALIDATION_RATIO = 0.15
TEST_RATIO = 0.15


# ============================================================
# ATTACK FAMILY MAPPING
# ============================================================

ATTACK_FAMILY_MAP = {
    "Benign": "Benign",

    # Brute Force
    "FTP-BruteForce": "Brute Force",
    "SSH-Bruteforce": "Brute Force",

    # DoS
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-Slowloris": "DoS",

    # DDoS
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",

    # Web attacks
    "Brute Force -Web": "Web Attack",
    "Brute Force -XSS": "Web Attack",
    "SQL Injection": "Web Attack",

    # Other attack families
    "Bot": "Bot",
    "Infilteration": "Infiltration",
}


# ============================================================
# SOURCE FILES USED FOR KNOWN-FAMILY DATASET
# ============================================================

SOURCE_FILES = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter_clean.csv",
]


# ============================================================
# VALIDATE CONFIGURATION
# ============================================================

def validate_configuration():

    ratio_sum = (
        TRAIN_RATIO
        + VALIDATION_RATIO
        + TEST_RATIO
    )

    if abs(ratio_sum - 1.0) > 1e-9:
        raise ValueError(
            "TRAIN_RATIO + VALIDATION_RATIO + TEST_RATIO "
            "must equal 1.0"
        )

    if not SOURCE_FILES:
        raise ValueError("SOURCE_FILES is empty.")

    print()
    print("=" * 80)
    print("CONFIGURATION VALIDATION")
    print("=" * 80)

    print(f"Train ratio      : {TRAIN_RATIO:.2f}")
    print(f"Validation ratio : {VALIDATION_RATIO:.2f}")
    print(f"Test ratio       : {TEST_RATIO:.2f}")
    print(f"Source files     : {len(SOURCE_FILES)}")

    print()
    print("Configuration is valid.")


# ============================================================
# LOAD ONE SOURCE FILE
# ============================================================

def load_file(file_path):
    """
    Load one cleaned CIC-IDS2018 CSV file in chunks.

    Timestamp handling:
    - Explicitly parse DD/MM/YYYY HH:MM:SS.
    - Remove invalid/unparseable timestamps.
    - Remove timestamps outside the expected dataset period.
    """

    print(f"Loading: {file_path.name}")

    chunks = []

    total_invalid_timestamp_rows = 0
    total_out_of_range_rows = 0
    total_header_rows = 0

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):

        # ----------------------------------------------------
        # Remove repeated CSV header rows
        # ----------------------------------------------------

        header_mask = (
            chunk["Label"].astype(str).str.strip() == "Label"
        )

        header_count = int(header_mask.sum())

        if header_count > 0:
            total_header_rows += header_count

        chunk = chunk.loc[~header_mask].copy()

        if chunk.empty:
            continue

        # ----------------------------------------------------
        # Parse timestamp explicitly
        #
        # CIC-IDS2018 format:
        # DD/MM/YYYY HH:MM:SS
        # ----------------------------------------------------

        chunk["Timestamp"] = pd.to_datetime(
            chunk["Timestamp"],
            format="%d/%m/%Y %H:%M:%S",
            errors="coerce",
        )

        # ----------------------------------------------------
        # Remove timestamps that failed parsing
        # ----------------------------------------------------

        invalid_parse_mask = chunk["Timestamp"].isna()

        invalid_parse_count = int(
            invalid_parse_mask.sum()
        )

        if invalid_parse_count > 0:
            total_invalid_timestamp_rows += (
                invalid_parse_count
            )

            print(
                f"  Removing {invalid_parse_count} "
                f"unparseable timestamp rows from "
                f"{file_path.name}"
            )

        chunk = chunk.loc[
            ~invalid_parse_mask
        ].copy()

        if chunk.empty:
            continue

        # ----------------------------------------------------
        # Remove clearly corrupted timestamps
        #
        # The dataset capture period is February-March 2018.
        # This catches the known 1970 timestamp corruption.
        # ----------------------------------------------------

        valid_timestamp_mask = (
            (chunk["Timestamp"] >= pd.Timestamp("2018-02-14"))
            &
            (
                chunk["Timestamp"]
                <= pd.Timestamp("2018-03-02 23:59:59")
            )
        )

        out_of_range_count = int(
            (~valid_timestamp_mask).sum()
        )

        if out_of_range_count > 0:

            total_out_of_range_rows += (
                out_of_range_count
            )

            print(
                f"  Removing {out_of_range_count} "
                f"out-of-range timestamp rows from "
                f"{file_path.name}"
            )

        chunk = chunk.loc[
            valid_timestamp_mask
        ].copy()

        if chunk.empty:
            continue

        # ----------------------------------------------------
        # Normalize labels
        # ----------------------------------------------------

        chunk["Label"] = (
            chunk["Label"]
            .astype(str)
            .str.strip()
        )

        chunks.append(chunk)

    # --------------------------------------------------------
    # Check whether anything remains
    # --------------------------------------------------------

    if not chunks:

        raise ValueError(
            f"No usable data found in {file_path.name}"
        )

    # --------------------------------------------------------
    # Combine chunks
    # --------------------------------------------------------

    df = pd.concat(
        chunks,
        ignore_index=True,
    )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print(
        f"  Header rows removed       : "
        f"{total_header_rows:,}"
    )

    print(
        f"  Invalid timestamps removed: "
        f"{total_invalid_timestamp_rows:,}"
    )

    print(
        f"  Out-of-range timestamps   : "
        f"{total_out_of_range_rows:,}"
    )

    print(
        f"  Usable rows               : "
        f"{len(df):,}"
    )

    return df


# ============================================================
# ADD TARGET COLUMNS
# ============================================================

def add_targets(df, source_file):

    # --------------------------------------------------------
    # Binary target
    # --------------------------------------------------------

    df["BinaryLabel"] = (
        df["Label"] != "Benign"
    ).astype("int8")

    # --------------------------------------------------------
    # Attack-family target
    # --------------------------------------------------------

    df["AttackFamily"] = (
        df["Label"]
        .map(ATTACK_FAMILY_MAP)
    )

    # --------------------------------------------------------
    # Check unknown labels
    # --------------------------------------------------------

    unknown = (
        df.loc[
            df["AttackFamily"].isna(),
            "Label",
        ]
        .unique()
    )

    if len(unknown) > 0:

        raise ValueError(
            f"Unknown labels found in "
            f"{source_file}: {unknown}"
        )

    # --------------------------------------------------------
    # Preserve source capture file
    # --------------------------------------------------------

    df["SourceFile"] = source_file

    return df


# ============================================================
# TEMPORAL SPLIT
# ============================================================

def temporal_split(df):

    # --------------------------------------------------------
    # Sort chronologically
    # --------------------------------------------------------

    df = (
        df
        .sort_values("Timestamp")
        .reset_index(drop=True)
    )

    n = len(df)

    # --------------------------------------------------------
    # Calculate boundaries
    # --------------------------------------------------------

    train_end = int(
        n * TRAIN_RATIO
    )

    validation_end = int(
        n * (
            TRAIN_RATIO
            + VALIDATION_RATIO
        )
    )

    # --------------------------------------------------------
    # Create chronological splits
    # --------------------------------------------------------

    train = df.iloc[
        :train_end
    ].copy()

    validation = df.iloc[
        train_end:validation_end
    ].copy()

    test = df.iloc[
        validation_end:
    ].copy()

    return (
        train,
        validation,
        test,
    )


# ============================================================
# PROCESS ONE SOURCE FILE
# ============================================================

def process_source_file(source_file):

    path = (
        PROCESSED_DIR
        / source_file
    )

    if not path.exists():

        raise FileNotFoundError(
            f"File not found: {path}"
        )

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    df = load_file(path)

    if df.empty:

        raise ValueError(
            f"No usable data found in "
            f"{source_file}"
        )

    # --------------------------------------------------------
    # Add targets
    # --------------------------------------------------------

    df = add_targets(
        df,
        source_file,
    )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Split each raw label separately.
    #
    # This prevents huge classes such as DDoS from
    # dominating the temporal split.
    #
    # Every raw attack campaign remains chronological.
    # --------------------------------------------------------

    train_parts = []
    validation_parts = []
    test_parts = []

    for label, group in df.groupby(
        "Label",
        sort=False,
    ):

        train, validation, test = (
            temporal_split(group)
        )

        train_parts.append(train)
        validation_parts.append(validation)
        test_parts.append(test)

    # --------------------------------------------------------
    # Combine label-specific splits
    # --------------------------------------------------------

    train_df = pd.concat(
        train_parts,
        ignore_index=True,
    )

    validation_df = pd.concat(
        validation_parts,
        ignore_index=True,
    )

    test_df = pd.concat(
        test_parts,
        ignore_index=True,
    )

    # --------------------------------------------------------
    # Verify row conservation for this source
    # --------------------------------------------------------

    original_count = len(df)

    split_count = (
        len(train_df)
        + len(validation_df)
        + len(test_df)
    )

    if split_count != original_count:

        raise ValueError(
            f"Row conservation failed for "
            f"{source_file}. "
            f"Original={original_count}, "
            f"Splits={split_count}"
        )

    return (
        train_df,
        validation_df,
        test_df,
    )


# ============================================================
# SAVE DATASET
# ============================================================

def save_dataset(df, path):

    # --------------------------------------------------------
    # Sort final dataset chronologically
    # --------------------------------------------------------

    df = (
        df
        .sort_values("Timestamp")
        .reset_index(drop=True)
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    df.to_csv(
        path,
        index=False,
    )

    print(
        f"Saved {len(df):,} rows -> {path}"
    )


# ============================================================
# DISTRIBUTION ANALYSIS
# ============================================================

def print_distribution(df, name):

    print("\n")
    print("=" * 80)
    print(f"{name.upper()} DISTRIBUTION")
    print("=" * 80)

    total = len(df)

    # --------------------------------------------------------
    # Attack family
    # --------------------------------------------------------

    print("\nAttack Family:")

    family_counts = (
        df["AttackFamily"]
        .value_counts()
    )

    for family, count in family_counts.items():

        percentage = (
            count / total
        ) * 100

        print(
            f"{family:<20}"
            f"{count:>12,} "
            f"{percentage:>8.4f}%"
        )

    # --------------------------------------------------------
    # Raw labels
    # --------------------------------------------------------

    print("\nRaw Labels:")

    label_counts = (
        df["Label"]
        .value_counts()
    )

    for label, count in label_counts.items():

        percentage = (
            count / total
        ) * 100

        print(
            f"{label:<30}"
            f"{count:>12,} "
            f"{percentage:>8.4f}%"
        )

    # --------------------------------------------------------
    # Binary
    # --------------------------------------------------------

    print("\nBinary:")

    benign = (
        df["BinaryLabel"] == 0
    ).sum()

    attack = (
        df["BinaryLabel"] == 1
    ).sum()

    print(
        f"Benign : {benign:>12,} "
        f"({benign / total * 100:.4f}%)"
    )

    print(
        f"Attack : {attack:>12,} "
        f"({attack / total * 100:.4f}%)"
    )


# ============================================================
# TIMESTAMP RANGE
# ============================================================

def print_time_range(df, name):

    print("\n" + "-" * 80)

    print(
        f"{name} time range:"
    )

    print(
        f"First: {df['Timestamp'].min()}"
    )

    print(
        f"Last : {df['Timestamp'].max()}"
    )


# ============================================================
# VERIFY FINAL DATASETS
# ============================================================

def verify_final_datasets(
    train_df,
    validation_df,
    test_df,
):

    print("\n")
    print("=" * 80)
    print("FINAL DATASET VERIFICATION")
    print("=" * 80)

    # --------------------------------------------------------
    # Row counts
    # --------------------------------------------------------

    total_rows = (
        len(train_df)
        + len(validation_df)
        + len(test_df)
    )

    print(
        f"Train rows      : {len(train_df):,}"
    )

    print(
        f"Validation rows : {len(validation_df):,}"
    )

    print(
        f"Test rows       : {len(test_df):,}"
    )

    print(
        f"Combined rows   : {total_rows:,}"
    )

    # --------------------------------------------------------
    # Empty datasets
    # --------------------------------------------------------

    if train_df.empty:
        raise ValueError(
            "Training dataset is empty."
        )

    if validation_df.empty:
        raise ValueError(
            "Validation dataset is empty."
        )

    if test_df.empty:
        raise ValueError(
            "Test dataset is empty."
        )

    # --------------------------------------------------------
    # Timestamp validation
    # --------------------------------------------------------

    for name, df in [
        ("Train", train_df),
        ("Validation", validation_df),
        ("Test", test_df),
    ]:

        if df["Timestamp"].isna().any():

            raise ValueError(
                f"{name} contains invalid timestamps."
            )

        if (
            df["Timestamp"]
            < pd.Timestamp("2018-02-14")
        ).any():

            raise ValueError(
                f"{name} contains timestamps "
                f"before 2018-02-14."
            )

        if (
            df["Timestamp"]
            > pd.Timestamp("2018-03-02 23:59:59")
        ).any():

            raise ValueError(
                f"{name} contains timestamps "
                f"after 2018-03-02."
            )

    # --------------------------------------------------------
    # Target validation
    # --------------------------------------------------------

    expected_families = set(
        ATTACK_FAMILY_MAP.values()
    )

    for name, df in [
        ("Train", train_df),
        ("Validation", validation_df),
        ("Test", test_df),
    ]:

        actual_families = set(
            df["AttackFamily"].unique()
        )

        unknown = (
            actual_families
            - expected_families
        )

        if unknown:

            raise ValueError(
                f"{name} contains unknown "
                f"attack families: {unknown}"
            )

    print()
    print(
        "Timestamp validation: PASSED"
    )

    print(
        "Attack-family validation: PASSED"
    )

    print(
        "Row integrity validation: PASSED"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("KNOWN-FAMILY TEMPORAL DATASET CREATION")
    print("=" * 80)

    # --------------------------------------------------------
    # Validate configuration
    # --------------------------------------------------------

    validate_configuration()

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Verify source files
    # --------------------------------------------------------

    print("\n")
    print("=" * 80)
    print("VERIFYING SOURCE FILES")
    print("=" * 80)

    for source_file in SOURCE_FILES:

        path = (
            PROCESSED_DIR
            / source_file
        )

        if not path.exists():

            raise FileNotFoundError(
                f"Source file does not exist:\n{path}"
            )

        print(
            f"OK: {source_file}"
        )

    # --------------------------------------------------------
    # Process every source file
    # --------------------------------------------------------

    train_parts = []
    validation_parts = []
    test_parts = []

    original_total = 0

    for source_file in SOURCE_FILES:

        print("\n" + "#" * 80)
        print(
            f"SOURCE: {source_file}"
        )
        print("#" * 80)

        train, validation, test = (
            process_source_file(
                source_file
            )
        )

        source_total = (
            len(train)
            + len(validation)
            + len(test)
        )

        original_total += source_total

        print(
            f"Train      : {len(train):,}"
        )

        print(
            f"Validation : {len(validation):,}"
        )

        print(
            f"Test       : {len(test):,}"
        )

        print(
            f"Total      : {source_total:,}"
        )

        train_parts.append(train)
        validation_parts.append(validation)
        test_parts.append(test)

    # --------------------------------------------------------
    # Combine all source files
    # --------------------------------------------------------

    train_df = pd.concat(
        train_parts,
        ignore_index=True,
    )

    validation_df = pd.concat(
        validation_parts,
        ignore_index=True,
    )

    test_df = pd.concat(
        test_parts,
        ignore_index=True,
    )

    # --------------------------------------------------------
    # Verify final datasets
    # --------------------------------------------------------

    verify_final_datasets(
        train_df,
        validation_df,
        test_df,
    )

    # --------------------------------------------------------
    # Verify total row conservation
    # --------------------------------------------------------

    combined_total = (
        len(train_df)
        + len(validation_df)
        + len(test_df)
    )

    print()

    print(
        f"Original usable rows : "
        f"{original_total:,}"
    )

    print(
        f"Split rows           : "
        f"{combined_total:,}"
    )

    if combined_total != original_total:

        raise ValueError(
            "Global row conservation failed."
        )

    print(
        "Global row conservation: PASSED"
    )

    # --------------------------------------------------------
    # Output paths
    # --------------------------------------------------------

    train_path = (
        OUTPUT_DIR / "train.csv"
    )

    validation_path = (
        OUTPUT_DIR / "validation.csv"
    )

    test_path = (
        OUTPUT_DIR / "test.csv"
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    save_dataset(
        train_df,
        train_path,
    )

    save_dataset(
        validation_df,
        validation_path,
    )

    save_dataset(
        test_df,
        test_path,
    )

    # --------------------------------------------------------
    # Distribution analysis
    # --------------------------------------------------------

    print_distribution(
        train_df,
        "Training",
    )

    print_time_range(
        train_df,
        "Training",
    )

    print_distribution(
        validation_df,
        "Validation",
    )

    print_time_range(
        validation_df,
        "Validation",
    )

    print_distribution(
        test_df,
        "Test",
    )

    print_time_range(
        test_df,
        "Test",
    )

    # --------------------------------------------------------
    # Source-file overlap
    #
    # NOTE:
    # Same source file appearing in all three sets is
    # intentional for this temporal experiment.
    # The rows are separated chronologically.
    # --------------------------------------------------------

    train_sources = set(
        train_df["SourceFile"].unique()
    )

    validation_sources = set(
        validation_df["SourceFile"].unique()
    )

    test_sources = set(
        test_df["SourceFile"].unique()
    )

    print("\n")
    print("=" * 80)
    print("SOURCE FILE OVERLAP")
    print("=" * 80)

    print(
        "Train ∩ Validation:",
        train_sources & validation_sources,
    )

    print(
        "Train ∩ Test:",
        train_sources & test_sources,
    )

    print(
        "Validation ∩ Test:",
        validation_sources & test_sources,
    )

    print()
    print(
        "NOTE: Source-file overlap is intentional."
    )

    print(
        "This experiment uses chronological separation "
        "within each capture file."
    )

    # --------------------------------------------------------
    # Final
    # --------------------------------------------------------

    print("\n")
    print("=" * 80)
    print("KNOWN-FAMILY TEMPORAL DATASET CREATION COMPLETE")
    print("=" * 80)

    print("\nOutput:")

    print(
        f"Train      : {train_path}"
    )

    print(
        f"Validation : {validation_path}"
    )

    print(
        f"Test       : {test_path}"
    )


if __name__ == "__main__":
    main()