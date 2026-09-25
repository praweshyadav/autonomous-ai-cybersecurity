from pathlib import Path
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")
OUTPUT_DIR = PROCESSED_DIR / "splits"

CHUNK_SIZE = 200_000


# ============================================================
# ATTACK FAMILY MAPPING
# ============================================================

ATTACK_FAMILY_MAP = {
    "Benign": "Benign",

    "FTP-BruteForce": "Brute Force",
    "SSH-Bruteforce": "Brute Force",

    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-Slowloris": "DoS",

    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",

    "Brute Force -Web": "Web Attack",
    "Brute Force -XSS": "Web Attack",
    "SQL Injection": "Web Attack",

    "Bot": "Bot",

    "Infilteration": "Infiltration",
}


# ============================================================
# DATASET SPLIT DEFINITION
# ============================================================

FILES = {
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "train",

    "Thursday-15-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "train",

    "Friday-16-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "train",

    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "train",

    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "train",

    "Thursday-22-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "train",

    "Friday-23-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "train",

    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter_clean.csv":
        "validation",

    "Thursday-01-03-2018_TrafficForML_CICFlowMeter_clean.csv":
        "test",

    "Friday-02-03-2018_TrafficForML_CICFlowMeter_clean.csv":
        "test",
}


# ============================================================
# PROCESS ONE FILE
# ============================================================

def process_file(file_path, split_name, output_path):
    print("\n" + "=" * 80)
    print(f"Processing: {file_path.name}")
    print(f"Split: {split_name}")
    print("=" * 80)

    first_chunk = not output_path.exists()
    total_rows = 0

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        # ----------------------------------------------------
        # Remove accidental header rows
        # ----------------------------------------------------

        chunk = chunk[chunk["Label"] != "Label"].copy()

        if chunk.empty:
            continue

        # ----------------------------------------------------
        # Binary label
        # ----------------------------------------------------

        chunk["BinaryLabel"] = (
            chunk["Label"] != "Benign"
        ).astype("int8")

        # ----------------------------------------------------
        # Attack family
        # ----------------------------------------------------

        chunk["AttackFamily"] = chunk["Label"].map(
            ATTACK_FAMILY_MAP
        )

        # Check for unknown labels
        unknown_labels = chunk.loc[
            chunk["AttackFamily"].isna(),
            "Label"
        ].unique()

        if len(unknown_labels) > 0:
            raise ValueError(
                f"Unknown labels found in {file_path.name}: "
                f"{unknown_labels}"
            )

        # ----------------------------------------------------
        # Source file
        # ----------------------------------------------------

        chunk["SourceFile"] = file_path.name

        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        chunk["Timestamp"] = pd.to_datetime(
            chunk["Timestamp"],
            errors="coerce",
            dayfirst=True
        )

        # Remove invalid timestamps
        chunk = chunk.dropna(
            subset=["Timestamp"]
        )

        total_rows += len(chunk)

        # ----------------------------------------------------
        # Write chunk
        # ----------------------------------------------------

        chunk.to_csv(
            output_path,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False
        )

        first_chunk = False

    print(f"Rows written: {total_rows:,}")

    return total_rows


# ============================================================
# COMBINE FILES FOR EACH SPLIT
# ============================================================

def create_split(split_name, filenames):

    output_path = OUTPUT_DIR / f"{split_name}.csv"

    # Remove existing file
    if output_path.exists():
        output_path.unlink()

    total_rows = 0

    print("\n")
    print("#" * 80)
    print(f"CREATING {split_name.upper()} SET")
    print("#" * 80)

    for filename in filenames:

        file_path = PROCESSED_DIR / filename

        if not file_path.exists():
            raise FileNotFoundError(
                f"File not found: {file_path}"
            )

        rows = process_file(
            file_path,
            split_name,
            output_path
        )

        total_rows += rows

    print("\n" + "-" * 80)
    print(f"{split_name.upper()} TOTAL: {total_rows:,}")
    print(f"Saved to: {output_path}")
    print("-" * 80)

    return output_path


# ============================================================
# DATASET SUMMARY
# ============================================================

def analyze_split(file_path, split_name):

    print("\n")
    print("=" * 80)
    print(f"{split_name.upper()} SET ANALYSIS")
    print("=" * 80)

    label_counts = {}
    family_counts = {}
    binary_counts = {}

    for chunk in pd.read_csv(
        file_path,
        usecols=[
            "Label",
            "AttackFamily",
            "BinaryLabel",
            "SourceFile"
        ],
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):

        # Label counts
        counts = chunk["Label"].value_counts()

        for label, count in counts.items():
            label_counts[label] = (
                label_counts.get(label, 0) + count
            )

        # Family counts
        counts = chunk["AttackFamily"].value_counts()

        for family, count in counts.items():
            family_counts[family] = (
                family_counts.get(family, 0) + count
            )

        # Binary counts
        counts = chunk["BinaryLabel"].value_counts()

        for value, count in counts.items():
            binary_counts[value] = (
                binary_counts.get(value, 0) + count
            )

    # --------------------------------------------------------
    # Label distribution
    # --------------------------------------------------------

    total = sum(label_counts.values())

    print("\nRAW LABEL DISTRIBUTION")
    print("-" * 80)

    for label, count in sorted(
        label_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        percentage = (count / total) * 100

        print(
            f"{label:<30} "
            f"{count:>12,} "
            f"{percentage:>8.4f}%"
        )

    # --------------------------------------------------------
    # Attack family distribution
    # --------------------------------------------------------

    print("\nATTACK FAMILY DISTRIBUTION")
    print("-" * 80)

    for family, count in sorted(
        family_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        percentage = (count / total) * 100

        print(
            f"{family:<30} "
            f"{count:>12,} "
            f"{percentage:>8.4f}%"
        )

    # --------------------------------------------------------
    # Binary distribution
    # --------------------------------------------------------

    print("\nBINARY DISTRIBUTION")
    print("-" * 80)

    benign = binary_counts.get(0, 0)
    attack = binary_counts.get(1, 0)

    benign_pct = (benign / total) * 100
    attack_pct = (attack / total) * 100

    print(
        f"Benign : {benign:>12,} "
        f"({benign_pct:.4f}%)"
    )

    print(
        f"Attack : {attack:>12,} "
        f"({attack_pct:.4f}%)"
    )

    # --------------------------------------------------------
    # Source files
    # --------------------------------------------------------

    print("\nSOURCE FILES")
    print("-" * 80)

    source_files = set()

    for chunk in pd.read_csv(
        file_path,
        usecols=["SourceFile"],
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):
        source_files.update(
            chunk["SourceFile"].unique()
        )

    for source in sorted(source_files):
        print(f"  - {source}")

    return source_files


# ============================================================
# LEAKAGE CHECK
# ============================================================

def check_source_overlap(train_sources,
                         validation_sources,
                         test_sources):

    print("\n")
    print("=" * 80)
    print("SOURCE FILE LEAKAGE CHECK")
    print("=" * 80)

    train_validation = train_sources & validation_sources
    train_test = train_sources & test_sources
    validation_test = validation_sources & test_sources

    if train_validation:
        print("ERROR: Train/Validation overlap:")
        for item in train_validation:
            print(f"  - {item}")

    if train_test:
        print("ERROR: Train/Test overlap:")
        for item in train_test:
            print(f"  - {item}")

    if validation_test:
        print("ERROR: Validation/Test overlap:")
        for item in validation_test:
            print(f"  - {item}")

    if not train_validation and not train_test and not validation_test:
        print("✓ No source-file overlap detected.")


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 80)
    print("CSE-CIC-IDS2018 DATASET SPLIT CREATION")
    print("=" * 80)

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Group files
    # --------------------------------------------------------

    train_files = [
        filename
        for filename, split in FILES.items()
        if split == "train"
    ]

    validation_files = [
        filename
        for filename, split in FILES.items()
        if split == "validation"
    ]

    test_files = [
        filename
        for filename, split in FILES.items()
        if split == "test"
    ]

    # --------------------------------------------------------
    # Create datasets
    # --------------------------------------------------------

    train_path = create_split(
        "train",
        train_files
    )

    validation_path = create_split(
        "validation",
        validation_files
    )

    test_path = create_split(
        "test",
        test_files
    )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    train_sources = analyze_split(
        train_path,
        "train"
    )

    validation_sources = analyze_split(
        validation_path,
        "validation"
    )

    test_sources = analyze_split(
        test_path,
        "test"
    )

    # --------------------------------------------------------
    # Leakage check
    # --------------------------------------------------------

    check_source_overlap(
        train_sources,
        validation_sources,
        test_sources
    )

    # --------------------------------------------------------
    # Final message
    # --------------------------------------------------------

    print("\n")
    print("=" * 80)
    print("DATASET SPLIT CREATION COMPLETE")
    print("=" * 80)

    print("\nOutput files:")

    print(f"  Train      : {train_path}")
    print(f"  Validation : {validation_path}")
    print(f"  Test       : {test_path}")

    print("\nNext step:")
    print("Review the distributions before training any model.")


if __name__ == "__main__":
    main()