from pathlib import Path

import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
)

OUTPUT_DIR = DATA_DIR / "known_attack_eval"


# ============================================================
# CONFIGURATION
# ============================================================

# These files will be used for training.
#
# Feb 23 contains Web/XSS/SQL attacks.
# Therefore the model will learn those attack families before
# we evaluate it on Feb 22.


TRAIN_FILES = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter_clean.csv",
]

TEST_FILES = [
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter_clean.csv",
]


# ============================================================
# PROCESS FILE
# ============================================================

def process_file(input_path, output_path, first_file):
    print(f"Processing: {input_path.name}")

    first_chunk = first_file
    total_rows = 0

    for chunk in pd.read_csv(
        input_path,
        chunksize=200_000
    ):

        # Remove accidental repeated header rows
        chunk = chunk[
            chunk["Label"].astype(str).str.strip() != "Label"
        ].copy()

        # Binary target
        chunk["BinaryLabel"] = (
            chunk["Label"].astype(str).str.strip() != "Benign"
        ).astype("int8")

        # Keep original capture file
        chunk["SourceFile"] = input_path.name

        # Parse timestamp explicitly as DD/MM/YYYY
        chunk["Timestamp"] = pd.to_datetime(
            chunk["Timestamp"],
            format="%d/%m/%Y %H:%M:%S",
            errors="coerce"
        )

        chunk = chunk.sort_values("Timestamp")

        # First chunk of the first file writes the header.
        # Everything after that is appended.
        chunk.to_csv(
            output_path,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False
        )

        first_chunk = False
        total_rows += len(chunk)

    print(f"  Rows written: {total_rows:,}")


# ============================================================
# BUILD SPLIT
# ============================================================

def build_split(file_names, split_name):

    output_path = OUTPUT_DIR / f"{split_name}.csv"

    # Remove old split so we start completely fresh
    if output_path.exists():
        output_path.unlink()

    first_file = True

    for file_name in file_names:

        input_path = DATA_DIR / file_name

        if not input_path.exists():
            raise FileNotFoundError(
                f"File not found:\n{input_path}"
            )

        process_file(
            input_path,
            output_path,
            first_file
        )

        first_file = False

    print()
    print(
        f"{split_name.upper()} split created:"
        f" {output_path}"
    )


# ============================================================
# ANALYZE SPLIT
# ============================================================

def analyze_split(path, split_name):

    print()
    print("=" * 70)
    print(f"{split_name.upper()} SUMMARY")
    print("=" * 70)

    label_counts = {}
    binary_counts = {}
    source_counts = {}

    total_rows = 0

    for chunk in pd.read_csv(
        path,
        chunksize=200_000
    ):

        total_rows += len(chunk)

        # Original labels
        for label, count in chunk["Label"].value_counts().items():
            label_counts[label] = (
                label_counts.get(label, 0) + int(count)
            )

        # Binary labels
        for label, count in chunk["BinaryLabel"].value_counts().items():
            binary_counts[label] = (
                binary_counts.get(label, 0) + int(count)
            )

        # Source files
        for source, count in chunk["SourceFile"].value_counts().items():
            source_counts[source] = (
                source_counts.get(source, 0) + int(count)
            )

    print(f"Total rows: {total_rows:,}")

    print()
    print("Labels:")
    for label, count in sorted(
        label_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        percentage = count / total_rows * 100

        print(
            f"{label:30s}"
            f"{count:12,}"
            f"  {percentage:8.4f}%"
        )

    print()
    print("Binary distribution:")

    benign = binary_counts.get(0, 0)
    attack = binary_counts.get(1, 0)

    print(f"Benign : {benign:,}")
    print(f"Attack : {attack:,}")

    if total_rows > 0:
        print(
            f"Attack %: "
            f"{attack / total_rows * 100:.4f}%"
        )

    print()
    print("Source files:")

    for source, count in source_counts.items():
        print(f"{source}: {count:,}")


# ============================================================
# VERIFY NO FILE OVERLAP
# ============================================================

def verify_no_overlap():

    train_set = set(TRAIN_FILES)
    test_set = set(TEST_FILES)

    overlap = train_set.intersection(test_set)

    print()
    print("=" * 70)
    print("SOURCE FILE OVERLAP CHECK")
    print("=" * 70)

    if overlap:
        raise ValueError(
            "ERROR: Source-file overlap detected:\n"
            + "\n".join(overlap)
        )

    print("No source-file overlap detected.")
    print("Train and test capture files are completely separate.")


# ============================================================
# MAIN
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 70)
    print("CREATING KNOWN-ATTACK EVALUATION SPLIT")
    print("=" * 70)

    print()
    print("Training files:")

    for file_name in TRAIN_FILES:
        print(f"  - {file_name}")

    print()
    print("Test file:")

    for file_name in TEST_FILES:
        print(f"  - {file_name}")

    verify_no_overlap()

    print()
    print("Creating training split...")
    build_split(
        TRAIN_FILES,
        "train"
    )

    print()
    print("Creating test split...")
    build_split(
        TEST_FILES,
        "test"
    )

    analyze_split(
        OUTPUT_DIR / "train.csv",
        "train"
    )

    analyze_split(
        OUTPUT_DIR / "test.csv",
        "test"
    )

    print()
    print("=" * 70)
    print("KNOWN-ATTACK EVALUATION SPLIT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()