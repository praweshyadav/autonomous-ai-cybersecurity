from pathlib import Path
from collections import Counter
import pandas as pd


PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")
CHUNK_SIZE = 200_000


def main():

    files = sorted(PROCESSED_DIR.glob("*_clean.csv"))

    print("=" * 70)
    print("PROCESSED DATASET VALIDATION")
    print("=" * 70)

    print(f"Files found: {len(files)}")
    print()

    total_rows = 0
    total_missing = 0
    total_bad_labels = 0

    all_labels = Counter()
    schemas = {}

    for i, file in enumerate(files, start=1):

        print("-" * 70)
        print(f"[{i}/{len(files)}] {file.name}")
        print("-" * 70)

        # -------------------------------------------------
        # Check schema
        # -------------------------------------------------

        header = pd.read_csv(file, nrows=0)

        schemas[file.name] = list(header.columns)

        print(f"Columns: {len(header.columns)}")

        # -------------------------------------------------
        # Process chunks
        # -------------------------------------------------

        file_rows = 0
        file_missing = 0
        file_bad_labels = 0
        file_labels = Counter()

        for chunk in pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ):

            file_rows += len(chunk)

            # Label statistics
            labels = chunk["Label"].astype(str).str.strip()

            file_labels.update(labels.value_counts().to_dict())

            # Bad header rows
            file_bad_labels += int(
                (labels == "Label").sum()
            )

            # Missing values
            file_missing += int(
                chunk.isna().sum().sum()
            )

        total_rows += file_rows
        total_missing += file_missing
        total_bad_labels += file_bad_labels

        all_labels.update(file_labels)

        print(f"Rows: {file_rows:,}")
        print(f"Missing values: {file_missing:,}")
        print(f"Bad Label rows: {file_bad_labels}")

        print("\nLabels:")
        for label, count in file_labels.most_common():
            print(f"  {label}: {count:,}")

        print()

    # -----------------------------------------------------
    # Schema validation
    # -----------------------------------------------------

    unique_schemas = {
        tuple(columns)
        for columns in schemas.values()
    }

    print("=" * 70)
    print("SCHEMA VALIDATION")
    print("=" * 70)

    print(f"Unique schemas: {len(unique_schemas)}")

    if len(unique_schemas) == 1:
        print("PASS: All processed files have identical schemas.")
    else:
        print("FAIL: Processed files have different schemas.")

    # -----------------------------------------------------
    # Overall labels
    # -----------------------------------------------------

    print()
    print("=" * 70)
    print("OVERALL LABEL DISTRIBUTION")
    print("=" * 70)

    for label, count in all_labels.most_common():
        print(f"{label}: {count:,}")

    # -----------------------------------------------------
    # Final validation
    # -----------------------------------------------------

    print()
    print("=" * 70)
    print("FINAL VALIDATION")
    print("=" * 70)

    print(f"Total rows: {total_rows:,}")
    print(f"Total missing values: {total_missing:,}")
    print(f"Total bad Label rows: {total_bad_labels}")

    expected_rows = 16_232_943

    print()
    print(f"Expected rows: {expected_rows:,}")

    if total_rows == expected_rows:
        print("PASS: Row count is correct.")
    else:
        print("WARNING: Row count differs from expected.")

    if total_missing == 0:
        print("PASS: No missing values remain.")
    else:
        print("WARNING: Missing values still exist.")

    if total_bad_labels == 0:
        print("PASS: No accidental header rows remain.")
    else:
        print("WARNING: Accidental header rows remain.")

    if len(unique_schemas) == 1:
        print("PASS: Schema is consistent.")
    else:
        print("WARNING: Schema is inconsistent.")

    print()
    print("=" * 70)
    print("VALIDATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()