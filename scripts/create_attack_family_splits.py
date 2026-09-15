from pathlib import Path

import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_PATH = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "attack_family"
    / "all_attack_families.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
    / "attack_family"
    / "known_family_splits"
)


# ============================================================
# CONFIGURATION
# ============================================================

CHUNK_SIZE = 200_000


# ============================================================
# CAPTURE-FILE GROUPS
# ============================================================

# Training capture files.
#
# These contain:
#   DDoS
#   DoS
#   Brute Force
#   Web Attack
#   Bot is NOT here
#   Infiltration is NOT here
#
# We will use separate files for validation/test so that
# capture campaigns do not leak across the splits.

TRAIN_FILES = {
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Thuesday-20-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Wednesday-21-02-2018_TrafficForML_CICFlowMeter_clean.csv",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter_clean.csv",
}


# Validation capture file.
#
# Feb 22 contains the same Web Attack family seen in Feb 23,
# but it is a completely different capture file.
VALIDATION_FILES = {
    "Friday-23-02-2018_TrafficForML_CICFlowMeter_clean.csv",
}


# Test capture files.
#
# These are completely unseen capture files.
#
# Mar 1 -> Infiltration
# Mar 2 -> Bot
#
# These families are NOT present in TRAIN.
#
# Therefore this test set is an OOD evaluation.
TEST_FILES = {
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter_clean.csv",
}


# ============================================================
# VERIFY CONFIGURATION
# ============================================================

def verify_file_groups():

    print("=" * 70)
    print("VERIFYING CAPTURE-FILE GROUPS")
    print("=" * 70)

    train_validation_overlap = (
        TRAIN_FILES & VALIDATION_FILES
    )

    train_test_overlap = (
        TRAIN_FILES & TEST_FILES
    )

    validation_test_overlap = (
        VALIDATION_FILES & TEST_FILES
    )

    if train_validation_overlap:
        raise ValueError(
            "Train/validation overlap detected:\n"
            + "\n".join(train_validation_overlap)
        )

    if train_test_overlap:
        raise ValueError(
            "Train/test overlap detected:\n"
            + "\n".join(train_test_overlap)
        )

    if validation_test_overlap:
        raise ValueError(
            "Validation/test overlap detected:\n"
            + "\n".join(validation_test_overlap)
        )

    print("No capture-file overlap detected.")

    print()
    print(f"Training files   : {len(TRAIN_FILES)}")
    print(f"Validation files : {len(VALIDATION_FILES)}")
    print(f"Test files       : {len(TEST_FILES)}")


# ============================================================
# CREATE SPLITS
# ============================================================

def create_splits():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    train_path = OUTPUT_DIR / "train.csv"
    validation_path = OUTPUT_DIR / "validation.csv"
    test_path = OUTPUT_DIR / "test.csv"

    # Remove previous outputs
    for path in [
        train_path,
        validation_path,
        test_path,
    ]:
        if path.exists():
            path.unlink()

    output_paths = {
        "train": train_path,
        "validation": validation_path,
        "test": test_path,
    }

    first_write = {
        "train": True,
        "validation": True,
        "test": True,
    }

    total_counts = {
        "train": 0,
        "validation": 0,
        "test": 0,
    }

    # --------------------------------------------------------
    # Read the family dataset in chunks.
    #
    # We use SourceFile to assign every row to exactly one
    # split.
    # --------------------------------------------------------

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            INPUT_PATH,
            chunksize=CHUNK_SIZE
        ),
        start=1
    ):

        print(
            f"Processing source chunk {chunk_number}..."
        )

        if "SourceFile" not in chunk.columns:
            raise ValueError(
                "SourceFile column is missing."
            )

        # ----------------------------------------------------
        # Normalize SourceFile
        # ----------------------------------------------------

        chunk["SourceFile"] = (
            chunk["SourceFile"]
            .astype(str)
            .str.strip()
        )

        # ----------------------------------------------------
        # Assign rows to splits
        # ----------------------------------------------------

        train_mask = (
            chunk["SourceFile"].isin(
                TRAIN_FILES
            )
        )

        validation_mask = (
            chunk["SourceFile"].isin(
                VALIDATION_FILES
            )
        )

        test_mask = (
            chunk["SourceFile"].isin(
                TEST_FILES
            )
        )

        # ----------------------------------------------------
        # Verify every row belongs to exactly one split
        # ----------------------------------------------------

        assigned_count = (
            train_mask.astype(int)
            + validation_mask.astype(int)
            + test_mask.astype(int)
        )

        if not (assigned_count == 1).all():

            problematic = chunk.loc[
                assigned_count != 1,
                "SourceFile"
            ].value_counts()

            print()
            print(
                "ERROR: Some rows could not be assigned "
                "to exactly one split."
            )

            print(problematic)

            raise ValueError(
                "Split assignment is incomplete."
            )

        # ----------------------------------------------------
        # Write each split
        # ----------------------------------------------------

        split_masks = {
            "train": train_mask,
            "validation": validation_mask,
            "test": test_mask,
        }

        for split_name, mask in split_masks.items():

            split_chunk = chunk.loc[
                mask
            ].copy()

            if split_chunk.empty:
                continue

            output_path = output_paths[
                split_name
            ]

            split_chunk.to_csv(
                output_path,
                mode=(
                    "w"
                    if first_write[split_name]
                    else "a"
                ),
                header=first_write[split_name],
                index=False
            )

            first_write[split_name] = False

            total_counts[split_name] += (
                len(split_chunk)
            )

    return output_paths, total_counts


# ============================================================
# ANALYZE SPLIT
# ============================================================

def analyze_split(
    split_name,
    split_path
):

    print()
    print("=" * 70)
    print(f"{split_name.upper()} DISTRIBUTION")
    print("=" * 70)

    family_counts = {}
    source_counts = {}
    total_rows = 0

    for chunk in pd.read_csv(
        split_path,
        usecols=[
            "AttackFamily",
            "SourceFile",
        ],
        chunksize=CHUNK_SIZE
    ):

        total_rows += len(chunk)

        # Family counts
        for family, count in (
            chunk["AttackFamily"]
            .value_counts()
            .items()
        ):

            family_counts[family] = (
                family_counts.get(
                    family,
                    0
                )
                + int(count)
            )

        # Source-file counts
        for source, count in (
            chunk["SourceFile"]
            .value_counts()
            .items()
        ):

            source_counts[source] = (
                source_counts.get(
                    source,
                    0
                )
                + int(count)
            )

    print(
        f"Total rows: {total_rows:,}"
    )

    print()
    print(
        f"{'Attack Family':20s}"
        f"{'Count':15s}"
        f"{'Percentage':15s}"
    )

    print("-" * 50)

    for family, count in sorted(
        family_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):

        percentage = (
            count / total_rows * 100
        )

        print(
            f"{family:20s}"
            f"{count:15,}"
            f"{percentage:14.4f}%"
        )

    print()
    print("Source files:")

    for source, count in sorted(
        source_counts.items()
    ):

        print(
            f"  {source}: {count:,}"
        )


# ============================================================
# VERIFY FINAL SPLITS
# ============================================================

def verify_final_splits():

    print()
    print("=" * 70)
    print("FINAL SPLIT VERIFICATION")
    print("=" * 70)

    split_files = {
        "train": TRAIN_FILES,
        "validation": VALIDATION_FILES,
        "test": TEST_FILES,
    }

    actual_files = {}

    for split_name in split_files:

        path = (
            OUTPUT_DIR
            / f"{split_name}.csv"
        )

        sources = set()

        for chunk in pd.read_csv(
            path,
            usecols=["SourceFile"],
            chunksize=CHUNK_SIZE
        ):

            sources.update(
                chunk["SourceFile"]
                .astype(str)
                .str.strip()
                .unique()
            )

        actual_files[split_name] = sources

    # --------------------------------------------------------
    # Check expected files
    # --------------------------------------------------------

    for split_name, expected in split_files.items():

        actual = actual_files[split_name]

        if actual != expected:

            print()
            print(
                f"ERROR in {split_name} split."
            )

            print(
                f"Expected: {sorted(expected)}"
            )

            print(
                f"Actual:   {sorted(actual)}"
            )

            raise ValueError(
                "Final split source-file assignment "
                "does not match configuration."
            )

    # --------------------------------------------------------
    # Check overlap
    # --------------------------------------------------------

    if (
        actual_files["train"]
        & actual_files["validation"]
    ):
        raise ValueError(
            "Train/validation overlap detected."
        )

    if (
        actual_files["train"]
        & actual_files["test"]
    ):
        raise ValueError(
            "Train/test overlap detected."
        )

    if (
        actual_files["validation"]
        & actual_files["test"]
    ):
        raise ValueError(
            "Validation/test overlap detected."
        )

    print(
        "All source-file assignments are correct."
    )

    print(
        "No source-file overlap exists."
    )


# ============================================================
# MAIN
# ============================================================

def main():

    if not INPUT_PATH.exists():

        raise FileNotFoundError(
            f"Input dataset not found:\n{INPUT_PATH}"
        )

    verify_file_groups()

    print()
    print("=" * 70)
    print("CREATING ATTACK FAMILY SPLITS")
    print("=" * 70)

    output_paths, total_counts = create_splits()

    print()
    print("=" * 70)
    print("SPLITS CREATED")
    print("=" * 70)

    for split_name, count in total_counts.items():

        print(
            f"{split_name.capitalize():12s}: "
            f"{count:,}"
        )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    for split_name, path in output_paths.items():

        analyze_split(
            split_name,
            path
        )

    # --------------------------------------------------------
    # Final verification
    # --------------------------------------------------------

    verify_final_splits()

    print()
    print("=" * 70)
    print("ATTACK FAMILY SPLITTING COMPLETE")
    print("=" * 70)

    print()
    print(f"Output directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()