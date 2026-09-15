from pathlib import Path

import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_DIR = (
    BASE_DIR
    / "data"
    / "processed"
    / "cse_cic_ids2018"
)

OUTPUT_DIR = (
    INPUT_DIR
    / "attack_family"
)


# ============================================================
# CONFIGURATION
# ============================================================

CHUNK_SIZE = 200_000


# ============================================================
# ATTACK FAMILY MAPPING
# ============================================================

ATTACK_FAMILY_MAP = {

    # --------------------------------------------------------
    # Benign
    # --------------------------------------------------------

    "Benign": "Benign",

    # --------------------------------------------------------
    # DDoS
    # --------------------------------------------------------

    "DDOS attack-HOIC": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",

    # --------------------------------------------------------
    # DoS
    # --------------------------------------------------------

    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-Slowloris": "DoS",

    # --------------------------------------------------------
    # Brute Force
    # --------------------------------------------------------

    "FTP-BruteForce": "Brute Force",
    "SSH-Bruteforce": "Brute Force",

    # --------------------------------------------------------
    # Web Attack
    # --------------------------------------------------------

    "Brute Force -Web": "Web Attack",
    "Brute Force -XSS": "Web Attack",
    "SQL Injection": "Web Attack",

    # --------------------------------------------------------
    # Bot
    # --------------------------------------------------------

    "Bot": "Bot",

    # --------------------------------------------------------
    # Infiltration
    # --------------------------------------------------------

    "Infilteration": "Infiltration",
}


# ============================================================
# FILE PROCESSING
# ============================================================

def process_file(input_path, output_path, first_file):
    print()
    print(f"Processing: {input_path.name}")

    first_chunk = first_file
    total_rows = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            input_path,
            chunksize=CHUNK_SIZE
        ),
        start=1
    ):

        print(f"  Chunk {chunk_number}...")

        # Remove accidental repeated header rows
        chunk = chunk[
            chunk["Label"].astype(str).str.strip() != "Label"
        ].copy()

        # Normalize original label
        chunk["Label"] = (
            chunk["Label"]
            .astype(str)
            .str.strip()
        )
        
        # ----------------------------------------------------
        # Preserve capture-file identity
        # ----------------------------------------------------

        chunk["SourceFile"] = input_path.name


        # Create attack family
        chunk["AttackFamily"] = (
            chunk["Label"].map(ATTACK_FAMILY_MAP)
        )

        # Check for unknown labels
        unknown_mask = chunk["AttackFamily"].isna()

        if unknown_mask.any():

            unknown_labels = (
                chunk.loc[
                    unknown_mask,
                    "Label"
                ]
                .value_counts()
            )

            print()
            print("ERROR: Unknown labels found:")

            for label, count in unknown_labels.items():
                print(f"  {label}: {count:,}")

            raise ValueError(
                "Attack family mapping is incomplete."
            )

        # Write first chunk of first file with header.
        # Everything else is appended.
        chunk.to_csv(
            output_path,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False
        )

        first_chunk = False
        total_rows += len(chunk)

    print(
        f"  Rows written: {total_rows:,}"
    )


# ============================================================
# CREATE FAMILY DATASET
# ============================================================

def create_family_dataset():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    print("=" * 70)
    print("CREATING ATTACK FAMILY DATASET")
    print("=" * 70)

    # --------------------------------------------------------
    # Only process the original cleaned CSV files.
    #
    # Do NOT process existing split directories.
    # --------------------------------------------------------

    input_files = sorted(
        INPUT_DIR.glob("*_clean.csv")
    )

    if not input_files:
        raise FileNotFoundError(
            f"No cleaned CSV files found in:\n{INPUT_DIR}"
        )

    print()
    print(
        f"Found {len(input_files)} cleaned files."
    )

    output_path = (
        OUTPUT_DIR
        / "all_attack_families.csv"
    )

    if output_path.exists():
        output_path.unlink()

    first_file = True

    for input_path in input_files:

        process_file(
            input_path,
            output_path,
            first_file
        )

        first_file = False

    return output_path


# ============================================================
# ANALYZE FAMILY DISTRIBUTION
# ============================================================

def analyze_distribution(output_path):

    print()
    print("=" * 70)
    print("ATTACK FAMILY DISTRIBUTION")
    print("=" * 70)

    family_counts = {}
    total_rows = 0

    for chunk in pd.read_csv(
        output_path,
        usecols=["AttackFamily"],
        chunksize=CHUNK_SIZE
    ):

        total_rows += len(chunk)

        counts = (
            chunk["AttackFamily"]
            .value_counts()
        )

        for family, count in counts.items():

            family_counts[family] = (
                family_counts.get(
                    family,
                    0
                )
                + int(count)
            )

    print()
    print(
        f"Total rows: {total_rows:,}"
    )

    print()

    print(
        f"{'Attack Family':20s}"
        f"{'Count':>15s}"
        f"{'Percentage':>15s}"
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


# ============================================================
# VERIFY LABEL MAPPING
# ============================================================

def verify_mapping(output_path):

    print()
    print("=" * 70)
    print("VERIFYING ORIGINAL LABEL → ATTACK FAMILY MAPPING")
    print("=" * 70)

    mapping_pairs = set()

    for chunk in pd.read_csv(
        output_path,
        usecols=[
            "Label",
            "AttackFamily"
        ],
        chunksize=CHUNK_SIZE
    ):

        pairs = chunk[
            [
                "Label",
                "AttackFamily"
            ]
        ].drop_duplicates()

        for _, row in pairs.iterrows():

            mapping_pairs.add(
                (
                    row["Label"],
                    row["AttackFamily"]
                )
            )

    for label, family in sorted(
        mapping_pairs
    ):

        print(
            f"{label:30s} → {family}"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    output_path = (
        create_family_dataset()
    )

    verify_mapping(
        output_path
    )

    analyze_distribution(
        output_path
    )

    print()
    print("=" * 70)
    print("ATTACK FAMILY DATASET CREATED SUCCESSFULLY")
    print("=" * 70)

    print()
    print(
        f"Output: {output_path}"
    )


if __name__ == "__main__":
    main()