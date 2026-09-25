from pathlib import Path

import pandas as pd


# =========================================================
# Paths
# =========================================================

PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")

CHUNK_SIZE = 200_000


# =========================================================
# Analyze labels
# =========================================================

def main() -> None:

    if not PROCESSED_DIR.exists():
        raise FileNotFoundError(
            f"Processed dataset directory not found: {PROCESSED_DIR}"
        )

    files = sorted(PROCESSED_DIR.glob("*.csv"))

    if not files:
        raise FileNotFoundError(
            f"No processed CSV files found in {PROCESSED_DIR}"
        )

    # Dictionary for global label counts
    label_counts = {}

    print()
    print("=" * 70)
    print("CSE-CIC-IDS2018 LABEL DISTRIBUTION")
    print("=" * 70)
    print(f"Files found: {len(files)}")
    print()

    # -----------------------------------------------------
    # Process every file
    # -----------------------------------------------------

    for file in files:

        print(f"Processing: {file.name}")

        file_counts = {}

        for chunk in pd.read_csv(
            file,
            usecols=["Label"],
            chunksize=CHUNK_SIZE,
        ):

            counts = chunk["Label"].value_counts()

            for label, count in counts.items():

                # Global count
                label_counts[label] = (
                    label_counts.get(label, 0) + int(count)
                )

                # File count
                file_counts[label] = (
                    file_counts.get(label, 0) + int(count)
                )

        print("  Labels found:", len(file_counts))
        print()

    # -----------------------------------------------------
    # Create result DataFrame
    # -----------------------------------------------------

    result = pd.DataFrame(
        list(label_counts.items()),
        columns=["Label", "Count"],
    )

    # Sort from largest to smallest
    result = result.sort_values(
        by="Count",
        ascending=False,
    ).reset_index(drop=True)

    # -----------------------------------------------------
    # Calculate percentages
    # -----------------------------------------------------

    total_rows = result["Count"].sum()

    result["Percentage"] = (
        result["Count"] / total_rows * 100
    )

    # -----------------------------------------------------
    # Print result
    # -----------------------------------------------------

    print("=" * 70)
    print("LABEL DISTRIBUTION")
    print("=" * 70)

    print(
        result.to_string(
            index=False,
            formatters={
                "Count": "{:,}".format,
                "Percentage": "{:.4f}%".format,
            },
        )
    )

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(f"Total rows: {total_rows:,}")
    print(f"Total classes: {len(result)}")

    # -----------------------------------------------------
    # Binary distribution
    # -----------------------------------------------------

    benign_count = label_counts.get("Benign", 0)

    attack_count = total_rows - benign_count

    benign_percentage = (
        benign_count / total_rows * 100
        if total_rows > 0
        else 0
    )

    attack_percentage = (
        attack_count / total_rows * 100
        if total_rows > 0
        else 0
    )

    print()
    print("Binary classification view:")
    print(f"  Benign:  {benign_count:,} ({benign_percentage:.4f}%)")
    print(f"  Attack:  {attack_count:,} ({attack_percentage:.4f}%)")

    print()
    print("=" * 70)
    print("LABEL ANALYSIS COMPLETE")
    print("=" * 70)


# =========================================================
# Entry point
# =========================================================

if __name__ == "__main__":
    main()