from pathlib import Path

import pandas as pd


# =========================================================
# Paths
# =========================================================

PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")

CHUNK_SIZE = 200_000


# =========================================================
# Main
# =========================================================

def main() -> None:

    print()
    print("=" * 80)
    print("CSE-CIC-IDS2018 LABEL DISTRIBUTION BY FILE")
    print("=" * 80)
    print()

    files = sorted(
        PROCESSED_DIR.glob("*_clean.csv")
    )

    if not files:
        raise FileNotFoundError(
            f"No cleaned CSV files found in {PROCESSED_DIR}"
        )

    # -----------------------------------------------------
    # Store results
    # -----------------------------------------------------

    results = {}

    # -----------------------------------------------------
    # Process every file
    # -----------------------------------------------------

    for file in files:

        print(f"Processing: {file.name}")

        counts = {}

        for chunk in pd.read_csv(
            file,
            usecols=["Label"],
            chunksize=CHUNK_SIZE,
        ):

            chunk_counts = (
                chunk["Label"]
                .value_counts()
            )

            for label, count in chunk_counts.items():

                counts[label] = (
                    counts.get(label, 0)
                    + int(count)
                )

        results[file.name] = counts

    # -----------------------------------------------------
    # Build table
    # -----------------------------------------------------

    all_labels = sorted(
        {
            label
            for counts in results.values()
            for label in counts
        }
    )

    table = pd.DataFrame(
        0,
        index=results.keys(),
        columns=all_labels,
        dtype="int64",
    )

    for filename, counts in results.items():

        for label, count in counts.items():

            table.loc[
                filename,
                label,
            ] = count

    # -----------------------------------------------------
    # Print detailed result
    # -----------------------------------------------------

    print()
    print("=" * 80)
    print("COUNTS BY FILE")
    print("=" * 80)
    print()

    print(table.to_string())

    # -----------------------------------------------------
    # Print compact attack presence
    # -----------------------------------------------------

    print()
    print("=" * 80)
    print("ATTACK TYPES PRESENT IN EACH FILE")
    print("=" * 80)
    print()

    for filename in table.index:

        attacks = []

        for label in table.columns:

            if label != "Benign":

                count = table.loc[
                    filename,
                    label,
                ]

                if count > 0:
                    attacks.append(
                        f"{label} ({count:,})"
                    )

        print()
        print(filename)

        if attacks:

            for attack in attacks:
                print(f"  - {attack}")

        else:

            print("  - No attacks")

    # -----------------------------------------------------
    # Attack coverage by file
    # -----------------------------------------------------

    print()
    print("=" * 80)
    print("NUMBER OF ATTACK TYPES PER FILE")
    print("=" * 80)
    print()

    for filename in table.index:

        attack_count = sum(
            1
            for label in table.columns
            if label != "Benign"
            and table.loc[filename, label] > 0
        )

        print(
            f"{filename}: "
            f"{attack_count} attack type(s)"
        )

    print()
    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)


# =========================================================
# Entry point
# =========================================================

if __name__ == "__main__":
    main()