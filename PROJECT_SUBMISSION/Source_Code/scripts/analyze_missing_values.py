from pathlib import Path
import pandas as pd


PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")
CHUNK_SIZE = 200_000


def main():

    files = sorted(PROCESSED_DIR.glob("*_clean.csv"))

    total_missing = {}

    print("=" * 70)
    print("MISSING VALUE ANALYSIS")
    print("=" * 70)

    for file in files:

        print(f"\nProcessing: {file.name}")

        for chunk in pd.read_csv(
            file,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ):

            missing = chunk.isna().sum()

            for column, count in missing.items():

                if count > 0:
                    total_missing[column] = (
                        total_missing.get(column, 0) + int(count)
                    )

    print()
    print("=" * 70)
    print("MISSING VALUES BY COLUMN")
    print("=" * 70)

    if not total_missing:
        print("No missing values found.")
        return

    for column, count in sorted(
        total_missing.items(),
        key=lambda x: x[1],
        reverse=True,
    ):
        print(f"{column}: {count:,}")

    print()
    print("=" * 70)
    print(f"TOTAL MISSING VALUES: {sum(total_missing.values()):,}")
    print("=" * 70)


if __name__ == "__main__":
    main()