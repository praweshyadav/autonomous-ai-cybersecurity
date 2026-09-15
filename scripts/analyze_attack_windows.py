from pathlib import Path
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")

CHUNK_SIZE = 200_000

# Columns required for this analysis
USECOLS = ["Timestamp", "Label"]


# ============================================================
# MAIN ANALYSIS
# ============================================================

def analyze_file(file_path):
    print(f"\nProcessing: {file_path.name}")

    attack_times = {}

    total_rows = 0

    for chunk in pd.read_csv(
        file_path,
        usecols=USECOLS,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):
        total_rows += len(chunk)

        # Parse timestamps
        chunk["Timestamp"] = pd.to_datetime(
            chunk["Timestamp"],
            errors="coerce",
            dayfirst=True
        )

        # Remove invalid timestamps
        chunk = chunk.dropna(subset=["Timestamp"])

        # Ignore benign traffic
        attack_chunk = chunk[chunk["Label"] != "Benign"]

        if attack_chunk.empty:
            continue

        # Group timestamps by attack label
        for label, group in attack_chunk.groupby("Label"):
            if label not in attack_times:
                attack_times[label] = []

            attack_times[label].append(
                (
                    group["Timestamp"].min(),
                    group["Timestamp"].max(),
                    len(group)
                )
            )

    print(f"Total rows: {total_rows:,}")

    # --------------------------------------------------------
    # Print attack windows
    # --------------------------------------------------------

    for label, windows in sorted(attack_times.items()):

        earliest = min(w[0] for w in windows)
        latest = max(w[1] for w in windows)
        total_attack_rows = sum(w[2] for w in windows)

        duration = latest - earliest

        print("\n" + "-" * 80)
        print(f"ATTACK: {label}")
        print("-" * 80)

        print(f"Attack flows : {total_attack_rows:,}")
        print(f"First event  : {earliest}")
        print(f"Last event   : {latest}")
        print(f"Duration     : {duration}")

        # ----------------------------------------------------
        # Daily distribution
        # ----------------------------------------------------

        daily_counts = {}

        for start, end, count in windows:
            day = start.date()

            if day not in daily_counts:
                daily_counts[day] = 0

            daily_counts[day] += count

        print("\nDaily distribution:")

        for day, count in sorted(daily_counts.items()):
            print(f"  {day}: {count:,}")


# ============================================================
# RUN
# ============================================================

def main():

    files = sorted(PROCESSED_DIR.glob("*_clean.csv"))

    if not files:
        print("ERROR: No cleaned CSV files found.")
        print(f"Expected directory: {PROCESSED_DIR}")
        return

    print("=" * 80)
    print("CSE-CIC-IDS2018 ATTACK WINDOW ANALYSIS")
    print("=" * 80)

    print(f"\nFiles found: {len(files)}")

    for file_path in files:
        analyze_file(file_path)

    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()