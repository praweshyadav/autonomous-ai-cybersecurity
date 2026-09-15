from pathlib import Path
from collections import Counter
import pandas as pd


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------
DATA_DIR = Path("data/raw/cse_cic_ids2018")
OUTPUT_DIR = Path("data/processed/dataset_audit")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# Find CSV files
# ---------------------------------------------------------
files = sorted(DATA_DIR.glob("*.csv"))

if not files:
    raise FileNotFoundError(f"No CSV files found in {DATA_DIR}")

print("=" * 70)
print("CSE-CIC-IDS2018 DATASET AUDIT")
print("=" * 70)
print(f"CSV files found: {len(files)}")
print()


# ---------------------------------------------------------
# Storage for results
# ---------------------------------------------------------
file_summary = []
all_labels = Counter()
global_missing = Counter()


# ---------------------------------------------------------
# Inspect every CSV
# ---------------------------------------------------------
for i, file in enumerate(files, start=1):

    print("-" * 70)
    print(f"[{i}/{len(files)}] {file.name}")
    print("-" * 70)

    # -----------------------------------------------------
    # Read header only
    # -----------------------------------------------------
    header = pd.read_csv(file, nrows=0)

    columns = header.columns.tolist()

    print(f"Columns: {len(columns)}")

    if "Label" not in columns:
        print("WARNING: Label column not found!")
        continue

    # -----------------------------------------------------
    # Process file in chunks
    # -----------------------------------------------------
    row_count = 0
    label_counts = Counter()
    missing_counts = Counter()

    for chunk in pd.read_csv(
        file,
        chunksize=200_000,
        low_memory=False
    ):

        row_count += len(chunk)

        # -----------------------------
        # Label distribution
        # -----------------------------
        labels = chunk["Label"].astype(str).str.strip()

        label_counts.update(labels.value_counts().to_dict())
        all_labels.update(labels.value_counts().to_dict())

        # -----------------------------
        # Missing values
        # -----------------------------
        missing = chunk.isna().sum()

        for column, count in missing.items():
            if count > 0:
                missing_counts[column] += int(count)
                global_missing[column] += int(count)

    # -----------------------------------------------------
    # Print file information
    # -----------------------------------------------------
    print(f"Rows: {row_count}")

    print("\nLabels:")
    for label, count in label_counts.most_common():
        print(f"  {label}: {count:,}")

    # Detect accidental header rows
    header_rows = label_counts.get("Label", 0)

    if header_rows:
        print(f"\nWARNING: Found {header_rows} row(s) where Label == 'Label'")

    # -----------------------------------------------------
    # Store summary
    # -----------------------------------------------------
    file_summary.append(
        {
            "file": file.name,
            "rows": row_count,
            "columns": len(columns),
            "unique_labels": len(label_counts),
            "header_rows": header_rows,
            "missing_values": sum(missing_counts.values()),
        }
    )

    print()


# ---------------------------------------------------------
# Overall label distribution
# ---------------------------------------------------------
print("=" * 70)
print("OVERALL LABEL DISTRIBUTION")
print("=" * 70)

for label, count in all_labels.most_common():
    print(f"{label}: {count:,}")


# ---------------------------------------------------------
# Overall missing values
# ---------------------------------------------------------
print()
print("=" * 70)
print("MISSING VALUES")
print("=" * 70)

if global_missing:
    for column, count in global_missing.most_common():
        print(f"{column}: {count:,}")
else:
    print("No missing values found.")


# ---------------------------------------------------------
# Save reports
# ---------------------------------------------------------
summary_df = pd.DataFrame(file_summary)

summary_df.to_csv(
    OUTPUT_DIR / "file_summary.csv",
    index=False
)

label_df = pd.DataFrame(
    all_labels.items(),
    columns=["Label", "Count"]
).sort_values(
    "Count",
    ascending=False
)

label_df.to_csv(
    OUTPUT_DIR / "label_distribution.csv",
    index=False
)


# ---------------------------------------------------------
# Final summary
# ---------------------------------------------------------
print()
print("=" * 70)
print("AUDIT COMPLETE")
print("=" * 70)

print(f"Files analyzed: {len(files)}")
print(f"Total rows: {sum(all_labels.values()):,}")

print()
print("Reports created:")
print(f"  {OUTPUT_DIR / 'file_summary.csv'}")
print(f"  {OUTPUT_DIR / 'label_distribution.csv'}")