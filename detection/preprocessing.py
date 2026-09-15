from pathlib import Path

import numpy as np
import pandas as pd


# =========================================================
# Paths
# =========================================================

RAW_DIR = Path("data/raw/cse_cic_ids2018")
PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")


# =========================================================
# Configuration
# =========================================================

CHUNK_SIZE = 200_000


# =========================================================
# Common 80-column schema
# =========================================================

COMMON_COLUMNS = [
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Tot",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Tot",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Pkt Len Min",
    "Pkt Len Max",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Var",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "CWE Flag Count",
    "ECE Flag Cnt",
    "Down/Up Ratio",
    "Pkt Size Avg",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts",
    "Subflow Fwd Byts",
    "Subflow Bwd Pkts",
    "Subflow Bwd Byts",
    "Init Fwd Win Byts",
    "Init Bwd Win Byts",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
    "Label",
]


# =========================================================
# Feature columns
# =========================================================

NUMERIC_COLUMNS = [
    column
    for column in COMMON_COLUMNS
    if column not in ["Timestamp", "Label"]
]


# =========================================================
# Clean one chunk
# =========================================================

def clean_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    """
    Clean one chunk of the CSE-CIC-IDS2018 dataset.

    Operations:
    1. Remove accidental repeated header rows.
    2. Convert numeric features to numeric dtype.
    3. Replace infinite values with NaN.
    4. Recalculate Flow Pkts/s.
    5. Recalculate Flow Byts/s.
    6. Handle undefined derived values.
    """

    # -----------------------------------------------------
    # 1. Clean label text
    # -----------------------------------------------------

    chunk["Label"] = (
        chunk["Label"]
        .astype(str)
        .str.strip()
    )

    # Remove accidental repeated header rows
    chunk = chunk[
        chunk["Label"] != "Label"
    ].copy()

    # -----------------------------------------------------
    # 2. Convert numeric columns
    # -----------------------------------------------------

    for column in NUMERIC_COLUMNS:
        chunk[column] = pd.to_numeric(
            chunk[column],
            errors="coerce",
        )

    # -----------------------------------------------------
    # 3. Replace infinite values
    # -----------------------------------------------------

    chunk.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True,
    )

    # =====================================================
    # 4. Recalculate Flow Pkts/s
    #
    # Flow Duration is measured in microseconds.
    #
    # Flow Pkts/s =
    #
    #     Tot Fwd Pkts + Tot Bwd Pkts
    #     ---------------------------
    #       Flow Duration / 1,000,000
    # =====================================================

    duration_seconds = (
        chunk["Flow Duration"] / 1_000_000
    )

    total_packets = (
        chunk["Tot Fwd Pkts"]
        + chunk["Tot Bwd Pkts"]
    )

    valid_duration = (
        duration_seconds > 0
    )

    calculated_flow_pkts_s = pd.Series(
        np.nan,
        index=chunk.index,
        dtype="float64",
    )

    calculated_flow_pkts_s.loc[
        valid_duration
    ] = (
        total_packets.loc[valid_duration]
        / duration_seconds.loc[valid_duration]
    )

    chunk["Flow Pkts/s"] = (
        calculated_flow_pkts_s
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
    )

    # =====================================================
    # 5. Recalculate Flow Byts/s
    #
    # Total bytes =
    #
    #     TotLen Fwd Pkts + TotLen Bwd Pkts
    #
    # Flow Byts/s =
    #
    #     Total bytes
    #     -----------
    #     duration_seconds
    # =====================================================

    total_bytes = (
        chunk["TotLen Fwd Pkts"]
        + chunk["TotLen Bwd Pkts"]
    )

    calculated_flow_byts_s = pd.Series(
        np.nan,
        index=chunk.index,
        dtype="float64",
    )

    calculated_flow_byts_s.loc[
        valid_duration
    ] = (
        total_bytes.loc[valid_duration]
        / duration_seconds.loc[valid_duration]
    )

    chunk["Flow Byts/s"] = (
        calculated_flow_byts_s
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
    )

    # -----------------------------------------------------
    # 6. Return cleaned chunk
    # -----------------------------------------------------

    return chunk


# =========================================================
# Process one CSV
# =========================================================

def process_file(input_file: Path) -> None:
    """
    Process one raw CSV file in chunks.
    """

    output_file = (
        PROCESSED_DIR
        / f"{input_file.stem}_clean.csv"
    )

    print("=" * 70)
    print(f"Processing: {input_file.name}")
    print(f"Output:    {output_file}")
    print("=" * 70)

    first_chunk = True

    total_input_rows = 0
    total_output_rows = 0

    # -----------------------------------------------------
    # Read the file in chunks
    # -----------------------------------------------------

    for chunk in pd.read_csv(
        input_file,
        usecols=lambda column: (
            column in COMMON_COLUMNS
        ),
        chunksize=CHUNK_SIZE,
        low_memory=False,
    ):

        total_input_rows += len(chunk)

        # -------------------------------------------------
        # Clean chunk
        # -------------------------------------------------

        cleaned = clean_chunk(chunk)

        total_output_rows += len(cleaned)

        # -------------------------------------------------
        # Write chunk
        # -------------------------------------------------

        cleaned.to_csv(
            output_file,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False,
        )

        first_chunk = False

        print(
            f"Processed rows: "
            f"{total_input_rows:,} "
            f"| Output rows: "
            f"{total_output_rows:,}"
        )

    # -----------------------------------------------------
    # File summary
    # -----------------------------------------------------

    print()
    print(f"Finished: {input_file.name}")
    print(f"Input rows:  {total_input_rows:,}")
    print(f"Output rows: {total_output_rows:,}")
    print()


# =========================================================
# Main
# =========================================================

def main() -> None:

    # -----------------------------------------------------
    # Check raw dataset directory
    # -----------------------------------------------------

    if not RAW_DIR.exists():
        raise FileNotFoundError(
            f"Raw dataset directory not found: {RAW_DIR}"
        )

    # -----------------------------------------------------
    # Create processed directory
    # -----------------------------------------------------

    PROCESSED_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # -----------------------------------------------------
    # Find raw CSV files
    # -----------------------------------------------------

    files = sorted(
        RAW_DIR.glob("*.csv")
    )

    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {RAW_DIR}"
        )

    # -----------------------------------------------------
    # Start
    # -----------------------------------------------------

    print()
    print("=" * 70)
    print("CSE-CIC-IDS2018 PREPROCESSING")
    print("=" * 70)
    print(f"Files found: {len(files)}")
    print()

    # -----------------------------------------------------
    # Process every file
    # -----------------------------------------------------

    for file in files:
        process_file(file)

    # -----------------------------------------------------
    # Complete
    # -----------------------------------------------------

    print("=" * 70)
    print("PREPROCESSING COMPLETE")
    print("=" * 70)


# =========================================================
# Entry point
# =========================================================

if __name__ == "__main__":
    main()