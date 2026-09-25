from pathlib import Path
import pandas as pd


PROCESSED_DIR = Path("data/processed/cse_cic_ids2018")

SAMPLE_SIZE = 10000


def analyze_file(file_path):

    print("\n" + "=" * 80)
    print(file_path.name)
    print("=" * 80)

    df = pd.read_csv(
        file_path,
        usecols=["Timestamp"],
        nrows=SAMPLE_SIZE
    )

    print("\nRaw timestamp examples:")

    for value in df["Timestamp"].head(20):
        print(f"  {repr(value)}")

    print("\nData type:")
    print(df["Timestamp"].dtype)

    # --------------------------------------------------------
    # Try normal parsing
    # --------------------------------------------------------

    parsed_default = pd.to_datetime(
        df["Timestamp"],
        errors="coerce"
    )

    print("\nDefault parsing:")
    print(
        f"Valid: {parsed_default.notna().sum():,}"
    )
    print(
        f"Invalid: {parsed_default.isna().sum():,}"
    )

    if parsed_default.notna().any():
        print(
            f"Min: {parsed_default.min()}"
        )
        print(
            f"Max: {parsed_default.max()}"
        )

    # --------------------------------------------------------
    # Try dayfirst parsing
    # --------------------------------------------------------

    parsed_dayfirst = pd.to_datetime(
        df["Timestamp"],
        errors="coerce",
        dayfirst=True
    )

    print("\nDay-first parsing:")

    print(
        f"Valid: {parsed_dayfirst.notna().sum():,}"
    )

    print(
        f"Invalid: {parsed_dayfirst.isna().sum():,}"
    )

    if parsed_dayfirst.notna().any():
        print(
            f"Min: {parsed_dayfirst.min()}"
        )
        print(
            f"Max: {parsed_dayfirst.max()}"
        )

    # --------------------------------------------------------
    # Values that produced suspicious dates
    # --------------------------------------------------------

    suspicious = parsed_dayfirst[
        parsed_dayfirst.dt.year < 2000
    ]

    print("\nSuspicious dates (< year 2000):")

    print(
        f"Count: {len(suspicious):,}"
    )

    if len(suspicious) > 0:

        print("\nCorresponding raw values:")

        for index in suspicious.index[:20]:

            print(
                f"  Raw: {repr(df.loc[index, 'Timestamp'])}"
                f" -> Parsed: {parsed_dayfirst.loc[index]}"
            )


def main():

    files = sorted(
        PROCESSED_DIR.glob("*_clean.csv")
    )

    print("=" * 80)
    print("CSE-CIC-IDS2018 TIMESTAMP FORMAT ANALYSIS")
    print("=" * 80)

    print(f"\nFiles found: {len(files)}")

    for file_path in files:
        analyze_file(file_path)

    print("\n")
    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()