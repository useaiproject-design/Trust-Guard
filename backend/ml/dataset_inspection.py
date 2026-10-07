import os
import pandas as pd


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")


FILES = [
    "DIVE_Labels.csv",
    "Tool_Results.csv",
    "PRE_ProcessedData.csv",
    "POST_ProcessedData.csv",
]


def inspect_file(filename):
    path = os.path.join(RAW_DIR, filename)

    print("\n" + "=" * 80)
    print(f"FILE: {filename}")
    print("=" * 80)

    if not os.path.exists(path):
        print("ERROR: File not found")
        return

    df = pd.read_csv(path, low_memory=False)

    print(f"\nRows: {df.shape[0]:,}")
    print(f"Columns: {df.shape[1]:,}")

    print("\nColumn names:")
    for i, column in enumerate(df.columns, start=1):
        print(f"{i:4}. {column}")

    print("\nData types:")
    print(df.dtypes.to_string())

    print("\nMissing values:")
    missing = df.isnull().sum()
    missing = missing[missing > 0].sort_values(ascending=False)

    if missing.empty:
        print("No missing values found.")
    else:
        print(missing.to_string())

    print("\nDuplicate rows:")
    print(df.duplicated().sum())

    print("\nFirst 3 rows:")
    print(df.head(3).to_string())


def main():
    print("=" * 80)
    print("TRUSTGUARD AI - DIVE DATASET INSPECTION")
    print("=" * 80)

    print(f"\nRaw dataset directory:")
    print(RAW_DIR)

    for filename in FILES:
        inspect_file(filename)

    print("\n" + "=" * 80)
    print("INSPECTION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()