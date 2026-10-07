import os
import pandas as pd


# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")


LABELS_FILE = os.path.join(RAW_DIR, "DIVE_Labels.csv")
PRE_FILE = os.path.join(RAW_DIR, "PRE_ProcessedData.csv")
POST_FILE = os.path.join(RAW_DIR, "POST_ProcessedData.csv")


OUTPUT_FILE = os.path.join(
    PROCESSED_DIR,
    "dive_ml_dataset.csv"
)


# --------------------------------------------------
# Main Dataset Builder
# --------------------------------------------------

def build_dataset():

    print("=" * 70)
    print("TRUSTGUARD AI - DIVE DATASET BUILDER")
    print("=" * 70)

    # Create processed directory if it doesn't exist
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    # --------------------------------------------------
    # 1. Load datasets
    # --------------------------------------------------

    print("\nLoading DIVE labels...")
    labels = pd.read_csv(LABELS_FILE)

    print("Loading PRE features...")
    pre = pd.read_csv(PRE_FILE, low_memory=False)

    print("Loading POST features...")
    post = pd.read_csv(POST_FILE, low_memory=False)

    print("\nOriginal dataset sizes:")

    print(f"Labels : {labels.shape}")
    print(f"PRE    : {pre.shape}")
    print(f"POST   : {post.shape}")

    # --------------------------------------------------
    # 2. Verify contractID
    # --------------------------------------------------

    required_files = {
        "Labels": labels,
        "PRE": pre,
        "POST": post
    }

    for name, df in required_files.items():

        if "contractID" not in df.columns:
            raise ValueError(
                f"{name} dataset does not contain contractID."
            )

        if df["contractID"].isnull().any():
            raise ValueError(
                f"{name} dataset contains missing contractID values."
            )

        if df["contractID"].duplicated().any():
            raise ValueError(
                f"{name} dataset contains duplicate contractID values."
            )

    print("\nContract ID validation: PASSED")

    # --------------------------------------------------
    # 3. Verify common contract population
    # --------------------------------------------------

    label_ids = set(labels["contractID"])
    pre_ids = set(pre["contractID"])
    post_ids = set(post["contractID"])

    common_ids = label_ids & pre_ids & post_ids

    print(f"\nCommon contract IDs: {len(common_ids):,}")

    if len(common_ids) != len(labels):
        raise ValueError(
            "Not all label contracts are present in PRE and POST datasets."
        )

    # --------------------------------------------------
    # 4. Merge PRE + POST
    # --------------------------------------------------

    print("\nMerging PRE and POST datasets...")

    dataset = pd.merge(
        pre,
        post,
        on="contractID",
        how="inner",
        suffixes=("_pre", "_post"),
        validate="one_to_one"
    )

    print(f"After PRE + POST merge: {dataset.shape}")

    # --------------------------------------------------
    # 5. Merge vulnerability labels
    # --------------------------------------------------

    print("\nMerging vulnerability labels...")

    dataset = pd.merge(
        dataset,
        labels,
        on="contractID",
        how="inner",
        validate="one_to_one"
    )

    print(f"Final dataset shape: {dataset.shape}")

    # --------------------------------------------------
    # 6. Final validation
    # --------------------------------------------------

    if dataset["contractID"].duplicated().any():
        raise ValueError(
            "Final dataset contains duplicate contract IDs."
        )

    if len(dataset) != len(common_ids):
        raise ValueError(
            "Final dataset does not contain exactly one row per contract."
        )

    print("\nFinal validation: PASSED")

    print(f"Contracts: {len(dataset):,}")
    print(f"Features + labels: {len(dataset.columns):,}")

    # --------------------------------------------------
    # 7. Save processed dataset
    # --------------------------------------------------

    print("\nSaving processed dataset...")

    dataset.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(f"\nSaved to:")
    print(OUTPUT_FILE)

    print("\n" + "=" * 70)
    print("DATASET BUILD COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    build_dataset()