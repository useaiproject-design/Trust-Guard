import os
import json
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder


# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODEL_DIR = os.path.join(BASE_DIR, "models")

INPUT_FILE = os.path.join(
    PROCESSED_DIR,
    "dive_ml_dataset.csv"
)

OUTPUT_DIR = os.path.join(
    PROCESSED_DIR,
    "ml_ready"
)


# ============================================================
# Target columns
# ============================================================

TARGET_COLUMNS = [
    "Reentrancy",
    "Access Control",
    "Arithmetic",
    "Unchecked Return Values",
    "DoS",
    "Bad Randomness",
    "Front Running",
    "Time manipulation"
]


# ============================================================
# Categorical columns
# ============================================================

CATEGORICAL_COLUMNS = [
    "CompilerVersion",
    "EVMVersion",
    "LicenseType",
    "Experimental Features",
    "mostFrequentOpcode_pre",
    "methodId",
    "part_of_day",
    "block_position",
    "mostFrequentOpcode_post"
]


# ============================================================
# Main preprocessing function
# ============================================================

def preprocess_dataset():

    print("=" * 70)
    print("TRUSTGUARD AI - DIVE DATA PREPROCESSING")
    print("=" * 70)

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    print("\nLoading processed DIVE dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    print(f"Input shape: {df.shape}")

    # --------------------------------------------------------
    # Validate target columns
    # --------------------------------------------------------

    missing_targets = [
        col for col in TARGET_COLUMNS
        if col not in df.columns
    ]

    if missing_targets:
        raise ValueError(
            f"Missing target columns: {missing_targets}"
        )

    print("\nTarget validation: PASSED")

    # --------------------------------------------------------
    # Validate categorical columns
    # --------------------------------------------------------

    missing_categorical = [
        col for col in CATEGORICAL_COLUMNS
        if col not in df.columns
    ]

    if missing_categorical:
        raise ValueError(
            f"Missing categorical columns: {missing_categorical}"
        )

    print("Categorical feature validation: PASSED")

    # --------------------------------------------------------
    # Validate missing values
    # --------------------------------------------------------

    total_missing = int(df.isna().sum().sum())

    print(f"\nTotal missing values: {total_missing}")

    if total_missing != 0:
        raise ValueError(
            "Unexpected missing values found in dataset."
        )

    # --------------------------------------------------------
    # Separate targets
    # --------------------------------------------------------

    y = df[TARGET_COLUMNS].copy()

    # --------------------------------------------------------
    # Remove identifier and targets from features
    # --------------------------------------------------------

    columns_to_remove = [
        "contractID"
    ] + TARGET_COLUMNS

    X = df.drop(
        columns=columns_to_remove
    )

    print(f"\nRaw feature matrix shape: {X.shape}")
    print(f"Target matrix shape: {y.shape}")

    # --------------------------------------------------------
    # Identify numeric columns
    # --------------------------------------------------------

    numeric_columns = [
        col for col in X.columns
        if col not in CATEGORICAL_COLUMNS
    ]

    print(f"\nNumeric features: {len(numeric_columns)}")
    print(f"Categorical features: {len(CATEGORICAL_COLUMNS)}")

    # --------------------------------------------------------
    # One-hot encode categorical features
    # --------------------------------------------------------

    print("\nEncoding categorical features...")

    encoder = OneHotEncoder(
        handle_unknown="ignore",
        sparse_output=False
    )

    encoded = encoder.fit_transform(
        X[CATEGORICAL_COLUMNS]
    )

    encoded_columns = encoder.get_feature_names_out(
        CATEGORICAL_COLUMNS
    )

    encoded_df = pd.DataFrame(
        encoded,
        columns=encoded_columns,
        index=X.index
    )

    # --------------------------------------------------------
    # Numeric feature dataframe
    # --------------------------------------------------------

    numeric_df = X[numeric_columns].copy()

    # --------------------------------------------------------
    # Combine numeric + encoded categorical features
    # --------------------------------------------------------

    X_processed = pd.concat(
        [
            numeric_df,
            encoded_df
        ],
        axis=1
    )

    # --------------------------------------------------------
    # Final validation
    # --------------------------------------------------------

    if X_processed.isna().any().any():
        raise ValueError(
            "Missing values detected after preprocessing."
        )

    if not X_processed.select_dtypes(
        exclude=["number"]
    ).empty:

        raise ValueError(
            "Non-numeric columns remain after preprocessing."
        )

    print(
        f"\nProcessed feature matrix shape: "
        f"{X_processed.shape}"
    )

    # --------------------------------------------------------
    # Train/test split
    #
    # NOTE:
    # We use the same split indices for every vulnerability
    # because this is a multi-label prediction problem.
    # --------------------------------------------------------

    train_indices, test_indices = train_test_split(
        X_processed.index,
        test_size=0.20,
        random_state=42,
        shuffle=True
    )

    X_train = X_processed.loc[train_indices]
    X_test = X_processed.loc[test_indices]

    y_train = y.loc[train_indices]
    y_test = y.loc[test_indices]

    # --------------------------------------------------------
    # Save datasets
    # --------------------------------------------------------

    print("\nSaving ML datasets...")

    X_train.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "X_train.csv"
        ),
        index=False
    )

    X_test.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "X_test.csv"
        ),
        index=False
    )

    y_train.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "y_train.csv"
        ),
        index=False
    )

    y_test.to_csv(
        os.path.join(
            OUTPUT_DIR,
            "y_test.csv"
        ),
        index=False
    )

    # --------------------------------------------------------
    # Save feature names
    # --------------------------------------------------------

    feature_names = list(
        X_processed.columns
    )

    with open(
        os.path.join(
            OUTPUT_DIR,
            "feature_names.json"
        ),
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            feature_names,
            f,
            indent=2
        )

    # --------------------------------------------------------
    # Save target names
    # --------------------------------------------------------

    with open(
        os.path.join(
            OUTPUT_DIR,
            "target_names.json"
        ),
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            TARGET_COLUMNS,
            f,
            indent=2
        )

    # --------------------------------------------------------
    # Print summary
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("PREPROCESSING COMPLETE")
    print("=" * 70)

    print(f"\nOriginal contracts : {len(df):,}")
    print(f"Training contracts : {len(X_train):,}")
    print(f"Testing contracts  : {len(X_test):,}")

    print(f"\nFinal ML features  : {X_processed.shape[1]:,}")
    print(f"Target labels      : {len(TARGET_COLUMNS)}")

    print("\nTargets:")

    for target in TARGET_COLUMNS:
        print(
            f"  {target}: "
            f"{int(y[target].sum()):,} vulnerable"
        )

    print("\nOutput directory:")
    print(OUTPUT_DIR)

    print("\n" + "=" * 70)


if __name__ == "__main__":
    preprocess_dataset()