import os
import json
import joblib
import pandas as pd
import numpy as np
import shap


# ============================================================
# Paths
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_DIR = os.path.join(
    BASE_DIR,
    "models"
)

ML_READY_DIR = os.path.join(
    BASE_DIR,
    "data",
    "processed",
    "ml_ready"
)

MODEL_FILE = os.path.join(
    MODEL_DIR,
    "severity_model.pkl"
)

X_TEST_FILE = os.path.join(
    ML_READY_DIR,
    "X_test.csv"
)

TARGET_FILE = os.path.join(
    ML_READY_DIR,
    "target_names.json"
)


# ============================================================
# Load model and target names
# ============================================================

model = joblib.load(
    MODEL_FILE
)

X_test = pd.read_csv(
    X_TEST_FILE
)

with open(
    TARGET_FILE,
    "r",
    encoding="utf-8"
) as f:

    TARGET_NAMES = json.load(f)


# ============================================================
# SHAP explanation
# ============================================================

def explain_prediction(
    X: pd.DataFrame,
    target_index: int = 0,
    top_n: int = 10
) -> list:

    """
    Generate SHAP feature contributions for one
    vulnerability classifier.

    target_index:
        0 = Reentrancy
        1 = Access Control
        2 = Arithmetic
        ...
    """

    if target_index < 0 or target_index >= len(
        model.estimators_
    ):
        raise ValueError(
            "Invalid target index."
        )

    estimator = model.estimators_[
        target_index
    ]

    explainer = shap.TreeExplainer(
        estimator
    )

    shap_values = explainer.shap_values(
        X
    )

    # --------------------------------------------------------
    # Handle SHAP output formats across versions
    # --------------------------------------------------------

    if isinstance(shap_values, list):

        if len(shap_values) == 2:
            values = shap_values[1]
        else:
            values = shap_values[0]

    elif isinstance(shap_values, np.ndarray):

        if shap_values.ndim == 3:

            # Samples × features × classes
            if shap_values.shape[2] == 2:
                values = shap_values[:, :, 1]
            else:
                values = shap_values[:, :, 0]

        else:

            values = shap_values

    else:

        values = np.asarray(
            shap_values
        )

    # --------------------------------------------------------
    # First sample
    # --------------------------------------------------------

    sample_values = values[0]

    feature_names = list(
        X.columns
    )

    contributions = []

    for feature, contribution in zip(
        feature_names,
        sample_values
    ):

        contributions.append(
            {
                "feature": feature,
                "contribution": float(
                    contribution
                ),
                "absolute_contribution": abs(
                    float(contribution)
                )
            }
        )

    # --------------------------------------------------------
    # Sort by absolute contribution
    # --------------------------------------------------------

    contributions.sort(
        key=lambda x: x[
            "absolute_contribution"
        ],
        reverse=True
    )

    # --------------------------------------------------------
    # Return top features
    # --------------------------------------------------------

    return contributions[:top_n]


# ============================================================
# Test
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("TRUSTGUARD AI - SHAP EXPLAINABILITY TEST")
    print("=" * 70)

    # Use one real test sample.
    sample = X_test.iloc[[0]]

    print(
        f"\nSample shape: {sample.shape}"
    )

    for index, target in enumerate(
        TARGET_NAMES
    ):

        print(
            f"\nExplaining: {target}"
        )

        explanation = explain_prediction(
            sample,
            target_index=index,
            top_n=5
        )

        for item in explanation:

            print(
                f"  {item['feature']}: "
                f"{item['contribution']:+.6f}"
            )

    print("\n" + "=" * 70)
    print("SHAP EXPLANATION TEST COMPLETE")
    print("=" * 70)